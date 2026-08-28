// Command tls-forge fetches URLs with a browser's TLS fingerprint, and — more
// usefully — proves that it does.
//
//	tls-forge capture            measure the browser on this machine
//	tls-forge compare            diff this library against that browser
//	tls-forge fetch <url>        make a request wearing the fingerprint
//	tls-forge serve              run the local echo server, point anything at it
//	tls-forge daemon             JSON lines on stdin/stdout, for other languages
//	tls-forge profiles           list what can be impersonated
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"

	"github.com/spf13/pflag"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags)"
var version = "dev"

// errDiffers reports a comparison that found differences.
//
// Not a failure of the program — the report is the output, and it has already
// been printed — but it must still exit non-zero so it can gate a release. A
// browser update is exactly the moment an impersonation stops being true, and
// it does so quietly.
var errDiffers = errors.New("the client and the browser differ")

func warnPublicListener(component, addr string, out *printer) {
	if listenerIsLoopback(addr) {
		return
	}
	out.printf("WARNING: %s is listening beyond loopback at %s without authentication.\n", component, addr)
	out.println("Restrict it with a firewall or bind it to 127.0.0.1/::1.")
	out.println()
}

func listenerIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return net.ParseIP(host).IsLoopback()
}

// Exit codes. A comparison that ran and disagreed is a different thing from one
// that could not run, and anything automating this has to tell them apart: a
// scheduled check that treats "the browser would not start" as "the profile has
// drifted" files an issue every week for a broken runner. They shared code 1
// until something needed the difference.
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitDiffers = 3
)

type command struct {
	name    string
	summary string
	// Two writers, not one. Results go to out; a warning goes to errOut,
	// because a line of commentary on stdout would land in the middle of the
	// JSON that batch is producing and break whatever is reading it.
	run func(ctx context.Context, args []string, out, errOut *printer) error
}

func commands() []command {
	return []command{
		{"fetch", "make a request with a browser fingerprint", runFetch},
		{"batch", "fetch a list of URLs, each through its own proxy", runBatch},
		{"capture", "measure the browser installed on this machine", runCapture},
		{"compare", "diff this library's handshake against the browser's", runCompare},
		{"profiles", "list the profiles that can be impersonated", runProfiles},
		{"proxy", "run a proxy that re-sends every request with the fingerprint", runProxy},
		{"serve", "run the local fingerprint echo server", runServe},
		{"daemon", "speak JSON lines on stdin/stdout", runDaemon},
		{"version", "print the version", runVersion},
	}
}

// exit is os.Exit, named so the entry point can be driven from a test. Without
// the seam, the wiring between argv, the signal handler and the exit code is the
// one part of the program nothing checks.
var exit = os.Exit

func main() {
	// One exit point. Commands return errors and print to the writer they are
	// given, which is what lets every one of them be driven from a test.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	releaseSignal(ctx, stop)
	exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// releaseSignal hands interrupts back to the runtime after the first one.
//
// NotifyContext catches the interrupt and cancels the context instead of
// letting it end the process. That is right for a command that can wind itself
// down, and wrong for one blocked on a read that never looks at a context: the
// signal is swallowed, nothing happens, and every further Ctrl-C is swallowed
// too. Measured before this: `tls-forge batch` waiting on standard input
// survived four of them.
//
// So the first interrupt still asks for an orderly stop, and any after it kill
// the process the way they would have if nothing had been listening.
func releaseSignal(ctx context.Context, stop func()) {
	go func() {
		<-ctx.Done()
		stop()
	}()
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	out, errOut := newPrinter(stdout), newPrinter(stderr)
	if len(args) == 0 {
		usage(errOut)
		return 2
	}

	name := args[0]
	for _, c := range commands() {
		if c.name != name {
			continue
		}
		err := c.run(ctx, args[1:], out, errOut)
		// A command that printed nothing because the pipe was closed did not
		// succeed, whatever it returned.
		if err == nil {
			err = out.err
		}
		switch {
		case err == nil:
			return exitOK
		case errors.Is(err, errDiffers):
			return exitDiffers
		case errors.Is(err, pflag.ErrHelp):
			return exitUsage
		case errors.Is(err, errUsage):
			errOut.println("tlsforge:", err)
			return exitUsage
		default:
			errOut.println("tlsforge:", err)
			return exitError
		}
	}

	if name == "-h" || name == "--help" || name == "help" {
		usage(out)
		return 0
	}
	errOut.printf("tlsforge: unknown command %q\n\n", name)
	usage(errOut)
	return 2
}

func usage(out *printer) {
	out.println("tls-forge — an HTTP client that sends a real browser's TLS fingerprint.")
	out.println()
	out.println("usage: tls-forge <command> [flags]")
	out.println()
	for _, c := range commands() {
		out.printf("  %-10s %s\n", c.name, c.summary)
	}
	out.println()
	out.println("Run `tls-forge <command> --help` for a command's flags.")
	out.println()
	out.println("Start with `tls-forge compare`: it opens your browser, measures it, measures")
	out.println("this library, and prints the differences. There should not be any.")
}

// errUsage marks a command that was never run because its arguments did not
// parse.
//
// It exits 2 rather than 1 for a reason beyond convention: compare uses 3 to
// mean "the fingerprints differ", so a mistyped flag cannot be mistaken for a
// broken impersonation by the CI job watching for exactly that.
var errUsage = errors.New("bad usage")

// parse reads a command's flags, reporting a bad one as a usage error.
func parse(fs *pflag.FlagSet, args []string) error {
	err := fs.Parse(args)
	if err == nil || errors.Is(err, pflag.ErrHelp) {
		return err
	}
	return fmt.Errorf("%w: %w", errUsage, err)
}

// requireNoArgs rejects positional arguments for commands whose entire input
// is flags. Without this, a misspelled flag such as `profiles chrome` is
// silently ignored and the command reports success for something it never did.
func requireNoArgs(fs *pflag.FlagSet) error {
	if fs.NArg() == 0 {
		return nil
	}
	fs.Usage()
	return fmt.Errorf("%w: %s takes no arguments", errUsage, fs.Name())
}

// newFlagSet returns a flag set that reports errors instead of exiting, so a
// bad flag is a non-zero exit from one place rather than a call to os.Exit from
// inside a command.
//
// pflag rather than the standard library, for the convention every other
// command-line tool follows: one dash introduces a short flag, two a long one,
// and `--flag=value` works. The standard package treats `-flag` and `--flag` as
// the same thing and has no notion of a short form at all.
func newFlagSet(name string, out io.Writer) *pflag.FlagSet {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	// pflag writes its own complaint about a bad flag to this writer. Discarded,
	// because run prints the error it gets back, and on stderr where every other
	// diagnostic goes; without this the same thing is said twice, once on each
	// stream.
	fs.SetOutput(io.Discard)
	fs.SortFlags = false
	// The default line is "Usage of capture:", which names neither the program
	// nor how to run the command.
	setUsage(fs, out, "usage: tls-forge "+name+" [flags]")
	return fs
}

// setUsage gives a command one usage block, so the seven of them cannot end up
// describing themselves seven different ways.
func setUsage(fs *pflag.FlagSet, out io.Writer, line string) {
	fs.Usage = func() {
		_, _ = io.WriteString(out, line+"\n")
		if flags := fs.FlagUsages(); flags != "" {
			_, _ = io.WriteString(out, "\nflags:\n"+flags)
		} else {
			_, _ = io.WriteString(out, "\nThis command takes no flags.\n")
		}
	}
}

func runVersion(_ context.Context, args []string, out, _ *printer) error {
	// A flag set for a command with no flags, so that --help answers here the
	// way it answers everywhere else rather than being read as a URL.
	fs := newFlagSet("version", out)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}
	out.println("tls-forge", version)
	return nil
}

// printer is the stream a command writes to. It keeps the first write error
// rather than returning one from every call.
//
// The alternative was to check the result of fifty-nine print calls or to
// discard fifty-nine errors, and both hide the case that matters: a shell
// pipeline like `tls-forge fetch … | head -1` closes stdout early, and a
// command that ignored that would go on writing into a dead pipe and exit 0.
// The failure is remembered once here and reported by run.
type printer struct {
	w   io.Writer
	err error
}

func newPrinter(w io.Writer) *printer { return &printer{w: w} }

// Write makes a printer an io.Writer, so it can back a flag.FlagSet, a JSON
// encoder and the daemon's output stream without any of them knowing about it.
func (p *printer) Write(b []byte) (int, error) {
	if p.err != nil {
		return 0, p.err
	}
	n, err := p.w.Write(b)
	if err != nil {
		p.err = err
	}
	return n, err
}

func (p *printer) printf(format string, args ...any) { _, _ = fmt.Fprintf(p, format, args...) }

func (p *printer) println(args ...any) { _, _ = fmt.Fprintln(p, args...) }
