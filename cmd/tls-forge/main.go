// Command tls-forge fetches URLs with a browser's TLS fingerprint, and — more
// usefully — proves that it does.
//
//	tls-forge capture            measure the browser on this machine
//	tls-forge compare            diff this library against that browser
//	tls-forge fetch <url>...     make requests wearing the fingerprint
//	tls-forge serve              run the local echo server, point anything at it
//	tls-forge daemon             JSON lines on stdin/stdout, for other languages
//	tls-forge profiles           list what can be impersonated
package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v2/engine"
	"io"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/spf13/pflag"

	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/redact"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=v1.0.0"
//
// Keep the variable linker-addressable. A computed initializer would silently
// overwrite -X at startup and hide a misleading stamp instead of rejecting it.
var version = ""

func init() {
	if version == "" {
		version = "v" + engine.Version()
	}
}

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
	// page or the JSON lines that fetch is producing and break whatever is
	// reading them.
	run func(ctx context.Context, args []string, out, errOut *printer) error
}

func commands() []command {
	return []command{
		{"fetch", "make requests with a browser fingerprint: one URL, or a list", runFetch},
		{"capture", "measure the browser installed on this machine", runCapture},
		{"compare", "diff this library's handshake against the browser's", runCompare},
		{"profiles", "list the profiles that can be impersonated", runProfiles},
		{"proxy", "run a proxy that re-sends every request with the fingerprint", runProxy},
		{"serve", "run the local fingerprint echo server", runServe},
		{"daemon", "speak JSON lines on stdin/stdout", runDaemon},
		{"version", "print the version", runVersion},
	}
}

// movedCommands are the names that used to be commands, each with where what
// it did has gone.
//
// Said rather than left as "unknown command": a script that has called batch
// for a year fails the day it is upgraded, and what it needs to read then is
// what to type instead.
var movedCommands = map[string]string{
	"batch": "batch is now fetch, which takes several URLs, --input FILE or --urls a,b,c.\n" +
		"  The list flag -i is now --input, and the body directory -d is now --output.\n" +
		"  Add --retry 3 for the tries batch made by default, and --json for JSON lines\n" +
		"  when one URL is named on the command line. A report's path is --report=PATH.",
}

// exit is os.Exit, named so the entry point can be driven from a test. Without
// the seam, the wiring between argv, the signal handler and the exit code is the
// one part of the program nothing checks.
var exit = os.Exit

// mainOut and mainErr are where main has a command write: the process's own
// standard output and error, named so that a test reads what the program says
// rather than having it said on the test's.
var mainOut, mainErr io.Writer = os.Stdout, os.Stderr

// stopSignals are what ask a command to stop: Ctrl-C, and SIGTERM, which is
// what `kill`, a service manager and `docker stop` send. On Windows, where
// nothing sends SIGTERM, the interrupt alone.
var stopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

func main() {
	// One exit point. Commands return errors and print to the writer they are
	// given, which is what lets every one of them be driven from a test.
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
	defer stop()
	releaseSignal(ctx, stop)
	exit(run(ctx, os.Args[1:], mainOut, mainErr))
}

// releaseSignal hands the signals back to the runtime after the first one.
//
// NotifyContext catches the signal and cancels the context instead of letting
// it end the process. That is right for a command that can wind itself down —
// a fetch writes its report, its session and the end of its trace, and the
// daemon answers the request it is making — and wrong for one stuck where it
// never looks at a context: the signal is swallowed, nothing happens, and
// every further Ctrl-C is swallowed too. Measured before this: a command
// waiting for a list on standard input survived four of them.
//
// So the first signal still asks for an orderly stop, and any after it end
// the process the way they would have if nothing had been listening.
func releaseSignal(ctx context.Context, stop func()) {
	go func() {
		<-ctx.Done()
		stop()
	}()
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	out, errOut := newPrinter(stdout), newPrinter(stderr)
	if err := engine.CheckBuildVersion(version); err != nil {
		errOut.println(err)
		return 2
	}
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
			errOut.println(prefixed(err))
			return exitUsage
		default:
			errOut.println(prefixed(err))
			return exitError
		}
	}

	if name == "-h" || name == "--help" || name == "help" {
		usage(out)
		return 0
	}
	if moved, ok := movedCommands[name]; ok {
		errOut.printf("tlsforge: %s\n", moved)
		return exitUsage
	}
	errOut.printf("tlsforge: unknown command %q\n\n", name)
	usage(errOut)
	return 2
}

// errorPrefix begins every line of an error tls-forge prints.
const errorPrefix = "tlsforge: "

// prefixed is an error as tls-forge prints it: every line of it beginning with
// errorPrefix, once.
//
// Once, because the library begins its own errors the same way, for the Go
// programs that print them, and one of those reaching here was printed as
// "tlsforge: tlsforge: Get …". A line that begins with the prefix keeps it
// rather than gaining a second, and one that begins with it more than once, as
// a library error wrapped in "tlsforge: %w" again does, keeps one. Only the
// start of a line is read: the rest is the error's own text, the library's
// included, and is printed as it is.
//
// Every line, because errors.Join puts each error it holds on a line of its
// own: a fetch that got no answer and then could not write its report failed
// twice, and the second line is as much an error as the first.
//
// And without the password of any URL in it. Every command's error is printed
// here, and a proxy that could not be read is quoted back whole by whatever
// tried to read it.
func prefixed(err error) string {
	lines := strings.Split(redact.Text(err.Error()), "\n")
	for i, line := range lines {
		for strings.HasPrefix(line, errorPrefix) {
			line = line[len(errorPrefix):]
		}
		// The name and its colon with nothing after them are the prefix too,
		// of a line with nothing else to say.
		if line == strings.TrimSuffix(errorPrefix, " ") {
			line = ""
		}
		lines[i] = errorPrefix + line
	}
	return strings.Join(lines, "\n")
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

// setUsage gives a command one usage block, so that the commands cannot end up
// describing themselves each a different way. A command with groups shows its
// flags under what each is for, which a command with many of them needs for
// one to be found.
func setUsage(fs *pflag.FlagSet, out io.Writer, line string, groups ...flagGroup) {
	fs.Usage = func() {
		_, _ = io.WriteString(out, line+"\n")
		switch flags := fs.FlagUsages(); {
		case flags == "":
			_, _ = io.WriteString(out, "\nThis command takes no flags.\n")
		case len(groups) == 0:
			_, _ = io.WriteString(out, "\nflags:\n"+flags)
		default:
			_, _ = io.WriteString(out, groupedFlags(flags, groups))
		}
	}
}

// flagGroup is a heading --help shows flags under, and the flags under it, by
// name, in the order they are shown.
type flagGroup struct {
	title string
	names []string
}

// flagLine is how a flag's own line begins in what pflag lists: its letter,
// when it has one, and its name.
var flagLine = regexp.MustCompile(`^\s+(?:-[^-\s], )?--([^\s=\[]+)`)

// groupedFlags is pflag's listing of a command's flags, in the one column pflag
// lines them all up in, with each flag under the heading of its group. A flag
// no group names is shown under a heading of its own at the end, so that one
// added without a group is still there to be found.
func groupedFlags(listing string, groups []flagGroup) string {
	// Each flag's lines: its own, and any its description runs on to.
	blocks := map[string]string{}
	var order []string
	name := ""
	for _, line := range strings.SplitAfter(listing, "\n") {
		if match := flagLine.FindStringSubmatch(line); match != nil {
			name = match[1]
			order = append(order, name)
		}
		blocks[name] += line
	}
	var out strings.Builder
	shown := map[string]bool{}
	section := func(title string, names []string) {
		var lines strings.Builder
		for _, name := range names {
			if block, ok := blocks[name]; ok && !shown[name] {
				shown[name] = true
				lines.WriteString(block)
			}
		}
		if lines.Len() > 0 {
			out.WriteString("\n" + title + ":\n" + lines.String())
		}
	}
	for _, group := range groups {
		section(group.title, group.names)
	}
	section("other flags", order)
	return out.String()
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
