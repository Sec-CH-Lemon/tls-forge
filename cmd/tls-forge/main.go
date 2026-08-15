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
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
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

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, out io.Writer) error
}

func commands() []command {
	return []command{
		{"fetch", "make a request with a browser fingerprint", runFetch},
		{"capture", "measure the browser installed on this machine", runCapture},
		{"compare", "diff this library's handshake against the browser's", runCompare},
		{"profiles", "list the profiles that can be impersonated", runProfiles},
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
	exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	name := args[0]
	for _, c := range commands() {
		if c.name != name {
			continue
		}
		err := c.run(ctx, args[1:], stdout)
		switch {
		case err == nil:
			return 0
		case errors.Is(err, errDiffers):
			return 1
		case errors.Is(err, flag.ErrHelp):
			return 2
		default:
			fmt.Fprintln(stderr, "tlsforge:", err)
			return 1
		}
	}

	if name == "-h" || name == "--help" || name == "help" {
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "tlsforge: unknown command %q\n\n", name)
	usage(stderr)
	return 2
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "tls-forge — an HTTP client that sends a real browser's TLS fingerprint.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "usage: tls-forge <command> [flags]")
	fmt.Fprintln(out)
	for _, c := range commands() {
		fmt.Fprintf(out, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Run `tls-forge <command> -h` for a command's flags.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Start with `tls-forge compare`: it opens your browser, measures it, measures")
	fmt.Fprintln(out, "this library, and prints the differences. There should not be any.")
}

// newFlagSet returns a flag set that reports errors instead of exiting, so a
// bad flag is a non-zero exit from one place rather than a call to os.Exit from
// inside a command.
func newFlagSet(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}

func runVersion(_ context.Context, _ []string, out io.Writer) error {
	fmt.Fprintln(out, "tls-forge", version)
	return nil
}
