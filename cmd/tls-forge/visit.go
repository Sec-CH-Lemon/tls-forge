package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/Sec-CH-Lemon/tls-forge/v2"
	"github.com/Sec-CH-Lemon/tls-forge/v2/capture"
	"github.com/Sec-CH-Lemon/tls-forge/v2/echo"
)

// A browser nobody here can launch — Firefox, Safari, a phone's — is measured
// by the person using it: tls-forge listens, and the person opens its page. The
// browser's first visit follows its warning about a certificate made for the
// run and only says what to do next; the visit measured is the next one, typed
// into a new tab. echo.WithManual has the reasons.

// visitFlags are what capture and compare take to measure a browser a person
// opens the page in, rather than one they launch themselves.
type visitFlags struct {
	manual *bool
	addr   *string
	host   *string
}

func addVisitFlags(fs *pflag.FlagSet) visitFlags {
	return visitFlags{
		manual: fs.Bool("manual", false,
			"measure a browser you open the page in yourself, which nothing here can launch: Firefox, Safari, a phone's"),
		addr: fs.String("addr", "127.0.0.1:0",
			"with --manual, where to listen; 0.0.0.0:8443 lets in a phone on this network"),
		host: fs.String("host", "localhost",
			"with --manual, the name or address the page is opened at, which its certificate is made for"),
	}
}

// check refuses flags that do not go together, before anything starts.
func (v visitFlags) check(fs *pflag.FlagSet) error {
	if *v.manual {
		for _, name := range []string{"browser", "headless", "browser-arg"} {
			if fs.Changed(name) {
				return fmt.Errorf("%w: --%s is for a browser tls-forge starts, and --manual waits for one you open",
					errUsage, name)
			}
		}
		return nil
	}
	for _, name := range []string{"addr", "host"} {
		if fs.Changed(name) {
			return fmt.Errorf("%w: --%s is for --manual, where a browser you open comes to tls-forge", errUsage, name)
		}
	}
	return nil
}

// namedHost refuses an address for --host where a profile is to be kept: a
// browser names no server to an address (RFC 6066), so the hello it sends
// there would make a profile that names none to any site. profile.FromCapture
// refuses that hello too, but only once a person has been through the visits.
func (v visitFlags) namedHost() error {
	if net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(*v.host, "["), "]")) == nil {
		return nil
	}
	return fmt.Errorf("%w: --host %s is an address, and a browser names no server to an address (no SNI): "+
		"a profile of what it sends would name none to any site. Give --host a name this machine is reached by%s",
		errUsage, *v.host, aNameLike())
}

// hostname is os.Hostname, which a test replaces.
var hostname = os.Hostname

// networkName is the name a phone on this network may reach this machine by:
// its host name, NAME.local where it says no domain, which Bonjour answers for;
// nothing when it has none, or it is an address.
func networkName() string {
	name, err := hostname()
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	switch {
	case err != nil || name == "" || net.ParseIP(name) != nil:
		return ""
	case !strings.Contains(name, "."):
		return name + ".local"
	}
	return name
}

// aNameLike gives a message an example of a name this machine may be reached
// by, when it has one.
func aNameLike() string {
	name := networkName()
	switch {
	case name == "":
		return ""
	case strings.HasSuffix(name, ".local"):
		return ", such as " + name + " (an iPhone finds a .local name by Bonjour)"
	}
	return ", such as " + name
}

// visitorWait is how long a browser a person opens is waited for when --timeout
// does not say: long enough to find a phone and type an address into it twice.
const visitorWait = 10 * time.Minute

// waitFor is the --timeout to keep: the one given, or a person's time for a
// browser a person opens.
func (v visitFlags) waitFor(fs *pflag.FlagSet, timeout time.Duration) time.Duration {
	if *v.manual && !fs.Changed("timeout") {
		return visitorWait
	}
	return timeout
}

// visitorReady is told the address a person is to open, once it is open. A
// variable so that a test can be that person.
var visitorReady = func(string) {}

// openForVisitors starts the server a person's browser comes to, and says how
// to bring it.
func openForVisitors(v visitFlags, component string, errOut *printer) (*echo.Server, error) {
	server, err := echo.Start(echo.WithAddr(*v.addr), echo.WithHost(*v.host), echo.WithManual(true))
	if err != nil {
		return nil, err
	}
	warnPublicListener(component, server.Addr(), errOut)
	address := server.URL() + "/"
	errOut.printf("waiting for a browser at %s\n", address)
	errOut.println("  1. Open that address in the browser to measure: type or paste it.")
	errOut.println("  2. It warns about the certificate, made for this run: accept it.")
	errOut.println("  3. Open the address again in a new tab, typed or pasted: that visit is measured.")
	errOut.printf("  4. Its page then gives a second address, %s, for HTTP/1.1: open it the same way,\n",
		server.CaptureURL()+"/")
	errOut.println("     again if the browser warns about the certificate there too; or finish without it on the page.")
	if !listenerIsLoopback(server.Addr()) && *v.host == "localhost" {
		errOut.println("A phone cannot open localhost: give --host a name it reaches this machine by" + aNameLike() + ".")
	}
	visitorReady(address)
	return server, nil
}

// measureVisitor waits, as long as it is given, for a browser a person opens
// the page in, and returns what it sent.
func measureVisitor(ctx context.Context, v visitFlags, wait time.Duration, errOut *printer) (*capture.Capture, error) {
	server, err := openForVisitors(v, "capture", errOut)
	if err != nil {
		return nil, err
	}
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return tlsforge.MeasureVisitorAt(ctx, server)
}

// compareVisitor is measureVisitor for a comparison: the browser, then this
// library on the same server.
func compareVisitor(ctx context.Context, v visitFlags, wait time.Duration, errOut *printer,
	opts ...tlsforge.Option) (*tlsforge.Comparison, error) {
	server, err := openForVisitors(v, "compare", errOut)
	if err != nil {
		return nil, err
	}
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return tlsforge.CompareVisitorAt(ctx, server, opts...)
}
