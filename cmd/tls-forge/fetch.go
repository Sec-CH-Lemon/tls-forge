package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/cookie"
	"github.com/Sec-CH-Lemon/tls-forge/daemon"
	"github.com/Sec-CH-Lemon/tls-forge/internal/atomicfile"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// headerFlag collects repeated -H "Name: value" flags, in the order given.
//
// A slice rather than a map, and in the order given, because that order is part
// of what this tool exists to control.
type headerFlag tlsforge.Header

func (h *headerFlag) String() string { return "" }

// Type names the value in the usage line, where pflag prints it after the flag.
func (h *headerFlag) Type() string { return "name: value" }

func (h *headerFlag) Set(value string) error {
	name, val, found := strings.Cut(value, ":")
	if !found {
		return fmt.Errorf("expected \"Name: value\", got %q", value)
	}
	*h = append(*h, profile.Field{
		Name:  strings.ToLower(strings.TrimSpace(name)),
		Value: strings.TrimSpace(val),
	})
	return nil
}

// clientFlags are the flags every command that makes requests shares.
type clientFlags struct {
	cookies     *cookieFlag
	cookieFile  *string
	cookieSet   *string
	saveCookies *string

	profile  *string
	proxy    *string
	timeout  *time.Duration
	insecure *bool

	// chose reports whether a flag was given rather than defaulted, which is
	// how "no profile named" is told from "--profile chrome".
	chose func(string) bool
}

// addScopedClientFlags keeps unsupported flags out of --help. Accepting
// --save-cookies on a command that never saves a session is worse than rejecting
// it as a usage error; the same is true of cookie input on the jar-less proxy.
func addScopedClientFlags(fs *pflag.FlagSet, cookieInput, cookieOutput bool) clientFlags {
	flags := clientFlags{
		cookies:     &cookieFlag{},
		cookieFile:  new(string),
		cookieSet:   new(string),
		saveCookies: new(string),
		chose:       fs.Changed,
	}
	if cookieInput {
		// -b is curl's letter for handing a request a cookie.
		fs.VarP(flags.cookies, "cookie", "b", "cookie as name=value, repeatable")
		// Long only: -c is concurrency in batch, and a letter that means two
		// things depending on the command is worse than no letter.
		flags.cookieFile = fs.String("cookies", "", "file of warmed cookies to start from")
		flags.cookieSet = fs.String("cookie-set", "",
			"which set in that file to use; one at random when not named")
	}
	if cookieOutput {
		flags.saveCookies = fs.String("save-cookies", "",
			"write the session this run ends with here; .txt writes a cookies.txt")
	}
	flags.profile = fs.StringP("profile", "p", tlsforge.DefaultProfile, "profile to impersonate")
	flags.proxy = fs.StringP("proxy", "x", "", "proxy URL, e.g. http://user:pass@host:port")
	flags.timeout = fs.DurationP("timeout", "t", tlsforge.Timeout, "request timeout")
	flags.insecure = fs.BoolP("insecure", "k", false, "skip certificate verification")
	return flags
}

// The full request flags used by fetch and batch.
func addClientFlags(fs *pflag.FlagSet) clientFlags {
	return addScopedClientFlags(fs, true, true)
}

// Daemon can start from a warmed session, but does not retain visited hosts to
// save when stdin closes.
func addDaemonFlags(fs *pflag.FlagSet) clientFlags {
	return addScopedClientFlags(fs, true, false)
}

// Proxy forwards its caller's Cookie header and deliberately has no jar.
func addProxyClientFlags(fs *pflag.FlagSet) clientFlags {
	return addScopedClientFlags(fs, false, false)
}

// cookieFlag collects --cookie, which is name=value and nothing more: anything
// needing a domain or an expiry belongs in a file.
type cookieFlag struct{ cookies []cookie.Cookie }

func (f *cookieFlag) String() string { return "" }
func (f *cookieFlag) Type() string   { return "name=value" }

func (f *cookieFlag) Set(pair string) error {
	parsed, err := cookie.Parse(pair)
	if err != nil {
		return err
	}
	f.cookies = append(f.cookies, parsed)
	return nil
}

// warmedCookies is the session a client starts with: whatever was named on the
// command line, over whatever came out of the file.
//
// The file first and the flags on top, so a cookie given by hand overrides the
// one of the same name in a set rather than being overridden by it.
func (f clientFlags) warmedCookies() ([]cookie.Cookie, string, error) {
	var chosen []cookie.Cookie
	var from string

	if *f.cookieFile != "" {
		data, err := os.ReadFile(*f.cookieFile)
		if err != nil {
			return nil, "", fmt.Errorf("tlsforge: %w", err)
		}
		file, err := cookie.Load(data)
		if err != nil {
			return nil, "", err
		}
		set, err := file.Pick(*f.cookieSet, pickCookieSet)
		if err != nil {
			return nil, "", err
		}
		live := set.Live(now())
		chosen = append(chosen, live.Cookies...)
		from = fmt.Sprintf("%s, set %s, %d cookies", *f.cookieFile, set.ID, len(live.Cookies))
		if dead := len(set.Cookies) - len(live.Cookies); dead > 0 {
			from += fmt.Sprintf(" (%d expired)", dead)
		}
	}
	return append(chosen, f.cookies.cookies...), from, nil
}

// saveSession writes what the jar ended up holding for the hosts that were
// asked, so a session warmed by a run can be used by the next one.
//
// Under an id naming when it was warmed, and appended to whatever the file
// already held: a file of sessions is built up over time rather than replaced
// by the last run.
func (f clientFlags) saveSession(client *tlsforge.Client, hosts []string, note string) (int, error) {
	if *f.saveCookies == "" {
		return 0, nil
	}
	set := cookie.Set{ID: now().Format("2006-01-02-15-04-05"), Warmed: now(), Note: note}
	seen := map[string]bool{}
	for _, host := range hosts {
		if seen[host] {
			continue
		}
		seen[host] = true
		held, err := client.CookiesFor(host)
		if err != nil {
			continue
		}
		for _, c := range held {
			set.Cookies = append(set.Cookies, cookie.Cookie{
				Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
				Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: c.Expires,
			})
		}
	}
	if len(set.Cookies) == 0 {
		return 0, nil
	}

	data, err := sessionFile(*f.saveCookies, set)
	if err != nil {
		return 0, err
	}
	// 0600: a warmed session is a credential. Replace atomically so a full disk
	// or interrupted process cannot leave half a credential file behind.
	if err := atomicfile.Write(*f.saveCookies, data, 0o600); err != nil {
		return 0, fmt.Errorf("tlsforge: %w", err)
	}
	return len(set.Cookies), nil
}

// sessionFile writes the session out in whichever format the name asks for.
//
// A `.txt` is a Netscape cookie file, which is a jar written down: it holds one
// session and is replaced, because that is what it means to everything else that
// reads one. Anything else is this project's JSON, which holds sets, so a run is
// added to what the file already had rather than replacing it.
func sessionFile(path string, set cookie.Set) ([]byte, error) {
	if strings.EqualFold(filepath.Ext(path), ".txt") {
		return set.EncodeNetscape(), nil
	}
	file := &cookie.File{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		loaded, err := cookie.Load(data)
		if err != nil {
			return nil, fmt.Errorf("tlsforge: reading existing sessions from %s: %w", path, err)
		}
		file = loaded
	case os.IsNotExist(err):
	case err != nil:
		return nil, fmt.Errorf("tlsforge: reading existing sessions from %s: %w", path, err)
	}
	file.Add(set)
	return file.Encode(), nil
}

// pickCookieSet chooses which warmed session to use. Seeded from the clock and
// named, so a test can make the choice repeatable.
var pickCookieSet = rand.New(rand.NewSource(time.Now().UnixNano()))

func (f clientFlags) client(extra ...tlsforge.Option) (*tlsforge.Client, error) {
	return f.clientVia(*f.proxy, extra...)
}

// clientVia builds a client through a named proxy, which batch needs because
// there the proxy comes from the list rather than from the flag.
func (f clientFlags) clientVia(proxy string, extra ...tlsforge.Option) (*tlsforge.Client, error) {
	opts := []tlsforge.Option{
		tlsforge.WithProfile(*f.profile),
		tlsforge.WithTimeout(*f.timeout),
	}
	warmed, _, err := f.warmedCookies()
	if err != nil {
		return nil, err
	}
	if len(warmed) > 0 {
		opts = append(opts, tlsforge.WithCookies(asClientCookies(warmed)))
	}
	if proxy != "" {
		opts = append(opts, tlsforge.WithProxy(proxy))
	}
	if *f.insecure {
		opts = append(opts, tlsforge.WithInsecureSkipVerify())
	}
	return tlsforge.New(append(opts, extra...)...)
}

// asClientCookies is the file's shape as the client's.
func asClientCookies(cookies []cookie.Cookie) []tlsforge.Cookie {
	out := make([]tlsforge.Cookie, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, tlsforge.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: c.Expires,
		})
	}
	return out
}

func runFetch(ctx context.Context, args []string, out, errOut *printer) (runErr error) {
	fs := newFlagSet("fetch", out)
	common := addClientFlags(fs)
	method := fs.StringP("method", "X", "GET", "HTTP method")
	data := fs.StringP("data", "d", "", "request body")
	showHeaders := fs.BoolP("include", "i", false, "print the status and response headers first")
	output := fs.StringP("output", "o", "", "write the body to a file instead of stdout")
	var headers headerFlag
	fs.VarP(&headers, "header", "H", "extra header, repeatable: -H \"Referer: https://…\"")
	setUsage(fs, out, "usage: tls-forge fetch [flags] <url>")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("%w: fetch takes exactly one URL", errUsage)
	}

	common.wear(errOut)
	client, err := common.client()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if _, from, err := common.warmedCookies(); err == nil && from != "" {
		errOut.printf("warmed from %s\n", from)
	}

	defer func() {
		// After the request, so what is written down is the session the run
		// ends with rather than the one it started from.
		if saved, err := common.saveSession(client, []string{fs.Arg(0)}, ""); err != nil {
			errOut.println("tlsforge:", err)
			if runErr == nil {
				runErr = err
			}
		} else if saved > 0 {
			errOut.printf("saved %d cookies to %s\n", saved, *common.saveCookies)
		}
	}()

	res, err := client.Do(&tlsforge.Request{
		Context: ctx,
		Method:  *method,
		URL:     fs.Arg(0),
		Header:  tlsforge.Header(headers),
		Body:    []byte(*data),
	})
	if err != nil {
		return err
	}

	if *showHeaders {
		out.printf("%d %s\n", res.Status, res.URL)
		names := make([]string, 0, len(res.Header))
		for name := range res.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			out.printf("%s: %s\n", name, strings.Join(res.Header[name], "; "))
		}
		out.println()
	}

	if *output != "" {
		if err := os.WriteFile(*output, res.Body, 0o644); err != nil {
			return err
		}
		out.printf("wrote %d bytes to %s\n", len(res.Body), *output)
		return nil
	}
	_, err = out.Write(res.Body)
	return err
}

func runDaemon(_ context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("daemon", out)
	common := addDaemonFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}

	common.wear(errOut)
	client, err := common.client()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// stdin is read directly rather than through the writer the command was
	// given: the protocol is a pipe, and tests substitute it through daemonInput.
	return daemon.Serve(daemonInput, out, client)
}

// daemonInput is os.Stdin, named so a test can supply a script instead.
var daemonInput io.Reader = os.Stdin
