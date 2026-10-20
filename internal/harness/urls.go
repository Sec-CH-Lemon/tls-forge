package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// URLsFixture is what testdata/chrome155-urls.json holds: what a browser sent
// for each URL a page went to, or a redirect sent it to, over HTTP/2 and over
// HTTP/1.1 alone, or that it sent nothing.
type URLsFixture struct {
	// Browser says which browser was measured, how it was run and where.
	Browser string `json:"browser"`
	// Measured are the dates it was, and How says how.
	Measured string             `json:"measured"`
	How      string             `json:"how"`
	Cases    map[string]URLCase `json:"cases"`
}

// URLCase is a URL as it was given, and what a browser sent for it.
type URLCase struct {
	Note string `json:"note"`
	// Input is the URL as the run page gave location.href, or as a
	// redirect's Location said it: the bench's TLS port in it is {P}, its
	// plain one {Q}.
	Input string `json:"input"`
	// Redirect says Input is the Location of a 302 from
	// https://www.example.com/r/302/<case>, and Typed that it was typed into
	// the address bar: the browser was started at it.
	Redirect bool    `json:"redirect,omitempty"`
	Typed    bool    `json:"typed,omitempty"`
	H2       SentURL `json:"h2"`
	H1       SentURL `json:"h1"`
}

// SentURL is what went out for a URL, no port of the bench's in it: the
// server name the TLS of its connection asked for (none in the clear, nor for
// an address), its scheme, its authority (:authority, Host) and its target
// (:path, the request line's); or, when nothing went out, why: the page's
// script threw ("thrown"), or no request came ("blocked").
type SentURL struct {
	SNI       string `json:"sni,omitempty"`
	Scheme    string `json:"scheme,omitempty"`
	Authority string `json:"authority,omitempty"`
	Target    string `json:"target,omitempty"`
	Refused   string `json:"refused,omitempty"`
}

// The reasons a SentURL gives for nothing.
const (
	refusedThrown  = "thrown"
	refusedBlocked = "blocked"
)

// LoadURLs reads a fixture of URLs.
func LoadURLs(path string) (*URLsFixture, error) { return load[URLsFixture](path) }

// Write writes the fixture to path as it is kept, as the fixture of requests
// is.
func (f *URLsFixture) Write(path string) error { return writeJSON(path, f) }

// urlCase is a URL the bench has a browser go to: as its run page gives it to
// location.href, or, redirect, as a 302's Location says it, or, typed, as one
// typed into the address bar, the browser started at it.
type urlCase struct {
	note            string
	input           string
	redirect, typed bool
}

// plainPorts are the ports but 80 that URL cases name for plain http to
// www.example.com, each taken to the bench's plain port (portRules), so that
// a request Chrome sends to one comes.
var plainPorts = []int{4190, 6000, 6679, 8080}

// portRule takes a name on a port to the bench's TLS port, or to its plain
// one.
type portRule struct {
	host  string
	port  int
	plain bool
}

// portRules are where the URL cases that name no port, 443, 80 or a port
// Chrome may block go: www.example.com on 443 to the TLS port, on 80 and
// plainPorts to the plain one; fallback.example.com on both to the plain one,
// where a TLS handshake fails, as with an https site that does not answer;
// intranet, a single label, and upgrade.test, a name under .test, as
// www.example.com (defaultPorts, Addr).
var portRules = func() []portRule {
	rules := []portRule{{"www.example.com", 443, false}, {"www.example.com", 80, true}}
	for _, port := range plainPorts {
		rules = append(rules, portRule{"www.example.com", port, true})
	}
	return append(rules, portRule{"fallback.example.com", 443, true}, portRule{"fallback.example.com", 80, true},
		portRule{"intranet", 443, false}, portRule{"intranet", 80, true},
		portRule{"upgrade.test", 443, false}, portRule{"upgrade.test", 80, true})
}()

// benchPort is the port a connection to host on port goes to, as portRules
// take it to the bench's tls and plain ports: port itself for a name and port
// they do not take.
func benchPort(host string, port, tls, plain int) int {
	for _, r := range portRules {
		if strings.EqualFold(r.host, host) && r.port == port {
			if r.plain {
				return plain
			}
			return tls
		}
	}
	return port
}

// urlCatalogue is every URL measured, by its case's name in the fixture. Its
// inputs name the bench's TLS port {P} and its plain port {Q}; the names and
// ports portRules take go to them.
var urlCatalogue = map[string]urlCase{
	// The host.
	"url-host-upper":     {note: "a name in capitals", input: "https://WWW.EXAMPLE.COM:{P}/p/url-host-upper"},
	"url-scheme-upper":   {note: "a scheme in capitals", input: "HTTPS://www.example.com:{P}/p/url-scheme-upper"},
	"url-host-idn":       {note: "a name in Cyrillic", input: "https://пример.example.com:{P}/p/url-host-idn"},
	"url-host-idn-upper": {note: "a name in Cyrillic capitals", input: "https://ПРИМЕР.example.com:{P}/p/url-host-idn-upper"},
	"url-host-fullwidth": {note: "a name in full-width letters", input: "https://ｗｗｗ.example.com:{P}/p/url-host-fullwidth"},
	"url-host-percent":   {note: "a name with a letter percent-encoded", input: "https://www.ex%61mple.com:{P}/p/url-host-percent"},
	"url-host-space":     {note: "a name with a space in it", input: "https://www.exa mple.com:{P}/p/url-host-space"},
	"url-ipv4-hex":       {note: "127.0.0.1 in hexadecimal parts", input: "http://0x7f.0.0.1:{Q}/p/url-ipv4-hex"},
	"url-ipv4-short":     {note: "127.0.0.1 in two parts", input: "http://127.1:{Q}/p/url-ipv4-short"},
	"url-ipv4-number":    {note: "127.0.0.1 as one number", input: "http://2130706433:{Q}/p/url-ipv4-number"},
	"url-ipv4-octal":     {note: "127.0.0.1 with an octal part", input: "http://0177.0.0.1:{Q}/p/url-ipv4-octal"},
	"url-ipv6-long":      {note: "[::1] written out", input: "http://[0:0:0:0:0:0:0:1]:{Q}/p/url-ipv6-long"},
	"url-ipv6-mapped":    {note: "127.0.0.1 as an IPv6 address", input: "http://[::FFFF:127.0.0.1]:{Q}/p/url-ipv6-mapped"},
	// The port.
	"url-port-default":      {note: "https on 443, said", input: "https://www.example.com:443/p/url-port-default"},
	"url-port-none":         {note: "https on no port", input: "https://www.example.com/p/url-port-none"},
	"url-port-default-http": {note: "http on 80, said", input: "http://www.example.com:80/p/url-port-default-http"},
	"url-port-zeros":        {note: "a port with zeros before it", input: "https://www.example.com:000{P}/p/url-port-zeros"},
	"url-port-unsafe":       {note: "a port Chrome blocks", input: "http://www.example.com:6000/p/url-port-unsafe"},
	"url-port-allowed":      {note: "a port Chrome does not block", input: "http://www.example.com:8080/p/url-port-allowed"},
	"url-port-too-big":      {note: "a port past 65535", input: "https://www.example.com:65536/p/url-port-too-big"},
	"url-port-zero":         {note: "port 0", input: "http://www.example.com:0/p/url-port-zero"},
	"url-port-sieve":        {note: "a port the Fetch standard blocks and Chromium's list has not", input: "http://www.example.com:4190/p/url-port-sieve"},
	"url-port-osaut":        {note: "another port the Fetch standard blocks and Chromium's list has not", input: "http://www.example.com:6679/p/url-port-osaut"},
	// The path.
	"url-path-dots":         {note: "dot segments", input: "https://www.example.com:{P}/p/a/./b/../url-path-dots"},
	"url-path-dots-encoded": {note: "dot segments percent-encoded", input: "https://www.example.com:{P}/p/a/%2e/b/%2E%2e/url-path-dots-encoded"},
	"url-path-backslash":    {note: "backslashes for slashes", input: `https://www.example.com:{P}\p\url-path-backslash`},
	"url-path-ascii":        {note: "the printable ASCII a path holds as it is given", input: "https://www.example.com:{P}/p/url-path-ascii/ !\"$&'()*+,-.:;<=>@[]^_`{|}~"},
	"url-path-percent":      {note: "a path percent-encoded, well and not", input: "https://www.example.com:{P}/p/url-path-percent/%41%7e%2F%2f%zz%"},
	"url-path-unicode":      {note: "a path of letters past ASCII", input: "https://www.example.com:{P}/p/url-path-unicode/é ж 😀"},
	"url-path-empty":        {note: "no path", input: "https://www.example.com:{P}"},
	"url-path-slashes":      {note: "a path of double slashes", input: "https://www.example.com:{P}//p//url-path-slashes"},
	// The query.
	"url-query-ascii":   {note: "the printable ASCII a query holds as it is given", input: "https://www.example.com:{P}/p/url-query-ascii? !\"$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
	"url-query-percent": {note: "a query percent-encoded, well and not", input: "https://www.example.com:{P}/p/url-query-percent?a=%41%7e%2F%zz%"},
	"url-query-unicode": {note: "a query of letters past ASCII", input: "https://www.example.com:{P}/p/url-query-unicode?q=é ж 😀"},
	"url-query-only":    {note: "a query and no path", input: "https://www.example.com:{P}?url-query-only"},
	"url-query-empty":   {note: "an empty query", input: "https://www.example.com:{P}/p/url-query-empty?"},
	// The fragment, whitespace, credentials.
	"url-fragment":   {note: "a fragment", input: "https://www.example.com:{P}/p/url-fragment?q=1#frag"},
	"url-whitespace": {note: "spaces around it, a tab and a newline in it", input: "  https://www.example.com:{P}/p/url-white\tspa\nce  "},
	"url-userinfo":   {note: "credentials", input: "https://u:p@www.example.com:{P}/p/url-userinfo"},
	// Locations.
	"url-redirect-relative":        {note: "a relative Location with dot segments", input: "../p/url-redirect-relative/./x/../y", redirect: true},
	"url-redirect-backslash":       {note: "a Location of backslashes", input: `\p\url-redirect-backslash`, redirect: true},
	"url-redirect-scheme-relative": {note: "a Location without a scheme", input: "//www.example.net:{P}/p/url-redirect-scheme-relative", redirect: true},
	"url-redirect-host-upper":      {note: "a Location with a name in capitals", input: "https://WWW.EXAMPLE.NET:{P}/p/url-redirect-host-upper", redirect: true},
	"url-redirect-space":           {note: "a Location with spaces in its path", input: "/p/url redirect space", redirect: true},
	"url-redirect-unicode":         {note: "a Location with letters past ASCII", input: "/p/url-redirect-é", redirect: true},
	"url-redirect-query":           {note: "a Location with a query to be encoded", input: "/p/url-redirect-query?a b'c\"d<e>", redirect: true},
	"url-redirect-fragment":        {note: "a Location with a fragment", input: "/p/url-redirect-fragment#f", redirect: true},
	"url-redirect-whitespace":      {note: "a Location with spaces around it", input: "  /p/url-redirect-whitespace  ", redirect: true},
	"url-redirect-port-default":    {note: "a Location on 443, said", input: "https://www.example.com:443/p/url-redirect-port-default", redirect: true},
	"url-redirect-bad-escape":      {note: "a Location with a percent that escapes nothing", input: "/p/url-redirect-bad%zz%", redirect: true},
	// HTTPS-Upgrades: plain http on 80, which Chrome tries over https first.
	"url-upgrade-link":           {note: "http to a name, no port", input: "http://www.example.com/p/url-upgrade-link"},
	"url-upgrade-redirect":       {note: "a Location of http to a name, no port", input: "http://www.example.com/p/url-upgrade-redirect", redirect: true},
	"url-upgrade-typed":          {note: "http to a name, no port, typed", input: "http://www.example.com/p/url-upgrade-typed", typed: true},
	"url-upgrade-userinfo":       {note: "http to a name with credentials", input: "http://u:p@www.example.com/p/url-upgrade-userinfo"},
	"url-upgrade-fallback":       {note: "http to a name whose https fails", input: "http://fallback.example.com/p/url-upgrade-fallback"},
	"url-upgrade-fallback-typed": {note: "http to a name whose https fails, typed", input: "http://fallback.example.com/p/url-upgrade-fallback-typed", typed: true},
	"url-upgrade-single-label":   {note: "http to a single label", input: "http://intranet/p/url-upgrade-single-label"},
	"url-upgrade-dot-test":       {note: "http to a name under .test", input: "http://upgrade.test/p/url-upgrade-dot-test"},
}

// urlScenarios are the URL cases as scenarios: each its run page, or its URL
// for one typed, the browser left to go where it goes.
func urlScenarios(cases map[string]urlCase) map[string]scenario {
	out := map[string]scenario{}
	for id, c := range cases {
		start := "{A}/urlrun/{ID}"
		if c.typed {
			start = c.input
		}
		out[id] = scenario{note: c.note, start: start, wait: "/never", settle: urlSettle}
	}
	return out
}

// urlSettle is how long a URL case is left to go where it goes.
var urlSettle = 2500 * time.Millisecond

// withURLs has a Server serve the run pages of cases.
func withURLs(cases map[string]urlCase) func(*Server) {
	return func(s *Server) { s.urls = cases }
}

// urlPage is the run page of the URL case id: it goes to the case's URL, or,
// for a Location, to the 302 that says it; a URL its script throws on it
// tells /urlthrown/ID.
func (s *Server) urlPage(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.urls[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, port, _ := net.SplitHostPort(r.Host)
	tlsPort, _ := strconv.Atoi(port)
	input, _ := json.Marshal(fill(c.input, id, origins(tlsPort, s.Plain)))
	script := fmt.Sprintf("try{location.href=%s}catch(e){fetch('/urlthrown/%s')}", input, id)
	if c.redirect {
		script = fmt.Sprintf("location.href='/r/302/%s?to='+encodeURIComponent(%s)", id, input)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!doctype html><title>url</title><script>%s</script>", script)
}

// MeasureURLs is what b sends for each URL case named in only, or every one,
// over HTTP/2 and over HTTP/1.1 alone: what the fixture holds for them. It
// says each case it ran to progress, when there is one.
func MeasureURLs(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]URLCase, error) {
	return measureURLs(ctx, b, urlCatalogue, only, measured, progress)
}

func measureURLs(ctx context.Context, b Browser, cases map[string]urlCase, only []string, t timing,
	progress io.Writer) (map[string]URLCase, error) {
	scenarios := urlScenarios(cases)
	ids, err := selected(scenarios, only)
	if err != nil {
		return nil, err
	}
	s, err := startServer(scenarios, withURLs(cases))
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if progress == nil {
		progress = io.Discard
	}
	out := map[string]URLCase{}
	for _, proto := range []string{"h2", "h1"} {
		port := map[string]int{"h2": s.H2, "h1": s.H1}[proto]
		browser := b
		if remaps, ok := b.(remapping); ok {
			browser = remaps.defaultPorts(port, s.Plain)
		}
		for _, id := range ids {
			entries, err := s.run(ctx, browser, id, scenarios[id], origins(port, s.Plain), t, progress)
			if err != nil {
				return nil, fmt.Errorf("harness: %s over %s: %w", id, proto, err)
			}
			got := out[id]
			got.Note, got.Input, got.Redirect, got.Typed = cases[id].note, cases[id].input, cases[id].redirect, cases[id].typed
			sent := s.sent(entries, id, cases[id])
			if proto == "h2" {
				got.H2 = sent
			} else {
				got.H1 = sent
			}
			out[id] = got
			_, _ = fmt.Fprintf(progress, "%s %s: %s\n", proto, id, sent)
		}
	}
	return out, nil
}

// sent is what went out for the URL case id, c, of entries: after its run
// page's request, or from the first for a URL typed, what sentAfter says.
func (s *Server) sent(entries []Entry, id string, c urlCase) SentURL {
	if c.typed {
		return s.sentAfter(entries, id, false)
	}
	for i, e := range entries {
		if pathOf(e.Target) == "/urlrun/"+id {
			return s.sentAfter(entries[i+1:], id, c.redirect)
		}
	}
	return SentURL{Refused: refusedBlocked}
}

// sentAfter is what went out for the URL case id, of entries: its 302's
// request when it is a Location's, and then the request it made, if any, but
// a favicon's.
func (s *Server) sentAfter(entries []Entry, id string, redirect bool) SentURL {
	for _, e := range entries {
		switch path := pathOf(e.Target); {
		case path == "/favicon.ico" || redirect && path == "/r/302/"+id:
		case path == "/urlthrown/"+id:
			return SentURL{Refused: refusedThrown}
		default:
			scheme, rest, _ := strings.Cut(e.Target, "://")
			authority, target := rest, ""
			if at := strings.IndexByte(rest, '/'); at >= 0 {
				authority, target = rest[:at], rest[at:]
			}
			return SentURL{SNI: e.SNI, Scheme: scheme, Authority: s.bare(authority), Target: target}
		}
	}
	return SentURL{Refused: refusedBlocked}
}

// URLServer is the bench's server for the URL cases, for a client to be held
// to what Chrome sent it: it answers each case's 302 and pages as it answered
// Chrome's.
type URLServer struct{ s *Server }

// StartURLServer starts the server of the URL cases.
func StartURLServer() (*URLServer, error) {
	s, err := startServer(urlScenarios(urlCatalogue), withURLs(urlCatalogue))
	if err != nil {
		return nil, err
	}
	return &URLServer{s: s}, nil
}

// URL is what a client goes to for the URL case id over proto, "h2" or "h1",
// as Chrome's run page went: the case's URL, or the 302 that says it, with
// the bench's ports in it.
func (u *URLServer) URL(id, proto string) (string, error) {
	c, ok := urlCatalogue[id]
	if !ok {
		return "", fmt.Errorf("harness: no URL case %q", id)
	}
	o := origins(u.port(proto), u.s.Plain)
	input := fill(c.input, id, o)
	if c.redirect {
		return o["A"] + "/r/302/" + id + "?to=" + url.QueryEscape(input), nil
	}
	return input, nil
}

// Addr is where a connection to addr goes for a case over proto, as Chrome's
// host resolver rules took it: to the loopback address, on the bench's TLS
// port of proto or its plain one where portRules take the name and port
// (defaultPorts).
func (u *URLServer) Addr(addr, proto string) string {
	host, port, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(port)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(benchPort(host, n, u.port(proto), u.s.Plain)))
}

func (u *URLServer) port(proto string) int {
	if proto == "h1" {
		return u.s.H1
	}
	return u.s.H2
}

// Sent is what went out for the URL case id since the server was started or
// Reset, as the fixture says what Chrome sent.
func (u *URLServer) Sent(id string) (SentURL, error) {
	entries, err := u.s.Requests()
	if err != nil {
		return SentURL{}, err
	}
	return u.s.sentAfter(entries, id, urlCatalogue[id].redirect), nil
}

// Reset forgets what was sent.
func (u *URLServer) Reset() { u.s.Reset() }

// Close stops the server.
func (u *URLServer) Close() error { return u.s.Close() }

func (u SentURL) String() string {
	if u.Refused != "" {
		return u.Refused
	}
	return fmt.Sprintf("%s %s%s (sni %q)", u.Scheme, u.Authority, u.Target, u.SNI)
}

// CompareURLs is how what a browser sent for each URL, got, differs from what
// the fixture holds, want, as Compare says it for requests: a case not
// measured, one the fixture has not, and every protocol of the others that
// went otherwise, after the case's name. Nothing when they are the same.
func CompareURLs(want, got map[string]URLCase) []string {
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(want)) {
		measured, ok := got[id]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s was not measured", id))
			continue
		}
		for _, p := range []struct {
			proto     string
			want, got SentURL
		}{{"h2", want[id].H2, measured.H2}, {"h1", want[id].H1, measured.H1}} {
			if p.got != p.want {
				diff = append(diff, fmt.Sprintf("%s over %s: %s, want %s", id, p.proto, p.got, p.want))
			}
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[id]; !ok {
			diff = append(diff, fmt.Sprintf("%s was measured, and the fixture has no such case", id))
		}
	}
	return diff
}
