package tlsforge

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	utls "github.com/igor-lemon/utls"

	"github.com/Sec-CH-Lemon/tls-forge/v4/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v4/profile"
)

// alpsFrame is an HTTP/2 frame of type typ, with flags, on stream, carrying
// payload, as a server gives one in ALPS.
func alpsFrame(typ, flags byte, stream uint32, payload []byte) []byte {
	n := len(payload)
	frame := []byte{byte(n >> 16), byte(n >> 8), byte(n), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[5:], stream)
	return append(frame, payload...)
}

// acceptCHEntries are each of values with its length in two bytes before it,
// as an ACCEPT_CH frame says an origin and a value.
func acceptCHEntries(values ...string) []byte {
	var out []byte
	for _, v := range values {
		out = append(binary.BigEndian.AppendUint16(out, uint16(len(v))), v...)
	}
	return out
}

func TestAnACCEPTCHFrameIsReadAsChromeReadsIt(t *testing.T) {
	o := origin{"https", "www.example.com", "8443"}
	page := o.String()
	acceptCH := func(pairs ...string) []byte { return alpsFrame(frameAcceptCH, 0, 0, acceptCHEntries(pairs...)) }
	for _, tc := range []struct {
		name  string
		alps  []byte
		value string
		asked bool
	}{
		{"no ALPS", nil, "", false},
		{"SETTINGS alone", alpsFrame(4, 0, 0, []byte{0, 1, 0, 1, 0, 0}), "", false},
		{"an entry in a frame of another type", alpsFrame(0xfa, 0, 0, acceptCHEntries(page, "a")), "", false},
		{"the page's origin", acceptCH(page, "sec-ch-ua-arch"), "sec-ch-ua-arch", true},
		{"after SETTINGS", append(alpsFrame(4, 0, 0, nil), acceptCH(page, "a")...), "a", true},
		{"nothing asked", acceptCH(page, ""), "", true},
		{"another origin", acceptCH("https://www.example.net:8443", "a"), "", false},
		{"two entries of the origin: the first's", acceptCH(page, "a", page, "b"), "a", true},
		{"another origin's entry, then the page's", acceptCH("https://www.example.net:8443", "a", page, "b"), "b", true},
		{"another origin's frame, then the page's", append(acceptCH("https://www.example.net:8443", "a"),
			acceptCH(page, "b")...), "b", true},
		{"the origin in capitals", acceptCH(strings.ToUpper(page), "a"), "", false},
		{"the origin with a path", acceptCH(page+"/", "a"), "", false},
		{"an empty origin", acceptCH("", "a"), "", false},
		{"an entry cut short", alpsFrame(frameAcceptCH, 0, 0, []byte{0, 99, 'h'}), "", false},
		{"a value cut short", alpsFrame(frameAcceptCH, 0, 0, append(acceptCHEntries(page), 0, 9, 'a')), "", false},
		{"an entry, then one cut short", alpsFrame(frameAcceptCH, 0, 0, append(acceptCHEntries(page, "a"), 0, 99)), "a", true},
		{"a frame cut short in an entry, then the page's", append(alpsFrame(frameAcceptCH, 0, 0, []byte{0, 99}),
			acceptCH(page, "b")...), "b", true},
		{"one on a stream", alpsFrame(frameAcceptCH, 0, 1, acceptCHEntries(page, "a")), "", false},
		{"one with a flag", alpsFrame(frameAcceptCH, 1, 0, acceptCHEntries(page, "a")), "", false},
		{"one on a stream, then one on none", append(alpsFrame(frameAcceptCH, 0, 1, acceptCHEntries(page, "a")),
			acceptCH(page, "b")...), "b", true},
		{"the reserved bit of its stream set", alpsFrame(frameAcceptCH, 0, 1<<31, acceptCHEntries(page, "a")), "a", true},
		{"a frame's header cut short", acceptCH(page, "a")[:8], "", false},
		{"a frame cut short", acceptCH(page, "a")[:12], "", false},
		{"a frame cut short after one that reads", append(alpsFrame(0xfa, 0, 0, nil), acceptCH(page, "a")[:20]...), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if value, asked := acceptCHOf(tc.alps, o); value != tc.value || asked != tc.asked {
				t.Errorf("acceptCHOf: %q, %v; want %q, %v", value, asked, tc.value, tc.asked)
			}
		})
	}
	// An IPv6 address in brackets, and a port that is its scheme's not
	// written.
	six := origin{"https", "::1", "443"}
	if value, _ := acceptCHOf(acceptCH("https://[::1]", "x"), six); value != "x" {
		t.Errorf("an IPv6 origin: %q", value)
	}
	if _, asked := acceptCHOf(acceptCH("https://[::1]:443", "x"), six); asked {
		t.Error("an origin with its scheme's port written was taken")
	}
}

// alpsConn is a connection whose TLS gave alps.
type alpsConn struct {
	net.Conn
	alps []byte
}

func (c alpsConn) ConnectionState() utls.ConnectionState {
	return utls.ConnectionState{NegotiatedProtocol: "h2", PeerApplicationSettings: c.alps}
}

func TestALPSIsWhatTheConnectionsTLSGave(t *testing.T) {
	plain, other := net.Pipe()
	t.Cleanup(func() { _ = plain.Close(); _ = other.Close() })
	if alpsOf(nil) != nil || alpsOf(plain) != nil {
		t.Error("a connection that is not TLS gave ALPS")
	}
	if got := alpsOf(alpsConn{alps: []byte{7}}); !slices.Equal(got, []byte{7}) {
		t.Errorf("alpsOf: %x", got)
	}
}

func TestTheHintsALPSAsksForAreThoseTheRequestDoesNotCarry(t *testing.T) {
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	c := newTestClient(t, WithProfileValue(p))
	o := origin{"https", "www.example.com", "443"}
	conn := func(value string) net.Conn {
		return alpsConn{alps: alpsFrame(frameAcceptCH, 0, 0, acceptCHEntries(o.String(), value))}
	}
	arch := profile.Field{Name: "sec-ch-ua-arch", Value: Header(p.ClientHints).Get("sec-ch-ua-arch")}
	model := profile.Field{Name: "sec-ch-ua-model", Value: Header(p.ClientHints).Get("sec-ch-ua-model")}
	bitness := profile.Field{Name: "sec-ch-ua-bitness", Value: Header(p.ClientHints).Get("sec-ch-ua-bitness")}
	for _, tc := range []struct {
		name string
		conn net.Conn
		hop  hop
		want Header
	}{
		{"asked in no order of Chrome's, in Chrome's order", conn("Sec-CH-UA-Model, sec-ch-ua-arch;x=1, nonsense"),
			hop{to: o}, Header{arch, model}},
		{"those the request carries left out", conn("sec-ch-ua-arch, sec-ch-ua-model, sec-ch-ua-bitness"),
			hop{to: o, hints: Header{model}, alps: Header{bitness}}, Header{arch}},
		{"those Chrome sends unasked left out", conn("sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform"), hop{to: o}, nil},
		{"nothing asked", conn(""), hop{to: o}, nil},
		{"another origin's", conn("sec-ch-ua-arch"), hop{to: origin{"https", "www.example.com", "8443"}}, nil},
		{"no ALPS", nil, hop{to: o}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.alpsHints(tc.conn, tc.hop); !slices.Equal(got, tc.want) {
				t.Errorf("alpsHints: %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTheHintsALPSAskedForGoAfterAccept(t *testing.T) {
	// The orders Chrome writes a page's request in once it started it again
	// with the hints a connection's ALPS asked for: after Accept, or after
	// the hints that follow it; a redirect's hop's hints moved there too.
	asked := "\x00ALPS hints"
	for _, tc := range []struct {
		name       string
		order      []string
		redirected bool
		want       []string
	}{
		{"a navigation", navigationOrder, false, []string{"authorization", slotHints, "upgrade-insecure-requests",
			"user-agent", "accept", asked, "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie", "priority"}},
		{"a form", formOrder, false, []string{"content-length", "cache-control", "authorization", slotHints,
			"upgrade-insecure-requests", "content-type", "user-agent", "origin", "accept", asked, "sec-fetch-site",
			"sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"}},
		{"a navigation started again for its critical hints", restartedOrder, false, []string{"authorization",
			"upgrade-insecure-requests", "user-agent", "accept", slotHints, asked, "sec-fetch-site", "sec-fetch-mode",
			"sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"}},
		{"a hop after a redirect", redirectedOrder, true, []string{"content-length", "cache-control", "authorization",
			"upgrade-insecure-requests", "content-type", "user-agent", "origin", "accept", slotHints, asked,
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding",
			"accept-language", "cookie", "priority"}},
	} {
		if got := alpsOrder(tc.order, tc.redirected); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
	if !slices.Contains(navigationOrder, slotHints) || slices.Contains(navigationOrder, asked) {
		t.Error("alpsOrder changed the order it was given")
	}
	// Each kind of a page's request takes its own; a script's takes none.
	alps := Header{{Name: "sec-ch-ua-arch", Value: `"arm"`}}
	page, form, script := &browserRequest{kind: KindNavigation}, &browserRequest{kind: KindForm, posted: true},
		&browserRequest{kind: KindFetch}
	for _, tc := range []struct {
		name string
		r    *browserRequest
		h    hop
		want []string
	}{
		{"a navigation", page, hop{alps: alps}, alpsOrder(navigationOrder, false)},
		{"a form", form, hop{alps: alps}, alpsOrder(formOrder, false)},
		{"a navigation started again", page, hop{alps: alps, restarted: true}, alpsOrder(restartedOrder, false)},
		{"a hop after a redirect", page, hop{alps: alps, redirected: true}, alpsOrder(redirectedOrder, true)},
		{"a navigation ALPS gave nothing", page, hop{}, navigationOrder},
		{"a script's request", script, hop{alps: alps}, scriptOrder(hop{})},
	} {
		if got := tc.r.order(tc.h); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
	// The hints ALPS asked for have a slot of their own, and are not in that
	// of the rest.
	h := hop{hints: Header{{Name: "sec-ch-ua-model"}}, alps: Header{{Name: "sec-ch-ua-arch"}, {Name: "sec-ch-ua-bitness"}}}
	if got := slotNames(slotALPSHints, h); !slices.Equal(got, []string{"sec-ch-ua-arch", "sec-ch-ua-bitness"}) {
		t.Errorf("the slot of the hints ALPS asked for: %q", got)
	}
	if got := slotNames(slotHints, h); slices.Contains(got, "sec-ch-ua-arch") || !slices.Contains(got, "sec-ch-ua-model") ||
		len(got) != len(profile.ClientHintOrder)-2 {
		t.Errorf("the slot of the hints: %q", got)
	}
	if got := slotNames(slotHints, hop{}); len(got) != len(profile.ClientHintOrder) {
		t.Errorf("the slot of the hints, ALPS giving none: %q", got)
	}
}

// alpsBench is a client wearing Chrome 155's profile to the bench's ALPS
// server of variant, and the origin it asks there.
func alpsBench(t *testing.T, server *harness.Server, variant string, opts ...Option) (*Client, string) {
	t.Helper()
	server.Reset()
	client := newTestClient(t, append([]Option{WithProfileValue(headlessChrome(t)), WithTimeout(5 * time.Second),
		WithTransportOption(tls_client.WithDialContext(
			func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, at, _ := net.SplitHostPort(addr)
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", at))
			}))}, opts...)...)
	return client, "https://www.example.com:" + strconv.Itoa(server.ALPS[variant])
}

// fieldNames are the names of a request's fields, as they went into HPACK.
func fieldNames(w harness.WrittenRequest) []string {
	var out []string
	for _, f := range w.Fields {
		name, _, _ := strings.Cut(f, ": ")
		out = append(out, name)
	}
	return out
}

// askedAfterAccept reports whether names have the hints the bench's accept-ch
// variant asks for right after Accept.
func askedAfterAccept(names []string) bool {
	at := slices.Index(names, "accept")
	return at >= 0 && len(names) >= at+4 &&
		slices.Equal(names[at+1:at+4], []string{"sec-ch-ua-arch", "sec-ch-ua-platform-version", "sec-ch-ua-full-version-list"})
}

// sentToALPS are the requests the bench's ALPS server of variant took since it
// was reset, each connection's in order.
func sentToALPS(t *testing.T, server *harness.Server, variant string) [][]harness.WrittenRequest {
	t.Helper()
	got := settledALPS(t, server, "", variant)
	return got.Connections
}

func TestAPageSentAgainCarriesTheHintsALPSGaveIt(t *testing.T) {
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	// A navigation answered 401, sent again with the credentials of its URL;
	// one answered 421, sent again. Each time with the hints after Accept,
	// the second unasked: the hop carries them.
	for _, path := range []string{"/auth/alps", "/misdirected/alps?first"} {
		client, origin := alpsBench(t, server, "accept-ch")
		u, _ := url.Parse(origin + path)
		u.User = url.UserPassword("u", "p")
		res, err := client.Do(&Request{Method: "GET", URL: u.String(), Browser: &BrowserContext{Kind: KindNavigation}})
		if err != nil || res.Status != 200 {
			t.Fatalf("%s: %v, %v", path, err, res)
		}
		client.CloseIdleConnections()
		var sent []harness.WrittenRequest
		for _, c := range sentToALPS(t, server, "accept-ch") {
			sent = append(sent, c...)
		}
		if len(sent) != 2 || !askedAfterAccept(fieldNames(sent[0])) || !askedAfterAccept(fieldNames(sent[1])) {
			t.Errorf("%s: sent %+v", path, sent)
		}
	}
	// A hop that carries them goes so on a connection whose ALPS asks for
	// none.
	ch := &chain{client: newTestClient(t, WithProfileValue(headlessChrome(t))),
		browser: &browserRequest{kind: KindNavigation}}
	ch.last = hop{to: origin{"https", "www.example.com", "443"}, alps: Header{{Name: "sec-ch-ua-arch", Value: `"arm"`}}}
	l := ch.layoutsOf(ch.last, "www.example.com")
	if order := l.http2[fhttp.HeaderOrderKey]; !slices.Equal(order[slices.Index(order, "accept")+1:][:1], []string{"sec-ch-ua-arch"}) {
		t.Errorf("the hop's order: %q", order)
	}
	if block := l.asked(); block != nil || ch.taken != nil {
		t.Errorf("a connection that asked for nothing gave %v, %v", block, ch.taken)
	}
}

func TestCriticalCHAsksInVainForAHintALPSGave(t *testing.T) {
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, tc := range []struct {
		name, variant, path string
		sent                int
	}{
		// ALPS gave the hint the answer says is critical: no second request.
		{"given by ALPS", "accept-ch", "/p/critical?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch", 1},
		// Without ALPS, the navigation is started again for it.
		{"not given", "none", "/p/critical?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch", 2},
		// One ALPS did not give: started again with it, the hints ALPS asked
		// for after it.
		{"another", "accept-ch", "/p/critical?accept=sec-ch-ua-model&critical=sec-ch-ua-model", 2},
		// A redirect that says it, to a page: the hop carried it, and the
		// page is asked once.
		{"said by a redirect", "accept-ch", "/r/302/critical?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch&to=/p/after", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, origin := alpsBench(t, server, tc.variant)
			if _, err := client.Do(&Request{Method: "GET", URL: origin + tc.path, Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
				t.Fatalf("Do: %v", err)
			}
			client.CloseIdleConnections()
			var sent []harness.WrittenRequest
			for _, c := range sentToALPS(t, server, tc.variant) {
				sent = append(sent, c...)
			}
			if len(sent) != tc.sent {
				t.Fatalf("%d requests sent, want %d: %+v", len(sent), tc.sent, sent)
			}
			if tc.name == "another" {
				names := fieldNames(sent[1])
				at := slices.Index(names, "accept")
				if !slices.Equal(names[at+1:at+8], []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
					"sec-ch-ua-model", "sec-ch-ua-arch", "sec-ch-ua-platform-version", "sec-ch-ua-full-version-list"}) {
					t.Errorf("started again with %q", names)
				}
			}
		})
	}
}

func TestOnlyHTTP2IsWrittenWithTheHintsALPSAskedFor(t *testing.T) {
	// HTTP/1.1 is never asked: ALPS is given for h2 alone.
	asks := 0
	l := newLayouts(fhttp.Header{"Accept": {"x"}, fhttp.HeaderOrderKey: {"accept"}},
		fhttp.Header{"Accept": {"y"}, fhttp.HeaderOrderKey: {"accept"}})
	l.asked = func() fhttp.Header {
		asks++
		return fhttp.Header{"Accept": {"z"}, fhttp.HeaderOrderKey: {"accept", "sec-ch-ua-arch"}, "Sec-Ch-Ua-Arch": {`"arm"`}}
	}
	req, _ := fhttp.NewRequest("GET", "https://example.test/", nil)
	req = l.wear(req)
	written := req.HeaderFor(fhttp.ProtocolHTTP1, fhttp.Header{"Accept": {"x"}, "Cookie": {"a=1"}})
	if asks != 0 || written.Get("Accept") != "y" {
		t.Errorf("over HTTP/1.1: asked %d times, wrote %v", asks, written)
	}
	written = req.HeaderFor(fhttp.ProtocolHTTP2, fhttp.Header{"Accept": {"x"}, "Cookie": {"a=1"}})
	if asks != 1 || written.Get("Accept") != "z" || written.Get("Sec-Ch-Ua-Arch") != `"arm"` || written.Get("Cookie") != "a=1" {
		t.Errorf("over HTTP/2: asked %d times, wrote %v", asks, written)
	}
}

func TestTheCookieGoesWithTheHintsALPSAskedFor(t *testing.T) {
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, origin := alpsBench(t, server, "accept-ch")
	for _, path := range []string{"/p/set?cookie=1", "/p/after"} {
		if _, err := client.Do(&Request{Method: "GET", URL: origin + path, Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	client.CloseIdleConnections()
	var sent []harness.WrittenRequest
	for _, c := range sentToALPS(t, server, "accept-ch") {
		sent = append(sent, c...)
	}
	if len(sent) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	names := fieldNames(sent[1])
	if !askedAfterAccept(names) || slices.Index(names, "cookie") != slices.Index(names, "accept-language")+1 ||
		strings.Count(strings.Join(names, " "), "cookie") != 2 {
		t.Errorf("the page after the cookies were set: %q", names)
	}
}

func TestAHopKeepsTheHintsALPSGaveItOnce(t *testing.T) {
	p := headlessChrome(t)
	ch := &chain{client: newTestClient(t, WithProfileValue(p)), browser: &browserRequest{kind: KindNavigation}}
	o := origin{"https", "www.example.com", "443"}
	bitness := profile.Field{Name: "sec-ch-ua-bitness", Value: Header(p.ClientHints).Get("sec-ch-ua-bitness")}
	// A hop that carries one, on a connection that asks for two more: the
	// one first, the two after it.
	ch.conn = alpsConn{alps: alpsFrame(frameAcceptCH, 0, 0, acceptCHEntries(o.String(), "sec-ch-ua-model, sec-ch-ua-arch"))}
	h := hop{to: o, alps: Header{bitness}}
	block := ch.alpsBlock(h, "www.example.com")
	order := block[fhttp.HeaderOrderKey]
	at := slices.Index(order, "accept")
	if !slices.Equal(order[at+1:at+4], []string{"sec-ch-ua-bitness", "sec-ch-ua-arch", "sec-ch-ua-model"}) ||
		len(block["Sec-Ch-Ua-Bitness"]) != 1 {
		t.Errorf("the block: %q", order)
	}
	if !slices.Equal(ch.taken.Names(), []string{"sec-ch-ua-arch", "sec-ch-ua-model"}) || len(h.alps) != 1 {
		t.Errorf("taken %q, the hop's own %q", ch.taken.Names(), h.alps.Names())
	}
	// Taken once, and kept when the next request takes nothing.
	ch.last = h
	ch.took()
	ch.took()
	if got := ch.last.alps.Names(); !slices.Equal(got, []string{"sec-ch-ua-bitness", "sec-ch-ua-arch", "sec-ch-ua-model"}) {
		t.Errorf("the hop carries %q", got)
	}
}

func TestTheLogSaysTheHintsALPSAskedFor(t *testing.T) {
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	book, logger := newLogBook(slog.LevelDebug)
	client, origin := alpsBench(t, server, "accept-ch", WithLogger(logger))
	if _, err := client.Do(&Request{Method: "GET", URL: origin + "/p/logged", Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	book.one(t, "client hints asked over ALPS", "origin", origin,
		"hints", "sec-ch-ua-arch,sec-ch-ua-platform-version,sec-ch-ua-full-version-list")
	// A script's request on the connection is given none.
	if _, err := client.Do(&Request{Method: "GET", URL: origin + "/p/fetched",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: origin + "/p/logged"}}); err != nil {
		t.Fatalf("fetch(): %v", err)
	}
	if found := book.with(t, "client hints asked over ALPS"); len(found) != 1 {
		t.Errorf("%d records of hints asked over ALPS", len(found))
	}
}
