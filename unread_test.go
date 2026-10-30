package tlsforge

import (
	"context"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
)

// unreadSite is a TLS server of h2 or HTTP/1.1 alone whose answers a request
// goes on from without reading them: /r (a 302 to /end), /auth (a 401 until
// it is sent u:p), /cch (a page asking for Sec-CH-UA-Arch, critical, until
// it comes) and /pf (CORS for a PUT; its preflight's answer the one held).
// Such an answer's head goes at once, its body of n bytes (4096) delay ms
// later, in parts gap ms apart, or with the head (now); with close, the
// connection is closed after it; with cl, its length is said. It says each
// request it was sent and the connection it came on, when an answer's body
// was sent or given up because its request ended (a reset stream, a closed
// connection), and when each connection closed.
type unreadSite struct {
	*httptest.Server
	mu      sync.Mutex
	events  []unreadEvent
	changed chan struct{}
}

type unreadEvent struct {
	what string // asked, sent, unwanted, closed
	path string // what was asked: its method, path and query
	conn string // the client's address
	at   time.Time
}

func newUnreadSite(t *testing.T, h2 bool) *unreadSite {
	t.Helper()
	s := &unreadSite{changed: make(chan struct{}, 1)}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.EnableHTTP2 = h2
	s.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			s.add("closed", "", c.RemoteAddr().String())
		}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func (s *unreadSite) add(what, path, conn string) {
	s.mu.Lock()
	s.events = append(s.events, unreadEvent{what, path, conn, time.Now()})
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *unreadSite) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	asked := r.Method + " " + r.URL.RequestURI()
	s.add("asked", asked, r.RemoteAddr)
	status := http.StatusOK
	switch {
	case r.URL.Path == "/r":
		w.Header().Set("Location", "/end")
		status = http.StatusFound
	case r.URL.Path == "/auth" && r.Header.Get("Authorization") != "Basic dTpw":
		w.Header().Set("WWW-Authenticate", `Basic realm="t"`)
		status = http.StatusUnauthorized
	case r.URL.Path == "/cch" && r.Header.Get("Sec-CH-UA-Arch") == "":
		w.Header().Set("Accept-CH", "Sec-CH-UA-Arch")
		w.Header().Set("Critical-CH", "Sec-CH-UA-Arch")
	case r.URL.Path == "/pf" && r.Method == http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", "PUT")
	default:
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = io.WriteString(w, "ok")
		return
	}
	n, parts, gap, delay := 4096, 1, 0, 0
	for k, v := range map[string]*int{"n": &n, "parts": &parts, "gap": &gap, "delay": &delay} {
		if q.Has(k) {
			*v, _ = strconv.Atoi(q.Get(k))
		}
	}
	if q.Has("close") {
		w.Header().Set("Connection", "close")
	}
	if q.Has("now") {
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, strings.Repeat("x", n))
		s.add("sent", asked, r.RemoteAddr)
		return
	}
	if q.Has("cl") {
		w.Header().Set("Content-Length", strconv.Itoa(n))
	}
	w.WriteHeader(status)
	w.(http.Flusher).Flush()
	wait := time.Duration(delay) * time.Millisecond
	for i := range parts {
		select {
		case <-time.After(wait):
		case <-r.Context().Done():
			s.add("unwanted", asked, r.RemoteAddr)
			return
		}
		size := n / parts
		if i == parts-1 {
			size = n - i*size
		}
		_, _ = io.WriteString(w, strings.Repeat("x", size))
		w.(http.Flusher).Flush()
		wait = time.Duration(gap) * time.Millisecond
	}
	s.add("sent", asked, r.RemoteAddr)
}

// nth is the n-th event (from 1) that matches, waited for within d; ok
// false when none came.
func (s *unreadSite) nth(n int, match func(unreadEvent) bool, d time.Duration) (unreadEvent, bool) {
	deadline := time.After(d)
	for {
		s.mu.Lock()
		seen := 0
		for _, e := range s.events {
			if match(e) {
				if seen++; seen == n {
					s.mu.Unlock()
					return e, true
				}
			}
		}
		s.mu.Unlock()
		select {
		case <-s.changed:
		case <-deadline:
			return unreadEvent{}, false
		}
	}
}

// event is the first event that matches, waited for within d.
func (s *unreadSite) event(match func(unreadEvent) bool, d time.Duration) (unreadEvent, bool) {
	return s.nth(1, match, d)
}

// asked is the n-th request the site was sent (from 1), within d.
func (s *unreadSite) asked(t *testing.T, n int, d time.Duration) unreadEvent {
	t.Helper()
	e, ok := s.nth(n, func(e unreadEvent) bool { return e.what == "asked" }, d)
	if !ok {
		t.Fatalf("request %d did not come", n)
	}
	return e
}

// dialingTo dials every connection of a client to addr.
func dialingTo(addr string) Option {
	return WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}))
}

// unreadKeys are the profile's keys of answers let go of unread.
var unreadKeys = []string{"h1.dropped_body", "h2.dropped_body", "h1.auth_body", "h2.auth_body",
	"h1.restart_body", "h2.restart_body", "h1.preflight_body", "h2.preflight_body"}

// unreadPolicy is every answer read as tls-forge always read it, no limit or
// grace said, but what over says.
func unreadPolicy(over map[string]any) map[string]any {
	p := map[string]any{}
	for _, k := range unreadKeys {
		p[k] = "read"
	}
	for _, k := range []string{"http.drain_bytes", "http.drain_ms", "http.first_bytes_ms", "h1.unread_grace_us", "h2.unread_grace_us"} {
		p[k] = nil
	}
	maps.Copy(p, over)
	return p
}

// about says whether got is about want: no sooner than 60ms before it, and
// no later than 400ms after.
func about(got, want time.Duration) bool {
	return got >= want-60*time.Millisecond && got <= want+400*time.Millisecond
}

// TestAnAnswerIsLetGoOfUnreadAsTheProfileSays sends a request whose answer it
// goes on from unread (a redirect, a 401, a navigation's Critical-CH, a
// preflight), the JSON alone changed, and holds it to what the server saw:
// when the next request came and on which connection, what became of the
// held body (sent, or given up as its stream was reset or its connection
// closed) and when, and when an HTTP/1.1 connection closed. Chrome's choices
// are measured (docs/profile-behavior.md); the rest are the engine's others.
func TestAnAnswerIsLetGoOfUnreadAsTheProfileSays(t *testing.T) {
	drain := func(mode string, ms int) map[string]any {
		return map[string]any{mode: "drain", "http.drain_bytes": 16384, "http.drain_ms": ms}
	}
	with := func(a map[string]any, kv ...any) map[string]any {
		b := maps.Clone(a)
		for i := 0; i < len(kv); i += 2 {
			b[kv[i].(string)] = kv[i+1]
		}
		return b
	}
	redirect := func(q string) *Request { return &Request{URL: "https://example.com/r?" + q} }
	auth := func(q string) *Request { return &Request{URL: "https://u:p@example.com/auth?" + q} }
	navigation := func(q string) *Request {
		return &Request{URL: "https://example.com/cch?" + q, Browser: &BrowserContext{Kind: KindNavigation}}
	}
	put := func(q string) *Request {
		return &Request{Method: "PUT", URL: "https://api.example.com/pf?" + q,
			Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/"}}
	}
	const late = 800 * time.Millisecond
	for _, tc := range []struct {
		name   string
		h2     bool
		policy map[string]any
		req    func(string) *Request
		query  string
		next   time.Duration // when the next request came after the first, about
		same   bool          // on the first's connection
		first  string        // what became of the held body: sent, unwanted
		at     time.Duration // when, about, after the first request
		kept   bool          // the first connection, not closed
		closed time.Duration // else when it closed, about
	}{
		// A redirect.
		{"h2 redirect close", true, map[string]any{"h2.dropped_body": "close"}, redirect, "delay=800", 0, true, "unwanted", 0, true, 0},
		{"h2 redirect close, the body within the grace", true, map[string]any{"h2.dropped_body": "close", "h2.unread_grace_us": 300_000}, redirect, "delay=60", 60 * time.Millisecond, true, "sent", 60 * time.Millisecond, true, 0},
		{"h2 redirect close, the body past the grace", true, map[string]any{"h2.dropped_body": "close", "h2.unread_grace_us": 100_000}, redirect, "delay=800", 100 * time.Millisecond, true, "unwanted", 100 * time.Millisecond, true, 0},
		{"h2 redirect drain", true, drain("h2.dropped_body", 3000), redirect, "delay=800", 0, true, "sent", late, true, 0},
		{"h2 redirect drain past its time", true, drain("h2.dropped_body", 300), redirect, "delay=800", 0, true, "unwanted", 300 * time.Millisecond, true, 0},
		{"h2 redirect read-all", true, map[string]any{"h2.dropped_body": "read-all"}, redirect, "delay=800", late, true, "sent", late, true, 0},
		{"h2 redirect read", true, nil, redirect, "delay=800", late, true, "sent", late, true, 0},
		{"h1 redirect drain", false, drain("h1.dropped_body", 3000), redirect, "delay=800", 0, false, "sent", late, true, 0},
		{"h1 redirect drain past its time", false, drain("h1.dropped_body", 300), redirect, "delay=800", 0, false, "unwanted", 300 * time.Millisecond, false, 300 * time.Millisecond},
		{"h1 redirect drain past its bytes", false, drain("h1.dropped_body", 3000), redirect, "delay=800&n=20000", 0, false, "sent", late, false, late},
		{"h1 redirect drain, the body with its head", false, with(drain("h1.dropped_body", 3000), "h1.unread_grace_us", 100_000), redirect, "now&n=8192", 0, true, "sent", 0, true, 0},
		{"h1 redirect drain, the body within the grace", false, with(drain("h1.dropped_body", 3000), "h1.unread_grace_us", 300_000), redirect, "delay=60", 60 * time.Millisecond, true, "sent", 60 * time.Millisecond, true, 0},
		{"h1 redirect close", false, map[string]any{"h1.dropped_body": "close"}, redirect, "delay=800", 0, false, "unwanted", 0, false, 0},
		{"h1 redirect close, the body with its head", false, map[string]any{"h1.dropped_body": "close", "h1.unread_grace_us": 100_000}, redirect, "now&n=20000", 0, true, "sent", 0, true, 0},
		{"h1 redirect read-all", false, map[string]any{"h1.dropped_body": "read-all"}, redirect, "delay=800", late, true, "sent", late, true, 0},
		{"h1 redirect read-all, the connection closed after", false, map[string]any{"h1.dropped_body": "read-all"}, redirect, "delay=800&close", 0, false, "unwanted", 0, false, 0},
		// 2 KiB at most of a body of unknown length, as the transport reads
		// it, and the connection closed with the rest unread.
		{"h1 redirect read", false, nil, redirect, "delay=800", late, false, "sent", late, false, late},
		// A 401 answered again.
		{"h2 401 close", true, map[string]any{"h2.auth_body": "close"}, auth, "delay=800", 0, true, "unwanted", 0, true, 0},
		{"h2 401 read", true, nil, auth, "delay=800", late, true, "sent", late, true, 0},
		{"h1 401 read-all", false, map[string]any{"h1.auth_body": "read-all"}, auth, "delay=800", late, true, "sent", late, true, 0},
		{"h1 401 read-all, the connection closed after", false, map[string]any{"h1.auth_body": "read-all"}, auth, "delay=800&close", 0, false, "unwanted", 0, false, 0},
		{"h1 401 close", false, map[string]any{"h1.auth_body": "close"}, auth, "delay=800", 0, false, "unwanted", 0, false, 0},
		// A navigation started again for its critical client hints.
		{"h2 restart close", true, map[string]any{"h2.restart_body": "close"}, navigation, "delay=800", 0, true, "unwanted", 0, true, 0},
		{"h2 restart read", true, nil, navigation, "delay=800", late, true, "sent", late, true, 0},
		{"h1 restart close", false, map[string]any{"h1.restart_body": "close"}, navigation, "delay=800", 0, false, "unwanted", 0, false, 0},
		{"h1 restart close, the body with its head", false, map[string]any{"h1.restart_body": "close", "h1.unread_grace_us": 100_000}, navigation, "now&n=20000", 0, true, "sent", 0, true, 0},
		// A preflight its request goes on from.
		{"h2 preflight first-bytes", true, map[string]any{"h2.preflight_body": "first-bytes", "http.first_bytes_ms": 0}, put, "delay=800", 0, true, "sent", late, true, 0},
		{"h2 preflight first-bytes, the body in parts", true, map[string]any{"h2.preflight_body": "first-bytes", "http.first_bytes_ms": 0}, put, "delay=800&n=8192&parts=2&gap=600", 0, true, "unwanted", late, true, 0},
		{"h2 preflight first-bytes past its time", true, map[string]any{"h2.preflight_body": "first-bytes", "http.first_bytes_ms": 300}, put, "delay=800", 0, true, "unwanted", 300 * time.Millisecond, true, 0},
		{"h2 preflight read", true, nil, put, "delay=800", late, true, "sent", late, true, 0},
		// Its chunk longer than what one read of the transport's buffer
		// takes, the rest is read within the grace.
		{"h1 preflight first-bytes", false, map[string]any{"h1.preflight_body": "first-bytes", "http.first_bytes_ms": 0, "h1.unread_grace_us": 100_000}, put, "delay=800", 0, false, "sent", late, true, 0},
		{"h1 preflight first-bytes, with no grace", false, map[string]any{"h1.preflight_body": "first-bytes", "http.first_bytes_ms": 0}, put, "delay=800", 0, false, "sent", late, false, late},
		{"h1 preflight first-bytes, the body in parts", false, map[string]any{"h1.preflight_body": "first-bytes", "http.first_bytes_ms": 0}, put, "delay=800&n=8192&parts=2&gap=600", 0, false, "unwanted", late, false, late},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			site := newUnreadSite(t, tc.h2)
			c := newTestClient(t, WithProfileValue(policyFile(t, unreadPolicy(tc.policy))), dialingTo(site.Listener.Addr().String()))
			ended := doing(c, tc.req(tc.query))
			first := site.asked(t, 1, 5*time.Second)
			next := site.asked(t, 2, 5*time.Second)
			if took := next.at.Sub(first.at); !about(took, tc.next) {
				t.Errorf("the next request came %v after the first, want about %v", took, tc.next)
			}
			if same := next.conn == first.conn; same != tc.same {
				t.Errorf("the next request on the first's connection: %v", same)
			}
			if err := endedWithin(t, ended, 5*time.Second); err != nil {
				t.Fatal(err)
			}
			body, ok := site.event(func(e unreadEvent) bool {
				return (e.what == "sent" || e.what == "unwanted") && e.path == first.path && e.conn == first.conn
			}, 3*time.Second)
			if !ok || body.what != tc.first || !about(body.at.Sub(first.at), tc.at) {
				t.Errorf("the held body: %s %v after (ok %v), want %s about %v", body.what, body.at.Sub(first.at), ok, tc.first, tc.at)
			}
			closed, ok := site.event(func(e unreadEvent) bool { return e.what == "closed" && e.conn == first.conn }, late+700*time.Millisecond)
			switch {
			case tc.kept && ok:
				t.Errorf("the first connection closed %v after it was asked on, want it kept", closed.at.Sub(first.at))
			case !tc.kept && (!ok || !about(closed.at.Sub(first.at), tc.closed)):
				t.Errorf("the first connection closed %v after (ok %v), want about %v", closed.at.Sub(first.at), ok, tc.closed)
			}
		})
	}
}

// TestA401AnsweredNoMoreIsLetGoOfAsADroppedAnswer: the 401 a request is given
// up for, its answers spent (one here), goes as dropped_body says, the error
// at once: over HTTP/2 its stream reset, over HTTP/1.1 drained in the
// background on a connection kept.
func TestA401AnsweredNoMoreIsLetGoOfAsADroppedAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		h2     bool
		policy map[string]any
		body   string // what became of the 401's body
		at     time.Duration
	}{
		{"h2", true, map[string]any{"h2.auth_body": "read-all", "h2.dropped_body": "close"}, "unwanted", 0},
		{"h1", false, map[string]any{"h1.auth_body": "read-all", "h1.dropped_body": "drain", "http.drain_bytes": 16384, "http.drain_ms": 3000}, "sent", 800 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			site := newUnreadSite(t, tc.h2)
			p := unreadPolicy(tc.policy)
			p["http.max_auth_restarts"] = 1
			c := newTestClient(t, WithProfileValue(policyFile(t, p)), dialingTo(site.Listener.Addr().String()))
			ended := doing(c, &Request{URL: "https://u:p@example.com/auth?delay=800"})
			first := site.asked(t, 1, 5*time.Second)
			err := endedWithin(t, ended, 5*time.Second)
			if err == nil || !strings.Contains(err.Error(), "asked for authentication again") {
				t.Fatalf("err = %v", err)
			}
			if took := time.Since(first.at); took > 400*time.Millisecond {
				t.Errorf("the request failed %v after the 401 came, want at once", took)
			}
			body, ok := site.event(func(e unreadEvent) bool {
				return (e.what == "sent" || e.what == "unwanted") && e.path == first.path
			}, 3*time.Second)
			if !ok || body.what != tc.body || !about(body.at.Sub(first.at), tc.at) {
				t.Errorf("the 401's body: %s %v after (ok %v), want %s about %v", body.what, body.at.Sub(first.at), ok, tc.body, tc.at)
			}
			if closed, ok := site.event(func(e unreadEvent) bool { return e.what == "closed" && e.conn == first.conn }, 1500*time.Millisecond); ok {
				t.Errorf("its connection closed %v after, want it kept", closed.at.Sub(first.at))
			}
			if _, again := site.nth(2, func(e unreadEvent) bool { return e.what == "asked" }, 0); again {
				t.Error("the 401 was answered")
			}
		})
	}
}

// TestAClosedClientLetsGoOfWhatItDrains: closing the client ends a body it
// waits on in the background for an answer it went on from, its
// connection closed.
func TestAClosedClientLetsGoOfWhatItDrains(t *testing.T) {
	site := newUnreadSite(t, false)
	c, err := New(WithInsecureSkipVerify(), WithProfileValue(policyFile(t, unreadPolicy(map[string]any{
		"http.instance_scope": "client", "h1.preflight_body": "first-bytes", "http.first_bytes_ms": 0}))), dialingTo(site.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(&Request{Method: "PUT", URL: "https://api.example.com/pf?delay=5000",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.com/"}}); err != nil {
		t.Fatal(err)
	}
	first := site.asked(t, 1, time.Second)
	began := time.Now()
	_ = c.Close()
	closed, ok := site.event(func(e unreadEvent) bool { return e.what == "closed" && e.conn == first.conn }, 2*time.Second)
	if !ok || closed.at.Sub(began) > 500*time.Millisecond {
		t.Fatalf("the preflight's connection closed %v after Close (ok %v), want at once", closed.at.Sub(began), ok)
	}
}

// countingBody is a body that says how much of it was read, and whether it
// was closed.
type countingBody struct {
	io.Reader
	n      int
	closed bool
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.n += n
	return n, err
}

func (b *countingBody) Close() error {
	b.closed = true
	return nil
}

// TestAnAnswerOfAnotherProtocolIsReadAsAlways: an answer over neither
// HTTP/1.1 nor HTTP/2 is read as tls-forge always read it, whatever the
// profile says of the two, and a negative limit leaves it to the transport.
func TestAnAnswerOfAnotherProtocolIsReadAsAlways(t *testing.T) {
	c := newTestClient(t, WithProfileValue(policyFile(t, unreadPolicy(map[string]any{"h1.auth_body": "close", "h2.auth_body": "close"}))))
	read := &countingBody{Reader: strings.NewReader(strings.Repeat("x", 100))}
	res := &fhttp.Response{ProtoMajor: 3, Body: read}
	c.leave("auth", res, 64)
	if read.n != 64 || !read.closed || res.Body != fhttp.NoBody {
		t.Fatalf("read %d, closed %v; want 64 read and closed", read.n, read.closed)
	}
	read = &countingBody{Reader: strings.NewReader("abc")}
	res = &fhttp.Response{ProtoMajor: 1, Body: read}
	c.leave("dropped", res, -1)
	if read.n != 0 || read.closed || res.Body != read {
		t.Fatalf("a body left to the transport was read %d, closed %v", read.n, read.closed)
	}
}

// TestClosingIdleConnectionsLetsGoOfWhatADrainHolds: CloseIdleConnections
// ends what the client drains in the background, its connection closed, and
// returns once it is: a request after the body would have come opens a
// connection of its own, where the drained one would have been kept for it.
func TestClosingIdleConnectionsLetsGoOfWhatADrainHolds(t *testing.T) {
	site := newUnreadSite(t, false)
	c := newTestClient(t, WithProfileValue(policyFile(t, unreadPolicy(map[string]any{
		"h1.dropped_body": "drain", "http.drain_bytes": 16384, "http.drain_ms": 3000}))), dialingTo(site.Listener.Addr().String()))
	if _, err := c.Do(&Request{URL: "https://example.com/r?delay=300"}); err != nil {
		t.Fatal(err)
	}
	first := site.asked(t, 1, time.Second)
	c.transports.mu.Lock()
	draining := slices.Collect(maps.Keys(c.transports.draining))
	c.transports.mu.Unlock()
	if len(draining) != 1 {
		t.Fatalf("%d answers drained, want the redirect's", len(draining))
	}
	c.CloseIdleConnections()
	select {
	case <-draining[0]:
	default:
		t.Fatal("CloseIdleConnections returned with the drain still at it")
	}
	closed, ok := site.event(func(e unreadEvent) bool { return e.what == "closed" && e.conn == first.conn }, time.Second)
	if !ok || closed.at.Sub(first.at) > 250*time.Millisecond {
		t.Fatalf("the drained connection closed %v after it was asked on (ok %v), want before its body", closed.at.Sub(first.at), ok)
	}
	time.Sleep(400 * time.Millisecond) // past when the body would have come
	if _, err := c.Do(&Request{URL: "https://example.com/end"}); err != nil {
		t.Fatal(err)
	}
	if last := site.asked(t, 3, time.Second); last.conn == first.conn {
		t.Fatal("the next request went on the drained connection")
	}
	c.transports.mu.Lock()
	left := len(c.transports.draining)
	c.transports.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d drains done but still kept", left)
	}
	// The drains of a client before are no business of a fresh one's.
	fresh, err := c.Fresh()
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	fresh.CloseIdleConnections()
}
