package tlsforge

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// resendSite is a server over TLS, speaking HTTP/2 or HTTP/1.1 alone, that
// does to each request what acts says for its path, one act a request, "ok"
// once they are spent: "refuse" (RST_STREAM REFUSED_STREAM), "goaway:N"
// (GOAWAY with code N above it), "goaway-close" (GOAWAY taking it, then a
// FIN), "close" (a FIN), "reset" (a RST), "partial" (a status line cut short,
// then a FIN), "401", "302:PATH", "408" (over HTTP/1.1 with Connection:
// close, the connection left to the client). It says what it was asked,
// "c1#0 GET /a" (the connection, the how-manyth request on it) and "c2#0 POST
// /x x" (with the body), and "c1 EOF" when a client closed a connection.
type resendSite struct {
	t     *testing.T
	url   string
	asked chan string
	mu    sync.Mutex
	acts  map[string][]string
}

func newResendSite(t *testing.T, h2 bool, acts map[string][]string) *resendSite {
	t.Helper()
	proto := "http/1.1"
	if h2 {
		proto = "h2"
	}
	ln := tlsListener(t, proto)
	s := &resendSite{t: t, url: "https://" + ln.Addr().String(), asked: make(chan string, 64), acts: acts}
	go func() {
		for n := 1; ; n++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if h2 {
				go s.serveH2(n, conn.(*tls.Conn))
			} else {
				go s.serveH1(n, conn.(*tls.Conn))
			}
		}
	}()
	return s
}

// act is what is done to the next request to path.
func (s *resendSite) act(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	acts := s.acts[path]
	if len(acts) == 0 {
		return "ok"
	}
	s.acts[path] = acts[1:]
	return acts[0]
}

func (s *resendSite) say(n, seq int, method, path string, body []byte) {
	what := fmt.Sprintf("c%d#%d %s %s", n, seq, method, path)
	if len(body) > 0 {
		what += " " + string(body)
	}
	s.asked <- what
}

// hangUp closes conn's TCP connection under its TLS: a FIN, or a RST.
func hangUp(conn *tls.Conn, reset bool) {
	if reset {
		conn.NetConn().(*net.TCPConn).SetLinger(0)
	}
	conn.NetConn().Close()
}

func (s *resendSite) serveH1(n int, conn *tls.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for seq := 0; ; seq++ {
		req, err := http.ReadRequest(br)
		if err != nil {
			s.asked <- fmt.Sprintf("c%d EOF", n)
			return
		}
		body, _ := io.ReadAll(req.Body)
		s.say(n, seq, req.Method, req.URL.Path, body)
		switch act := s.act(req.URL.Path); {
		case act == "close", act == "reset":
			hangUp(conn, act == "reset")
			return
		case act == "partial":
			io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-")
			hangUp(conn, false)
			return
		case act == "408":
			io.WriteString(conn, "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 3\r\n\r\n408")
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			io.Copy(io.Discard, conn)
			s.asked <- fmt.Sprintf("c%d EOF", n)
			return
		case act == "401":
			io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"r\"\r\nContent-Length: 0\r\n\r\n")
		case strings.HasPrefix(act, "302:"):
			io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: "+act[4:]+"\r\nContent-Length: 0\r\n\r\n")
		default:
			io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	}
}

func (s *resendSite) serveH2(n int, conn *tls.Conn) {
	defer conn.Close()
	if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
		s.asked <- fmt.Sprintf("c%d EOF", n)
		return
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	_ = fr.WriteSettings()
	type asked struct {
		method, path string
		body         []byte
	}
	streams := map[uint32]*asked{}
	seq := 0
	var last uint32 // the last stream answered
	answer := func(id uint32, status int, fields ...string) {
		var block bytes.Buffer
		enc := hpack.NewEncoder(&block)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
		for i := 0; i < len(fields); i += 2 {
			_ = enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
		}
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, BlockFragment: block.Bytes()})
		_ = fr.WriteData(id, true, []byte(strconv.Itoa(status)))
		last = id
	}
	// done does to the request of stream id what its path's act says, and
	// says whether the connection goes on.
	done := func(id uint32) bool {
		a := streams[id]
		delete(streams, id)
		s.say(n, seq, a.method, a.path, a.body)
		seq++
		switch act := s.act(a.path); {
		case act == "refuse":
			_ = fr.WriteRSTStream(id, http2.ErrCodeRefusedStream)
		case strings.HasPrefix(act, "goaway:"):
			code, _ := strconv.Atoi(act[7:])
			_ = fr.WriteGoAway(last, http2.ErrCode(code), nil)
		case act == "goaway-close":
			_ = fr.WriteGoAway(id, http2.ErrCodeNo, nil)
			hangUp(conn, false)
			return false
		case act == "close", act == "reset":
			hangUp(conn, act == "reset")
			return false
		case act == "401":
			answer(id, 401, "www-authenticate", `Basic realm="r"`)
		case strings.HasPrefix(act, "302:"):
			answer(id, 302, "location", act[4:])
		case act == "408":
			answer(id, 408)
		default:
			answer(id, 200)
		}
		return true
	}
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			s.asked <- fmt.Sprintf("c%d EOF", n)
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.MetaHeadersFrame:
			streams[f.StreamID] = &asked{method: f.PseudoValue("method"), path: f.PseudoValue("path")}
			if f.StreamEnded() && !done(f.StreamID) {
				return
			}
		case *http2.DataFrame:
			a := streams[f.StreamID]
			if a == nil {
				continue
			}
			a.body = append(a.body, f.Data()...)
			if len(f.Data()) > 0 {
				_ = fr.WriteWindowUpdate(0, uint32(len(f.Data())))
			}
			if f.StreamEnded() && !done(f.StreamID) {
				return
			}
		}
	}
}

// expect reads what the site was asked, the ends of connections aside but
// those named, which must be want, then nothing more for a moment.
func (s *resendSite) expect(want ...string) {
	s.t.Helper()
	var got []string
	ends := strings.Contains(strings.Join(want, ","), "EOF")
	for len(got) < len(want) {
		select {
		case what := <-s.asked:
			if strings.HasSuffix(what, "EOF") && !ends {
				continue
			}
			got = append(got, what)
		case <-time.After(5 * time.Second):
			s.t.Fatalf("got %q, then nothing, want %q", got, want)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		s.t.Fatalf("got %q, want %q", got, want)
	}
	for {
		select {
		case what := <-s.asked:
			if !strings.HasSuffix(what, "EOF") {
				s.t.Fatalf("got %q after %q", what, got)
			}
		case <-time.After(150 * time.Millisecond):
			return
		}
	}
}

// resendCase is one request after another to a site, as a page goes on: what
// the site does, the JSON changed, the request, what the site is asked and
// what the request comes to.
type resendCase struct {
	name   string
	acts   map[string][]string
	change map[string]any
	fresh  bool   // the request goes first, on a connection of its own
	post   bool   // a fetch() POST of "x"
	path   string // /x
	user   string // credentials in its URL
	want   []string
	status int // 0 for none: the request fails
}

// TestARequestGoesAgainAsChromeSendsItAgainOverHTTP2 holds the shipped
// profile, its retry keys alone changed, to what Chrome 155 was measured to
// send again (review 2026-10-24, rc-h2-*): a refused stream at once on its
// connection, twice at most, a POST with its body; a stream above a GOAWAY
// with NO_ERROR on another connection, those two sharing the count; nothing
// after a GOAWAY with another code; a reused connection lost under it,
// closed or reset, or after a GOAWAY that took it, once on another, whose
// own loss is final, as is that of a new one; a 408 its answer. The count is
// the hop's: its answer to a 401 shares it, the next hop of a redirect has
// its own. Without the keys, the transport as it was: a stream above any
// GOAWAY goes again.
func TestARequestGoesAgainAsChromeSendsItAgainOverHTTP2(t *testing.T) {
	legacy := map[string]any{"h2.retries": nil, "h2.retry_errors": nil, "h2.retry_delay_ms": nil, "http.connection_error_retries": nil, "http.connection_error_methods": nil}
	runResends(t, true, []resendCase{
		{name: "refused once", acts: map[string][]string{"/x": {"refuse"}}, want: []string{"c1#1 GET /x", "c1#2 GET /x"}, status: 200},
		{name: "refused twice", acts: map[string][]string{"/x": {"refuse", "refuse"}}, want: []string{"c1#1 GET /x", "c1#2 GET /x", "c1#3 GET /x"}, status: 200},
		{name: "refused thrice", acts: map[string][]string{"/x": {"refuse", "refuse", "refuse"}}, want: []string{"c1#1 GET /x", "c1#2 GET /x", "c1#3 GET /x"}},
		{name: "refused POST", acts: map[string][]string{"/x": {"refuse"}}, post: true, want: []string{"c1#1 POST /x x", "c1#2 POST /x x"}, status: 200},
		{name: "goaway", acts: map[string][]string{"/x": {"goaway:0"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "goaway thrice", acts: map[string][]string{"/x": {"goaway:0", "goaway:0", "goaway:0"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x", "c3#0 GET /x"}},
		{name: "goaway protocol error", acts: map[string][]string{"/x": {"goaway:1"}}, want: []string{"c1#1 GET /x"}},
		{name: "goaway internal error", acts: map[string][]string{"/x": {"goaway:2"}}, want: []string{"c1#1 GET /x"}},
		{name: "goaway enhance your calm", acts: map[string][]string{"/x": {"goaway:11"}}, want: []string{"c1#1 GET /x"}},
		{name: "closed", acts: map[string][]string{"/x": {"close"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "reset", acts: map[string][]string{"/x": {"reset"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "closed POST", acts: map[string][]string{"/x": {"close"}}, post: true, want: []string{"c1#1 POST /x x", "c2#0 POST /x x"}, status: 200},
		{name: "closed twice", acts: map[string][]string{"/x": {"close", "close"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}},
		{name: "closed fresh", acts: map[string][]string{"/x": {"close"}}, fresh: true, want: []string{"c1#0 GET /x"}},
		{name: "goaway then closed", acts: map[string][]string{"/x": {"goaway-close"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "408", acts: map[string][]string{"/x": {"408"}}, want: []string{"c1#1 GET /x"}, status: 408},
		{name: "refused goaway refused", acts: map[string][]string{"/x": {"refuse", "goaway:0", "refuse"}}, want: []string{"c1#1 GET /x", "c1#2 GET /x", "c2#0 GET /x"}},
		{name: "refused refused closed", acts: map[string][]string{"/x": {"refuse", "refuse", "close"}}, want: []string{"c1#1 GET /x", "c1#2 GET /x", "c1#3 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "401 shares the count", acts: map[string][]string{"/x": {"refuse", "refuse", "401", "refuse"}}, user: "u:p", want: []string{"c1#1 GET /x", "c1#2 GET /x", "c1#3 GET /x", "c1#4 GET /x"}},
		{name: "a redirect counts afresh", acts: map[string][]string{"/x": {"refuse", "refuse", "302:/y"}, "/y": {"refuse", "refuse"}}, want: []string{"c1#1 GET /x", "c1#2 GET /x", "c1#3 GET /x", "c1#4 GET /y", "c1#5 GET /y", "c1#6 GET /y"}, status: 200},
		{name: "legacy goaway protocol error", acts: map[string][]string{"/x": {"goaway:1"}}, change: legacy, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "legacy closed", acts: map[string][]string{"/x": {"close"}}, change: legacy, want: []string{"c1#1 GET /x"}},
	})
}

// TestARequestGoesAgainAsChromeSendsItAgainOverHTTP1 holds the shipped
// profile to what Chrome 155 was measured to send again over HTTP/1.1
// (rc-h1-*): a request whose reused connection was closed or reset before any
// of its answer came at once on another, a POST with its body; not one whose
// answer had begun, nor one on a new connection, whose loss is final; and a
// request answered 408 on a reused connection, which the client closes. The
// JSON alone changes it: a 408 the answer without h1.request_timeout_resend,
// a POST not sent again when idempotent methods alone are, and without the
// keys Go's rule, a GET again, a POST not.
func TestARequestGoesAgainAsChromeSendsItAgainOverHTTP1(t *testing.T) {
	legacy := map[string]any{"h2.retries": nil, "h2.retry_errors": nil, "h2.retry_delay_ms": nil, "http.connection_error_retries": nil, "http.connection_error_methods": nil, "h1.request_timeout_resend": nil}
	runResends(t, false, []resendCase{
		{name: "closed", acts: map[string][]string{"/x": {"close"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "reset", acts: map[string][]string{"/x": {"reset"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "closed POST", acts: map[string][]string{"/x": {"close"}}, post: true, want: []string{"c1#1 POST /x x", "c2#0 POST /x x"}, status: 200},
		{name: "reset POST", acts: map[string][]string{"/x": {"reset"}}, post: true, want: []string{"c1#1 POST /x x", "c2#0 POST /x x"}, status: 200},
		{name: "idempotent alone", acts: map[string][]string{"/x": {"close"}}, post: true, change: map[string]any{"http.connection_error_methods": "idempotent"}, want: []string{"c1#1 POST /x x"}},
		{name: "partial", acts: map[string][]string{"/x": {"partial"}}, want: []string{"c1#1 GET /x"}},
		{name: "closed twice", acts: map[string][]string{"/x": {"close", "close"}}, want: []string{"c1#1 GET /x", "c2#0 GET /x"}},
		{name: "closed fresh", acts: map[string][]string{"/x": {"close"}}, fresh: true, want: []string{"c1#0 GET /x"}},
		{name: "408", acts: map[string][]string{"/x": {"408"}}, want: []string{"c1#1 GET /x", "c1 EOF", "c2#0 GET /x"}, status: 200},
		{name: "408 POST", acts: map[string][]string{"/x": {"408"}}, post: true, want: []string{"c1#1 POST /x x", "c1 EOF", "c2#0 POST /x x"}, status: 200},
		{name: "408 twice", acts: map[string][]string{"/x": {"408", "408"}}, want: []string{"c1#1 GET /x", "c1 EOF", "c2#0 GET /x"}, status: 408},
		{name: "408 fresh", acts: map[string][]string{"/x": {"408"}}, fresh: true, want: []string{"c1#0 GET /x"}, status: 408},
		{name: "408 not resent", acts: map[string][]string{"/x": {"408"}}, change: map[string]any{"h1.request_timeout_resend": false}, want: []string{"c1#1 GET /x"}, status: 408},
		{name: "legacy GET", acts: map[string][]string{"/x": {"close"}}, change: legacy, want: []string{"c1#1 GET /x", "c2#0 GET /x"}, status: 200},
		{name: "legacy POST", acts: map[string][]string{"/x": {"close"}}, change: legacy, post: true, want: []string{"c1#1 POST /x x"}},
		{name: "legacy 408", acts: map[string][]string{"/x": {"408"}}, change: legacy, want: []string{"c1#1 GET /x"}, status: 408},
	})
}

func runResends(t *testing.T, h2 bool, cases []resendCase) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			site := newResendSite(t, h2, tc.acts)
			c := newTestClient(t, WithProfileValue(policyFile(t, tc.change)), WithTimeout(10*time.Second))
			if !tc.fresh {
				get(t, c, site.url+"/a", nil)
				site.expect("c1#0 GET /a")
			}
			page := site.url + "/a"
			target := site.url + "/x"
			if tc.user != "" {
				target = strings.Replace(target, "https://", "https://"+tc.user+"@", 1)
			}
			req := &Request{URL: target, Browser: &BrowserContext{Kind: KindNavigation, Initiator: page}}
			if tc.post {
				req = &Request{Method: "POST", URL: target, Body: []byte("x"), Header: Header{{Name: "Content-Type", Value: "text/plain;charset=UTF-8"}},
					Browser: &BrowserContext{Kind: KindFetch, Initiator: page}}
			}
			began := time.Now()
			res, err := c.Do(req)
			site.expect(tc.want...)
			switch {
			case tc.status == 0 && err == nil:
				t.Fatalf("answered %d, want it to fail", res.Status)
			case tc.status != 0 && err != nil:
				t.Fatalf("%v, want %d", err, tc.status)
			case tc.status != 0 && res.Status != tc.status:
				t.Fatalf("answered %d, want %d", res.Status, tc.status)
			}
			if took := time.Since(began); took > time.Second {
				t.Errorf("took %v: a request waited before it went again", took)
			}
		})
	}
}
