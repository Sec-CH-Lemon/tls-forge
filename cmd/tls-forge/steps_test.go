package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge"
)

// drivenTries drives two tries through every hook a client reports through,
// and is the trace they made and the record of each.
func drivenTries(t *testing.T) ([]traceEvent, []*try) {
	t.Helper()
	file := &brokenFile{}
	traceInto(t, file)
	trace, err := openTrace("anywhere", "fetch", "", now(), traceArgs{})
	if err != nil {
		t.Fatalf("openTrace: %v", err)
	}
	lane := trace.main()

	// Through a proxy, over TLS, with a redirect to plain HTTP on the
	// connection already open, and a request whose sending failed there.
	proxied := &try{}
	a := lane.attempt("GET", "https://example.test/start?token=s3cr3t", 1, 1, "http://user:pw@proxy.test:8080", proxied)
	hooks := a.hooks()
	hooks.DNSStart("example.test")
	hooks.DNSDone(nil, nil)
	hooks.ConnectStart("tcp", "[2001:db8::1]:443")
	hooks.ConnectStart("tcp", "192.0.2.1:443")
	hooks.ConnectDone("tcp", "[2001:db8::1]:443", errors.New("no route to host"))
	hooks.ConnectDone("tcp", "192.0.2.1:443", nil)
	hooks.GotConn(tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:443", TLSVersion: "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2", Resumed: true,
		ProxyHeader: tlsforge.NewHeader("X-Exit-IP", "203.0.113.1")})
	hooks.WroteRequest(tlsforge.Header{{Name: ":method", Value: "GET"}, {Name: "cookie", Value: "session=abc"}}, nil)
	hooks.FirstByte()
	hooks.Redirect(302, "http://example.test/next?token=s3cr3t")
	hooks.GotConn(tlsforge.ConnInfo{RemoteAddr: "192.0.2.1:80", Reused: true})
	hooks.WroteRequest(tlsforge.Header{{Name: "user-agent", Value: "x"}}, errors.New("broken pipe"))
	hooks.FirstByte()
	a.end(&tlsforge.Response{Status: 200, Body: []byte("page"), URL: "http://example.test/next",
		Header: map[string][]string{"Content-Type": {"text/html"}}}, nil)

	// Nowhere to go: the lookup failed, and so did the try.
	lost := &try{}
	b := lane.attempt("GET", "https://nowhere.test/", 1, 2, "", lost)
	hooks = b.hooks()
	hooks.DNSStart("nowhere.test")
	hooks.DNSDone(nil, errors.New("no such host"))
	b.end(nil, errors.New("lookup failed"))

	if err := trace.close(nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	return parseTrace(t, file.Bytes()), []*try{proxied, lost}
}

// eventLines are the events of a trace, but for its metadata, as lines of
// what each says, without when.
func eventLines(t *testing.T, events []traceEvent) []string {
	t.Helper()
	var lines []string
	for _, event := range events {
		if event.Phase == phaseMetadata {
			continue
		}
		args, err := json.Marshal(event.Args)
		if err != nil {
			t.Fatalf("args: %v", err)
		}
		if event.Name == "fetch" && event.Phase == phaseBegin {
			// The run's own, whose args say when it began.
			args = []byte("{…}")
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s", event.Phase, event.Cat, event.Name, args))
	}
	return lines
}

// stepLines are the steps a try kept, as lines of what each says.
func stepLines(tries []*try) []string {
	var lines []string
	for _, kept := range tries {
		for _, s := range kept.Steps {
			lines = append(lines, fmt.Sprintf("%s | %s | %s | %v", s.Name, s.Note, strings.ReplaceAll(s.Written, "\n", "\\n"), s.Cut))
		}
		lines = append(lines, fmt.Sprintf("end %d %q", kept.Status, kept.Error))
	}
	return lines
}

func TestEveryStepIsTracedAndKeptAsItWas(t *testing.T) {
	// What each step says, in the trace and in the record a report is written
	// from, held to the letter: a fact said under a name, or left out, is what
	// a viewer of the trace and the report read.
	events, tries := drivenTries(t)
	wantEvents := []string{
		"B run fetch {…}",
		`B request GET https://example.test/start?token=s3cr3t {"attempt":1,"proxy":"http://user@proxy.test:8080","run":1,"url":"https://example.test/start?token=s3cr3t"}`,
		`X net dns {"addrs":null,"host":"example.test"}`,
		`X net connect {"addr":"192.0.2.1:443","addrs":["[2001:db8::1]:443","192.0.2.1:443"],"failed":["no route to host"],"network":"tcp"}`,
		`X net proxy+tls {"alpn":"h2","cipher":"TLS_AES_128_GCM_SHA256","proxy_answer":["x-exit-ip: 203.0.113.1"],"remote":"192.0.2.1:443","resumed":true,"reused":false,"tls":"TLS 1.3"}`,
		`X http send {"alpn":"h2","cipher":"TLS_AES_128_GCM_SHA256","headers":[":method: GET","cookie: session=***"],"proxy_answer":["x-exit-ip: 203.0.113.1"],"remote":"192.0.2.1:443","resumed":true,"reused":false,"tls":"TLS 1.3"}`,
		"X http wait null",
		`X http receive {"status":302}`,
		`i http redirect {"location":"http://example.test/next?token=s3cr3t","status":302}`,
		`X http send {"error":"broken pipe","headers":["user-agent: x"],"remote":"192.0.2.1:80","reused":true}`,
		"X http wait null",
		`X http receive {"status":200}`,
		`E   {"bytes":4,"final_url":"http://example.test/next","headers":["Content-Type: text/html"],"status":200}`,
		`B request GET https://nowhere.test/ {"attempt":2,"run":1,"url":"https://nowhere.test/"}`,
		`X net dns {"addrs":null,"error":"no such host","host":"nowhere.test"}`,
		`E   {"error":"lookup failed"}`,
		"E   null",
	}
	if got := eventLines(t, events); !slices.Equal(got, wantEvents) {
		t.Errorf("the trace says\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantEvents, "\n"))
	}
	wantSteps := []string{
		"dns | example.test |  | false",
		"connect | 192.0.2.1:443 · failed: no route to host |  | false",
		"proxy+tls | TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2 · session resumed |  | false",
		`send |  | :method: GET\ncookie: session=*** | false`,
		"wait |  |  | false",
		"receive |  |  | false",
		"redirect | 302 → http://example.test/next?token=s3cr3t |  | false",
		"send | on the connection already open to 192.0.2.1:80 · broken pipe | user-agent: x | false",
		"wait |  |  | false",
		"receive |  |  | false",
		`end 200 ""`,
		"dns | nowhere.test · no such host |  | false",
		`end 0 "lookup failed"`,
	}
	if got := stepLines(tries); !slices.Equal(got, wantSteps) {
		t.Errorf("the record says\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantSteps, "\n"))
	}
}
