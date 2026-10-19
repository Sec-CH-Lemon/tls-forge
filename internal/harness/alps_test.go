package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/http2"
)

// alpsFixture is the fixture of ALPS, from the package's directory.
const alpsFixture = "../../testdata/chrome155-alps.json"

// h2Client is a client of the bench's ALPS server at port: HTTP/2 offered
// alone unless protos says otherwise.
func h2Client(port int, protos ...string) *http.Client {
	if protos == nil {
		protos = []string{"h2"}
	}
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(port))
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: protos}, //nolint:gosec // the bench's
		ForceAttemptHTTP2: slices.Contains(protos, "h2"),
	}}
}

func TestTheALPSServerAnswersHTTP2AndHTTP1(t *testing.T) {
	s := started(t, alpsCatalogue)
	for _, tc := range []struct {
		variant, proto string
		protos         []string
	}{
		{"none", "HTTP/2.0", nil},
		{"settings", "HTTP/2.0", nil},
		{"empty", "HTTP/1.1", []string{"http/1.1"}},
	} {
		s.Reset()
		c := h2Client(s.ALPS[tc.variant], tc.protos...)
		res, err := c.Get("https://www.example.com:" + strconv.Itoa(s.ALPS[tc.variant]) + "/p/a")
		if err != nil {
			t.Fatalf("%s: %v", tc.variant, err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		c.CloseIdleConnections()
		entries := requests(t, s)
		handshakes := s.ALPSHandshakes()
		if res.Proto != tc.proto || len(entries) != 1 || len(handshakes) != 1 || handshakes[0].Conn != entries[0].Conn {
			t.Errorf("%s: %s, kept %+v and %+v", tc.variant, res.Proto, entries, handshakes)
		}
		if tc.proto == "HTTP/2.0" && len(handshakes[0].Settings) == 0 {
			t.Errorf("%s: no SETTINGS kept: %+v", tc.variant, handshakes[0])
		}
	}
	// A GOAWAY is kept with its error and debug data, and a handshake that
	// fails is not kept.
	s.Reset()
	port := s.ALPS["empty"]
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // the bench's
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	framer := http2.NewFramer(conn, conn)
	_, _ = conn.Write([]byte(http2.ClientPreface))
	_ = framer.WriteSettings()
	_ = framer.WriteGoAway(0, http2.ErrCodeProtocol, []byte("why"))
	for !slices.ContainsFunc(s.ALPSHandshakes(), func(h ALPSHandshake) bool { return h.GoAway != "" }) {
		if _, err := framer.ReadFrame(); err != nil {
			break
		}
	}
	_ = conn.Close()
	if got := s.ALPSHandshakes(); len(got) != 1 || got[0].GoAway != "PROTOCOL_ERROR: why" {
		t.Errorf("the GOAWAY: %+v", got)
	}
	raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_, _ = raw.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	_ = raw.(*net.TCPConn).CloseWrite()
	_, _ = io.ReadAll(raw)
	_ = raw.Close()
	if got := s.ALPSHandshakes(); len(got) != 1 {
		t.Errorf("a handshake that failed was kept: %+v", got)
	}
}

func TestAnALPSConnectionThatArrivesAsTheServerClosesIsClosedToo(t *testing.T) {
	s := started(t, alpsCatalogue)
	ours, theirs := net.Pipe()
	defer func() { _ = theirs.Close() }()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.done.Add(1)
	s.acceptALPS(&oneConnListener{conn: ours}, "none")
	if _, err := ours.Write([]byte("x")); err == nil {
		t.Error("the connection was left open")
	}
	s.mu.Lock()
	s.closed = false
	s.mu.Unlock()
}

func TestAnALPSServerThatCannotStartSaysWhy(t *testing.T) {
	failing := errors.New("no")
	old := listen
	t.Cleanup(func() { listen = old })
	calls := 0
	listen = func(network, addr string) (net.Listener, error) {
		// Three ports, the settled server's, and the IPv6 one are had; the
		// first of the ALPS server's is not.
		if calls++; calls < 6 {
			return net.Listen(network, addr)
		}
		return nil, failing
	}
	if _, err := startServer(alpsCatalogue); !errors.Is(err, failing) {
		t.Errorf("startServer: %v", err)
	}
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	if _, err := StartALPSServer(); !errors.Is(err, failing) {
		t.Errorf("StartALPSServer: %v", err)
	}
	if _, err := MeasureALPS(context.Background(), &oneConnection{}, nil, nil); !errors.Is(err, failing) {
		t.Errorf("MeasureALPS: %v", err)
	}
}

func TestALPSIsMeasuredConnectionByConnection(t *testing.T) {
	scenarios := map[string]scenario{
		"one": {note: "one", script: "1", wait: "/p/a", alps: "empty", quiet: true},
		"two": {note: "two", script: "1", wait: "/p/a", alps: "empty", quiet: true},
	}
	b := &oneConnection{then: func(string) []string { return []string{"/p/a"} }, split: 1}
	var progress bytes.Buffer
	got, err := measureALPS(context.Background(), b, scenarios, nil, quick, &progress)
	if err != nil {
		t.Fatalf("measureALPS: %v", err)
	}
	if progress.String() != "alps one: an origin's requests on more than one connection, run again\n"+
		"alps one: 1 connections\nalps two: 1 connections\n" {
		t.Errorf("progress %q", progress.String())
	}
	one := got["one"]
	if one.Note != "one" || len(one.Handshakes) != 1 || one.Handshakes[0].ALPN != "h2" || len(one.Connections) != 1 ||
		len(one.Connections[0]) != 2 || one.Connections[0][1].URL != "https://www.example.com/p/a" {
		t.Errorf("one: %+v", one)
	}
	if _, err := measureALPS(context.Background(), b, scenarios, []string{"one"}, quick, nil); err != nil {
		t.Errorf("measureALPS with nothing to say it to: %v", err)
	}
}

func TestAnALPSMeasurementSaysWhyItIsNone(t *testing.T) {
	scenarios := map[string]scenario{"b": {note: "b", script: "1", wait: "/p/a", alps: "empty"}}
	if _, err := measureALPS(context.Background(), &oneConnection{}, scenarios, []string{"c"}, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "there is no scenario c") {
		t.Errorf("an unknown scenario: %v", err)
	}
	if _, err := measureALPS(context.Background(), &oneConnection{fail: true}, scenarios, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "b: the browser would not open") {
		t.Errorf("a browser that does not open: %v", err)
	}
	b := &oneConnection{then: func(string) []string { return []string{"/p/a"} }, split: runs}
	if _, err := measureALPS(context.Background(), b, scenarios, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "in each of 5 runs") {
		t.Errorf("a browser that never asks on one connection: %v", err)
	}
	// What cannot be read of the requests says why.
	s := started(t, alpsCatalogue)
	if _, err := s.ALPSOf("x", "none", []Entry{{Proto: "h2", Conn: 1, Block: []byte{0xff}}}); err == nil {
		t.Error("a header block that does not read was taken")
	}
}

func TestEveryDifferenceInWhatWasMadeOfALPSIsSaid(t *testing.T) {
	h := ALPSHandshake{Codepoint: extALPS, Protocols: []string{"h2"}, ALPN: "h2", Negotiated: true, Flight: []string{"EE+F"},
		Settings: []string{"1=65536"}}
	want := ALPSScenario{Handshakes: []ALPSHandshake{h}, Connections: [][]WrittenRequest{{{Method: "GET", URL: "https://a/1",
		Fields: []string{"x"}}}}}
	other := func(change func(*ALPSHandshake)) ALPSScenario {
		g := want
		g.Handshakes = []ALPSHandshake{h}
		change(&g.Handshakes[0])
		return g
	}
	for _, tc := range []struct {
		name string
		got  ALPSScenario
		diff int
	}{
		{"the same", want, 0},
		{"a handshake more", ALPSScenario{Handshakes: []ALPSHandshake{h, h}, Connections: want.Connections}, 1},
		{"another code point", other(func(h *ALPSHandshake) { h.Codepoint = extALPSOld }), 1},
		{"other protocols", other(func(h *ALPSHandshake) { h.Protocols = nil }), 1},
		{"another ALPN", other(func(h *ALPSHandshake) { h.ALPN = "http/1.1" }), 1},
		{"not negotiated", other(func(h *ALPSHandshake) { h.Negotiated = false }), 1},
		{"settings of its own", other(func(h *ALPSHandshake) { h.ClientSettings = "00" }), 1},
		{"another flight", other(func(h *ALPSHandshake) { h.Flight = []string{"EE", "F"} }), 1},
		{"other SETTINGS", other(func(h *ALPSHandshake) { h.Settings = nil }), 1},
		{"a GOAWAY", other(func(h *ALPSHandshake) { h.GoAway = "PROTOCOL_ERROR: x" }), 1},
		{"no requests", ALPSScenario{Handshakes: want.Handshakes}, 1},
	} {
		if diff := DiffALPS(want, tc.got); len(diff) != tc.diff {
			t.Errorf("%s: %q", tc.name, diff)
		}
	}
	if got := h.String(); got != `ALPS 17613 for [h2], h2, negotiated true, client settings "", flight [EE+F], SETTINGS [1=65536], GOAWAY ""` {
		t.Errorf("String: %s", got)
	}
	got := CompareALPS(map[string]ALPSScenario{"a": want, "b": want, "c": want},
		map[string]ALPSScenario{"a": want, "c": ALPSScenario{Handshakes: want.Handshakes}, "d": want})
	if !slices.Equal(got, []string{"b was not measured", "c: 0 connections, want 1",
		"d was measured, and the fixture has no such scenario"}) {
		t.Errorf("CompareALPS: %q", got)
	}
}

func TestSettingsAndVariantsAreSaidAsTheBenchMakesThem(t *testing.T) {
	if got := settingsOf(append(settingsFrame(1, 65536, 4, 7)[9:], 0, 1)); !slices.Equal(got, []string{"1=65536", "4=7"}) {
		t.Errorf("settingsOf: %q", got)
	}
	if got := acceptCHFrame("o", "h"); !bytes.Equal(got, []byte{0, 0, 6, 0x89, 0, 0, 0, 0, 0, 0, 1, 'o', 0, 1, 'h'}) {
		t.Errorf("acceptCHFrame: %x", got)
	}
	if got := alpsNames(map[string]scenario{"a": {alps: "empty"}, "b": {alps: "empty"}, "c": {}, "d": {alps: "data"}}); !slices.Equal(got, []string{"data", "empty"}) {
		t.Errorf("alpsNames: %q", got)
	}
	if got := originOf(12345); got != "https://www.example.com:12345" {
		t.Errorf("originOf: %s", got)
	}
}

func TestAFixtureOfALPSIsWrittenAsItIsKept(t *testing.T) {
	committed, err := os.ReadFile(alpsFixture)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fixture, err := LoadALPS(alpsFixture)
	if err != nil {
		t.Fatalf("LoadALPS: %v", err)
	}
	path := filepath.Join(t.TempDir(), "alps.json")
	if err := fixture.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if wrote, _ := os.ReadFile(path); !bytes.Equal(wrote, committed) {
		t.Errorf("wrote it otherwise:\n%s", wrote)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(fixture.Scenarios)), slices.Sorted(maps.Keys(alpsCatalogue))) {
		t.Errorf("the fixture's scenarios: %v", slices.Sorted(maps.Keys(fixture.Scenarios)))
	}
}
