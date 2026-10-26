package harness

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/igor-lemon/utls"
)

// startedFalseStart is a FalseStartServer of shapes, closed with the test.
func startedFalseStart(t *testing.T, shapes map[string]FalseStartShape, hold time.Duration) *FalseStartServer {
	t.Helper()
	s, err := startFalseStartServer(shapes, hold)
	if err != nil {
		t.Fatalf("startFalseStartServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// gcm is a scenario of ECDHE and AES-128-GCM over HTTP/1.1.
var gcm = FalseStartShape{Note: "n", Suite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Protocols: []string{"http/1.1"}}

// dialPage dials the relay of the page at url on the loopback address.
func dialPage(t *testing.T, page string) net.Conn {
	t.Helper()
	port := page[strings.LastIndex(page, ":")+1 : len(page)-1]
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// askFalseStarting asks for the page at url over HTTP/1.1 through a client
// of the uTLS fork that false starts, and is the status line of its answer.
func askFalseStarting(t *testing.T, page string) string {
	t.Helper()
	conn := utls.Client(dialPage(t, page), &utls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
		FalseStart: true})
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return line
}

func TestAFixtureOfFalseStartIsWrittenAsItIsKept(t *testing.T) {
	f := &FalseStartFixture{Browser: "b", Measured: "2026-10-19", How: "<how>", Scenarios: map[string]FalseStartScenario{
		"s": {FalseStartShape: gcm, Proto: "HTTP/1.1", Early: true}}}
	path := filepath.Join(t.TempDir(), "falsestart.json")
	if err := f.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := LoadFalseStart(path)
	if err != nil || got.How != "<how>" || !got.Scenarios["s"].Early || got.Scenarios["s"].Suite != gcm.Suite {
		t.Errorf("read back %+v, %v", got, err)
	}
}

func TestEveryFalseStartScenarioNamesASuiteGoHas(t *testing.T) {
	shapes := FalseStartShapes()
	if !maps.EqualFunc(shapes, falseStartCatalogue, func(a, b FalseStartShape) bool { return a.Suite == b.Suite }) {
		t.Fatal("the shapes are not the catalogue's")
	}
	delete(shapes, "fs-h1-rsa-aes128gcm")
	if _, ok := falseStartCatalogue["fs-h1-rsa-aes128gcm"]; !ok {
		t.Error("a change of the shapes changed the catalogue")
	}
	for id, shape := range falseStartCatalogue {
		if _, ok := suiteNamed(shape.Suite); !ok || shape.Note == "" {
			t.Errorf("%s: %+v", id, shape)
		}
	}
	if _, ok := suiteNamed("TLS_NONE"); ok {
		t.Error("a suite Go does not have is named")
	}
	// Every server of the catalogue starts, each at a port of its own.
	s, err := StartFalseStartServer(0)
	if err != nil {
		t.Fatalf("StartFalseStartServer: %v", err)
	}
	defer func() { _ = s.Close() }()
	pages := map[string]bool{}
	for id := range falseStartCatalogue {
		pages[s.URL(id)] = true
	}
	if len(pages) != len(falseStartCatalogue) {
		t.Errorf("%d pages for %d scenarios", len(pages), len(falseStartCatalogue))
	}
}

func TestARequestBeforeTheServersFinishedIsEarly(t *testing.T) {
	s := startedFalseStart(t, map[string]FalseStartShape{"s": gcm}, 300*time.Millisecond)
	if _, err := s.Scenario("s"); err == nil || err.Error() != "harness: the page of s was not asked for" {
		t.Errorf("before it was asked for: %v", err)
	}
	// Go's client waits for the server's Finished.
	if s.Asked("s") {
		t.Fatal("asked before anything was")
	}
	res, body := get(t, "GET", s.URL("s"), nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "<title>page</title>") || !s.Asked("s") {
		t.Fatalf("the page: %d %q", res.StatusCode, body)
	}
	if sc, err := s.Scenario("s"); err != nil || sc.Early || sc.Proto != "HTTP/1.1" || sc.Suite != gcm.Suite {
		t.Errorf("Go's client: %+v, %v", sc, err)
	}
	// One that false starts does not.
	s.Reset()
	if line := askFalseStarting(t, s.URL("s")); line != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("the answer: %q", line)
	}
	if sc, err := s.Scenario("s"); err != nil || !sc.Early || sc.Proto != "HTTP/1.1" {
		t.Errorf("a client that false starts: %+v, %v", sc, err)
	}
	// The server's flight was held back after the request had come.
	s.mu.Lock()
	r := s.conns["s"][0]
	s.mu.Unlock()
	if held := r.released.Sub(r.firstApp); held < 150*time.Millisecond {
		t.Errorf("the server's flight went %s after the request", held)
	}
}

func TestTheEarliestRequestSaysWhetherAScenarioWasEarly(t *testing.T) {
	at := func(ms int) time.Time { return time.Unix(0, 0).Add(time.Duration(ms) * time.Millisecond) }
	s := startedFalseStart(t, map[string]FalseStartShape{"s": gcm}, 0)
	for _, tc := range []struct {
		name  string
		conns []*relayed
		want  bool
	}{
		{"none sent anything", []*relayed{{}, {released: at(5)}}, false},
		{"a later one early", []*relayed{{firstApp: at(9), released: at(5)}, {firstApp: at(20)}}, false},
		{"the earliest early", []*relayed{{}, {firstApp: at(9), released: at(5)}, {firstApp: at(3), released: at(5)}}, true},
	} {
		s.mu.Lock()
		s.conns["s"], s.asked["s"] = tc.conns, "HTTP/1.1"
		s.mu.Unlock()
		if sc, err := s.Scenario("s"); err != nil || sc.Early != tc.want {
			t.Errorf("%s: %+v, %v", tc.name, sc, err)
		}
	}
	for _, tc := range []struct {
		name string
		r    relayed
		want bool
	}{
		{"nothing sent", relayed{released: at(5)}, false},
		{"sent while held", relayed{firstApp: at(5)}, true},
		{"sent before it was let go", relayed{firstApp: at(4), released: at(5)}, true},
		{"sent when it was", relayed{firstApp: at(5), released: at(5)}, false},
		{"sent after", relayed{firstApp: at(6), released: at(5)}, false},
	} {
		if got := tc.r.early(); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

// failingWrites is a connection every write to fails.
type failingWrites struct{ net.Conn }

func (failingWrites) Write([]byte) (int, error) { return 0, errors.New("no") }

func TestARecordIsPassedOnWhole(t *testing.T) {
	src, feed := net.Pipe()
	dst, drain := net.Pipe()
	var seen []byte
	done := make(chan error, 1)
	go func() { done <- forward(dst, src, func(typ byte) { seen = append(seen, typ) }) }()
	record := []byte{23, 3, 3, 0, 2, 'h', 'i'}
	go func() { _, _ = feed.Write(record) }()
	got := make([]byte, len(record))
	if _, err := io.ReadFull(drain, got); err != nil || !bytes.Equal(got, record) {
		t.Fatalf("passed on %x, %v", got, err)
	}
	_ = feed.Close()
	if err := <-done; !errors.Is(err, io.EOF) || !bytes.Equal(seen, []byte{23}) {
		t.Errorf("forward: %v, seen %v", err, seen)
	}
	// A record cut short ends it, and so does a write that fails.
	src, feed = net.Pipe()
	go func() { _, _ = feed.Write([]byte{23, 3, 3, 0, 9, 1}); _ = feed.Close() }()
	if err := forward(dst, src, func(byte) {}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("cut short: %v", err)
	}
	src, feed = net.Pipe()
	go func() { _, _ = feed.Write(record) }()
	if err := forward(failingWrites{}, src, func(byte) {}); err == nil || err.Error() != "no" {
		t.Errorf("a write that fails: %v", err)
	}
}

func TestARelayWithNoServerLetsItsConnectionGo(t *testing.T) {
	s := startedFalseStart(t, map[string]FalseStartShape{"s": gcm}, 0)
	// The server stopped; its relay goes on.
	_ = s.closers[1].Close()
	conn := dialPage(t, s.URL("s"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("a connection to a server that is not there was kept")
	}
}

func TestAFalseStartServerThatCannotStartSaysWhy(t *testing.T) {
	failing := errors.New("no")
	oldKey, oldRSA, oldListen, oldCreate := newKey, newRSAKey, listen, createCertificate
	t.Cleanup(func() { newKey, newRSAKey, listen, createCertificate = oldKey, oldRSA, oldListen, oldCreate })
	shapes := map[string]FalseStartShape{"a": gcm, "b": gcm}
	newKey = func() (*ecdsa.PrivateKey, error) { return nil, failing }
	if _, err := startFalseStartServer(shapes, 0); !errors.Is(err, failing) {
		t.Errorf("no ECDSA key: %v", err)
	}
	newKey = oldKey
	newRSAKey = func() (*rsa.PrivateKey, error) { return nil, failing }
	if _, err := startFalseStartServer(shapes, 0); !errors.Is(err, failing) {
		t.Errorf("no RSA key: %v", err)
	}
	newRSAKey = oldRSA
	calls := 0
	createCertificate = func(rand io.Reader, template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
		if calls++; calls == 2 {
			return nil, failing
		}
		return oldCreate(rand, template, parent, pub, priv)
	}
	if _, err := startFalseStartServer(shapes, 0); !errors.Is(err, failing) {
		t.Errorf("no RSA certificate: %v", err)
	}
	createCertificate = oldCreate
	if _, err := startFalseStartServer(map[string]FalseStartShape{"a": {Suite: "TLS_NONE"}}, 0); err == nil ||
		err.Error() != "harness: a: no cipher suite TLS_NONE" {
		t.Errorf("a suite Go does not have: %v", err)
	}
	// Each listener, of the first scenario and of the second.
	for allowed := range 4 {
		calls := 0
		listen = func(network, addr string) (net.Listener, error) {
			if calls++; calls <= allowed {
				return net.Listen(network, addr)
			}
			return nil, failing
		}
		if _, err := startFalseStartServer(shapes, 0); !errors.Is(err, failing) {
			t.Errorf("%d listeners: %v", allowed, err)
		}
	}
}

// fsBrowser asks for the page it opens with Go's client, unless it fails or
// is silent.
type fsBrowser struct {
	fail, silent bool
	opened       []string
}

func (b *fsBrowser) Open(_ context.Context, page, _ string) (func(), error) {
	if b.fail {
		return nil, errors.New("the fake would not open " + page)
	}
	b.opened = append(b.opened, page)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if !b.silent {
			if res, err := client().Get(page); err == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}
		}
	}()
	return func() { <-done }, nil
}

func (b *fsBrowser) DumpDOM(context.Context, string) ([]byte, error) { return nil, nil }

func TestFalseStartIsMeasuredScenarioByScenario(t *testing.T) {
	shapes := map[string]FalseStartShape{"a": gcm, "b": {Note: "n", Suite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		Protocols: []string{"h2", "http/1.1"}}}
	var progress bytes.Buffer
	b := &fsBrowser{}
	got, err := measureFalseStart(context.Background(), b, shapes, nil, quick, 50*time.Millisecond, &progress)
	if err != nil {
		t.Fatalf("measureFalseStart: %v", err)
	}
	if len(got) != 2 || got["a"].Proto != "HTTP/1.1" || got["b"].Proto != "HTTP/2.0" || got["a"].Early || got["b"].Early ||
		progress.String() != "tls1.2 a: HTTP/1.1, early false\ntls1.2 b: HTTP/2.0, early false\n" || len(b.opened) != 2 {
		t.Errorf("measured %+v, said %q", got, progress.String())
	}
	if got, err := measureFalseStart(context.Background(), &fsBrowser{}, shapes, []string{"b"}, quick, 0, nil); err != nil ||
		len(got) != 1 || got["b"].Proto != "HTTP/2.0" {
		t.Errorf("only b: %+v, %v", got, err)
	}
}

func TestAFalseStartMeasurementSaysWhyItIsNone(t *testing.T) {
	shapes := map[string]FalseStartShape{"a": gcm}
	if _, err := MeasureFalseStart(context.Background(), &fsBrowser{}, []string{"none"}, nil); err == nil ||
		err.Error() != "harness: there is no scenario none" {
		t.Errorf("an unknown scenario: %v", err)
	}
	if _, err := measureFalseStart(context.Background(), &fsBrowser{fail: true}, shapes, nil, quick, 0, nil); err == nil ||
		!strings.HasPrefix(err.Error(), "harness: a: the fake would not open https://www.example.com:") {
		t.Errorf("a browser that does not open: %v", err)
	}
	if _, err := measureFalseStart(context.Background(), &fsBrowser{silent: true}, shapes, nil, quick, 0, nil); err == nil ||
		err.Error() != "harness: a: its page was not asked for within 2s: <nil>" {
		t.Errorf("a browser that asks for nothing: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := measureFalseStart(ctx, &fsBrowser{silent: true}, shapes, nil, quick, 0, nil); err == nil ||
		!strings.HasSuffix(err.Error(), "within 2s: context canceled") {
		t.Errorf("a measurement stopped: %v", err)
	}
	// Stopped once its page is asked for, before it has waited after.
	waiting := timing{poll: quick.poll, limit: quick.limit, after: time.Hour}
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := measureFalseStart(ctx, &fsBrowser{}, shapes, nil, waiting, 0, nil)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	if err := <-done; err == nil || !strings.HasSuffix(err.Error(), "context canceled") {
		t.Errorf("stopped while it waited after: %v", err)
	}
	tempNowhere(t)
	if _, err := measureFalseStart(context.Background(), &fsBrowser{}, shapes, nil, quick, 0, nil); err == nil {
		t.Error("measured with nowhere to keep a profile")
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := measureFalseStart(context.Background(), &fsBrowser{}, shapes, nil, quick, 0, nil); !errors.Is(err, failing) {
		t.Errorf("measured with no server: %v", err)
	}
}

func TestWhatFalseStartsDifferInIsSaid(t *testing.T) {
	want := FalseStartScenario{FalseStartShape: gcm, Proto: "HTTP/2.0", Early: true}
	for _, tc := range []struct {
		name string
		got  FalseStartScenario
		diff []string
	}{
		{"alike", want, nil},
		{"proto", FalseStartScenario{Proto: "HTTP/1.1", Early: true}, []string{"asked over HTTP/1.1, want HTTP/2.0"}},
		{"late", FalseStartScenario{Proto: "HTTP/2.0"}, []string{"asked before the server's Finished false, want true"}},
	} {
		if got := DiffFalseStart(want, tc.got); !slices.Equal(got, tc.diff) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
	got := CompareFalseStart(map[string]FalseStartScenario{"a": want, "b": want},
		map[string]FalseStartScenario{"a": {Proto: "HTTP/2.0"}, "c": want})
	if !slices.Equal(got, []string{"a: asked before the server's Finished false, want true", "b was not measured",
		"c was measured, and the fixture has no such scenario"}) {
		t.Errorf("CompareFalseStart: %q", got)
	}
}
