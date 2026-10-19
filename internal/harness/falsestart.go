package harness

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// FalseStartFixture is what testdata/chrome155-falsestart.json holds: over
// which protocol a browser asked a TLS 1.2 server for a page, and whether it
// asked before the server's Finished, for each server of the catalogue.
type FalseStartFixture struct {
	Browser   string                        `json:"browser"`
	Measured  string                        `json:"measured"`
	How       string                        `json:"how"`
	Scenarios map[string]FalseStartScenario `json:"scenarios"`
}

// FalseStartShape is a scenario's server, of TLS 1.2 alone: its one cipher
// suite, by Go's name for it, and the protocols it takes by ALPN, none for
// none.
type FalseStartShape struct {
	Note      string   `json:"note"`
	Suite     string   `json:"suite"`
	Protocols []string `json:"protocols"`
}

// FalseStartScenario is a scenario as a browser went through it: the
// protocol of its request as the server read it, and whether the request's
// first record came while the server's session ticket, ChangeCipherSpec and
// Finished were held back.
type FalseStartScenario struct {
	FalseStartShape
	Proto string `json:"proto"`
	Early bool   `json:"early"`
}

// LoadFalseStart reads a fixture of False Start.
func LoadFalseStart(path string) (*FalseStartFixture, error) { return load[FalseStartFixture](path) }

// Write writes the fixture to path as it is kept, as the fixture of requests
// is.
func (f *FalseStartFixture) Write(path string) error { return writeJSON(path, f) }

// falseStartCatalogue is every scenario of False Start, by its name in the
// fixture: where BoringSSL false starts (ECDHE, an AEAD, ALPN) and where it
// does not.
var falseStartCatalogue = map[string]FalseStartShape{
	"fs-h2-ecdhe-ecdsa-aes128gcm": {"ECDHE, AES-128-GCM, h2", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		[]string{"h2", "http/1.1"}},
	"fs-h1-ecdhe-ecdsa-aes128gcm": {"ECDHE, AES-128-GCM, http/1.1", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		[]string{"http/1.1"}},
	"fs-h2-ecdhe-rsa-chacha20": {"ECDHE, ChaCha20-Poly1305, h2", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		[]string{"h2", "http/1.1"}},
	"fs-noalpn-ecdhe-ecdsa-aes128gcm": {"ECDHE, AES-128-GCM, and no protocol taken by ALPN",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", nil},
	"fs-h1-ecdhe-rsa-aes128cbc": {"ECDHE, AES-128-CBC, http/1.1", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		[]string{"http/1.1"}},
	"fs-h1-rsa-aes128gcm": {"an RSA key exchange, AES-128-GCM, http/1.1", "TLS_RSA_WITH_AES_128_GCM_SHA256",
		[]string{"http/1.1"}},
}

// FalseStartShapes is the server of every scenario of False Start, by its name
// in the fixture.
func FalseStartShapes() map[string]FalseStartShape { return maps.Clone(falseStartCatalogue) }

// suiteNamed is the cipher suite Go's crypto/tls calls name.
func suiteNamed(name string) (uint16, bool) {
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if s.Name == name {
			return s.ID, true
		}
	}
	return 0, false
}

// FalseStartServer answers, for each scenario, over TLS 1.2 alone at a port of
// its own, through a relay that keeps when the client's first record of
// application data came on each connection, and holds back what the server
// sends after the client's ChangeCipherSpec for hold: its session ticket,
// ChangeCipherSpec and Finished. A client that false starts sends its request
// in the meantime; one that waits sends it after.
type FalseStartServer struct {
	shapes  map[string]FalseStartShape
	hold    time.Duration
	ports   map[string]int
	closers []io.Closer
	done    sync.WaitGroup
	mu      sync.Mutex
	conns   map[string][]*relayed
	asked   map[string]string
}

// StartFalseStartServer starts a FalseStartServer for the catalogue, holding
// the server's flight back for hold.
func StartFalseStartServer(hold time.Duration) (*FalseStartServer, error) {
	return startFalseStartServer(falseStartCatalogue, hold)
}

func startFalseStartServer(shapes map[string]FalseStartShape, hold time.Duration) (*FalseStartServer, error) {
	ecdsaCert, err := certificate()
	if err != nil {
		return nil, err
	}
	rsaCert, err := rsaCertificate()
	if err != nil {
		return nil, err
	}
	s := &FalseStartServer{shapes: shapes, hold: hold, ports: map[string]int{}, conns: map[string][]*relayed{},
		asked: map[string]string{}}
	for _, id := range slices.Sorted(maps.Keys(shapes)) {
		if err := s.serve(id, shapes[id], ecdsaCert, rsaCert); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// serve starts the server of the scenario id and the relay in front of it.
func (s *FalseStartServer) serve(id string, shape FalseStartShape, ecdsaCert, rsaCert tls.Certificate) error {
	suite, known := suiteNamed(shape.Suite)
	if !known {
		return fmt.Errorf("harness: %s: no cipher suite %s", id, shape.Suite)
	}
	cert := rsaCert
	if strings.Contains(shape.Suite, "_ECDSA_") {
		cert = ecdsaCert
	}
	back, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("harness: %w", err)
	}
	front, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = back.Close()
		return fmt.Errorf("harness: %w", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.asked[id] = r.Proto
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html>" + quietIcon + "<title>page</title><p>page</p>"))
	}), ReadHeaderTimeout: 10 * time.Second}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}, NextProtos: shape.Protocols}
	s.ports[id] = front.Addr().(*net.TCPAddr).Port
	s.closers = append(s.closers, front, server)
	s.done.Add(2)
	go func() {
		defer s.done.Done()
		_ = server.Serve(tls.NewListener(back, config))
	}()
	go func() {
		defer s.done.Done()
		s.relay(id, front, back.Addr().String())
	}()
	return nil
}

// URL is the page of the scenario id, at www.example.com, which the browser
// takes to the loopback address.
func (s *FalseStartServer) URL(id string) string {
	return fmt.Sprintf("https://www.example.com:%d/", s.ports[id])
}

// relayed is a connection through the relay: when the client's first record
// of application data came, and when the server's flight was let go.
type relayed struct {
	firstApp, released time.Time
}

// early says whether the client's application data came before the server's
// flight was let go, or while it was still held back.
func (r *relayed) early() bool {
	return !r.firstApp.IsZero() && (r.released.IsZero() || r.firstApp.Before(r.released))
}

// relay takes each connection to front on to the server at target until
// front is closed.
func (s *FalseStartServer) relay(id string, front net.Listener, target string) {
	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		client, err := front.Accept()
		if err != nil {
			return
		}
		r := &relayed{}
		s.mu.Lock()
		s.conns[id] = append(s.conns[id], r)
		s.mu.Unlock()
		conns.Add(1)
		go func() {
			defer conns.Done()
			s.carry(client, target, r)
		}()
	}
}

// carry relays one connection, record by record, keeping what r keeps.
func (s *FalseStartServer) carry(client net.Conn, target string, r *relayed) {
	defer func() { _ = client.Close() }()
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	finished := make(chan struct{})
	var once sync.Once
	go func() {
		defer func() { _ = server.(*net.TCPConn).CloseWrite() }()
		_ = forward(server, client, func(typ byte) {
			switch typ {
			case recordChangeCipher:
				once.Do(func() { close(finished) })
			case recordApplication:
				s.mu.Lock()
				if r.firstApp.IsZero() {
					r.firstApp = time.Now()
				}
				s.mu.Unlock()
			}
		})
	}()
	held := false
	_ = forward(client, server, func(byte) {
		select {
		case <-finished:
			if !held {
				held = true
				time.Sleep(s.hold)
				s.mu.Lock()
				r.released = time.Now()
				s.mu.Unlock()
			}
		default:
		}
	})
}

// forward passes each record src sends on to dst, telling seen of its type
// first, until either fails.
func forward(dst, src net.Conn, seen func(typ byte)) error {
	for {
		typ, record, err := readRecordOf(src)
		if err != nil {
			return err
		}
		seen(typ)
		if _, err := dst.Write(record); err != nil {
			return err
		}
	}
}

// readRecordOf reads a TLS record whole, its header included.
func readRecordOf(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	record := make([]byte, 5+(int(header[3])<<8|int(header[4])))
	copy(record, header)
	_, err := io.ReadFull(conn, record[5:])
	return header[0], record, err
}

// Asked says whether the scenario id's page was asked for.
func (s *FalseStartServer) Asked(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked[id] != ""
}

// Scenario is the scenario id as the server saw it since it was reset: the
// protocol of its request, and whether the earliest request of its
// connections came before the server's Finished; an error when it was not
// asked for.
func (s *FalseStartServer) Scenario(id string) (FalseStartScenario, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.asked[id] == "" {
		return FalseStartScenario{}, fmt.Errorf("harness: the page of %s was not asked for", id)
	}
	out := FalseStartScenario{FalseStartShape: s.shapes[id], Proto: s.asked[id]}
	var first *relayed
	for _, r := range s.conns[id] {
		if !r.firstApp.IsZero() && (first == nil || r.firstApp.Before(first.firstApp)) {
			first = r
		}
	}
	out.Early = first != nil && first.early()
	return out, nil
}

// Reset forgets what every scenario was asked and sent.
func (s *FalseStartServer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns, s.asked = map[string][]*relayed{}, map[string]string{}
}

// Close stops every server and relay, and ends the connections they have.
func (s *FalseStartServer) Close() error {
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.done.Wait()
	return nil
}

// rsaCertificate is a certificate of a fresh RSA key for the names the bench
// serves, taken on trust as the ECDSA one is.
func rsaCertificate() (tls.Certificate, error) {
	key, err := newRSAKey()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: %w", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"example.com", "*.example.com"}, KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := createCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// newRSAKey is the RSA key rsaCertificate signs with, which a test makes
// fail.
var newRSAKey = func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }

// falseStartMeasured is the timing the fixture was measured with: a page is
// asked for within a second, and the relay lets the server's flight go a
// second after the client's Finished.
var falseStartMeasured = timing{poll: 50 * time.Millisecond, limit: 20 * time.Second, after: 300 * time.Millisecond}

// MeasureFalseStart is what b does in each scenario of False Start named in
// only, or every one: what the fixture holds for them. It says each scenario
// it ran to progress, when there is one.
func MeasureFalseStart(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]FalseStartScenario, error) {
	return measureFalseStart(ctx, b, falseStartCatalogue, only, falseStartMeasured, time.Second, progress)
}

func measureFalseStart(ctx context.Context, b Browser, shapes map[string]FalseStartShape, only []string, t timing,
	hold time.Duration, progress io.Writer) (map[string]FalseStartScenario, error) {
	for _, id := range only {
		if _, ok := shapes[id]; !ok {
			return nil, fmt.Errorf("harness: there is no scenario %s", id)
		}
	}
	ids := slices.Sorted(maps.Keys(shapes))
	if len(only) > 0 {
		ids = slices.Sorted(slices.Values(only))
	}
	s, err := startFalseStartServer(shapes, hold)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if progress == nil {
		progress = io.Discard
	}
	out := map[string]FalseStartScenario{}
	for _, id := range ids {
		sc, err := s.runFalseStart(ctx, b, id, t)
		if err != nil {
			return nil, fmt.Errorf("harness: %s: %w", id, err)
		}
		out[id] = sc
		_, _ = fmt.Fprintf(progress, "tls1.2 %s: %s, early %v\n", id, sc.Proto, sc.Early)
	}
	return out, nil
}

// runFalseStart opens the scenario id in a fresh profile of b's until its page
// was asked for, and a little after, and is what the server saw.
func (s *FalseStartServer) runFalseStart(ctx context.Context, b Browser, id string, t timing) (FalseStartScenario, error) {
	dir, err := os.MkdirTemp("", "tls-forge-harness-")
	if err != nil {
		return FalseStartScenario{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	s.Reset()
	stop, err := b.Open(ctx, s.URL(id), dir)
	if err != nil {
		return FalseStartScenario{}, err
	}
	asked := false
	for deadline := time.Now().Add(t.limit); !asked && time.Now().Before(deadline); {
		if asked = s.Asked(id); !asked && !sleep(ctx, t.poll) {
			break
		}
	}
	if asked {
		asked = sleep(ctx, t.after)
	}
	sc, err := s.Scenario(id)
	stop()
	if !asked {
		return FalseStartScenario{}, fmt.Errorf("its page was not asked for within %s: %v", t.limit, ctx.Err())
	}
	return sc, err
}

// DiffFalseStart is how got differs from want: a line for each difference,
// none when they are alike.
func DiffFalseStart(want, got FalseStartScenario) []string {
	var out []string
	if got.Proto != want.Proto {
		out = append(out, fmt.Sprintf("asked over %s, want %s", got.Proto, want.Proto))
	}
	if got.Early != want.Early {
		out = append(out, fmt.Sprintf("asked before the server's Finished %v, want %v", got.Early, want.Early))
	}
	return out
}

// CompareFalseStart is how the scenarios a browser went through, got, differ
// from what the fixture holds, want, as Compare says it for requests.
func CompareFalseStart(want, got map[string]FalseStartScenario) []string {
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(want)) {
		measured, ok := got[id]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s was not measured", id))
			continue
		}
		for _, d := range DiffFalseStart(want[id], measured) {
			diff = append(diff, id+": "+d)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[id]; !ok {
			diff = append(diff, fmt.Sprintf("%s was measured, and the fixture has no such scenario", id))
		}
	}
	return diff
}
