package tlsforge

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tls_client "github.com/igor-lemon/tls-client"
)

// lines is a key log, written to by any goroutine.
type lines struct {
	mu  sync.Mutex
	got strings.Builder
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.got.Write(p)
}

// secret is a line of the NSS key log format: a label, the client random of
// the handshake and the secret, in hex.
var secret = regexp.MustCompile(`^(CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|` +
	`SERVER_TRAFFIC_SECRET_0|CLIENT_RANDOM) [0-9a-f]{64} [0-9a-f]{64,96}$`)

// secrets are the lines of text, sorted, each held to the format.
func secrets(t *testing.T, text string) []string {
	t.Helper()
	if text != "" && !strings.HasSuffix(text, "\n") {
		t.Errorf("a key log that ends in the middle of a line: %q", text)
	}
	out := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		out = nil
	}
	for _, line := range out {
		if !secret.MatchString(line) {
			t.Errorf("not a line of a key log: %q", line)
		}
	}
	slices.Sort(out)
	return out
}

// (l *lines) secrets are what l holds, line by line.
func (l *lines) secrets(t *testing.T) []string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	return secrets(t, l.got.String())
}

// keyedServer is a TLS server, offering HTTP/2 or not, that writes its own
// secrets to keys, and answers with the protocol it was asked over.
func keyedServer(t *testing.T, h2 bool, keys io.Writer) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	server.EnableHTTP2 = h2
	server.TLS = &tls.Config{KeyLogWriter: keys}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestTheSecretsOfEveryConnectionAreWrittenAsTheServerHasThem(t *testing.T) {
	// The client's lines of each handshake are the server's, so Wireshark,
	// given them, reads what went over the connection; over HTTP/2 and
	// HTTP/1.1, both of which the transport dials and shakes hands for.
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"HTTP/2.0", true}, {"HTTP/1.1", false}} {
		t.Run(tc.name, func(t *testing.T) {
			var server, client lines
			site := keyedServer(t, tc.h2, &server)
			res, err := newTestClient(t, WithKeyLogWriter(&client)).Get(site.URL)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if res.Text() != tc.name {
				t.Errorf("went over %s", res.Text())
			}
			got, want := client.secrets(t), server.secrets(t)
			if len(want) != 4 || !slices.Equal(got, want) {
				t.Errorf("the client wrote\n%s\nthe server\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// keyedProxy is an HTTPS proxy that writes its own secrets to keys, and whose
// certificate the test's clients trust.
func keyedProxy(t *testing.T, keys io.Writer) *connectProxy {
	t.Helper()
	via := startConnectProxyOver(t, &tls.Config{KeyLogWriter: keys}, exitAnswer)
	roots := x509.NewCertPool()
	roots.AddCert(via.server.Certificate())
	original := proxyRoots
	t.Cleanup(func() { proxyRoots = original })
	proxyRoots = roots
	return via
}

func TestOneWriterTakesTheSecretsOfManyConnectionsLineByLine(t *testing.T) {
	// Clients made of one writer, and those Fresh makes of them, at once, half
	// of them through an HTTPS proxy: utls writes the sites' secrets and
	// crypto/tls the proxy's, each under a lock of its own, so tls-forge's
	// alone keeps them from writing at once to a writer that is not safe for
	// concurrent use (-race). Each line whole, every one the servers'.
	var siteKeys, proxyKeys lines
	site := keyedServer(t, true, &siteKeys)
	via := keyedProxy(t, &proxyKeys)
	var unsafe strings.Builder
	direct := newTestClient(t, WithKeyLogWriter(&unsafe))
	proxied := newTestClient(t, WithKeyLogWriter(&unsafe), WithProxy(via.server.URL))
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client, err := []*Client{direct, proxied}[i%2].Fresh()
			if err != nil {
				t.Errorf("Fresh: %v", err)
				return
			}
			defer func() { _ = client.Close() }()
			if _, err := client.Get(site.URL); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()
	keyLogMu.Lock()
	written := unsafe.String()
	keyLogMu.Unlock()
	want := append(siteKeys.secrets(t), proxyKeys.secrets(t)...)
	slices.Sort(want)
	if got := secrets(t, written); len(want) != 4*12+4*6 || !slices.Equal(got, want) {
		t.Errorf("the clients wrote %d lines, the site and the proxy %d", len(got), len(want))
	}
}

func TestAnHTTPSProxysSecretsAreWrittenWithTheSites(t *testing.T) {
	// The connection to the proxy, which tls-forge shakes hands for itself,
	// and the site's inside its tunnel, both in the file, though Wireshark
	// 4.6.9 takes no TLS apart inside the proxy's.
	var proxyKeys, siteKeys, client lines
	via := keyedProxy(t, &proxyKeys)
	site := keyedServer(t, true, &siteKeys)
	if _, err := newTestClient(t, WithKeyLogWriter(&client), WithProxy(via.server.URL)).Get(site.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := append(proxyKeys.secrets(t), siteKeys.secrets(t)...)
	slices.Sort(want)
	if got := client.secrets(t); len(want) != 8 || !slices.Equal(got, want) {
		t.Errorf("the client wrote\n%s\nthe proxy and the site\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// failing is a key log that cannot be written.
type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, errors.New("the disk is full") }

func TestAKeyLogThatCannotBeWrittenFailsTheHandshake(t *testing.T) {
	// As crypto/tls's does: a caller that asked for the secrets learns they
	// were not written. No writer, no key log, and nothing fails.
	site := keyedServer(t, true, io.Discard)
	if _, err := newTestClient(t, WithKeyLogWriter(failing{})).Get(site.URL); err == nil ||
		!strings.Contains(err.Error(), "the disk is full") {
		t.Errorf("Get: %v", err)
	}
	if _, err := newTestClient(t, WithKeyLogWriter(nil)).Get(site.URL); err != nil {
		t.Errorf("Get with no writer: %v", err)
	}
	if keyLogOf(nil) != nil {
		t.Error("no writer is a key log")
	}
}

func TestAKeyLogThatFailedHoldsUpNoOtherClientsHandshake(t *testing.T) {
	// utls writes the secrets of every client of the process under one lock,
	// which it kept held when a write failed: each later handshake that wrote
	// its secrets, of any client, waited for it for good, and go test -count=2
	// hung in the second TestTheSecretsOfEveryConnectionAreWrittenAsTheServerHasThem.
	// The client whose key log failed fails, and the next one goes on.
	failed := keyedServer(t, true, io.Discard)
	if err := endedWithin(t, doing(newTestClient(t, WithKeyLogWriter(failing{})), &Request{URL: failed.URL}), 5*time.Second); err == nil ||
		!strings.Contains(err.Error(), "the disk is full") {
		t.Fatalf("Get: %v", err)
	}
	var server, client lines
	site := keyedServer(t, true, &server)
	if err := endedWithin(t, doing(newTestClient(t, WithKeyLogWriter(&client)), &Request{URL: site.URL}), 5*time.Second); err != nil {
		t.Fatalf("Get after a key log failed: %v", err)
	}
	if got, want := client.secrets(t), server.secrets(t); len(want) != 4 || !slices.Equal(got, want) {
		t.Errorf("the client wrote\n%s\nthe server\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestTransportOptionsOfTheCallersTakeTheSecretsOfSitesAway(t *testing.T) {
	// As GO.md says of every transport option tls-forge sets: the caller's
	// replace them, the key log for sites with them.
	var client lines
	site := keyedServer(t, true, io.Discard)
	given := newTestClient(t, WithKeyLogWriter(&client),
		WithTransportOption(tls_client.WithTransportOptions(&tls_client.TransportOptions{})))
	if _, err := given.Get(site.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := client.secrets(t); len(got) != 0 {
		t.Errorf("wrote %q", got)
	}
}
