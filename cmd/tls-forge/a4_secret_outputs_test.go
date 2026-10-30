package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls/http3"
	utls "github.com/igor-lemon/utls"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// A request URL with a password fetch refuses is said without it, however it
// is spelt: one slash or three after the scheme, none, a tab in the password.
func TestFetchSaysNoPasswordOfAURLItRefuses(t *testing.T) {
	tabbed := secret[:4] + "\t" + secret[4:]
	for _, raw := range []string{
		"https:/alice:" + secret + "@example.test:6000/",
		"https:///alice:" + secret + "@example.test:6000/",
		"https:alice:" + secret + "@example.test:6000/",
		"https://alice:" + tabbed + "@example.test:6000/",
	} {
		code, stdout, stderr := exec(t, "fetch", "--no-exit-lookup", raw)
		if code != 2 || !strings.Contains(stderr, "entry 1") {
			t.Fatalf("%q: exit %d: %s", raw, code, stderr)
		}
		for _, part := range []string{secret, secret[:4], secret[4:]} {
			if strings.Contains(stdout+stderr, part) {
				t.Errorf("%q: the password said: %s%s", raw, stdout, stderr)
			}
		}
	}
}

func checkAdditionalSecretOutputs(t *testing.T) {
	t.Helper()
	t.Run("public URL errors", func(t *testing.T) {
		client, err := tlsforge.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		raw := "https://alice:" + secret + "@[bad/?access_token=" + secret
		_, canonical := tlsforge.CanonicalURL(raw)
		_, own := tlsforge.OwnPage(raw)
		_, cookies := client.CookiesFor(raw)
		for _, err := range []error{canonical, own, cookies, client.Validate(&tlsforge.Request{URL: raw})} {
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Errorf("unsafe error: %v", err)
			}
		}
	})
	for _, protocol := range []string{"HTTP/1.1", "HTTP/2.0", "HTTP/3.0"} {
		t.Run("headers and query in diagnostics over "+protocol, func(t *testing.T) {
			var received atomic.Bool
			var came atomic.Value
			heard := func(proto string, header func(string) string, query url.Values) {
				came.Store(proto)
				received.Store(header("X-Auth") == secret && header("X-Authorization") == secret && query.Get("access_token") == secret)
			}
			site, args := secretSite(t, protocol, heard)
			dir := t.TempDir()
			retainSecretEvidence(t, "diagnostics-"+strings.ReplaceAll(protocol, "/", ""), dir)
			ambient := filepath.Join(t.TempDir(), "ambient.keys")
			if err := os.WriteFile(ambient, []byte("sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSLKEYLOGFILE", ambient)
			code, stdout, stderr := exec(t, append(append([]string{"fetch", "-k", "--no-exit-lookup", "--json", "-o", filepath.Join(dir, "out"),
				"--pcap", "--log", filepath.Join(dir, "run.jsonl"), "--trace", filepath.Join(dir, "trace.json"),
				"--report=" + filepath.Join(dir, "report"), "--report-format", "html,json",
				"-H", "X-Auth: " + secret, "-H", "X-Authorization: " + secret}, args...), site+"/?access_token="+secret)...)
			if code != 0 || !received.Load() || came.Load() != protocol {
				t.Fatalf("exit %d, over %v, credentials changed on wire=%v: %s", code, came.Load(), !received.Load(), stderr)
			}
			nowhereSaid(t, dir, stdout, stderr)
			if got, err := os.ReadFile(ambient); err != nil || string(got) != "sentinel" {
				t.Fatalf("ambient keylog modified: %q %v", got, err)
			}
		})
	}
	t.Run("forward HTTP proxy reused connection", func(t *testing.T) {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "the page") }))
		defer origin.Close()
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		var peers sync.Map
		var connections, authenticated atomic.Int32
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, seen := peers.LoadOrStore(r.RemoteAddr, true); !seen {
				connections.Add(1)
			}
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+secret))
			if r.Header.Get("Proxy-Authorization") == want && r.URL.IsAbs() {
				authenticated.Add(1)
			}
			forward := r.Clone(r.Context())
			forward.RequestURI = ""
			forward.Header.Del("Proxy-Authorization")
			forward.Header.Del("Proxy-Connection")
			response, err := transport.RoundTrip(forward)
			if err != nil {
				http.Error(w, "owned origin failed", http.StatusBadGateway)
				return
			}
			defer func() { _ = response.Body.Close() }()
			for name, values := range response.Header {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(response.StatusCode)
			_, _ = io.Copy(w, response.Body)
		}))
		defer proxy.Close()
		proxyURL, err := url.Parse(proxy.URL)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		retainSecretEvidence(t, "forward-proxy", dir)
		t.Setenv("RUN_PROXY", "http://alice:"+secret+"@"+proxyURL.Host)
		code, stdout, stderr := execWorkflow(t, "fetch", "--proxy-env", "RUN_PROXY", "--no-exit-lookup", "--reuse-connection", "--repeat", "2",
			"--json", "-o", filepath.Join(dir, "out"), "--pcap", "--log", filepath.Join(dir, "run.jsonl"), "--trace", filepath.Join(dir, "trace.json"), origin.URL)
		if code != 0 {
			t.Fatalf("forward proxy exit %d: %s", code, stderr)
		}
		if connections.Load() != 1 || authenticated.Load() != 2 {
			t.Fatalf("reuse not established: %d connections, %d authenticated requests", connections.Load(), authenticated.Load())
		}
		nowhereSaid(t, dir, stdout, stderr)
		basic := base64.StdEncoding.EncodeToString([]byte("alice:" + secret))
		files, _ := filepath.Glob(filepath.Join(dir, "out", "*.pcapng"))
		if len(files) != 2 {
			t.Fatalf("%d captures for two requests", len(files))
		}
		for _, name := range files {
			data, err := os.ReadFile(name)
			if err != nil || strings.Contains(string(data), basic) || !strings.Contains(string(data), "Proxy-Authorization: Basic "+strings.Repeat("*", len(basic))) {
				t.Fatalf("unsafe forward capture %s: %v", name, err)
			}
		}
	})
}

// Opt-in evidence retention is test-only; the ordinary suite uses temporary
// files. Artifacts may contain TLS secrets and belong in private captures.
func retainSecretEvidence(t *testing.T, label, dir string) {
	t.Helper()
	if root := os.Getenv("TLSFORGE_A4_EVIDENCE"); root != "" {
		t.Cleanup(func() {
			if err := os.CopyFS(filepath.Join(root, label), os.DirFS(dir)); err != nil {
				t.Errorf("retain evidence: %v", err)
			}
		})
	}
}

// secretSite is a site the run asks over protocol, telling heard what each
// request came with; its URL and the arguments that reach it over that
// protocol (HTTP/3 by a name whose HTTPS record says h3).
func secretSite(t *testing.T, protocol string, heard func(proto string, header func(string) string, query url.Values)) (string, []string) {
	t.Helper()
	answer := func(w http.ResponseWriter, r *http.Request) {
		heard(r.Proto, r.Header.Get, r.URL.Query())
		fmt.Fprint(w, "the page")
	}
	switch protocol {
	case "HTTP/1.1":
		server := httptest.NewTLSServer(http.HandlerFunc(answer))
		t.Cleanup(server.Close)
		return server.URL, nil
	case "HTTP/2.0":
		server := httptest.NewUnstartedServer(http.HandlerFunc(answer))
		server.EnableHTTP2 = true
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.URL, nil
	}
	var udp net.PacketConn
	var tcp net.Listener
	for tries := 1; ; tries++ {
		var err error
		if udp, err = net.ListenPacket("udp4", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if tcp, err = net.Listen("tcp4", udp.LocalAddr().String()); err == nil {
			break
		}
		_ = udp.Close()
		if tries == 10 {
			t.Fatal(err)
		}
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(answer))
	server.Listener = lateHandshakes{tcp}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.TLS.Certificates[0]
	h3 := &http3.Server{Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
		heard(r.Proto, r.Header.Get, r.URL.Query())
		fmt.Fprint(w, "the page")
	}), TLSConfig: &utls.Config{Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos: []string{"h3"}}}
	go func() { _ = h3.Serve(udp) }()
	t.Cleanup(func() { _ = h3.Close(); _ = udp.Close() })
	_, port, _ := net.SplitHostPort(tcp.Addr().String())
	return "https://h3.test:" + port, []string{"--dns-server", h3NamesAt(t)}
}
