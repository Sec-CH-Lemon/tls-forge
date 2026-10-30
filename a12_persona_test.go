package tlsforge

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	fhttp "github.com/igor-lemon/fhttp"
	"golang.org/x/net/dns/dnsmessage"
)

var a12PersonaHints = []string{
	"device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr", "viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height",
	"sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-arch", "sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-form-factors",
	"sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency",
}

func TestA12ConcurrentPersonasAndFreshKeepTheirJSONSnapshot(t *testing.T) {
	var count atomic.Int32
	hints := strings.Join(a12PersonaHints, ", ")
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Accept-CH", hints)
		w.Header().Set("Critical-CH", hints)
		w.Header().Set("Cache-Control", "no-store")
		a12PersonaBody(t, w, r.Header, r.Proto)
	}))
	site.EnableHTTP2 = true
	site.StartTLS()
	t.Cleanup(site.Close)
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i, memory := range []string{"4", "16"} {
		p, err := profile.Get("chrome_156_macos")
		if err != nil {
			t.Fatal(err)
		}
		p.Name = "a12_independent_persona"
		for n := range p.ClientHints {
			if p.ClientHints[n].Name == "device-memory" || p.ClientHints[n].Name == "sec-ch-device-memory" {
				p.ClientHints[n].Value = memory
			}
		}
		raw, err := p.Save()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "persona.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		raw, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		p, err = profile.Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{}
		for _, f := range p.ClientHints {
			want[f.Name] = f.Value
		}
		c, err := New(WithProfileValue(p), WithInsecureSkipVerify())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		for n := range p.ClientHints {
			p.ClientHints[n].Value = "unrelated-owner-edit"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := range 3 {
				current := c
				if attempt == 2 {
					var err error
					current, err = c.Fresh()
					if err != nil {
						failures <- err
						return
					}
					defer current.Close()
				}
				res, err := current.Get(fmt.Sprintf("%s/client%d", site.URL, i))
				if err != nil {
					failures <- err
					continue
				}
				var got map[string]string
				if err := json.Unmarshal(res.Body, &got); err != nil {
					failures <- err
					continue
				}
				for _, name := range a12PersonaHints {
					if got[name] != want[name] {
						failures <- fmt.Errorf("client%d request%d %s=%q, JSON%q", i, attempt, name, got[name], want[name])
						break
					}
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if count.Load() != 12 {
		t.Fatalf("origin count%d, want twelve network requests without shared opt-ins/cache", count.Load())
	}
}

// The peer receives no expected persona. Every answer asks for the same
// standards-named hints and returns only what actually reached the origin.
func a12PersonaBody(t *testing.T, w io.Writer, header interface{ Get(string) string }, protocol string) {
	t.Helper()
	got := map[string]string{"@protocol": protocol}
	for _, name := range a12PersonaHints {
		got[name] = header.Get(name)
	}
	if err := json.NewEncoder(w).Encode(got); err != nil {
		t.Error(err)
	}
}

func TestA12EveryPersonaReachesH1H2H3AndOwnsEachRequest(t *testing.T) {
	paths, err := filepath.Glob("profile/data/chrome_*/*.json")
	if err != nil || len(paths) != 18 {
		t.Fatalf("profile inventory: %v, %v", paths, err)
	}
	for _, path := range paths {
		for _, protocol := range []string{"h1", "h2", "h3"} {
			t.Run(filepath.Dir(path)+"/"+filepath.Base(path)+"/"+protocol, func(t *testing.T) {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				p, err := profile.Load(raw)
				if err != nil {
					t.Fatal(err)
				}
				p.Name = "a12_persona_without_browser_dispatch"
				if protocol == "h3" {
					// This checks persona headers on H3, independently of the
					// cold DNS/TCP race. Keep fallback available, but give the
					// owned HTTPS record and QUIC handshake explicit budgets.
					for _, key := range []string{"dns.https_wait_min_ms", "dns.https_wait_max_ms", "quic.tcp_wait_cold_ms", "quic.tcp_wait_max_ms"} {
						p.Behavior[key] = json.RawMessage(`1000`)
					}
				}
				want := map[string]string{}
				for _, f := range p.ClientHints {
					want[f.Name] = f.Value
				}
				var count atomic.Int32
				hints := strings.Join(a12PersonaHints, ", ")
				var url string
				options := []Option{WithProfileValue(p), WithInsecureSkipVerify()}
				if protocol == "h3" {
					var tcp, connections *atomic.Int32
					url, tcp, connections = h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
						count.Add(1)
						w.Header().Set("Accept-CH", hints)
						w.Header().Set("Critical-CH", hints)
						w.Header().Set("Cache-Control", "no-store")
						a12PersonaBody(t, w, r.Header, r.Proto)
					}))
					name := "persona.a12.example.test"
					dns := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
						switch q.Type {
						case dnsmessage.TypeA:
							return []dnsRecord{{name: name, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
						case dnsmessage.TypeHTTPS:
							return []dnsRecord{{name: q.Name.String(), https: service(1, name, alpnParam("h3", "h2"))}}, 0, 0
						}
						return nil, 0, 0
					})
					url = strings.Replace(url, "127.0.0.1", name, 1)
					options = append(options, WithDNSServer(dns.addr))
					t.Cleanup(func() {
						if tcp.Load() != 0 || connections.Load() != 2 {
							t.Errorf("actual transports: TCP%d H3%d, want0/2 isolated connections", tcp.Load(), connections.Load())
						}
					})
				} else {
					site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						count.Add(1)
						w.Header().Set("Accept-CH", hints)
						w.Header().Set("Critical-CH", hints)
						w.Header().Set("Cache-Control", "no-store")
						a12PersonaBody(t, w, r.Header, r.Proto)
					}))
					site.EnableHTTP2 = protocol == "h2"
					site.StartTLS()
					t.Cleanup(site.Close)
					url = site.URL
				}
				c, err := New(options...)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				for range 2 {
					res, err := c.Get(url)
					if err != nil {
						t.Fatal(err)
					}
					var got map[string]string
					if err := json.Unmarshal(res.Body, &got); err != nil {
						t.Fatalf("actual body %q: %v", res.Body, err)
					}
					if want := map[string]string{"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol]; got["@protocol"] != want {
						t.Fatalf("actual protocol%q, want%s", got["@protocol"], want)
					}
					for _, name := range a12PersonaHints {
						if want[name] == "" || got[name] != want[name] {
							t.Errorf("%s actual%q JSON%q", name, got[name], want[name])
						}
					}
				}
				if count.Load() != 4 {
					t.Fatalf("origin count%d, want one cold Critical-CH restart per independent request", count.Load())
				}
			})
		}
	}
}
