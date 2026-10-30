package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestA9NoAuxiliaryRequestsByDefault(t *testing.T) {
	for _, mode := range []string{"direct", "probe", "resolve", "multi-way"} {
		for _, disable := range []string{"default", "--no-exit-lookup=false", "--no-exit-lookup"} {
			t.Run(mode+"/"+disable, func(t *testing.T) {
				asked := countingService(t)
				var resolved atomic.Int32
				resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					resolved.Add(1)
					_, _ = w.Write([]byte(`{"ip":"203.0.113.9"}`))
				}))
				t.Cleanup(resolver.Close)
				site, seen := countingSite(t, http.Header{"Cf-Ray": {"test-AMS"}})
				dir := t.TempDir()
				args := []string{"fetch", "--insecure", "--report=" + filepath.Join(dir, "run"), "--report-format", "json,html"}
				if disable != "default" {
					args = append(args, disable)
				}
				proxy := ""
				switch mode {
				case "probe":
					proxy = "http://" + startProxy(t).addr
				case "resolve":
					proxy = "http://user:pw@" + startProxySaying(t, func(int) string { return "X-Brd-IP: r123\r\n" }).addr
					file := filepath.Join(dir, "exits.json")
					raw := fmt.Sprintf(`{"fields":[{"header":"x-brd-ip","resolve":{"user":"{user}-ip-{value}","url":%q,"format":"json","ip":"ip"}}]}`, resolver.URL)
					if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "--exit-headers", file)
				case "multi-way":
					a, b := startProxy(t), startProxy(t)
					list := writeList(t, "urls.json", fmt.Sprintf(`[{"url":%q,"proxy":%q},{"url":%q,"proxy":%q}]`, site.URL+"/a", "http://"+a.addr, site.URL+"/b", "http://"+b.addr))
					args = append(args, "--input", list)
				}
				if proxy != "" {
					args = append(args, "--proxy", proxy)
				}
				if mode != "multi-way" {
					args = append(args, site.URL+"/page")
				}
				if code, _, stderr := exec(t, args...); code != 0 {
					t.Fatalf("exit %d: %s", code, stderr)
				}
				html := reportOf(t, filepath.Join(dir, "run.html"))
				if !strings.Contains(html, "No request was made to determine exit addresses.") || strings.Contains(html, "comes out was asked of") {
					t.Error("report describes an unrequested lookup as a request")
				}
				pages := int32(1)
				if mode == "multi-way" {
					pages = 2
				}
				if asked.Load() != 0 || resolved.Load() != 0 || seen("/cdn-cgi/trace") != 0 || seen("/page") != pages {
					t.Errorf("address_requests=%d resolver_requests=%d probes=%d pages=%d, want 0/0/0/%d", asked.Load(), resolved.Load(), seen("/cdn-cgi/trace"), seen("/page"), pages)
				}
				t.Logf("address_requests=%d resolver_requests=%d probes=%d pages=%d", asked.Load(), resolved.Load(), seen("/cdn-cgi/trace"), seen("/page"))
			})
		}
	}
}

func TestA9AddressQueriesVerifyTLSDespiteInsecure(t *testing.T) {
	var asked atomic.Int32
	service := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	service.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	service.StartTLS()
	t.Cleanup(service.Close)
	flags := insecureFlags(t)
	client, err := flags.asker("")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = (addressService{URL: service.URL, read: readJSON}).ask(context.Background(), client)
	if err == nil || !strings.Contains(err.Error(), "certificate") || asked.Load() != 0 {
		t.Errorf("untrusted service: error=%v HTTP_requests=%d, want certificate rejection before HTTP", err, asked.Load())
	}
	_, err = askThrough(context.Background(), flags, "", service.URL)
	if err == nil || !strings.Contains(err.Error(), "certificate") || asked.Load() != 0 {
		t.Errorf("untrusted resolver: error=%v HTTP_requests=%d", err, asked.Load())
	}
}

func TestA9ExitLookupRequiresPositiveOptIn(t *testing.T) {
	for _, extra := range [][]string{nil, {"--exit-lookup=false"}, {"--exit-lookup"}, {"--exit-lookup", "--no-exit-lookup=false"}, {"--exit-lookup", "--no-exit-lookup"}} {
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			asked := countingService(t)
			site, seen := countingSite(t, nil)
			args := append([]string{"fetch", "--insecure"}, extra...)
			args = append(args, site.URL)
			code, _, stderr := exec(t, args...)
			conflict := len(extra) == 2 && extra[1] == "--no-exit-lookup"
			wantCode, wantAsked, wantPage := 0, int32(0), int32(1)
			if conflict {
				wantCode, wantPage = 2, 0
			} else if len(extra) > 0 && extra[0] == "--exit-lookup" {
				wantAsked = 1
			}
			if code != wantCode || asked.Load() != wantAsked || seen("/page") != wantPage {
				t.Errorf("exit=%d lookup=%d page=%d; want %d/%d/%d: %s", code, asked.Load(), seen("/page"), wantCode, wantAsked, wantPage, stderr)
			}
			if wantAsked == 1 && !strings.Contains(stderr, "(by "+ipServices[0].name()+")") {
				t.Errorf("actual service not named: %s", stderr)
			}
			if wantAsked == 0 && !conflict && !strings.Contains(stderr, errNotAsked.Error()) {
				t.Errorf("missing not-requested reason: %s", stderr)
			}
		})
	}
}
