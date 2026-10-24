package tlsforge

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPlainHTTPUsesTheHTTPSProxysNegotiatedProtocol(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var mu sync.Mutex
			var received []string
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Proxy-Connection") != "" {
					t.Error("proxy credentials/hop field reached origin")
				}
				body, _ := io.ReadAll(r.Body)
				fmt.Fprintf(w, "%s:%s", r.Method, body)
			}))
			defer origin.Close()
			proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				received = append(received, r.Proto+" "+r.Method)
				mu.Unlock()
				if r.Method == "CONNECT" || r.Host != strings.TrimPrefix(origin.URL, "http://") || (r.ProtoMajor == 1 && !r.URL.IsAbs()) {
					http.Error(w, "ordinary forwarding to owned origin required", 400)
					return
				}
				wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("owned:synthetic-password"))
				if r.Header.Get("Proxy-Authorization") != wantAuth {
					t.Errorf("missing proxy auth over %s", protocol)
				}
				if protocol == "h2" && (r.Header.Get("Proxy-Connection") != "" || r.Header.Get("Connection") != "") {
					t.Error("H2 proxy hop fields")
				}
				copy := r.Clone(r.Context())
				copy.RequestURI = ""
				copy.URL.Scheme, copy.URL.Host = "http", r.Host
				copy.Header.Del("Proxy-Authorization")
				copy.Header.Del("Proxy-Connection")
				transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true}
				defer transport.CloseIdleConnections()
				res, err := transport.RoundTrip(copy)
				if err != nil {
					http.Error(w, err.Error(), 502)
					return
				}
				defer res.Body.Close()
				for k, vs := range res.Header {
					w.Header()[k] = vs
				}
				w.WriteHeader(res.StatusCode)
				io.Copy(w, res.Body)
			}))
			proxy.EnableHTTP2 = protocol == "h2"
			proxy.TLS = &tls.Config{NextProtos: []string{protocol}}
			proxy.StartTLS()
			defer proxy.Close()
			previous := proxyRoots
			proxyRoots = x509.NewCertPool()
			proxyRoots.AddCert(proxy.Certificate())
			defer func() { proxyRoots = previous }()
			// POSTs without a context, as given.
			client := newTestClient(t, WithProxy(strings.Replace(proxy.URL, "://", "://owned:synthetic-password@", 1)),
				WithProfileValue(asGivenProfile(t, DefaultProfile)))
			for i, method := range []string{"GET", "POST", "POST", "GET"} {
				if i == 3 {
					client.CloseIdleConnections()
				}
				var body []byte
				if method == "POST" {
					body = bytes.Repeat([]byte{0, 1, 255, 'x'}, 257)
				}
				res, err := client.Do(&Request{URL: origin.URL + "/probe", Method: method, Body: body})
				if err != nil {
					t.Fatalf("%s: %v", method, err)
				}
				if res.Status != 200 || !bytes.Equal(res.Body, append([]byte(method+":"), body...)) {
					t.Fatalf("forwarded body/status: %+v", res)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(received) != 4 {
				t.Fatal(received)
			}
			prefix := "HTTP/1.1 "
			if protocol == "h2" {
				prefix = "HTTP/2.0 "
			}
			for _, r := range received {
				if !strings.HasPrefix(r, prefix) {
					t.Fatal(received)
				}
			}
		})
	}
}
