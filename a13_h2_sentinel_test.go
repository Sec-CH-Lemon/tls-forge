package tlsforge

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// fhttp's MaxUint32 sentinel advertises a large advisory SETTINGS value while
// Framer still enforces its 16 MiB default. Both halves are wire assertions.
func TestA13HTTP2HeaderSentinelKeepsResourceBound(t *testing.T) {
	p := policyFile(t, nil)
	for i := range p.HTTP2.Settings {
		if p.HTTP2.Settings[i].ID == 6 {
			p.HTTP2.Settings[i].Value = math.MaxUint32
		}
	}
	data, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	p, err = profile.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	echo := startEcho(t)
	seen := measure(t, newTestClient(t, WithProfileValue(p)), echo)
	found := false
	for _, s := range seen.HTTP2.Settings {
		if s.ID == 6 && s.Value == math.MaxUint32 {
			found = true
		}
	}
	if !found {
		t.Fatal("advertised sentinel changed")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "requires H2", 400)
			return
		}
		n := 1
		if r.URL.Path == "/large" {
			n = 8192
		}
		for range n {
			w.Header().Add("X-Limit", strings.Repeat("a", 2048))
		}
		_, _ = w.Write([]byte("bounded"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := newTestClient(t, WithProfileValue(p))
	small, err := client.Get(server.URL + "/small")
	if err != nil || string(small.Body) != "bounded" {
		t.Fatalf("positive: %+v %v", small, err)
	}
	if _, err = client.Get(server.URL + "/large"); err == nil || !strings.Contains(err.Error(), "response header list larger") {
		t.Fatalf("16 MiB ceiling not enforced: %v", err)
	}
}
