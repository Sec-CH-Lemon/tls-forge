package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// namesAt is a DNS server over UDP that finds every name at 127.0.0.1 and
// keeps what it was asked.
func namesAt(t *testing.T) (string, func() []string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var mu sync.Mutex
	var asked []string
	go func() {
		for {
			buf := make([]byte, 1500)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			mu.Lock()
			asked = append(asked, q.Type.String()+" "+q.Name.String())
			mu.Unlock()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
			}
			reply, _ := b.Finish()
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return pc.LocalAddr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

func TestFetchLooksNamesUpWithTheDNSServerItIsGiven(t *testing.T) {
	// A name only the server knows is reached; its HTTPS records are asked
	// of the server too, as the profile asks for them.
	var host string
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { host = r.Host }))
	defer site.Close()
	dns, asked := namesAt(t)
	_, port, _ := net.SplitHostPort(site.Listener.Addr().String())
	url := "https://only.dns.test:" + port + "/"
	logFile := filepath.Join(t.TempDir(), "run.jsonl")
	code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--dns-server", dns, "--log", logFile, url)
	if code != 0 || host != "only.dns.test:"+port {
		t.Fatalf("exit code %d, host %q:\n%s", code, host, stderr)
	}
	if !strings.Contains(stderr, "dns         "+dns+" · names are looked up there") {
		t.Errorf("the run does not say where it looks names up:\n%s", stderr)
	}
	if log, _ := os.ReadFile(logFile); !strings.Contains(string(log), `"dns_server":"`+dns+`"`) {
		t.Errorf("the log does not say it:\n%s", log)
	}
	got := strings.Join(asked(), "\n")
	if !strings.Contains(got, "TypeA only.dns.test.") || !strings.Contains(got, "TypeHTTPS _"+port+"._https.only.dns.test.") {
		t.Errorf("asked:\n%s", got)
	}
}
