package tlsforge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	tc "github.com/igor-lemon/tls-client"
	"github.com/quic-go/qpack"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestBodyPresenceFramingOnActualH1H2(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			s := newRecorder(t, proto, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = io.WriteString(w, "ok")
			}))
			c := contextClient(t, s)
			for i, tt := range []struct {
				method string
				body   []byte
				want   []string
			}{
				{"GET", nil, nil}, {"POST", nil, []string{"0"}}, {"PUT", nil, []string{"0"}},
				{"PATCH", nil, nil}, {"DELETE", nil, nil}, {"OPTIONS", nil, nil},
				{"PATCH", []byte{}, []string{"0"}}, {"DELETE", []byte{}, []string{"0"}}, {"OPTIONS", []byte{}, []string{"0"}},
				{"PATCH", []byte("x"), []string{"1"}}, {"PATCH", bytes.Repeat([]byte("a"), 123), []string{"123"}},
			} {
				r, err := c.Do(&Request{Method: tt.method, URL: fmt.Sprintf("https://example.test/p/%d", i), Body: tt.body, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.test/page"}})
				if err != nil || string(r.Body) != "ok" {
					t.Fatalf("%s: %v", tt.method, err)
				}
				requests := s.requests()
				got := requests[len(requests)-1]
				var lengths []string
				for _, h := range got.headers {
					if h[0] == "content-length" || h[0] == "Content-Length" {
						lengths = append(lengths, h[1])
					}
				}
				if !reflect.DeepEqual(lengths, tt.want) {
					t.Fatalf("%s explicit=%t: lengths%q,want%q", tt.method, tt.body != nil, lengths, tt.want)
				}
				got.bodyMu.Lock()
				body := got.body
				got.bodyMu.Unlock()
				if body != string(tt.body) {
					t.Fatal("payload changed")
				}
			}
			n := len(s.requests())
			for _, method := range []string{"GET", "HEAD"} {
				_, err := c.Do(&Request{Method: method, URL: "https://example.test/never", Body: []byte{}, Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://example.test/page"}})
				if err == nil || len(s.requests()) != n {
					t.Fatal("explicit empty forbidden Fetch upload reached origin", method, err)
				}
			}
		})
	}
}

func TestJSONFramingControlsH1H2WithoutBrowserNameDispatch(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		for _, method := range []string{"PATCH", "REPORT"} {
			t.Run(proto+method, func(t *testing.T) {
				s := newRecorder(t, proto, nil)
				// Without a context, which a profile that says so sends as given.
				p := asGivenProfile(t, "chrome_155_macos")
				p.Name = "unrelated-profile-name"
				raw, _ := json.Marshal([]string{method})
				p.Behavior["http.zero_content_length_methods"] = raw
				c := contextClient(t, s, WithProfileValue(p))
				if _, err := c.Do(&Request{Method: method, URL: "https://example.test/p"}); err != nil {
					t.Fatal(err)
				}
				req := s.requests()[0]
				found := false
				for _, h := range req.headers {
					if h[0] == "content-length" || h[0] == "Content-Length" {
						if h[1] != "0" {
							t.Fatal(h)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("JSON method vector did not reach actual wire")
				}
			})
		}
	}
}

func TestProfileFramingReachesActualH3QPACK(t *testing.T) {
	for _, tt := range []struct {
		name string
		body []byte
		want string
	}{{"absent", nil, ""}, {"empty", []byte{}, "0"}, {"positive", []byte("abc"), "3"}} {
		t.Run(tt.name, func(t *testing.T) {
			url, wire := qpackWirePeer(t)
			p, err := profile.Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			c := newTestClient(t, WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(4*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			if _, err = c.Do(&Request{Method: "PATCH", URL: url, Body: tt.body, Browser: &BrowserContext{Kind: KindFetch, Initiator: url}}); err != nil {
				t.Fatal(err)
			}
			var block []byte
			select {
			case block = <-wire:
			case <-time.After(time.Second):
				t.Fatal("missing QUIC request headers")
			}
			decode := qpack.NewDecoder().Decode(block)
			var lengths []string
			for {
				f, err := decode()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if f.Name == "content-length" {
					lengths = append(lengths, f.Value)
				}
			}
			if tt.want == "" && len(lengths) != 0 || tt.want != "" && !reflect.DeepEqual(lengths, []string{tt.want}) {
				t.Fatal(tt.name, lengths, tt.want)
			}
		})
	}
}

// Older browser fixtures record bytes only; an empty string denotes absence.
// Explicit zero-byte BodyInit is covered separately by []byte{} above.
func capturedBody(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}
