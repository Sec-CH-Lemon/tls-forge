package tlsforge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	tc "github.com/igor-lemon/tls-client"
)

func TestContentCodingMatchesChrome156Witness(t *testing.T) {
	var fixture struct {
		Browser string `json:"browser"`
		Cases   []struct {
			Protocol string `json:"protocol"`
			Encoding string `json:"encoding"`
			Body     string `json:"body_hex"`
			Error    bool   `json:"error"`
			Decoded  string `json:"decoded_hex"`
		} `json:"coding_cases"`
	}
	data, err := os.ReadFile("testdata/chrome156-response-security.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Browser != "Chrome/156.0.8078.48" || len(fixture.Cases) != 80 {
		t.Fatal("incomplete witness")
	}
	for _, protocol := range []string{"h1", "h2"} {
		server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
			i, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
			if err != nil || i < 0 || i >= len(fixture.Cases) {
				http.NotFound(w, r)
				return
			}
			row := fixture.Cases[i]
			body, err := hex.DecodeString(row.Body)
			if err != nil {
				t.Error(err)
				return
			}
			if row.Encoding != "" {
				w.Header().Set("Content-Encoding", row.Encoding)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		})
		client := newTestClient(t, server.dialing())
		for i, row := range fixture.Cases {
			if row.Protocol != protocol {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", protocol, i), func(t *testing.T) {
				response, err := client.Do(&Request{URL: fmt.Sprintf("https://probe.test/%d", i), Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://probe.test/"}})
				if (err != nil) != row.Error {
					t.Fatalf("coding %s: error %v, want failure %v", row.Encoding, err, row.Error)
				}
				if err == nil && hex.EncodeToString(response.Body) != row.Decoded {
					t.Fatal("body differs from browser witness")
				}
			})
		}
	}
}

func TestJSONOwnsContentCodingLimitAndOverflow(t *testing.T) {
	body := gzipped(t, gzipped(t, []byte("decoded")))
	for _, protocol := range []string{"h1", "h2"} {
		server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip, gzip")
			_, _ = w.Write(body)
		})
		var wg sync.WaitGroup
		for _, choice := range []struct {
			limit  int
			action string
		}{{1, "error"}, {2, "error"}, {1, "raw"}} {
			p := policyFile(t, map[string]any{"http.max_content_codings": choice.limit, "http.content_coding_overflow": choice.action})
			p.Name = "renamed_firefox_metadata_999"
			p.UserAgent = "identity does not select decoding"
			client := newTestClient(t, WithProfileValue(p), server.dialing())
			wg.Add(1)
			go func() {
				defer wg.Done()
				response, err := client.Get("https://probe.test/")
				if choice.limit == 1 && choice.action == "error" {
					if err == nil {
						t.Error("JSON depth limit ignored")
					}
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				want := []byte("decoded")
				if choice.action == "raw" {
					want = body
				}
				if !bytes.Equal(response.Body, want) {
					t.Error("JSON overflow choice ignored or leaked across clients")
				}
			}()
		}
		wg.Wait()
	}
	p := shippedProfile(t, "chrome_155_macos")
	p.Behavior["http.max_content_codings"] = json.RawMessage(`65`)
	var dials atomic.Int32
	_, err := New(WithProfileValue(p), WithTransportOption(tc.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("unexpected dial")
	})))
	if err == nil || dials.Load() != 0 {
		t.Fatalf("invalid depth was not rejected offline: error=%v dials=%d", err, dials.Load())
	}
}
