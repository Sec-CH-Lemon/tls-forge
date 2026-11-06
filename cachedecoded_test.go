package tlsforge

import (
	"bytes"
	"compress/zlib"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// A body a coding ends before the transport's does, as zlib's deflate stops
// at its checksum, is read to its end all the same, as Chromium's
// GzipSourceStream reads the bytes after it: the cache keeps the answer, and
// it is answered from it the next time.
func TestAFreshAnswerIsKeptWhateverItsCoding(t *testing.T) {
	encode := map[string]func([]byte) []byte{
		"deflate": func(b []byte) []byte {
			var out bytes.Buffer
			w := zlib.NewWriter(&out)
			_, _ = w.Write(b)
			_ = w.Close()
			return out.Bytes()
		},
		"br": func(b []byte) []byte {
			var out bytes.Buffer
			w := brotli.NewWriter(&out)
			_, _ = w.Write(b)
			_ = w.Close()
			return out.Bytes()
		},
		"zstd": func(b []byte) []byte {
			w, _ := zstd.NewWriter(nil)
			return w.EncodeAll(b, nil)
		},
	}
	for _, proto := range []string{"h1", "h2"} {
		for coding, encoded := range encode {
			s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "max-age=60")
				w.Header().Set("Content-Encoding", coding)
				_, _ = w.Write(encoded([]byte("owned")))
			})
			c := contextClient(t, s)
			for range 2 {
				r, err := c.Do(&Request{URL: "https://example.com/page", Browser: &BrowserContext{Kind: KindFetch,
					Initiator: "https://example.com/seed"}})
				if err != nil || string(r.Body) != "owned" {
					t.Fatalf("%s %s: %v %v", proto, coding, r, err)
				}
			}
			if got := s.requests(); len(got) != 1 {
				t.Errorf("%s %s: the origin was asked %d times", proto, coding, len(got))
			}
		}
	}
}
