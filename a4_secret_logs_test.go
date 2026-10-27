package tlsforge

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestSecretQueriesStayOutOfTheLogOverBothProtocols(t *testing.T) {
	// HTTP/2 writes a request's path and query as :path, a redirect's
	// Location and the next hop's Referer quote URLs too, and an answered
	// challenge names the URL it was answered for: each is masked as a URL
	// is, everywhere the log writes it.
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			site := tlsSite(t, h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/start":
					http.Redirect(w, r, "/next?api_key=NEVER-KEEP-2&ok=1", http.StatusFound)
				case "/auth":
					if r.Header.Get("Authorization") == "" {
						w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					fallthrough
				default:
					w.Header().Set("Content-Location", "/kept?session_token=NEVER-KEEP-3")
					_, _ = w.Write([]byte(r.Proto))
				}
			}))
			var log bytes.Buffer
			client, err := New(WithProfile("chrome_155_macos"), WithInsecureSkipVerify(),
				WithLogger(slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: LevelTrace}))))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			for _, target := range []string{
				site.URL + "/start?access_token=NEVER-KEEP-1&ok=1",
				strings.Replace(site.URL, "https://", "https://u:p@", 1) + "/auth?access_token=NEVER-KEEP-4&ok=1",
			} {
				res, err := client.Do(&Request{URL: target})
				if err != nil || res.Status != http.StatusOK {
					t.Fatalf("%s: %v %v", target, res, err)
				}
				if want := map[bool]string{true: "HTTP/2.0", false: "HTTP/1.1"}[h2]; string(res.Body) != want {
					t.Fatalf("answered over %s, want %s", res.Body, want)
				}
			}
			written := log.String()
			for _, secret := range []string{"NEVER-KEEP-1", "NEVER-KEEP-2", "NEVER-KEEP-3", "NEVER-KEEP-4"} {
				if strings.Contains(written, secret) {
					t.Errorf("the log wrote %s", secret)
				}
			}
			for _, kept := range []string{"ok=1", "challenge answered", "/next?", "/kept?"} {
				if !strings.Contains(written, kept) {
					t.Errorf("the log lost %q", kept)
				}
			}
			if h2 && !strings.Contains(written, ":path: /start?access_token=***") {
				t.Error("the log has no masked :path")
			}
		})
	}
}
