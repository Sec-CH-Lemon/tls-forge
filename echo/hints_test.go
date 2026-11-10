package echo

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestTheCapturePageAsksForEveryClientHintAServerAsksFor(t *testing.T) {
	// Chrome's hints in Chrome's order, as profiles have them, and of them the
	// ones a server has to ask for, in a meta http-equiv Accept-CH, which
	// applies to the page's own requests alone and which no later visit
	// carries (measured on Chrome 155: its fetch() sent all 21, the next
	// navigation none).
	if !slices.Equal(clientHints, profile.DefaultHintOrder()) {
		t.Errorf("the hints %v, Chrome's %v", clientHints, profile.DefaultHintOrder())
	}
	if !slices.Equal(askedHints(), profile.AskedClientHints()) {
		t.Errorf("asked %v, a server asks for %v", askedHints(), profile.AskedClientHints())
	}
	for _, name := range unaskedHints {
		if !slices.Contains(clientHints, name) || slices.Contains(askedHints(), name) {
			t.Errorf("%s: sent unasked, yet asked for, or no hint of Chrome's", name)
		}
	}
	for _, server := range []*Server{startServer(t), startServer(t, WithManual(true))} {
		client := http2Client()
		openPage(t, client, server.URL()+"/")
		_, page := openPage(t, client, server.URL()+"/")
		want := `<meta http-equiv="Accept-CH" content="` + strings.Join(askedHints(), ", ") + `">`
		if !strings.Contains(page, want) || strings.Contains(page, clientHintsPlaceholder) ||
			strings.Index(page, want) > strings.Index(page, "<script>") {
			t.Errorf("the page asks for:\n%s", page)
		}
	}
}

// reported is the capture of a navigation whose page reported over client,
// its report carrying headers.
func reported(t *testing.T, client *http.Client, server *Server, headers [][2]string) *capture.Capture {
	t.Helper()
	_, page := openPage(t, http2Client(), server.URL()+"/")
	const marker = "/collect?navigation="
	start := strings.Index(page, marker)
	end := strings.IndexByte(page[start:], '\'')
	req, err := http.NewRequest("POST", server.URL()+page[start:start+end], strings.NewReader(`{"user_agent":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", visitorAgent)
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /collect: %v", err)
	}
	_ = res.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := server.Await(ctx)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	return sess.Capture(capture.SourceBrowser)
}

func TestAReportKeepsTheClientHintsItCameWith(t *testing.T) {
	// Whatever order they came in and however spelt, by their names in lower
	// case in Chrome's order; the unasked too, and no header that is no hint.
	sent := [][2]string{
		{"Sec-CH-UA-Platform-Version", `"19.0.0"`}, {"X-Not-A-Hint", "1"}, {"Sec-CH-UA", `"Chromium";v="155"`},
		{"Device-Memory", "8"}, {"sec-ch-prefers-color-scheme", "light"}, {"Sec-CH-UA-Model", `""`},
	}
	want := []capture.HeaderField{
		{Name: "device-memory", Value: "8"}, {Name: "sec-ch-ua", Value: `"Chromium";v="155"`},
		{Name: "sec-ch-ua-platform-version", Value: `"19.0.0"`}, {Name: "sec-ch-ua-model", Value: `""`},
		{Name: "sec-ch-prefers-color-scheme", Value: "light"},
	}
	for _, tc := range []struct {
		name   string
		client *http.Client
	}{
		{"over HTTP/2", http2Client()},
		{"over HTTP/1.1", http1Client()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startServer(t)
			got := reported(t, tc.client, server, sent)
			if !slices.Equal(got.ClientHints, want) {
				t.Errorf("kept %v, want %v", got.ClientHints, want)
			}
		})
	}
}

func TestAReportWithoutClientHintsKeepsNone(t *testing.T) {
	// As a browser that sends none, Firefox's or Safari's, sends: none, and
	// nothing said of them.
	server := startServer(t)
	got := reported(t, http2Client(), server, [][2]string{{"X-Not-A-Hint", "1"}})
	if got.ClientHints != nil {
		t.Errorf("kept %v", got.ClientHints)
	}
	data, err := json.Marshal(got)
	if err != nil || strings.Contains(string(data), "client_hints") {
		t.Errorf("said %s, %v", data, err)
	}
}
