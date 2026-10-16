package main

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// deflatedServer answers over HTTP/2 with a page sent as deflate in the zlib
// form RFC 9110 gives the name: the coding the transport hung on until the
// request's deadline.
func deflatedServer(t *testing.T, page string) *httptest.Server {
	t.Helper()
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	_, _ = writer.Write([]byte(page))
	_ = writer.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(compressed.Bytes())
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestFetchShowsADecodedPageWithFieldsThatDescribeIt(t *testing.T) {
	page := strings.Repeat("a page worth compressing. ", 50)
	server := deflatedServer(t, page)

	code, stdout, stderr := exec(t, "fetch", "-k", "-i", "--timeout", "10s", server.URL+"/page")
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	head, body, found := strings.Cut(stdout, "\n\n")
	if !found || body != page {
		t.Fatalf("stdout is not the fields, a blank line and the decoded page:\n%q", stdout)
	}
	// The fields of the wire would tell a reader to decode the page again.
	for _, field := range []string{"content-encoding", "content-length"} {
		if strings.Contains(head, field) {
			t.Errorf("%s is printed with a decoded page:\n%s", field, head)
		}
	}

	code, stdout, stderr = exec(t, "fetch", "-k", "--json", "--timeout", "10s", server.URL+"/page")
	if code != 0 {
		t.Fatalf("--json: exit code = %d\n%s", code, stderr)
	}
	var line struct {
		Bytes int    `json:"bytes"`
		Body  string `json:"body"`
	}
	if err := json.Unmarshal([]byte(stdout), &line); err != nil {
		t.Fatalf("--json: %v in %q", err, stdout)
	}
	if line.Bytes != len(page) || line.Body != page {
		t.Errorf("--json: %d bytes, body %q…, want the decoded page of %d", line.Bytes, line.Body[:min(len(line.Body), 30)], len(page))
	}
}
