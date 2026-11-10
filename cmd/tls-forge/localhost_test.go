package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/internal/localhost"
)

// atLocalhost puts server, made and not yet started, at 127.0.0.1 and at
// [::1] on one port (localhost.Joined), and is it: its URL names 127.0.0.1 as
// before, and a client, or a proxy, that asks for it by localhost reaches it
// whichever of the two it tries first. Such a client tries [::1] first on
// macOS, where Go's resolver puts it first: at 127.0.0.1 alone, as httptest
// puts a server, the server lost the client now and then to another program's
// socket at [::1] on its port (2026-10-25: "http: server gave HTTP response to
// HTTPS client").
func atLocalhost(t *testing.T, server *httptest.Server) *httptest.Server {
	t.Helper()
	listener, err := localhost.Joined(net.Listen)
	if err != nil {
		t.Fatalf("listening at localhost: %v", err)
	}
	_ = server.Listener.Close()
	server.Listener = listener
	return server
}

func TestASiteAskedForByLocalhostAnswersAtBothAddresses(t *testing.T) {
	// The sites tests ask for by localhost answer at [::1] as at 127.0.0.1,
	// on one port, and the listener httptest made is let go of.
	made := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("made"))
	}))
	httptests := made.Listener.Addr().String()
	atLocalhost(t, made).StartTLS()
	t.Cleanup(made.Close)
	if conn, err := net.Dial("tcp", httptests); err == nil {
		_ = conn.Close()
		t.Errorf("the listener httptest made at %s is still there", httptests)
	}
	keyed, _ := keyedSite(t, io.Discard)
	for _, tc := range []struct {
		name       string
		server     *httptest.Server
		path, says string
	}{
		{"atLocalhost", made, "/", "made"},
		{"cookieEcho", cookieEcho(t), "/", ""},
		{"keyedSite", keyed, "/", "answer-"},
		{"cloudflareSite", cloudflareSite(t), "/page", "page"},
	} {
		_, port, _ := net.SplitHostPort(strings.TrimPrefix(tc.server.URL, "https://"))
		for _, host := range []string{"127.0.0.1", "[::1]"} {
			// A client of its own each time, so that no connection to the
			// other address carries the request.
			client, err := tlsforge.New(tlsforge.WithInsecureSkipVerify())
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Get("https://" + host + ":" + port + tc.path)
			_ = client.Close()
			if err != nil || !res.OK() || !strings.HasPrefix(string(res.Body), tc.says) {
				t.Errorf("%s at %s: %v, %v", tc.name, host, res, err)
			}
		}
	}
}
