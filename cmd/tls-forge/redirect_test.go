package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// chainOf answers /chain/N with a redirect to /chain/N-1 and /chain/0 with a
// page, and says how many requests it was asked and how many reached the page.
func chainOf(t *testing.T) (*httptest.Server, func() (requests, ends int32)) {
	t.Helper()
	var requests, ends atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/chain/"))
		if n == 0 {
			ends.Add(1)
			_, _ = w.Write([]byte("landed"))
			return
		}
		http.Redirect(w, r, "/chain/"+strconv.Itoa(n-1), http.StatusFound)
	}))
	t.Cleanup(server.Close)
	return server, func() (int32, int32) { return requests.Load(), ends.Load() }
}

func TestFetchFollowsNineteenRedirectsAndNoMore(t *testing.T) {
	// As Chrome 155 does: 20 requests, the 20th redirect not followed, and
	// nothing past it asked; in a browser context too.
	for _, kind := range [][]string{nil, {"--request-kind", "navigation"}} {
		for _, tc := range []struct {
			redirects      int
			code           int
			requests, ends int32
		}{
			{19, 0, 20, 1}, {20, 1, 20, 0}, {21, 1, 20, 0},
		} {
			t.Run(fmt.Sprintf("%v/%d", kind, tc.redirects), func(t *testing.T) {
				server, count := chainOf(t)
				args := append(append([]string{"fetch"}, kind...), fmt.Sprintf("%s/chain/%d", server.URL, tc.redirects))
				code, _, stderr := exec(t, args...)
				if code != tc.code {
					t.Errorf("exit code = %d, want %d\n%s", code, tc.code, stderr)
				}
				if failed := strings.Contains(stderr, "the 20th redirect was not followed"); failed != (tc.code != 0) {
					t.Errorf("stderr:\n%s", stderr)
				}
				if requests, ends := count(); requests != tc.requests || ends != tc.ends {
					t.Errorf("the server was asked %d times, the page %d; want %d and %d", requests, ends,
						tc.requests, tc.ends)
				}
			})
		}
	}
}
