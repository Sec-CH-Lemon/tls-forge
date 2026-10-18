package harness

import (
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// Misdirection is how the bench answers under /misdirected/: 421
// (Misdirected Request) when misdirected says so, setting a cookie m for
// ?mcookie; for ?auth a 401 asking for Basic, of the realm "bench", until the
// request says u:p; and otherwise nothing, the caller answering as under
// /cors/. CORS allows both. Exported so that answeringAsMeasured in
// browser_test.go answers as the bench did. The zero value is ready.
type Misdirection struct {
	mu sync.Mutex
	// asked are the URLs asked for, by host and request URI, for ?first, and
	// for ?authfirst behind "authorized ".
	asked []string
}

// Answers answers r and reports so, when it is answered here: r came on a
// connection whose TLS asked for name, empty in the clear.
func (m *Misdirection) Answers(w http.ResponseWriter, r *http.Request, name string) bool {
	q := r.URL.Query()
	switch {
	case m.misdirected(r, name):
		allow(w, r)
		if q.Has("mcookie") {
			w.Header().Add("Set-Cookie", "m=1; Max-Age=3600; Path=/")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte("misdirected"))
	case q.Has("auth") && r.Header.Get("Authorization") != benchAuthorization:
		allow(w, r)
		w.Header().Set("WWW-Authenticate", `Basic realm="bench"`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<!doctype html><title>401</title><p>401</p>"))
	default:
		return false
	}
	return true
}

// misdirected reports whether r is answered 421: with ?always every time,
// with ?first the first time its URL is asked for, with ?authfirst the first
// time it is asked for with Authorization, and otherwise when the TLS of the
// connection it came on asked for another name than its host, as a server
// answers a request for a name it does not serve sent over a connection to
// one it does. In the clear, a request is not.
func (m *Misdirection) misdirected(r *http.Request, name string) bool {
	q, url := r.URL.Query(), r.Host+r.URL.RequestURI()
	switch {
	case q.Has("always"),
		q.Has("first") && m.first(url),
		q.Has("authfirst") && r.Header.Get("Authorization") != "" && m.first("authorized "+url):
		return true
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return name != "" && !strings.EqualFold(host, name)
}

// first reports whether url is asked for the first time since the
// Misdirection was made or forgot.
func (m *Misdirection) first(url string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if slices.Contains(m.asked, url) {
		return false
	}
	m.asked = append(m.asked, url)
	return true
}

// Forget forgets which URLs were asked for.
func (m *Misdirection) Forget() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.asked = nil
}
