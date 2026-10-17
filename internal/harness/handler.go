package harness

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// setCookies sets the cookies a request asks for with ?cookie: two, one of
// them SameSite=None, for any value, and one of each SameSite for 2.
func setCookies(w http.ResponseWriter, r *http.Request) {
	set := r.URL.Query().Get("cookie")
	if set == "" {
		return
	}
	w.Header().Add("Set-Cookie", "a=1; Max-Age=3600; Path=/")
	w.Header().Add("Set-Cookie", "b=2; Max-Age=3600; Path=/; SameSite=None; Secure")
	if set == "2" {
		w.Header().Add("Set-Cookie", "c=3; Max-Age=3600; Path=/; SameSite=Strict")
		w.Header().Add("Set-Cookie", "d=4; Max-Age=3600; Path=/; SameSite=Lax")
	}
}

// allow lets the request's origin read the answer, with credentials.
func allow(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

// preflighted answers a preflight: allowed, for what it asks, kept for maxage.
func preflighted(w http.ResponseWriter, r *http.Request, maxage string) {
	allow(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
	if asked := r.Header.Get("Access-Control-Request-Headers"); asked != "" {
		w.Header().Set("Access-Control-Allow-Headers", asked)
	}
	w.Header().Set("Access-Control-Max-Age", maxage)
	w.WriteHeader(http.StatusNoContent)
}

// serve answers as the scenarios need:
//
//   - ?accept= and ?critical= are said as Accept-CH and Critical-CH, empty too;
//   - /done/ID is a scenario's page saying it is done;
//   - /r/STATUS/... redirects to ?to with STATUS, CORS allowing it but for
//     ?noacao, saying Referrer-Policy as ?rp does, and a preflight of it is
//     allowed and kept for none;
//   - /chain/N redirects to /chain/N+1;
//   - /cors/... answers what CORS allows, a preflight allowed but for ?deny and
//     kept as long as ?maxage says;
//   - /auth/... asks for HTTP authentication (authPage);
//   - /run/ID is the scenario's run page;
//   - anything else is a page, which goes on to ?next by a refresh.
//
// ?cookie sets cookies, but on a preflight.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	q, path := r.URL.Query(), r.URL.Path
	if q.Has("accept") {
		w.Header().Set("Accept-CH", q.Get("accept"))
	}
	if q.Has("critical") {
		w.Header().Set("Critical-CH", q.Get("critical"))
	}
	switch {
	case strings.HasPrefix(path, "/done/"):
		allow(w, r)
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, "/r/"):
		if r.Method == http.MethodOptions {
			preflighted(w, r, "0")
			return
		}
		status, err := strconv.Atoi(strings.Split(path, "/")[2])
		if err != nil || status < 300 || status > 399 {
			http.Error(w, "no redirect status", http.StatusBadRequest)
			return
		}
		setCookies(w, r)
		if q.Get("noacao") == "" {
			allow(w, r)
		}
		if policy := q.Get("rp"); policy != "" {
			w.Header().Set("Referrer-Policy", policy)
		}
		w.Header().Set("Location", q.Get("to"))
		w.WriteHeader(status)
	case strings.HasPrefix(path, "/chain/"):
		n, err := strconv.Atoi(strings.TrimPrefix(path, "/chain/"))
		if err != nil {
			http.Error(w, "no link of a chain", http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/chain/"+strconv.Itoa(n+1))
		w.WriteHeader(http.StatusFound)
	case strings.HasPrefix(path, "/cors/"):
		if r.Method == http.MethodOptions {
			if q.Get("deny") != "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			preflighted(w, r, q.Get("maxage"))
			return
		}
		allow(w, r)
		setCookies(w, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	case strings.HasPrefix(path, "/auth/"):
		authPage(w, r)
	case strings.HasPrefix(path, "/run/"):
		s.runPage(w, r, strings.TrimPrefix(path, "/run/"))
	case path == "/favicon.ico":
		http.NotFound(w, r)
	default:
		setCookies(w, r)
		allow(w, r)
		page(w, q.Get("next"))
	}
}

// page writes a page, which goes on to next by a refresh when there is one.
func page(w http.ResponseWriter, next string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	refresh := ""
	if next != "" {
		refresh = `<meta http-equiv="refresh" content="0;url=` + next + `">`
	}
	_, _ = w.Write([]byte("<!doctype html>" + refresh + "<title>page</title><p>page</p>"))
}

// benchAuthorization is what a page under /auth/ takes: u:p, Basic, as {U}
// has them in its URL.
const benchAuthorization = "Basic dTpw"

// authPage answers a page under /auth/: 401 with a Basic challenge, after a
// Digest one for ?offer=digest, until the request says benchAuthorization;
// then a redirect to ?to, or a page that goes on to ?next.
func authPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.Header.Get("Authorization") != benchAuthorization {
		if q.Get("offer") == "digest" {
			w.Header().Add("WWW-Authenticate", `Digest realm="bench", nonce="b3ec7d4c", qop="auth"`)
		}
		w.Header().Add("WWW-Authenticate", `Basic realm="bench"`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<!doctype html><title>401</title><p>401</p>"))
		return
	}
	if to := q.Get("to"); to != "" {
		w.Header().Set("Location", to)
		w.WriteHeader(http.StatusFound)
		return
	}
	page(w, q.Get("next"))
}

// runPage is the page scenario id runs in: its body, and its script, which
// tells /done/ID when it is done.
func (s *Server) runPage(w http.ResponseWriter, r *http.Request, id string) {
	sc, ok := s.catalogue[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	setCookies(w, r)
	// The origins the page's script reaches are on the port it was asked on.
	_, port, _ := net.SplitHostPort(r.Host)
	tlsPort, _ := strconv.Atoi(port)
	o := origins(tlsPort, s.Plain)
	head := ""
	if sc.referrer != "" {
		head = `<meta name="referrer" content="` + sc.referrer + `">`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head>%s<title>run</title></head><body>%s<script>\nconst done=()=>fetch('/done/%s');\n%s\n</script></body></html>",
		head, fill(sc.html, id, o), id, fill(sc.script, id, o))
}
