package harness

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// setCookies sets the cookies a request asks for with ?cookie: two, one of
// them SameSite=None, for any value, and one of each SameSite for 2; and with
// ?big=N one whose value is N bytes.
func setCookies(w http.ResponseWriter, r *http.Request) {
	if n, err := strconv.Atoi(r.URL.Query().Get("big")); err == nil && n > 0 {
		w.Header().Add("Set-Cookie", "big="+strings.Repeat("x", n)+"; Max-Age=3600; Path=/")
	}
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
//   - ?close ends the connection once answered, as Connection: close says,
//     which over HTTP/2 the server says with GOAWAY;
//   - /done/ID is a scenario's page saying it is done;
//   - /r/STATUS/... redirects to ?to with STATUS, or to the path ?plain of
//     its host over plain HTTP (a form's field, which no port is written in),
//     CORS allowing it but for ?noacao, saying Referrer-Policy as ?rp does,
//     and a preflight of it is allowed and kept for none;
//   - /chain/N redirects to /chain/N+1;
//   - /cors/... answers what CORS allows, a preflight allowed but for ?deny and
//     kept as long as ?maxage says;
//   - /misdirected/... is answered as Misdirection answers, a 421
//     (Misdirected Request) or a 401, and otherwise as /cors/... is;
//   - /auth/... asks for HTTP authentication (authPage), /digest/... for
//     Digest authentication (DigestPage);
//   - /run/ID is the scenario's run page;
//   - anything else is a page, which goes on to ?next by a refresh, ?after
//     seconds after it has loaded.
//
// ?cookie sets cookies, but on a preflight. ?keep=NAME sets a cookie of that
// name on any answer but a preflight's, and ?pfkeep=NAME on a preflight's
// alone: what a later request carries says which answers' cookies a browser
// kept; ?sc=VALUE, said again for more, sets a Set-Cookie of each value on
// any answer but a preflight's. Under /cors/, ?noacao is an answer CORS
// refuses.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	q, path := r.URL.Query(), r.URL.Path
	if q.Has("accept") {
		w.Header().Set("Accept-CH", q.Get("accept"))
	}
	if q.Has("critical") {
		w.Header().Set("Critical-CH", q.Get("critical"))
	}
	if q.Has("close") {
		w.Header().Set("Connection", "close")
	}
	keep := q.Get("keep")
	if r.Method == http.MethodOptions {
		keep = q.Get("pfkeep")
	}
	if keep != "" {
		w.Header().Add("Set-Cookie", keep+"=1; Max-Age=3600; Path=/; SameSite=None; Secure")
	}
	if r.Method != http.MethodOptions {
		for _, value := range q["sc"] {
			w.Header().Add("Set-Cookie", value)
		}
	}
	if strings.HasPrefix(path, "/misdirected/") && s.misdirection.Answers(w, r, servedNameOf(r)) {
		return
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
		location := q.Get("to")
		if plain := q.Get("plain"); plain != "" {
			host := (&url.URL{Host: r.Host}).Hostname()
			location = "http://" + net.JoinHostPort(host, strconv.Itoa(s.Plain)) + plain
		}
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	case strings.HasPrefix(path, "/chain/"):
		n, err := strconv.Atoi(strings.TrimPrefix(path, "/chain/"))
		if err != nil {
			http.Error(w, "no link of a chain", http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/chain/"+strconv.Itoa(n+1))
		w.WriteHeader(http.StatusFound)
	case strings.HasPrefix(path, "/cors/"), strings.HasPrefix(path, "/misdirected/"):
		if r.Method == http.MethodOptions {
			if q.Get("deny") != "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			preflighted(w, r, q.Get("maxage"))
			return
		}
		if q.Get("noacao") == "" {
			allow(w, r)
		}
		setCookies(w, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	case strings.HasPrefix(path, "/auth/"):
		authPage(w, r)
	case strings.HasPrefix(path, "/digest/"):
		DigestPage(w, r)
	case strings.HasPrefix(path, "/run/"):
		s.runPage(w, r, strings.TrimPrefix(path, "/run/"))
	case strings.HasPrefix(path, "/urlrun/"):
		s.urlPage(w, r, strings.TrimPrefix(path, "/urlrun/"))
	case strings.HasPrefix(path, "/urlthrown/"):
		w.WriteHeader(http.StatusNoContent)
	case path == "/favicon.ico":
		http.NotFound(w, r)
	default:
		setCookies(w, r)
		allow(w, r)
		page(w, q.Get("next"), q.Get("after"), q.Has("quiet"))
	}
}

// quietIcon is an icon a page names of its own, so that the browser asks for
// no /favicon.ico once it has loaded.
const quietIcon = `<link rel="icon" href="data:,">`

// page writes a page, which goes on to next by a refresh when there is one,
// after seconds after it has loaded, or at once when that says nothing, and
// names an icon of its own when quiet.
func page(w http.ResponseWriter, next, after string, quiet bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	head := ""
	if quiet {
		head = quietIcon
	}
	if after == "" {
		after = "0"
	}
	if next != "" {
		head += `<meta http-equiv="refresh" content="` + after + `;url=` + next + `">`
	}
	_, _ = w.Write([]byte("<!doctype html>" + head + "<title>page</title><p>page</p>"))
}

// benchUser and benchPassword are the credentials the pages under /auth/ and
// /digest/ take, as {U} has them in its URL; benchAuthorization is them in
// Basic.
const (
	benchUser, benchPassword = "u", "p"
	benchAuthorization       = "Basic dTpw"
)

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
	page(w, q.Get("next"), "", false)
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
	// The origins the page's script reaches are on the port it was asked on,
	// or, for a page over plain HTTP, the TLS port its run says in ?tls.
	_, port, _ := net.SplitHostPort(r.Host)
	if tls := r.URL.Query().Get("tls"); tls != "" {
		port = tls
	}
	tlsPort, _ := strconv.Atoi(port)
	o := origins(tlsPort, s.Plain)
	head := ""
	if sc.referrer != "" {
		head = `<meta name="referrer" content="` + sc.referrer + `">`
	}
	if sc.quiet {
		head += quietIcon
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head>%s<title>run</title></head><body>%s<script>\nconst done=()=>fetch('/done/%s');\n%s\n</script></body></html>",
		head, fill(sc.html, id, o), id, fill(sc.script, id, o))
}
