package echo

import (
	"html"
	"net"
	"slices"
	"strings"
)

// manualVisit is what a browser a person drives is shown when its visit to the
// capture page is not the one to measure, or nil when it is.
//
// Its first visit is never measured. It follows the browser's warning about a
// certificate made for this run, and what a browser sends after the person
// says yes can be a reload of the page that was refused; it is not what it
// sends when somebody opens an address. That visit only shows it what to do
// next, and ends its connection, as every answer outside a measurement does.
// A later one is measured when it is the first request on a connection of its
// own and is a page opened from the address bar rather than reloaded or
// reached by a link.
func (s *Server) manualVisit(sess *Session, req *request) []byte {
	return s.visited(visitorOf(sess, req.headers), req.headers, sess.requestCount() > 1, s.URL())
}

// visited is manualVisit's rule for a visitor, by the fields of its visit,
// on a connection that carried another request when carried says so, at a
// listener whose address is the one to open again: every listener has a first
// visit of its own, since a browser may keep a certificate it was talked into
// for one port, as Firefox does, and warn again on another.
func (s *Server) visited(visitor string, headers map[string]string, carried bool, address string) []byte {
	s.mu.Lock()
	trusted := s.trusted[visitor]
	if !trusted {
		s.trusted[visitor] = true
		s.trustedOrder = append(s.trustedOrder, visitor)
		if past := len(s.trustedOrder) - s.limits.kept; past > 0 {
			for _, old := range s.trustedOrder[:past] {
				delete(s.trusted, old)
			}
			s.trustedOrder = slices.Delete(s.trustedOrder, 0, past)
		}
	}
	s.mu.Unlock()

	if !trusted {
		return manualPage("This browser has accepted the certificate made for this run.", address)
	}
	why := notFresh(headers)
	if carried {
		why = "it came on a connection that had already carried another"
	}
	if why != "" {
		return manualPage("That visit was not measured: "+why+".", address)
	}
	return nil
}

// visitorOf tells one browser from another: by the address it came from, a
// phone from this machine, and by its user agent, Firefox from Safari on one
// machine.
func visitorOf(sess *Session, headers map[string]string) string {
	host, _, err := net.SplitHostPort(sess.remote)
	if err != nil {
		host = sess.remote
	}
	return host + "\n" + headers["user-agent"]
}

// manualHTTP1 serves the HTTP/1.1 visit of a browser a person opens, at the
// listener that offers HTTP/1.1 alone: as at the main one, its first visit only
// shows what to do next, and the next, typed into a new tab, is measured. It
// joins the navigation of the browser's HTTP/2 visit, which waits for it, and
// completes the capture; before that visit there is nothing to join.
func (s *Server) manualHTTP1(conn net.Conn, sess *Session, req *http1Request) error {
	headers := map[string]string{}
	for _, field := range req.Headers {
		headers[strings.ToLower(field.Name)] = field.Value
	}
	visitor := visitorOf(sess, headers)
	if page := s.visited(visitor+"\nhttp/1.1", headers, false, s.CaptureURL()); page != nil {
		return writeCaptureHTTP1Response(conn, "200", "text/html; charset=utf-8", "", page)
	}
	s.mu.Lock()
	target := s.awaiting[visitor]
	delete(s.awaiting, visitor)
	s.mu.Unlock()
	if target == nil {
		page := manualPage("This browser has not been measured over HTTP/2 yet: that visit comes first.", s.URL())
		return writeCaptureHTTP1Response(conn, "200", "text/html; charset=utf-8", "", page)
	}
	target.mu.Lock()
	target.http1 = cloneHTTP1(&req.HTTP1)
	target.mu.Unlock()
	err := writeCaptureHTTP1Response(conn, "200", "text/html; charset=utf-8", "", donePage("over HTTP/1.1 too"))
	s.complete(target)
	return err
}

// awaitHTTP1 keeps the navigation of a visitor that reported back, to be
// joined by its HTTP/1.1 visit: the latest it reported, and the visitors that
// reported last, those past kept forgotten.
func (s *Server) awaitHTTP1(visitor string, target *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.awaitingOrder = append(slices.DeleteFunc(s.awaitingOrder, func(v string) bool { return v == visitor }), visitor)
	s.awaiting[visitor] = target
	if past := len(s.awaitingOrder) - s.limits.kept; past > 0 {
		for _, old := range s.awaitingOrder[:past] {
			delete(s.awaiting, old)
		}
		s.awaitingOrder = slices.Delete(s.awaitingOrder, 0, past)
	}
}

// donePage tells the person at the browser the capture is complete, how.
func donePage(how string) []byte {
	return []byte(strings.Replace(donePageTemplate, "__HOW__", html.EscapeString(how), 1))
}

const donePageTemplate = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>tls-forge capture</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; padding:2rem 1.25rem; font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  main { max-width:40rem; margin:0 auto; }
</style>
<main>
  <h1>tls-forge capture</h1>
  <p>This browser is measured, __HOW__. You can close this tab: the command line has the result.</p>
</main>
`

// notFresh says why a page visit is not one made by opening the address, which
// is the visit a profile records, or nothing when it is one. A browser that
// does not send a field is not held to it: older ones send no Sec-Fetch-*.
func notFresh(headers map[string]string) string {
	opened := func(name, want string) bool {
		got, sent := headers[name]
		return !sent || got == want
	}
	switch {
	case headers["cache-control"] != "" || headers["pragma"] != "":
		return "it was a reload"
	case headers["referer"] != "" || !opened("sec-fetch-site", "none"):
		return "it came from a link, not from the address bar"
	case !opened("sec-fetch-mode", "navigate") || !opened("sec-fetch-dest", "document"):
		return "it was not a page being opened"
	}
	return ""
}

// requestCount is how many requests the connection has carried so far.
func (s *Session) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// manualPage tells the person at the browser what to do next: open the
// address again, in a new tab.
func manualPage(said, address string) []byte {
	page := strings.Replace(manualPageTemplate, "__SAID__", html.EscapeString(said), 1)
	page = strings.Replace(page, "__ADDRESS__", html.EscapeString(address+"/"), 1)
	return []byte(page)
}

const manualPageTemplate = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>tls-forge capture</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fff; --muted:#666; --line:#e3e3e3; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e8e8e8; --bg:#141414; --muted:#9b9b9b; --line:#2c2c2c; } }
  body { margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
         font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  main { max-width:40rem; margin:0 auto; }
  h1 { font-size:1.25rem; margin:0 0 1rem; }
  p.sub { color:var(--muted); }
  code { display:block; padding:.75rem; border:1px solid var(--line); border-radius:.5rem;
         font:14px ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; user-select:all; }
</style>
<main>
  <h1>tls-forge capture</h1>
  <p>__SAID__</p>
  <p>To measure it, open a new tab, and type or paste this address into it:</p>
  <code>__ADDRESS__</code>
  <p class="sub">Not in this tab, and not as a reload or a link: the visit that is
  measured is one a person makes by opening the address.</p>
</main>
`
