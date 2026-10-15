package echo

import (
	"html"
	"net"
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
	visitor := visitorOf(sess, req)
	s.mu.Lock()
	trusted := s.trusted[visitor]
	s.trusted[visitor] = true
	s.mu.Unlock()

	if !trusted {
		return manualPage("This browser has accepted the certificate made for this run.", s.URL())
	}
	why := notFresh(req.headers)
	if sess.requestCount() > 1 {
		why = "it came on a connection that had already carried another"
	}
	if why != "" {
		return manualPage("That visit was not measured: "+why+".", s.URL())
	}
	return nil
}

// visitorOf tells one browser from another: by the address it came from, a
// phone from this machine, and by its user agent, Firefox from Safari on one
// machine.
func visitorOf(sess *Session, req *request) string {
	host, _, err := net.SplitHostPort(sess.remote)
	if err != nil {
		host = sess.remote
	}
	return host + "\n" + req.headers["user-agent"]
}

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
