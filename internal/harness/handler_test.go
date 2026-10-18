package harness

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// served is what the server answers req with.
func served(s *Server, method, target string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for i := 0; i < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	s.serve(w, req)
	return w
}

func TestTheServerAnswersAsTheScenariosNeed(t *testing.T) {
	s := &Server{catalogue: map[string]scenario{
		"x":         {html: `<a href="{X}/p/x">x</a>`, script: "fetch('{S}/cors/{ID}').then(done);"},
		"referrer":  {referrer: "no-referrer"},
		"localhost": {script: "location.href='{H}/p/x';"},
	}, Plain: 4000}
	origin := []string{"Origin", "https://www.example.com"}
	for _, tc := range []struct {
		name, method, target string
		header               []string
		status               int
		want                 map[string]string
		cookies              int
		body                 string
	}{
		{name: "hints asked for, an empty one too", method: "GET", target: "/p/x?accept=sec-ch-ua-arch&critical=",
			status: 200, want: map[string]string{"Accept-CH": "sec-ch-ua-arch", "Critical-CH": ""}},
		{name: "done", method: "GET", target: "/done/x", header: origin, status: 204,
			want: map[string]string{"Access-Control-Allow-Origin": "https://www.example.com", "Access-Control-Allow-Credentials": "true"}},
		{name: "a redirect", method: "GET", target: "/r/307/x?to=/p/y&cookie=2&rp=no-referrer", header: origin, status: 307,
			want:    map[string]string{"Location": "/p/y", "Referrer-Policy": "no-referrer", "Access-Control-Allow-Origin": "https://www.example.com"},
			cookies: 4},
		{name: "a redirect CORS does not allow", method: "GET", target: "/r/302/x?to=/p/y&noacao=1", header: origin, status: 302,
			want: map[string]string{"Location": "/p/y", "Access-Control-Allow-Origin": ""}},
		{name: "a redirect's preflight", method: "OPTIONS", target: "/r/307/x?to=/p/y&cookie=1",
			header: append(slices.Clone(origin), "Access-Control-Request-Headers", "x-foo"), status: 204,
			want: map[string]string{"Access-Control-Allow-Headers": "x-foo", "Access-Control-Max-Age": "0",
				"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE", "Location": ""}},
		{name: "a redirect of no status", method: "GET", target: "/r/abc/x?to=/", status: 400},
		{name: "a redirect of a status that is none", method: "GET", target: "/r/200/x?to=/", status: 400},
		{name: "a chain", method: "GET", target: "/chain/3", status: 302, want: map[string]string{"Location": "/chain/4"}},
		{name: "a chain of no link", method: "GET", target: "/chain/x", status: 400},
		{name: "a CORS answer", method: "GET", target: "/cors/x?cookie=1", header: origin, status: 200,
			want:    map[string]string{"Content-Type": "application/json", "Access-Control-Allow-Origin": "https://www.example.com"},
			cookies: 2, body: `{"ok":true}`},
		{name: "a preflight allowed", method: "OPTIONS", target: "/cors/x?maxage=600", header: origin, status: 204,
			want: map[string]string{"Access-Control-Max-Age": "600", "Access-Control-Allow-Headers": ""}},
		{name: "a preflight refused", method: "OPTIONS", target: "/cors/x?deny=1", header: origin, status: 403,
			want: map[string]string{"Access-Control-Allow-Origin": ""}},
		{name: "misdirected every time", method: "GET", target: "/misdirected/x?always=1&cookie=1", header: origin,
			status: 421, body: "misdirected",
			want: map[string]string{"Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "https://www.example.com"}},
		{name: "not misdirected, in the clear", method: "GET", target: "/misdirected/x?cookie=1", header: origin, status: 200,
			want:    map[string]string{"Content-Type": "application/json", "Access-Control-Allow-Origin": "https://www.example.com"},
			cookies: 2, body: `{"ok":true}`},
		{name: "a preflight of what is not misdirected", method: "OPTIONS", target: "/misdirected/x?maxage=0", header: origin,
			status: 204, want: map[string]string{"Access-Control-Max-Age": "0"}},
		{name: "misdirected, with a cookie", method: "GET", target: "/misdirected/x?always=1&mcookie=1", status: 421, cookies: 1,
			body: "misdirected"},
		{name: "not misdirected, asking for credentials", method: "GET", target: "/misdirected/x?auth=1", header: origin,
			status: 401, body: "<p>401</p>",
			want: map[string]string{"WWW-Authenticate": `Basic realm="bench"`, "Content-Type": "text/html; charset=utf-8",
				"Access-Control-Allow-Origin": "https://www.example.com"}},
		{name: "not misdirected, and given them", method: "GET", target: "/misdirected/x?auth=1",
			header: []string{"Authorization", "Basic dTpw"}, status: 200, body: `{"ok":true}`},
		{name: "a page asked as if misdirected", method: "GET", target: "/p/x?always=1&auth=1", status: 200,
			body: "<title>page</title>"},
		{name: "a run page", method: "GET", target: "https://www.example.com:443/run/x?cookie=1", status: 200, cookies: 2,
			want: map[string]string{"Content-Type": "text/html; charset=utf-8"},
			body: "<!doctype html><html><head><title>run</title></head><body><a href=\"https://www.example.net:443/p/x\">x</a><script>\n" +
				"const done=()=>fetch('/done/x');\nfetch('https://api.example.com:443/cors/x').then(done);\n</script></body></html>"},
		{name: "a run page with its referrer policy", method: "GET", target: "/run/referrer", status: 200,
			body: `<!doctype html><html><head><meta name="referrer" content="no-referrer"><title>run</title></head>`},
		{name: "a run page with no port asked on", method: "GET", target: "http://localhost/run/localhost", status: 200,
			body: "location.href='http://www.example.com:4000/p/x';"},
		{name: "no such scenario", method: "GET", target: "/run/nothing", status: 404},
		{name: "a favicon", method: "GET", target: "/favicon.ico", status: 404},
		{name: "a page that goes on", method: "GET", target: "/p/x?next=/p/y&cookie=1", header: origin, status: 200, cookies: 2,
			body: `<!doctype html><meta http-equiv="refresh" content="0;url=/p/y"><title>page</title><p>page</p>`},
		{name: "a page", method: "GET", target: "/p/x", status: 200, want: map[string]string{"Connection": ""},
			body: "<!doctype html><title>page</title><p>page</p>"},
		{name: "a page that goes on after a while", method: "GET", target: "/p/x?after=2&next=/run/y", status: 200,
			body: `<!doctype html><meta http-equiv="refresh" content="2;url=/run/y"><title>page</title>`},
		{name: "a page that ends its connection", method: "GET", target: "/p/x?close=1", status: 200,
			want: map[string]string{"Connection": "close"}, body: "<!doctype html><title>page</title>"},
		{name: "authentication asked for", method: "GET", target: "/auth/x/a?next=/p/y", status: 401,
			want: map[string]string{"WWW-Authenticate": `Basic realm="bench"`, "Content-Type": "text/html; charset=utf-8"},
			body: "<p>401</p>"},
		{name: "authentication with other credentials", method: "GET", target: "/auth/x/a", header: []string{"Authorization", "Basic dTp4"},
			status: 401, want: map[string]string{"WWW-Authenticate": `Basic realm="bench"`}},
		{name: "authenticated, a page that goes on", method: "GET", target: "/auth/x/a?next=/p/y", header: []string{"Authorization", "Basic dTpw"},
			status: 200, want: map[string]string{"WWW-Authenticate": ""},
			body: `<!doctype html><meta http-equiv="refresh" content="0;url=/p/y"><title>page</title><p>page</p>`},
		{name: "authenticated, a redirect", method: "GET", target: "/auth/x/a?to=/auth/x/b", header: []string{"Authorization", "Basic dTpw"},
			status: 302, want: map[string]string{"Location": "/auth/x/b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := served(s, tc.method, tc.target, tc.header...)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			for name, want := range tc.want {
				if got := w.Header().Get(name); got != want {
					t.Errorf("%s: %q, want %q", name, got, want)
				}
			}
			if got := len(w.Header().Values("Set-Cookie")); got != tc.cookies {
				t.Errorf("%d cookies, want %d", got, tc.cookies)
			}
			if !strings.Contains(w.Body.String(), tc.body) {
				t.Errorf("body %q, want %q in it", w.Body.String(), tc.body)
			}
		})
	}
	// Hints are not asked for unless said, and cookies are not set on a
	// preflight.
	w := served(s, http.MethodOptions, "/cors/x?cookie=1")
	if _, asked := w.Header()["Accept-Ch"]; asked || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("headers %v", w.Header())
	}
	// Digest is offered before Basic when asked, each in a field of its own.
	w = served(s, http.MethodGet, "/auth/x/a?offer=digest")
	if got := w.Header().Values("WWW-Authenticate"); len(got) != 2 || !strings.HasPrefix(got[0], "Digest realm=\"bench\", nonce=") || got[1] != `Basic realm="bench"` {
		t.Errorf("challenges %v", got)
	}
	// Misdirected the first time a URL is asked for, by host and request URI,
	// since the server started or was reset.
	for i, want := range []int{421, 200, 421, 421, 200} {
		target := "/misdirected/x?first=1"
		switch i {
		case 2:
			target = "/misdirected/y?first=1"
		case 3:
			s.Reset()
		}
		if w := served(s, http.MethodGet, target); w.Code != want {
			t.Errorf("%s, the %d. time: %d, want %d", target, i+1, w.Code, want)
		}
	}
	// A 421 says so, and nothing more.
	if body := served(s, http.MethodGet, "/misdirected/x?always=1").Body.String(); body != "misdirected" {
		t.Errorf("a 421 said %q", body)
	}
	// A 421 the first time, a 401 until it is sent u:p, and a 421 the first
	// time it is: as asked for one after the other, and with each alone.
	basic := []string{"Authorization", "Basic dTpw"}
	for _, tc := range []struct {
		target string
		header [][]string
		want   []int
	}{
		{"/misdirected/a?first=1&auth=1&authfirst=1", [][]string{nil, nil, basic, basic}, []int{421, 401, 421, 200}},
		{"/misdirected/b?auth=1&authfirst=1", [][]string{nil, basic, basic}, []int{401, 421, 200}},
		{"/misdirected/c?authfirst=1", [][]string{nil, nil, basic, basic}, []int{200, 200, 421, 200}},
	} {
		for i, header := range tc.header {
			if w := served(s, http.MethodGet, tc.target, header...); w.Code != tc.want[i] {
				t.Errorf("%s, the %d. time: %d, want %d", tc.target, i+1, w.Code, tc.want[i])
			}
		}
	}
	// Cookies of every SameSite are the four, and in order.
	w = served(s, http.MethodGet, "/p/x?cookie=2")
	if got := w.Header().Values("Set-Cookie"); len(got) != 4 || !strings.HasPrefix(got[3], "d=4") || !strings.Contains(got[2], "SameSite=Strict") {
		t.Errorf("cookies %v", got)
	}
}
