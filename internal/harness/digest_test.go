package harness

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// TestThePagesTakeWhatChromeAnswered serves every request Chrome sent to a
// page that asks for authentication again, with what it said in
// Authorization: a page takes it where Chrome went on to another URL, and asks
// again where Chrome asked for the same URL next, or stopped there. So each
// Digest answer Chrome worked out is one the pages' RFC 7616 arithmetic takes.
func TestThePagesTakeWhatChromeAnswered(t *testing.T) {
	fixture, err := LoadRequests(requestsFixture)
	if err != nil {
		t.Fatalf("LoadRequests: %v", err)
	}
	s := &Server{catalogue: catalogue}
	checked := map[string]int{}
	for id, measured := range fixture.Scenarios {
		p := catalogue[id].planned(id, origins(443, 80))
		stopped := p.wait == "/never" || p.times > 1
		for proto, requests := range map[string][]Request{"h2": measured.H2, "h1": measured.H1} {
			for i, r := range requests {
				u, _ := url.Parse(r.URL)
				if !strings.HasPrefix(u.Path, "/auth/") && !strings.HasPrefix(u.Path, "/digest/") {
					continue
				}
				var header []string
				for _, h := range r.Headers {
					if strings.EqualFold(h[0], "authorization") {
						header = []string{"Authorization", h[1]}
					}
				}
				asked := i+1 < len(requests) && requests[i+1].Method == r.Method && requests[i+1].URL == r.URL ||
					i+1 == len(requests) && stopped
				w := servedAt(s, r.Method, u, header...)
				if got := w.Code == http.StatusUnauthorized; got != asked {
					t.Errorf("%s over %s, request %d (%s %s): status %d", id, proto, i+1, r.Method, r.URL, w.Code)
				}
				checked[id]++
			}
		}
	}
	for id := range fixture.Scenarios {
		if strings.HasPrefix(id, "auth-") && checked[id] < 2 {
			t.Errorf("%s: %d requests checked", id, checked[id])
		}
	}
}

// servedAt is what the server answers a request for u with, its target the
// path and query as a browser sends them, to the host of u.
func servedAt(s *Server, method string, u *url.URL, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, u.RequestURI(), nil)
	req.Host = u.Host
	for i := 0; i < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	s.serve(w, req)
	return w
}

// answer is a Digest answer to a page of the offers, by u:p unless said.
func answer(method, uri, realm, algorithm, nonce, nc, cnonce, qop, password string) string {
	h := digestHash(algorithm)
	ha1 := hexDigest(h, "u:"+realm+":"+password)
	if strings.HasSuffix(strings.ToLower(algorithm), "-sess") {
		ha1 = hexDigest(h, ha1+":"+nonce+":"+cnonce)
	}
	middle := ""
	if qop != "" {
		middle = nc + ":" + cnonce + ":" + qop + ":"
	}
	response := hexDigest(h, ha1+":"+nonce+":"+middle+hexDigest(h, method+":"+uri))
	out := `Digest username="u", realm="` + realm + `", nonce="` + nonce + `", uri="` + uri + `"`
	if algorithm != "" {
		out += ", algorithm=" + algorithm
	}
	out += `, response="` + response + `"`
	if qop != "" {
		out += ", qop=" + qop + ", nc=" + nc + `, cnonce="` + cnonce + `"`
	}
	return out
}

func TestAPageUnderDigestAsksAsItsOfferSays(t *testing.T) {
	s := &Server{}
	page := "/digest/auth/x/a?next=/digest/auth/x/b%3Fnext%3D/p/x-end"
	uri := page
	right := answer("GET", uri, "bench", "", firstNonce, "00000001", "0a4f113b0a4f113b", "auth", "p")
	for _, tc := range []struct {
		name, target, authorization string
		status                      int
		want                        map[string][]string
		body                        string
	}{
		{name: "asked for", target: page, status: 401,
			want: map[string][]string{"WWW-Authenticate": {`Digest realm="bench", nonce="b3ec7d4c", qop="auth"`}}, body: "<p>401</p>"},
		{name: "answered, a page that goes on by a URL of its origin", target: page, authorization: right, status: 200,
			body: `content="0;url=https://www.example.com/digest/auth/x/b?next=/p/x-end"`},
		{name: "answered, a redirect to a URL of its origin", target: "/digest/auth/x/a?to=/p/y",
			authorization: answer("GET", "/digest/auth/x/a?to=/p/y", "bench", "", firstNonce, "00000002", "0a4f113b0a4f113b", "auth", "p"),
			status:        302, want: map[string][]string{"Location": {"https://www.example.com/p/y"}}},
		{name: "answered, a page that goes nowhere", target: "/digest/auth/x/a",
			authorization: answer("GET", "/digest/auth/x/a", "bench", "", firstNonce, "00000001", "c", "auth", "p"), status: 200,
			body: "<!doctype html><title>page</title>"},
		{name: "answered with another password", target: page,
			authorization: answer("GET", uri, "bench", "", firstNonce, "00000001", "0a4f113b0a4f113b", "auth", "x"), status: 401},
		{name: "Basic, which it does not offer", target: page, authorization: "Basic dTpw", status: 401},
		{name: "no such offer", target: "/digest/none/x/a", status: 404},
		{name: "two challenges, in order", target: "/digest/md5-first/x/a", status: 401,
			want: map[string][]string{"WWW-Authenticate": {`Digest realm="bench", nonce="b3ec7d4c", algorithm=MD5, qop="auth"`,
				`Digest realm="bench", nonce="b3ec7d4c", algorithm=SHA-256, qop="auth"`}}},
		{name: "either answered", target: "/digest/md5-first/x/a",
			authorization: answer("GET", "/digest/md5-first/x/a", "bench", "SHA-256", firstNonce, "00000001", "c", "auth", "p"), status: 200},
		{name: "Basic as well", target: "/digest/after-basic/x/a", authorization: "Basic dTpw", status: 200},
		{name: "Basic as well, and not with other credentials", target: "/digest/after-basic/x/a", authorization: "Basic dTp4", status: 401,
			want: map[string][]string{"WWW-Authenticate": {`Basic realm="bench"`, `Digest realm="bench", nonce="b3ec7d4c", qop="auth"`}}},
		{name: "the first nonce out of date", target: "/digest/stale/x/a",
			authorization: answer("GET", "/digest/stale/x/a", "bench", "", firstNonce, "00000001", "c", "auth", "p"), status: 401,
			want: map[string][]string{"WWW-Authenticate": {`Digest realm="bench", nonce="f7a91c2e", qop="auth", stale=true`}}},
		{name: "the next nonce taken", target: "/digest/stale/x/a",
			authorization: answer("GET", "/digest/stale/x/a", "bench", "", freshNonce, "00000001", "c", "auth", "p"), status: 200},
		{name: "the first nonce taken once", target: "/digest/stale-later/x/a",
			authorization: answer("GET", "/digest/stale-later/x/a", "bench", "", firstNonce, "00000001", "c", "auth", "p"), status: 200},
		{name: "and out of date the second time", target: "/digest/stale-later/x/a",
			authorization: answer("GET", "/digest/stale-later/x/a", "bench", "", firstNonce, "00000002", "c", "auth", "p"), status: 401,
			want: map[string][]string{"WWW-Authenticate": {`Digest realm="bench", nonce="f7a91c2e", qop="auth", stale=true`}}},
		{name: "and at a count past nine, said in hexadecimal", target: "/digest/stale-later/x/a",
			authorization: answer("GET", "/digest/stale-later/x/a", "bench", "", firstNonce, "0000000a", "c", "auth", "p"), status: 401},
		{name: "a nonce it did not ask with", target: "/digest/stale-later/x/a",
			authorization: answer("GET", "/digest/stale-later/x/a", "bench", "", "other", "00000001", "c", "auth", "p"), status: 401,
			want: map[string][]string{"WWW-Authenticate": {`Digest realm="bench", nonce="b3ec7d4c", qop="auth"`}}},
		{name: "the next nonce of an offer that has none", target: "/digest/auth/x/a",
			authorization: answer("GET", "/digest/auth/x/a", "bench", "", freshNonce, "00000001", "c", "auth", "p"), status: 401},
		{name: "every answer out of date", target: "/digest/stale-forever/x/a",
			authorization: answer("GET", "/digest/stale-forever/x/a", "bench", "", freshNonce, "00000001", "c", "auth", "p"), status: 401,
			want: map[string][]string{"WWW-Authenticate": {`Digest realm="bench", nonce="f7a91c2e", qop="auth", stale=true`}}},
		{name: "a nonce of its own", target: "/digest/unquoted/x/a",
			authorization: `Digest username="u", realm="bench", nonce="YjNlYzdkNGM=", uri="/digest/unquoted/x/a", response="` +
				hexDigest(digestHash(""), hexDigest(digestHash(""), "u:bench:p")+":YjNlYzdkNGM=:00000001:c:auth:"+hexDigest(digestHash(""), "GET:/digest/unquoted/x/a")) +
				`", opaque="lost", qop=auth, nc=00000001, cnonce="c"`, status: 200},
		{name: "an answer that cannot be read", target: page, authorization: `Digest username="u`, status: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := servedAt(s, http.MethodGet, &url.URL{Host: "www.example.com", Path: pathOf(tc.target), RawQuery: rawQuery(tc.target)},
				authorizationOf(tc.authorization)...)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			for name, want := range tc.want {
				if got := w.Header().Values(name); !slices.Equal(got, want) {
					t.Errorf("%s: %q, want %q", name, got, want)
				}
			}
			if !strings.Contains(w.Body.String(), tc.body) {
				t.Errorf("body %q, want %q in it", w.Body.String(), tc.body)
			}
		})
	}
}

func rawQuery(target string) string {
	_, query, _ := strings.Cut(target, "?")
	return query
}

func authorizationOf(value string) []string {
	if value == "" {
		return nil
	}
	return []string{"Authorization", value}
}

func TestADigestAnswerIsTakenOnlyAsItsChallengeSays(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/digest/x/y?z=1", nil)
	uri := req.RequestURI
	sha := digestChallenge{realm: "bench", algorithm: "SHA-256-sess", auth: true, opaque: "o", userhash: true}
	h := digestHash("SHA-256")
	ha1 := hexDigest(h, hexDigest(h, "u:bench:p")+":n:c")
	right := map[string]string{"username": hexDigest(h, "u:bench"), "realm": "bench", "nonce": "n", "uri": uri,
		"algorithm": "sha-256-SESS", "opaque": "o", "qop": "auth", "nc": "00000001", "cnonce": "c", "userhash": "true",
		"response": hexDigest(h, ha1+":n:00000001:c:auth:"+hexDigest(h, "POST:"+uri))}
	if !sha.answered(right, req) {
		t.Fatalf("the right answer is not taken: %v", right)
	}
	for name := range right {
		values := []string{"", "other"}
		if upper := strings.ToUpper(right[name]); name != "algorithm" && upper != right[name] {
			// Only the algorithm is said in any case.
			values = append(values, upper)
		}
		for _, value := range values {
			wrong := map[string]string{}
			for k, v := range right {
				wrong[k] = v
			}
			wrong[name] = value
			if sha.answered(wrong, req) {
				t.Errorf("taken with %s=%q", name, value)
			}
		}
		missing := map[string]string{}
		for k, v := range right {
			if k != name {
				missing[k] = v
			}
		}
		if sha.answered(missing, req) {
			t.Errorf("taken without %s", name)
		}
	}
	extra := map[string]string{"stale": "true"}
	for k, v := range right {
		extra[k] = v
	}
	if sha.answered(extra, req) {
		t.Error("taken with more than it says")
	}
	// No qop: neither nc nor cnonce, and the response of RFC 2069.
	plain := digestChallenge{realm: "r"}
	md5 := digestHash("")
	said := map[string]string{"username": "u", "realm": "r", "nonce": "n", "uri": uri,
		"response": hexDigest(md5, hexDigest(md5, "u:r:p")+":n:"+hexDigest(md5, "POST:"+uri))}
	if !plain.answered(said, req) {
		t.Errorf("RFC 2069's answer is not taken: %v", said)
	}
	said["nc"] = "00000001"
	if plain.answered(said, req) {
		t.Error("taken with a nonce count it was not asked for")
	}
}

func TestTheHashOfAnAlgorithmIsItsNamesInAnyCase(t *testing.T) {
	for algorithm, want := range map[string]string{
		"":             "900150983cd24fb0d6963f7d28e17f72",
		"MD5-sess":     "900150983cd24fb0d6963f7d28e17f72",
		"Sha-256":      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"SHA-256-sess": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"SHA-512-256":  "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
	} {
		if got := hexDigest(digestHash(algorithm), "abc"); got != want {
			t.Errorf("%q: %s, want %s", algorithm, got, want)
		}
	}
}

func TestADigestAnswerIsReadAsChromeWritesIt(t *testing.T) {
	for _, tc := range []struct {
		text string
		want map[string]string
	}{
		{`username="u", realm="a\"b\\c", qop=auth, nc=00000001`,
			map[string]string{"username": "u", "realm": `a"b\c`, "qop": "auth", "nc": "00000001"}},
		{`Nonce="", Algorithm=MD5`, map[string]string{"nonce": "", "algorithm": "MD5"}},
		{`opaque="a, b=c"`, map[string]string{"opaque": "a, b=c"}},
		{`a=1,b=2`, map[string]string{"a": "1,b=2"}},
		{`a="x\`, nil},
		{`a="x"`, map[string]string{"a": "x"}},
		{`a="x"y`, nil},
		{`a="x",b=1`, nil},
		{`a=1, a=2`, nil},
		{`=1`, nil},
		{`a`, nil},
		{``, nil},
		{`a=1, `, nil},
	} {
		got, ok := digestParams(tc.text)
		if ok != (tc.want != nil) || len(got) != len(tc.want) {
			t.Errorf("digestParams(%q) = %v, %v", tc.text, got, ok)
			continue
		}
		for name, value := range tc.want {
			if got[name] != value {
				t.Errorf("digestParams(%q)[%s] = %q, want %q", tc.text, name, got[name], value)
			}
		}
	}
}

func TestAPathIsResolvedAgainstTheOriginItWasAskedOf(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/digest/auth/x/a", nil)
	r.Host = "www.example.com:8443"
	for ref, want := range map[string]string{"/p/y?q=1": "https://www.example.com:8443/p/y?q=1", "": "",
		"https://elsewhere/": "https://elsewhere/"} {
		if got := onOrigin(r, ref); got != want {
			t.Errorf("onOrigin(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestEveryOfferAsksWithItsNonceWhereItSaysAndTakesItsOwnAnswer(t *testing.T) {
	for name, offer := range digestOffers {
		w := httptest.NewRecorder()
		offer.ask(w, "N", true)
		fields := w.Header().Values("WWW-Authenticate")
		if len(fields) != len(offer.fields) {
			t.Errorf("%s: %q", name, fields)
		}
		for i, field := range fields {
			if placed := strings.Contains(offer.fields[i], "{nonce}"); placed != strings.HasSuffix(field, ", stale=true") ||
				placed != strings.Contains(field, `"N"`) {
				t.Errorf("%s: %q", name, field)
			}
		}
		// Each Digest challenge it offers takes an answer worked out as it
		// says, with the nonce it asks with first.
		for _, c := range offer.digests {
			nonce := offer.nonce
			if nonce == "" {
				nonce = firstNonce
			}
			req := httptest.NewRequest(http.MethodGet, "/digest/"+name+"/x/a", nil)
			said := map[string]string{"username": "u", "realm": c.realm, "nonce": nonce, "uri": req.RequestURI}
			for k, v := range map[string]string{"algorithm": c.algorithm, "opaque": c.opaque} {
				if v != "" {
					said[k] = v
				}
			}
			h := digestHash(c.algorithm)
			ha1 := hexDigest(h, "u:"+c.realm+":p")
			if strings.HasSuffix(c.algorithm, "-sess") {
				ha1 = hexDigest(h, ha1+":"+nonce+":c")
			}
			middle := ""
			if c.auth {
				said["qop"], said["nc"], said["cnonce"] = "auth", "00000001", "c"
				middle = "00000001:c:auth:"
			}
			if c.userhash {
				said["username"], said["userhash"] = hexDigest(h, "u:"+c.realm), "true"
			}
			said["response"] = hexDigest(h, ha1+":"+nonce+":"+middle+hexDigest(h, "GET:"+req.RequestURI))
			if !c.answered(said, req) {
				t.Errorf("%s: its own answer %v is not taken", name, said)
			}
		}
	}
}
