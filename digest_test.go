package tlsforge

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestADigestChallengeIsReadAsChromiumReadsIt(t *testing.T) {
	for _, tc := range []struct {
		name, params string
		want         digest
		realm        string
		ok           bool
	}{
		{"what the bench asks with", `realm="bench", nonce="b3ec7d4c", qop="auth"`,
			digest{realm: "bench", nonce: "b3ec7d4c", qop: true}, "bench", true},
		{"names and values in any case, tokens, escapes, the last of a name", `REALM=bench, nonce="decoy", Nonce="b3ec\"7d4c", ` +
			`Algorithm=sha-256, QOP="AUTH-INT , Auth", opaque="o\\p", domain="/x/", charset=UTF-8, stale=TRUE`,
			digest{realm: "bench", nonce: `b3ec"7d4c`, algorithm: "SHA-256", qop: true, opaque: `o\p`}, "bench", true},
		{"MD5 named", `nonce=n, algorithm="md5"`, digest{nonce: "n", algorithm: "MD5"}, "", true},
		{"MD5-sess", `nonce=n, algorithm=MD5-SESS`, digest{nonce: "n", algorithm: "MD5-sess"}, "", true},
		{"SHA-256-sess", `nonce=n, algorithm=Sha-256-Sess`, digest{nonce: "n", algorithm: "SHA-256-sess"}, "", true},
		{"the last algorithm", `nonce=n, algorithm=MD5, algorithm=SHA-256`, digest{nonce: "n", algorithm: "SHA-256"}, "", true},
		{"a hashed username", `nonce=n, userhash=TRUE`, digest{nonce: "n", userhash: true}, "", true},
		{"a username not hashed", `nonce=n, userhash=yes`, digest{nonce: "n"}, "", true},
		{"auth-int alone, which Chrome does not answer", `nonce=n, qop="auth-int"`, digest{nonce: "n"}, "", true},
		{"auth among others", `nonce=n, qop="auth-int,auth,x"`, digest{nonce: "n", qop: true}, "", true},
		{"a token with = in it, and a quote that does not end", `realm=bench, nonce=YjNlYzdkNGM=, qop=auth, opaque="lost`,
			digest{realm: "bench", nonce: "YjNlYzdkNGM=", qop: true, opaque: "lost"}, "bench", true},
		{"a realm in Latin-1", "realm=\"\xe9t\xe9\", nonce=n", digest{realm: "\xe9t\xe9", nonce: "n"}, "été", true},
		{"an algorithm Chrome does not know", `nonce=n, algorithm=SHA-512-256`, digest{}, "", false},
		{"one it does not know, then one it does", `nonce=n, algorithm=x, algorithm=MD5`, digest{}, "", false},
		{"one it knows, then one it does not", `nonce=n, algorithm=MD5, algorithm=x`, digest{}, "", false},
		{"no nonce", `realm="r", qop="auth"`, digest{}, "", false},
		{"an empty nonce", `realm="r", nonce=""`, digest{}, "", false},
		{"a parameter of no value", `realm="r", nonce="n", opaque=`, digest{}, "", false},
		{"a part that is no parameter", `realm="r", nonce="n", x`, digest{}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, realm, ok := readDigest(tc.params)
			if ok != tc.ok || ok && (*got != tc.want || realm != tc.realm) {
				t.Errorf("readDigest(%q) = %+v, %q, %v", tc.params, got, realm, ok)
			}
		})
	}
	// A Digest challenge is read for its scheme, realm in UTF-8.
	if c, ok := readChallenge("Digest realm=\"\xe9\", nonce=n", false); !ok || c.realm != "é" || c.digest.realm != "\xe9" {
		t.Errorf("readChallenge = %+v, %v", c, ok)
	}
}

func TestADigestAnswerIsWorkedOutAsRFC7616Has(t *testing.T) {
	// RFC 7616, 3.9.1, and RFC 2617, 3.5, said in Chromium's order.
	cnonce := func(c string) func() string { return func() string { return c } }
	const nonce = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"
	const client = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
	const opaque = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
	mufasa := credentials{"Mufasa", "Circle of Life"}
	for _, tc := range []struct {
		name  string
		d     digest
		cred  credentials
		draw  string
		want  string
		count int
	}{
		{"MD5", digest{realm: "http-auth@example.org", nonce: nonce, opaque: opaque, algorithm: "MD5", qop: true}, mufasa, client,
			`Digest username="Mufasa", realm="http-auth@example.org", nonce="` + nonce + `", uri="/dir/index.html", algorithm=MD5, ` +
				`response="8ca523f5e9506fed4657c9700eebdbec", opaque="` + opaque + `", qop=auth, nc=00000001, cnonce="` + client + `"`, 1},
		{"SHA-256", digest{realm: "http-auth@example.org", nonce: nonce, opaque: opaque, algorithm: "SHA-256", qop: true}, mufasa, client,
			`Digest username="Mufasa", realm="http-auth@example.org", nonce="` + nonce + `", uri="/dir/index.html", algorithm=SHA-256, ` +
				`response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", opaque="` + opaque +
				`", qop=auth, nc=00000001, cnonce="` + client + `"`, 1},
		{"RFC 2617, no algorithm named", digest{realm: "testrealm@host.com", nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			opaque: "5ccc069c403ebaf9f0171e9517f40e41", qop: true}, credentials{"Mufasa", "Circle Of Life"}, "0a4f113b",
			`Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", ` +
				`response="6629fae49393a05397450978507c4ef1", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=00000001, cnonce="0a4f113b"`, 1},
		// What needs a backslash is given one, and the count is said in
		// hexadecimal.
		{"quotes and backslashes, a count past nine", digest{realm: `a"b`, nonce: `c\d`, opaque: `"`, qop: true}, credentials{`u"`, "p"}, "c",
			`Digest username="u\"", realm="a\"b", nonce="c\\d", uri="/dir/index.html", response="` +
				hexDigest(md5Hash, hexDigest(md5Hash, `u":a"b:p`)+`:c\d:0000001a:c:auth:`+hexDigest(md5Hash, "GET:/dir/index.html")) +
				`", opaque="\"", qop=auth, nc=0000001a, cnonce="c"`, 26},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.d.answer(tc.cred, tc.d.realm, "GET", "/dir/index.html", tc.count, cnonce(tc.draw)); got != tc.want {
				t.Errorf("answer\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
	// With no qop, no client nonce is drawn unless the algorithm is of a
	// session, which works it in.
	never := func() string { t.Error("a client nonce was drawn"); return "" }
	plain := digest{realm: "r", nonce: "n"}
	if got := plain.answer(credentials{"u", "p"}, "r", "GET", "/", 1, never); got != `Digest username="u", realm="r", nonce="n", uri="/", `+
		`response="`+hexDigest(md5Hash, hexDigest(md5Hash, "u:r:p")+":n:"+hexDigest(md5Hash, "GET:/"))+`"` {
		t.Errorf("answer with no qop %s", got)
	}
	sess := digest{realm: "r", nonce: "n", algorithm: "MD5-sess"}
	ha1 := hexDigest(md5Hash, hexDigest(md5Hash, "u:r:p")+":n:c")
	if got := sess.answer(credentials{"u", "p"}, "r", "PUT", "/", 1, cnonce("c")); !strings.Contains(got,
		`, algorithm=MD5-sess, response="`+hexDigest(md5Hash, ha1+":n:"+hexDigest(md5Hash, "PUT:/"))+`"`) || strings.Contains(got, "cnonce") {
		t.Errorf("answer of a session with no qop %s", got)
	}
	// A hashed username is the hash of username:realm, the realm in UTF-8,
	// and said so last.
	hashed := digest{realm: "\xe9", nonce: "n", algorithm: "SHA-256", userhash: true}
	if got := hashed.answer(credentials{"u", "p"}, "é", "GET", "/", 1, never); !strings.HasPrefix(got,
		`Digest username="`+hexDigest(sha256Hash, "u:é")+`", realm="`+"\xe9"+`"`) || !strings.HasSuffix(got, `", userhash=true`) {
		t.Errorf("answer with a hashed username %s", got)
	}
}

// The hashes of the algorithms.
var (
	md5Hash    = (&digest{}).hash()
	sha256Hash = (&digest{algorithm: "SHA-256-sess"}).hash()
)

// digestAnswer is a parameter of a Digest answer of Chrome's.
var digestAnswer = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|[^,]*)`)

func TestEveryDigestAnswerChromeSentIsWorkedOutAgain(t *testing.T) {
	// Each answer of the fixture, worked out again from what it says and the
	// client nonce Chrome drew for it, with u:p, is what Chrome sent.
	seen := map[string]bool{}
	for id, measured := range loadChromeRequests(t).Scenarios {
		for _, r := range slices.Concat(measured.H2, measured.H1) {
			said := r.header("authorization")
			text, ok := strings.CutPrefix(said, "Digest ")
			if !ok {
				continue
			}
			params := map[string]string{}
			for _, m := range digestAnswer.FindAllStringSubmatch(text, -1) {
				value := m[2]
				if strings.HasPrefix(value, `"`) {
					value = unquoted(value)
				}
				params[m[1]] = value
			}
			d := digest{realm: params["realm"], nonce: params["nonce"], opaque: params["opaque"], algorithm: params["algorithm"],
				qop: params["qop"] == "auth", userhash: params["userhash"] == "true"}
			count := 0
			for _, c := range params["nc"] {
				count = count*16 + strings.IndexRune("0123456789abcdef", c)
			}
			if !d.qop {
				count = 1
			}
			uri := params["uri"]
			if got := d.answer(credentials{"u", "p"}, latin1(d.realm), r.Method, uri, count,
				func() string { return params["cnonce"] }); got != said {
				t.Errorf("%s: %s %s\n  Chrome %s\n  again  %s", id, r.Method, r.URL, said, got)
			}
			seen["algorithm "+d.algorithm] = true
			seen["qop "+params["qop"]] = true
			seen["userhash "+params["userhash"]] = true
			seen["opaque"] = seen["opaque"] || d.opaque != ""
		}
	}
	// Every algorithm, with qop and without, a hashed username, an opaque.
	for _, want := range []string{"algorithm ", "algorithm MD5", "algorithm MD5-sess", "algorithm SHA-256",
		"algorithm SHA-256-sess", "qop auth", "qop ", "userhash true", "opaque"} {
		if !seen[want] {
			t.Errorf("no answer of %s", want)
		}
	}
}

func TestAClientNonceIsDrawnAsChromeDrawsIt(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		cnonce := newCnonce()
		if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(cnonce) {
			t.Fatalf("client nonce %q", cnonce)
		}
		seen[cnonce] = true
	}
	if len(seen) != 64 {
		t.Errorf("%d client nonces of 64 were new", len(seen))
	}
	// Every digit is drawn, as eight random bytes in hexadecimal.
	digits := map[rune]bool{}
	for cnonce := range maps.Keys(seen) {
		for _, d := range cnonce {
			digits[d] = true
		}
	}
	if len(digits) != 16 {
		t.Errorf("digits drawn %v", digits)
	}
}

func TestAValueIsQuotedAsChromiumQuotesIt(t *testing.T) {
	for in, want := range map[string]string{"": `""`, "a b": `"a b"`, `a"b\c`: `"a\"b\\c"`, `\\"`: `"\\\\\""`} {
		if got := quoted(in); got != want {
			t.Errorf("quoted(%q) = %s, want %s", in, got, want)
		}
	}
}
