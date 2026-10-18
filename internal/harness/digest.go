package harness

import (
	"cmp"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"net/http"
	"strconv"
	"strings"
)

// Digest authentication as the pages under /digest/NAME/ ask for it: each
// offers what digestOffers says of NAME, and takes an answer worked out with
// u:p, checked as RFC 7616 has a server check one, so that an answer worked
// out otherwise than the bench expects is turned down and its scenario does
// not reach its end.

// The nonces the pages ask with: the first, unless an offer says another, and
// the one an offer whose first is out of date asks with next.
const firstNonce, freshNonce = "b3ec7d4c", "f7a91c2e"

// digestOffer is what a page under /digest/NAME/ asks with and takes.
type digestOffer struct {
	// fields are the WWW-Authenticate fields of its 401, in order, the nonce
	// where {nonce} is; digests are its Digest challenges an answer may be to,
	// as each means to be answered.
	fields  []string
	digests []digestChallenge
	// nonce is the nonce it asks with first, firstNonce unless its fields say
	// another themselves; basic says it takes u:p in Basic as well; stale is the nonce count from which
	// an answer with the first nonce is out of date, asked for again with
	// freshNonce and stale=true, and 0 for never; forever, an offer every
	// answer to which is out of date, whatever its nonce.
	nonce   string
	basic   bool
	stale   int
	forever bool
}

// digestChallenge is what an answer to a Digest challenge is worked out with
// and says: the realm, the algorithm, said back in any case (none, MD5
// unnamed), the opaque said back, whether it says qop=auth, the one qop
// answered, and whether the username is hashed.
type digestChallenge struct {
	realm, algorithm, opaque string
	auth, userhash           bool
}

// The challenges of the offers below.
var (
	digestAuth   = digestChallenge{realm: "bench", auth: true}
	digestMD5    = digestChallenge{realm: "bench", algorithm: "MD5", auth: true}
	digestSHA256 = digestChallenge{realm: "bench", algorithm: "SHA-256", auth: true}
)

const (
	askAuth   = `Digest realm="bench", nonce="{nonce}", qop="auth"`
	askMD5    = `Digest realm="bench", nonce="{nonce}", algorithm=MD5, qop="auth"`
	askSHA256 = `Digest realm="bench", nonce="{nonce}", algorithm=SHA-256, qop="auth"`
	askBasic  = `Basic realm="bench"`
)

// digestOffers are the offers by name.
var digestOffers = map[string]digestOffer{
	"auth":     {fields: []string{askAuth}, digests: []digestChallenge{digestAuth}},
	"md5":      {fields: []string{askMD5}, digests: []digestChallenge{digestMD5}},
	"md5-sess": {fields: []string{`Digest realm="bench", nonce="{nonce}", algorithm=MD5-sess, qop="auth"`}, digests: []digestChallenge{{realm: "bench", algorithm: "MD5-sess", auth: true}}},
	"sha256":   {fields: []string{askSHA256}, digests: []digestChallenge{digestSHA256}},
	"sha256-sess": {fields: []string{`Digest realm="bench", nonce="{nonce}", algorithm=SHA-256-sess, qop="auth"`},
		digests: []digestChallenge{{realm: "bench", algorithm: "SHA-256-sess", auth: true}}},
	"no-qop":   {fields: []string{`Digest realm="bench", nonce="{nonce}"`}, digests: []digestChallenge{{realm: "bench"}}},
	"auth-int": {fields: []string{`Digest realm="bench", nonce="{nonce}", qop="auth-int"`}, digests: []digestChallenge{{realm: "bench"}}},
	"qop-list": {fields: []string{`Digest realm="bench", nonce="{nonce}", qop="auth-int,auth"`}, digests: []digestChallenge{digestAuth}},
	"opaque": {fields: []string{`Digest realm="bench", nonce="{nonce}", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop="auth"`},
		digests: []digestChallenge{{realm: "bench", auth: true, opaque: "5ccc069c403ebaf9f0171e9517f40e41"}}},
	"userhash": {fields: []string{`Digest realm="bench", nonce="{nonce}", algorithm=SHA-256, qop="auth", userhash=true`},
		digests: []digestChallenge{{realm: "bench", algorithm: "SHA-256", auth: true, userhash: true}}},
	"no-realm": {fields: []string{`Digest nonce="{nonce}", qop="auth"`}, digests: []digestChallenge{{auth: true}}},
	"unknown-algorithm": {fields: []string{`Digest realm="bench", nonce="{nonce}", algorithm=SHA-512-256, qop="auth"`, askBasic},
		digests: []digestChallenge{{realm: "bench", algorithm: "SHA-512-256", auth: true}}, basic: true},
	"no-nonce":      {fields: []string{`Digest realm="bench", qop="auth"`, askBasic}, basic: true},
	"empty-value":   {fields: []string{`Digest realm="bench", nonce="{nonce}", qop="auth", opaque=`, askBasic}, digests: []digestChallenge{digestAuth}, basic: true},
	"after-basic":   {fields: []string{askBasic, askAuth}, digests: []digestChallenge{digestAuth}, basic: true},
	"md5-first":     {fields: []string{askMD5, askSHA256}, digests: []digestChallenge{digestMD5, digestSHA256}},
	"sha256-first":  {fields: []string{askSHA256, askMD5}, digests: []digestChallenge{digestSHA256, digestMD5}},
	"stale":         {fields: []string{askAuth}, digests: []digestChallenge{digestAuth}, stale: 1},
	"stale-later":   {fields: []string{askAuth}, digests: []digestChallenge{digestAuth}, stale: 2},
	"stale-forever": {fields: []string{askAuth}, digests: []digestChallenge{digestAuth}, forever: true},
	// Schemes Chrome prefers to Digest.
	"ntlm":      {fields: []string{"NTLM", askAuth, askBasic}, digests: []digestChallenge{digestAuth}, basic: true},
	"negotiate": {fields: []string{"Negotiate", askAuth, askBasic}, digests: []digestChallenge{digestAuth}, basic: true},
	// Names and values in other cases, values as tokens, escapes, parameters
	// said twice, and ones of no matter.
	"quoting": {fields: []string{`Digest REALM=bench, nonce="decoy", Nonce="b3ec\"7d4c", Algorithm=sha-256, QOP="AUTH-INT , Auth", opaque="o\\p", domain="/digest/", charset=UTF-8, stale=TRUE`},
		digests: []digestChallenge{{realm: "bench", algorithm: "SHA-256", auth: true, opaque: `o\p`}}, nonce: `b3ec"7d4c`},
	// A value that is a token with "=" in it, and a quote that does not end.
	"unquoted": {fields: []string{`Digest realm=bench, nonce=YjNlYzdkNGM=, qop=auth, opaque="lost`},
		digests: []digestChallenge{{realm: "bench", auth: true, opaque: "lost"}}, nonce: "YjNlYzdkNGM="},
}

// The ways a page takes the Authorization it is sent.
type verdict int

const (
	asked verdict = iota
	taken
	outOfDate
)

// DigestPage answers a page under /digest/NAME/ as the bench does, which a
// test of what a client sends answers with too: 401 asking as the offer NAME
// says until it is answered with u:p, then a redirect to ?to, or a page that
// goes on to ?next, each a path resolved against the page's origin and none of
// its credentials, so that what follows is sent what the browser keeps for the
// realm rather than what a URL carries.
func DigestPage(w http.ResponseWriter, r *http.Request) {
	name, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/digest/"), "/")
	offer, ok := digestOffers[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch offer.verdict(r) {
	case asked:
		offer.ask(w, firstNonce, false)
		return
	case outOfDate:
		offer.ask(w, freshNonce, true)
		return
	}
	q := r.URL.Query()
	if to := q.Get("to"); to != "" {
		w.Header().Set("Location", onOrigin(r, to))
		w.WriteHeader(http.StatusFound)
		return
	}
	page(w, onOrigin(r, q.Get("next")), "")
}

// onOrigin is ref, a path, as a URL of the origin r was asked of, which it
// was asked of over TLS; anything else as it is.
func onOrigin(r *http.Request, ref string) string {
	if !strings.HasPrefix(ref, "/") {
		return ref
	}
	return "https://" + r.Host + ref
}

// ask answers with a 401 asking as o does, with nonce, said to be the one an
// out-of-date answer is asked again with when stale.
func (o digestOffer) ask(w http.ResponseWriter, nonce string, stale bool) {
	for _, field := range o.fields {
		if strings.Contains(field, "{nonce}") {
			field = strings.ReplaceAll(field, "{nonce}", nonce)
			if stale {
				field += ", stale=true"
			}
		}
		w.Header().Add("WWW-Authenticate", field)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("<!doctype html><title>401</title><p>401</p>"))
}

// verdict is how a page offering o takes r's Authorization: u:p in Basic when
// it offers Basic, or a Digest answer to one of its challenges with a nonce it
// asked with, the first out of date from the count o.stale says.
func (o digestOffer) verdict(r *http.Request) verdict {
	auth := r.Header.Get("Authorization")
	if o.basic && auth == benchAuthorization {
		return taken
	}
	text, ok := strings.CutPrefix(auth, "Digest ")
	if !ok {
		return asked
	}
	// An answer that cannot be read has no parameters, which no answer is.
	said, _ := digestParams(text)
	for _, c := range o.digests {
		if !c.answered(said, r) {
			continue
		}
		if o.forever {
			return outOfDate
		}
		nc, _ := strconv.ParseUint(said["nc"], 16, 32)
		switch nonce := said["nonce"]; {
		case o.stale > 0 && nonce == freshNonce:
			return taken
		case nonce != cmp.Or(o.nonce, firstNonce):
			return asked
		case o.stale > 0 && nc >= uint64(o.stale):
			return outOfDate
		}
		return taken
	}
	return asked
}

// answered reports whether said, the parameters of a Digest answer to r, are
// what an answer to c with u:p says: nothing more and nothing less, and the
// response worked out from them as RFC 7616 has it.
func (c digestChallenge) answered(said map[string]string, r *http.Request) bool {
	h := digestHash(c.algorithm)
	user := benchUser
	if c.userhash {
		user = hexDigest(h, benchUser+":"+c.realm)
	}
	ha1 := hexDigest(h, benchUser+":"+c.realm+":"+benchPassword)
	if strings.HasSuffix(c.algorithm, "-sess") {
		ha1 = hexDigest(h, ha1+":"+said["nonce"]+":"+said["cnonce"])
	}
	ha2 := hexDigest(h, r.Method+":"+r.RequestURI)
	response := ha1 + ":" + said["nonce"] + ":"
	if c.auth {
		response += said["nc"] + ":" + said["cnonce"] + ":auth:"
	}
	want := map[string]string{"username": user, "realm": c.realm, "uri": r.RequestURI,
		"response": hexDigest(h, response+ha2), "nonce": said["nonce"]}
	for name, value := range map[string]string{"algorithm": c.algorithm, "opaque": c.opaque} {
		if value != "" {
			want[name] = value
		}
	}
	if c.auth {
		want["qop"], want["nc"], want["cnonce"] = "auth", said["nc"], said["cnonce"]
	}
	if c.userhash {
		want["userhash"] = "true"
	}
	if len(said) != len(want) {
		return false
	}
	for name, value := range want {
		got, ok := said[name]
		if !ok || got != value && (name != "algorithm" || !strings.EqualFold(got, value)) {
			return false
		}
	}
	return true
}

// digestHash is the hash of a Digest algorithm, by its name in any case: MD5
// for none.
func digestHash(algorithm string) func() hash.Hash {
	switch strings.TrimSuffix(strings.ToLower(algorithm), "-sess") {
	case "sha-256":
		return sha256.New
	case "sha-512-256":
		return sha512.New512_256
	}
	return md5.New
}

func hexDigest(h func() hash.Hash, text string) string {
	d := h()
	d.Write([]byte(text))
	return hex.EncodeToString(d.Sum(nil))
}

// digestParams are the parameters of a Digest answer as Chrome writes one:
// name=value with ", " between them, a value a token or a quoted string whose
// backslashes take the character after them; names in lower case. Anything
// else, or a name said twice, makes them unreadable.
func digestParams(text string) (map[string]string, bool) {
	params := map[string]string{}
	for {
		name, rest, ok := strings.Cut(text, "=")
		name = strings.ToLower(name)
		if _, twice := params[name]; !ok || twice || name == "" {
			return nil, false
		}
		var value strings.Builder
		if quoted, ok := strings.CutPrefix(rest, `"`); ok {
			i := 0
			for ; i < len(quoted) && quoted[i] != '"'; i++ {
				if quoted[i] == '\\' && i+1 < len(quoted) {
					i++
				}
				value.WriteByte(quoted[i])
			}
			if i == len(quoted) {
				return nil, false
			}
			rest = quoted[i+1:]
		} else {
			end := strings.Index(rest, ", ")
			if end < 0 {
				end = len(rest)
			}
			value.WriteString(rest[:end])
			rest = rest[end:]
		}
		params[name] = value.String()
		if rest == "" {
			return params, true
		}
		if text, ok = strings.CutPrefix(rest, ", "); !ok {
			return nil, false
		}
	}
}
