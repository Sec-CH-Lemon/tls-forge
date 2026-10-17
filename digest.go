package tlsforge

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// Digest authentication, RFC 7616, as Chromium's HttpAuthHandlerDigest reads
// a challenge and answers it, measured on Chrome 155 (the auth-digest-*
// scenarios of testdata/chrome155-requests.json): MD5 and SHA-256, each with
// its -sess, the qop auth and none, an opaque said back, a hashed username,
// and the nonce counted on from answer to answer.

// digest is what a Digest challenge says.
type digest struct {
	// realm is the realm's bytes as said, which an answer says and is worked
	// out with; nonce and opaque are as said.
	realm, nonce, opaque string
	// algorithm is the one the challenge names, as an answer names it, empty
	// for none, which is MD5; qop says the challenge offers auth, the one qop
	// Chrome answers; userhash that the username goes hashed.
	algorithm     string
	qop, userhash bool
}

// digestAlgorithms are the algorithms Chrome answers, by their names in lower
// case: as an answer names them.
var digestAlgorithms = map[string]string{"md5": "MD5", "md5-sess": "MD5-sess", "sha-256": "SHA-256",
	"sha-256-sess": "SHA-256-sess"}

// readDigest is a Digest challenge's parameters as Chromium reads them, and
// its realm in UTF-8: names in any case, the last of a name counting, those
// it does not know passed over. Parameters it cannot read, an algorithm it
// does not know or no nonce make no challenge.
func readDigest(params string) (*digest, string, bool) {
	pairs, readable := authParams(params)
	d, realm := &digest{}, ""
	for _, p := range pairs {
		switch strings.Map(lowerASCII, p.name) {
		case "realm":
			d.realm, realm = p.value, latin1(p.value)
		case "nonce":
			d.nonce = p.value
		case "opaque":
			d.opaque = p.value
		case "algorithm":
			name, known := digestAlgorithms[strings.Map(lowerASCII, p.value)]
			if !known {
				return nil, "", false
			}
			d.algorithm = name
		case "userhash":
			d.userhash = strings.Map(lowerASCII, p.value) == "true"
		case "qop":
			d.qop = offersAuth(p.value)
		}
	}
	return d, realm, readable && d.nonce != ""
}

// digestAgain is what a Digest challenge to an answer says of it, as
// Chromium's handler reads one: its realm in UTF-8, and whether it says the
// nonce answered was out of date, from its parameters up to any it cannot
// read.
func digestAgain(params string) (string, bool) {
	pairs, _ := authParams(params)
	realm := ""
	for _, p := range pairs {
		switch strings.Map(lowerASCII, p.name) {
		case "stale":
			if strings.Map(lowerASCII, p.value) == "true" {
				return realm, true
			}
		case "realm":
			realm = latin1(p.value)
		}
	}
	return realm, false
}

// offersAuth reports whether a list of qop values has auth, in any case: the
// values between its commas outside quotes, trimmed, as Chromium reads them.
func offersAuth(list string) bool {
	for list != "" {
		var value string
		value, list = nextParam(list)
		if strings.Map(lowerASCII, strings.Trim(value, " \t")) == "auth" {
			return true
		}
	}
	return false
}

// answer is the Authorization of an answer to d with cred, for a request of
// method for uri, d's count'th: its parameters in Chromium's order, each said
// as it says it. realm is d's in UTF-8, which a hashed username is worked out
// with; draw is a client nonce, drawn when the answer has one.
func (d *digest) answer(cred credentials, realm, method, uri string, count int, draw func() string) string {
	nc, cnonce := fmt.Sprintf("%08x", count), ""
	if d.qop || d.sess() {
		cnonce = draw()
	}
	username := cred.username
	if d.userhash {
		username = hexDigest(d.hash(), username+":"+realm)
	}
	out := "Digest username=" + quoted(username) + ", realm=" + quoted(d.realm) + ", nonce=" + quoted(d.nonce) +
		", uri=" + quoted(uri)
	if d.algorithm != "" {
		out += ", algorithm=" + d.algorithm
	}
	out += `, response="` + d.response(cred, method, uri, cnonce, nc) + `"`
	if d.opaque != "" {
		out += ", opaque=" + quoted(d.opaque)
	}
	if d.qop {
		out += ", qop=auth, nc=" + nc + ", cnonce=" + quoted(cnonce)
	}
	if d.userhash {
		out += ", userhash=true"
	}
	return out
}

// response is the response of an answer to d with cred, for a request of
// method for uri, with the client nonce cnonce and the nonce count nc, as RFC
// 7616 works it out: H(H(A1):nonce:nc:cnonce:auth:H(A2)), or for no qop, as
// RFC 2069 has it, H(H(A1):nonce:H(A2)). A1 is username:realm:password, the
// realm's bytes as said, and for -sess H(A1) is hashed again with the nonce
// and the client nonce; A2 is method:uri.
func (d *digest) response(cred credentials, method, uri, cnonce, nc string) string {
	h := d.hash()
	ha1 := hexDigest(h, cred.username+":"+d.realm+":"+cred.password)
	if d.sess() {
		ha1 = hexDigest(h, ha1+":"+d.nonce+":"+cnonce)
	}
	counted := ""
	if d.qop {
		counted = nc + ":" + cnonce + ":auth:"
	}
	return hexDigest(h, ha1+":"+d.nonce+":"+counted+hexDigest(h, method+":"+uri))
}

// sess reports an algorithm of a session: MD5-sess or SHA-256-sess.
func (d *digest) sess() bool { return strings.HasSuffix(d.algorithm, "-sess") }

// hash is d's algorithm's: SHA-256 for SHA-256 and SHA-256-sess, MD5 for the
// rest.
func (d *digest) hash() func() hash.Hash {
	if strings.HasPrefix(d.algorithm, "SHA-256") {
		return sha256.New
	}
	return md5.New
}

// hexDigest is the hash of text, in lower-case hexadecimal.
func hexDigest(h func() hash.Hash, text string) string {
	sum := h()
	sum.Write([]byte(text))
	return hex.EncodeToString(sum.Sum(nil))
}

// quoted is text in quotes, a backslash before each quote and backslash in
// it, as Chromium's HttpUtil::Quote says it.
func quoted(text string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}

// newCnonce is a client nonce as Chromium draws one: eight random bytes in
// lower-case hexadecimal, 16 digits.
func newCnonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
