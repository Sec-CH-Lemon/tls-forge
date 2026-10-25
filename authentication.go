package tlsforge

import (
	"encoding/base64"
	"github.com/igor-lemon/utls/behavior"
	"net/url"
	"slices"
	"strings"
	"sync"
)

// HTTP authentication, as Chrome 155 was measured going about it (the auth-*
// scenarios of testdata/chrome155-requests.json), which is what Chromium's
// HttpAuthController and HttpAuthCache do with its Basic and Digest handlers:
// a URL's credentials are never sent before a 401 asks for them; a 401 is
// answered in the scheme it offers that Chrome prefers among those it can
// read, the first of equals, with the URL's credentials once and then with
// those kept for the realm, the request sent again with Authorization; and
// what was answered with is kept for its origin, realm and scheme, sent
// unasked to the directory it was answered in and to those under it, Digest's
// nonce counted on, and given to a 401 of the realm and scheme anywhere else
// at that origin. A URL that carries credentials is sent nothing unasked.
// Chrome prefers NTLM to both, and on Windows Negotiate to all three: a 401 it
// would answer in either, which tls-forge does not answer, is left as it is.

// credentials are what a challenge is answered with.
type credentials struct{ username, password string }

// credentialsOf are the credentials a URL carries, when it carries a username:
// as Chromium has it, a password alone is none.
func credentialsOf(user *url.Userinfo) (credentials, bool) {
	if user == nil || user.Username() == "" {
		return credentials{}, false
	}
	return credentials{user.Username(), password(user)}, true
}

// basic is the Authorization of a Basic answer with c.
func (c credentials) basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password))
}

// challenge is a challenge of a 401 Chrome can answer, as its handler of the
// scheme reads it.
type challenge struct {
	// scheme is its scheme in lower case; field is the field it was said in,
	// which an answer sent unasked is worked out from again; realm is its
	// realm in UTF-8, which what was answered with is kept by.
	scheme, field, realm string
	// digest is what a Digest challenge says, and nil for one of another
	// scheme.
	digest *digest
}

// readChallenge is a field of WWW-Authenticate as Chromium reads one: its
// scheme the first token, in any case, and the rest as the handler of the
// scheme reads it: Basic's and Digest's parameters; for NTLM, and for
// Negotiate on Windows alone, nothing, as the first challenge of either.
// Another scheme, or a challenge its handler cannot read, is none Chrome
// answers.
func readChallenge(field string, windows bool) (challenge, bool) {
	scheme, params := schemeOf(field)
	c := challenge{scheme: scheme, field: field}
	ok := false
	switch scheme {
	case "basic":
		c.realm, ok = basicRealm(params)
	case "digest":
		c.digest, c.realm, ok = readDigest(params)
	case "ntlm":
		ok = firstRound(params)
	case "negotiate":
		ok = windows && firstRound(params)
	}
	return c, ok
}

// schemeOf is a challenge's scheme, its first token in lower case, and what
// follows it, trimmed, as Chromium's tokenizer has them.
func schemeOf(field string) (string, string) {
	field = strings.TrimLeft(field, " \t")
	scheme, rest := field, ""
	if i := strings.IndexAny(field, " \t"); i >= 0 {
		scheme, rest = field[:i], field[i:]
	}
	return strings.Map(lowerASCII, scheme), strings.Trim(rest, " \t")
}

// firstRound reports whether params, what follows NTLM or Negotiate, are
// those of the first challenge of either: nothing, once the padding of a
// token is taken off, as Chromium reads them.
func firstRound(params string) bool {
	for len(params)%4 != 0 && strings.HasSuffix(params, "=") {
		params = params[:len(params)-1]
	}
	return params == ""
}

// challengeOf is a field of WWW-Authenticate as this client reads it:
// Negotiate for a client of a Windows profile alone, as elsewhere Chrome takes
// it only for the sites a policy names, and none is named.
func (c *Client) challengeOf(field string) (challenge, bool) {
	answer, ok := readChallenge(field, c.behavior().Flag("http.negotiate_auth"))
	if ok && answer.digest != nil {
		algorithm := answer.digest.algorithm
		if algorithm == "" {
			algorithm = "MD5"
		}
		ok = slices.Contains(c.behavior().Strings("http.digest_algorithms"), algorithm)
	}
	return answer, ok
}

// bestChallenge is the challenge of a 401's fields Chrome answers: the one of
// the scheme it prefers most among those it can read, the first of equals.
// Before one is read, the best is of no scheme, which scores nothing.
func (c *Client) bestChallenge(fields []string) (challenge, bool) {
	var best challenge
	for _, field := range fields {
		if read, ok := c.challengeOf(field); ok && c.schemeScore(read.scheme) > c.schemeScore(best.scheme) {
			best = read
		}
	}
	return best, best.scheme != ""
}

// answer is the Authorization of an answer to c with cred, for a request of
// method for uri, its count'th from c's challenge; draw is a client nonce.
func (c challenge) answer(cred credentials, method, uri string, count int, draw func() string) string {
	if c.digest == nil {
		return cred.basic()
	}
	return c.digest.answer(cred, c.realm, method, uri, count, draw)
}

// What a 401 says of an answer sent: turned down, a Digest nonce out of date,
// or a challenge of another realm.
type verdict int

const (
	turnedDown verdict = iota
	outOfDate
	otherRealm
)

// says are the verdicts as the log says them.
var says = map[verdict]string{turnedDown: "turned down", outOfDate: "out of date", otherRealm: "another realm"}

// respond is what fields, the challenges of a 401 to an answer to c, say of
// it, as Chromium's handler of c's scheme reads them, and the field that said
// it: the first of c's scheme the handler can read decides, Digest's by its
// parameters up to any it cannot read. One that says stale=true says the
// Digest nonce answered was out of date; one of another realm is another
// realm's; any other, or none, turns the answer down.
func (c challenge) respond(fields []string) (verdict, string) {
	for _, field := range fields {
		scheme, params := schemeOf(field)
		if scheme != c.scheme {
			continue
		}
		var realm string
		if c.digest == nil {
			var readable bool
			if realm, readable = basicRealm(params); !readable {
				continue
			}
		} else {
			var stale bool
			if realm, stale = digestAgain(params); stale {
				return outOfDate, field
			}
		}
		if realm != c.realm {
			return otherRealm, field
		}
		return turnedDown, field
	}
	return turnedDown, ""
}

// basicRealm is the realm of a Basic challenge's parameters as Chromium's
// handler reads it: the last realm, its bytes read as Latin-1, empty for none;
// and whether every parameter could be read.
func basicRealm(params string) (string, bool) {
	pairs, readable := authParams(params)
	realm := ""
	for _, p := range pairs {
		if strings.Map(lowerASCII, p.name) == "realm" {
			realm = latin1(p.value)
		}
	}
	return realm, readable
}

// authParam is a parameter of a challenge: its name as said, and its value.
type authParam struct{ name, value string }

// authParams are the parameters of a challenge as Chromium's
// NameValuePairsIterator reads them, and whether it read them all: parts
// between commas outside quotes, each trimmed of spaces and tabs, the empty
// passed over, each name=value. A part without "=" or a name, with a quote in
// its name or with no value ends them, unread. A value that begins with a
// quote is unquoted.
func authParams(text string) ([]authParam, bool) {
	var params []authParam
	for text != "" {
		var part string
		part, text = nextParam(text)
		if part = strings.Trim(part, " \t"); part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.Trim(name, " \t"), strings.Trim(value, " \t")
		if !ok || name == "" || strings.Contains(name, `"`) || value == "" {
			return params, false
		}
		if strings.HasPrefix(value, `"`) {
			value = unquoted(value)
		}
		params = append(params, authParam{name, value})
	}
	return params, true
}

// nextParam is text up to its first comma outside quotes, and what follows
// that comma.
func nextParam(text string) (string, string) {
	quoted := false
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c == '\\' && quoted:
			i++
		case c == '"':
			quoted = !quoted
		case c == ',' && !quoted:
			return text[:i], text[i+1:]
		}
	}
	return text, ""
}

// unquoted is a value that begins with a quote as Chromium reads one: what
// lies between it and a quote that ends the value, a backslash taking the
// character after it and one at the end dropped; or, when no quote ends it,
// what follows the first quote, as it is.
func unquoted(value string) string {
	if len(value) == 1 || !strings.HasSuffix(value, `"`) {
		return value[1:]
	}
	var out strings.Builder
	escaped := false
	for _, c := range []byte(value[1 : len(value)-1]) {
		if c == '\\' && !escaped {
			escaped = true
			continue
		}
		escaped = false
		out.WriteByte(c)
	}
	return out.String()
}

// latin1 is text whose bytes are Latin-1, in UTF-8.
func latin1(text string) string {
	runes := make([]rune, len(text))
	for i := range len(text) {
		runes[i] = rune(text[i])
	}
	return string(runes)
}

// authCache is what a session keeps of the challenges it answered, as
// Chromium's HttpAuthCache keeps them: by origin, realm and scheme, the
// challenge answered last and how often it was answered, the credentials and
// the directories they were answered in, the most recently used first. It
// forgets the least recently used past maxAuthEntries, and an entry's least
// recently added directory past maxAuthPaths, as Chromium does.
type authCache struct {
	behavior behavior.Policy
	mu       sync.Mutex
	entries  []*authEntry
	// draw is a client nonce for a Digest answer.
	draw func() string
}

// The most a cache keeps, Chromium's kMaxNumRealmEntries and
// kMaxNumPathsPerRealmEntry.
var (
	maxAuthEntries = legacyPolicy().Int("http.auth_cache_entries")
	maxAuthPaths   = legacyPolicy().Int("http.auth_cache_paths")
)

type authEntry struct {
	at            origin
	realm, scheme string
	// field is the challenge answered last, which an answer sent unasked is
	// worked out from, and count the answers it has had, Digest's nonce
	// count.
	field       string
	count       int
	credentials credentials
	// paths are directories, each ending in "/", none under another, the
	// latest first.
	paths []string
}

// kept is what a cache gives a request sent unasked: the challenge to answer,
// how many answers it has had with this one, and the credentials.
type kept struct {
	field       string
	count       int
	credentials credentials
}

// forPath is what is sent unasked to path at an origin: the entry whose
// directory is the closest above the directory of path, of any realm or
// scheme, its count gone up by the answer it is for.
func (c *authCache) forPath(at origin, path string) (kept, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dir := parentDirectory(path)
	best, longest := -1, 0
	for i, e := range c.entries {
		if e.at != at {
			continue
		}
		for _, p := range e.paths {
			if strings.HasPrefix(dir, p) && len(p) > longest {
				best, longest = i, len(p)
			}
		}
	}
	if best < 0 {
		return kept{}, false
	}
	e := c.used(best)
	e.count++
	return kept{field: e.field, count: e.count, credentials: e.credentials}, true
}

// forRealm are the credentials kept for a realm and scheme at an origin.
func (c *authCache) forRealm(at origin, realm, scheme string) (credentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i := c.find(at, realm, scheme); i >= 0 {
		return c.used(i).credentials, true
	}
	return credentials{}, false
}

// keep keeps credentials for a challenge answered at an origin, at path: they
// replace any kept for its realm and scheme, the challenge is the one answered
// once, and the directory of path joins its directories unless one of them is
// above it, in place of those under it.
func (c *authCache) keep(at origin, answered challenge, cred credentials, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var e *authEntry
	if i := c.find(at, answered.realm, answered.scheme); i >= 0 {
		e = c.used(i)
	} else {
		e = &authEntry{at: at, realm: answered.realm, scheme: answered.scheme}
		c.entries = slices.Insert(c.entries, 0, e)
		if len(c.entries) > c.runtimeBehavior().Int("http.auth_cache_entries") {
			c.entries = c.entries[:c.runtimeBehavior().Int("http.auth_cache_entries")]
		}
	}
	e.field, e.count, e.credentials = answered.field, 1, cred
	dir := parentDirectory(path)
	if slices.ContainsFunc(e.paths, func(p string) bool { return strings.HasPrefix(dir, p) }) {
		return
	}
	e.paths = slices.DeleteFunc(e.paths, func(p string) bool { return strings.HasPrefix(p, dir) })
	e.paths = slices.Insert(e.paths, 0, dir)
	if len(e.paths) > c.runtimeBehavior().Int("http.auth_cache_paths") {
		e.paths = e.paths[:c.runtimeBehavior().Int("http.auth_cache_paths")]
	}
}

// renew keeps field, a challenge that says the nonce answered is out of date,
// for a realm and scheme at an origin, its count begun again at 1 as
// Chromium begins it; and reports whether anything is kept for them.
func (c *authCache) renew(at origin, realm, scheme, field string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.find(at, realm, scheme)
	if i < 0 {
		return false
	}
	e := c.used(i)
	e.field, e.count = field, 1
	return true
}

// drop forgets a realm and scheme at an origin when what it keeps are the
// credentials the server turned down, and not newer ones.
func (c *authCache) drop(at origin, realm, scheme string, cred credentials) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i := c.find(at, realm, scheme); i >= 0 && c.entries[i].credentials == cred {
		c.entries = slices.Delete(c.entries, i, i+1)
	}
}

// find is where the entry of a realm and scheme at an origin is, or -1.
func (c *authCache) find(at origin, realm, scheme string) int {
	return slices.IndexFunc(c.entries, func(e *authEntry) bool {
		return e.at == at && e.realm == realm && e.scheme == scheme
	})
}

// used moves the entry at i to the front, the most recently used, and is it.
func (c *authCache) used(i int) *authEntry {
	e := c.entries[i]
	c.entries = slices.Insert(slices.Delete(c.entries, i, i+1), 0, e)
	return e
}

// parentDirectory is the directory a path is in, up to its last "/" and with
// it, as RFC 2617 has a protection space reach; "/" for an empty path, which
// is the root's.
func parentDirectory(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i+1]
	}
	return "/"
}

// requestPath is the path of a URL as it goes out: escaped, "/" when it has
// none.
func requestPath(u *url.URL) string {
	if path := u.EscapedPath(); path != "" {
		return path
	}
	return "/"
}

func (c *authCache) runtimeBehavior() behavior.Policy {
	if c.behavior != nil {
		return c.behavior
	}
	return legacyPolicy()
}
func (c *Client) schemeScore(s string) int {
	return slices.Index(c.behavior().Strings("http.auth_scheme_order"), s) + 1
}
