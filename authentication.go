package tlsforge

import (
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"sync"
)

// HTTP authentication, as Chrome 155 was measured going about it (the auth-*
// scenarios of testdata/chrome155-requests.json), which is what Chromium's
// HttpAuthController and HttpAuthCache do for Basic: a URL's credentials are
// never sent before a 401 asks for them; a 401 with a Basic challenge is
// answered once with them, the request sent again with Authorization; and
// what was answered with is kept for its origin and realm, sent unasked to the
// directory it was answered in and to those under it, and given to a 401 of
// the realm anywhere else at that origin. A URL that carries credentials is
// sent nothing unasked. Digest, NTLM and Negotiate, which Chrome prefers to
// Basic, are not answered.

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

// preferredSchemes are the schemes Chrome answers rather than Basic when a 401
// offers one of them as well, which tls-forge does not answer at all.
var preferredSchemes = []string{"digest", "ntlm", "negotiate"}

// basicChallenge is the realm of the Basic challenge a 401 answers with, as
// Chromium reads WWW-Authenticate: each field one challenge, its scheme the
// first token, in any case; then parameters, of which the last realm counts,
// its bytes read as Latin-1, a field whose parameters cannot be read is no
// challenge. No Basic one, or one of a scheme Chrome prefers, is nothing to
// answer.
func basicChallenge(fields []string) (string, bool) {
	realm, found := "", false
	for _, field := range fields {
		field = strings.TrimLeft(field, " \t")
		scheme, rest := field, ""
		if i := strings.IndexAny(field, " \t"); i >= 0 {
			scheme, rest = field[:i], field[i+1:]
		}
		scheme = strings.Map(lowerASCII, scheme)
		if slices.Contains(preferredSchemes, scheme) {
			return "", false
		}
		if scheme != "basic" || found {
			continue
		}
		if params, ok := authParams(rest); ok {
			realm, found = latin1(params["realm"]), true
		}
	}
	return realm, found
}

// authParams are the parameters of a challenge, name=value separated by
// commas, a value a token or a quoted string; the last of a name counts, and
// names are in lower case. A part without "=" or a name, or a quoted string
// that does not end, makes them unreadable.
func authParams(text string) (map[string]string, bool) {
	params := map[string]string{}
	for text != "" {
		var part string
		part, text = nextParam(text)
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.Trim(name, " \t"), strings.Trim(value, " \t")
		if !ok || name == "" {
			return nil, false
		}
		if strings.HasPrefix(value, `"`) {
			if value, ok = unquoted(value); !ok {
				return nil, false
			}
		}
		params[strings.Map(lowerASCII, name)] = value
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

// unquoted is a quoted string's text, a backslash taking the character after
// it as it is; nothing when the quote does not end it.
func unquoted(value string) (string, bool) {
	var out strings.Builder
	for i := 1; i < len(value); i++ {
		switch c := value[i]; {
		case c == '\\' && i+1 < len(value):
			i++
			out.WriteByte(value[i])
		case c == '"':
			return out.String(), i == len(value)-1
		default:
			out.WriteByte(c)
		}
	}
	return "", false
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
// Chromium's HttpAuthCache keeps them for Basic: by origin and realm, the
// credentials and the directories they were answered in, the most recently
// used first. It forgets the least recently used past maxAuthEntries, and an
// entry's least recently added directory past maxAuthPaths, as Chromium does.
type authCache struct {
	mu      sync.Mutex
	entries []*authEntry
}

// The most a cache keeps, Chromium's kMaxNumRealmEntries and
// kMaxNumPathsPerRealmEntry.
const (
	maxAuthEntries = 20
	maxAuthPaths   = 10
)

type authEntry struct {
	at          origin
	realm       string
	credentials credentials
	// paths are directories, each ending in "/", none under another, the
	// latest first.
	paths []string
}

// forPath is the realm and credentials sent unasked to path at an origin: the
// entry whose directory is the closest above the directory of path.
func (c *authCache) forPath(at origin, path string) (string, credentials, bool) {
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
		return "", credentials{}, false
	}
	e := c.used(best)
	return e.realm, e.credentials, true
}

// forRealm are the credentials kept for a realm at an origin.
func (c *authCache) forRealm(at origin, realm string) (credentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i := c.find(at, realm); i >= 0 {
		return c.used(i).credentials, true
	}
	return credentials{}, false
}

// keep keeps credentials for a realm at an origin, answered at path: they
// replace any kept for it, and the directory of path joins its directories
// unless one of them is above it, in place of those under it.
func (c *authCache) keep(at origin, realm string, cred credentials, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var e *authEntry
	if i := c.find(at, realm); i >= 0 {
		e = c.used(i)
	} else {
		e = &authEntry{at: at, realm: realm}
		c.entries = slices.Insert(c.entries, 0, e)
		if len(c.entries) > maxAuthEntries {
			c.entries = c.entries[:maxAuthEntries]
		}
	}
	e.credentials = cred
	dir := parentDirectory(path)
	if slices.ContainsFunc(e.paths, func(p string) bool { return strings.HasPrefix(dir, p) }) {
		return
	}
	e.paths = slices.DeleteFunc(e.paths, func(p string) bool { return strings.HasPrefix(p, dir) })
	e.paths = slices.Insert(e.paths, 0, dir)
	if len(e.paths) > maxAuthPaths {
		e.paths = e.paths[:maxAuthPaths]
	}
}

// drop forgets a realm at an origin when what it keeps are the credentials
// the server turned down, and not newer ones.
func (c *authCache) drop(at origin, realm string, cred credentials) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i := c.find(at, realm); i >= 0 && c.entries[i].credentials == cred {
		c.entries = slices.Delete(c.entries, i, i+1)
	}
}

// find is where the entry of a realm at an origin is, or -1.
func (c *authCache) find(at origin, realm string) int {
	return slices.IndexFunc(c.entries, func(e *authEntry) bool { return e.at == at && e.realm == realm })
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
