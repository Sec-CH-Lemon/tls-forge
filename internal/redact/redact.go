// Package redact takes secrets out of what is written down to be kept: a log,
// a trace, a report, a line of JSON. All of them are made to be passed on, to
// whoever is asked why a request failed, and a proxy password or a session
// cookie is not the kind of thing to hand over with them.
//
// What stays is what a person needs to see what happened: a proxy's username,
// which tells two proxies apart; the names of cookies, since which cookie went
// out is the question; the scheme of an Authorization header, since Basic and
// Bearer fail for different reasons.
package redact

import (
	"net/url"
	"strings"
	"unicode"
)

// Masked stands in for a value that is not written down.
const Masked = "***"

// URL is a URL without the password in it, its username kept.
func URL(raw string) string {
	// The URL Standard's reading takes out what a browser reads as the
	// password; what is left is still read as Go reads it, so that what does
	// not parse goes whole, a password with a "/" in it among it.
	raw, special := standardURL(queries(raw))
	if raw == "" || !strings.Contains(raw, "@") {
		return raw
	}
	parsed := raw
	schemeLess := !special && !strings.Contains(raw, "://")
	if schemeLess {
		// url.Parse reads "alice:secret@host" as an opaque URL whose scheme is
		// alice, so User is nil and the password used to pass through unchanged.
		parsed = "proxy://" + raw
	}
	u, err := url.Parse(parsed)
	if err != nil {
		// Unparseable but carrying an "@" — drop everything before the last one
		// rather than guess at its shape and print a password by accident.
		return "[redacted]@" + raw[strings.LastIndex(raw, "@")+1:]
	}
	if u.User == nil {
		// Parsed, and the "@" belongs to the path or the query rather than to
		// any credentials. Rewriting it would corrupt a URL that holds nothing
		// worth hiding.
		return raw
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return raw
	}
	u.User = url.User(u.User.Username())
	safe := u.String()
	if schemeLess {
		safe = strings.TrimPrefix(safe, "proxy://")
	}
	return safe
}

// Error is what an error says, with the password of the proxy it went through
// taken out of it, and of any other URL it quotes.
//
// Needed on top of URL because a proxy's URL turns up inside error messages:
// url.Parse quotes back the whole string it could not parse, so a mistyped
// proxy writes its own password into the text that was just cleaned of it.
func Error(err error, proxy string) string {
	return Text(withoutProxy(err.Error(), proxy))
}

// Err is err as it may be shown: what it says with the password of each proxy
// taken out, as Error does, and err itself underneath, for errors.Is and
// errors.As. err itself when it says nothing that needs it, and nil for nil.
//
// For an error that leaves the program, to a terminal, a log or somebody
// else's process: the text is what goes, and what it was is still there for a
// program that asks.
func Err(err error, proxies ...string) error {
	if err == nil {
		return nil
	}
	said := err.Error()
	safe := said
	for _, proxy := range proxies {
		safe = withoutProxy(safe, proxy)
	}
	if safe = Text(safe); safe == said {
		return err
	}
	return &masked{said: safe, err: err}
}

// masked is an error that says less than the one it wraps.
type masked struct {
	said string
	err  error
}

func (m *masked) Error() string { return m.said }
func (m *masked) Unwrap() error { return m.err }

// withoutProxy is text with a proxy's password taken out of where it quotes it:
// as it was given, which knows the proxy without a scheme as well, and as a
// URL normalises it.
func withoutProxy(text, proxy string) string {
	safe := URL(proxy)
	if safe == proxy {
		return text
	}
	text = strings.ReplaceAll(text, proxy, safe)
	if u, err := url.Parse(proxy); err == nil && u.User != nil {
		if _, ok := u.User.Password(); ok {
			text = strings.ReplaceAll(text, u.User.String()+"@", url.User(u.User.Username()).String()+"@")
		}
	}
	return text
}

// Text is text with the password taken out of every URL in it, wherever it is
// and whether or not it would parse: what an error quotes back, a URL that
// could not be read included, which is the URL most likely to be quoted.
//
// A URL is a "://" and what follows it up to a "/" or a space, or a special
// scheme of the URL Standard (http, https, ws, wss, ftp), in any case, and its
// ":" followed by any slashes and backslashes, or none, as the Standard reads
// "https:/u:p@host" and "https:u:p@host". Its userinfo is everything before
// the last "@" in that, and the password what follows the first ":" of the
// userinfo. Quotes are not where a URL ends, since a password may hold one,
// escaped, nor is a backslash, which is how a quoted one escapes a tab.
func Text(text string) string {
	text = queries(text)
	if !strings.Contains(text, "@") {
		return text
	}
	text = specialAuthorities(text)
	if !strings.Contains(text, "://") {
		return text
	}
	var out strings.Builder
	for {
		start := strings.Index(text, "://")
		if start < 0 {
			out.WriteString(text)
			return out.String()
		}
		start += len("://")
		out.WriteString(text[:start])
		text = text[start:]
		end := strings.IndexFunc(text, func(r rune) bool { return r == '/' || unicode.IsSpace(r) })
		if end < 0 {
			end = len(text)
		}
		authority := text[:end]
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			if name, password, found := strings.Cut(authority[:at], ":"); found && password != "" {
				authority = name + authority[at:]
			}
		}
		out.WriteString(authority)
		text = text[end:]
	}
}

// specialSchemes are the schemes the URL Standard calls special and reads an
// authority after with any slashes or backslashes, or none (file aside, which
// has no credentials).
var specialSchemes = []string{"http", "https", "ws", "wss", "ftp"}

// specialAt is the length of the special scheme text[i:] begins with, and its
// colon, when it begins with one and nothing of a scheme comes before it; else
// 0.
func specialAt(text string, i int) int {
	if i > 0 && isSchemeByte(text[i-1]) {
		return 0
	}
	for _, scheme := range specialSchemes {
		if end := i + len(scheme); end < len(text) && text[end] == ':' && asciiFold(text[i:end]) == scheme {
			return len(scheme) + 1
		}
	}
	return 0
}

func isSchemeByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'
}

// asciiFold is s in lower case, ASCII letters alone: a scheme is ASCII, and
// Unicode case folding would take a long s for an s.
func asciiFold(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// specialAuthorities is text with the password taken out of the authority of
// every URL of a special scheme in it, read as the URL Standard reads one
// after its slashes, or none. In free text an authority ends at a "/", "?",
// "#" or space.
func specialAuthorities(text string) string {
	var out strings.Builder
	last := 0
	for i := 0; i < len(text); i++ {
		n := specialAt(text, i)
		if n == 0 {
			continue
		}
		start := i + n
		for start < len(text) && (text[start] == '/' || text[start] == '\\') {
			start++
		}
		end := start + strings.IndexFunc(text[start:], func(r rune) bool { return r == '/' || r == '?' || r == '#' || unicode.IsSpace(r) })
		if end < start {
			end = len(text)
		}
		if from, to, ok := passwordIn(text[start:end]); ok {
			out.WriteString(text[last : start+from])
			last = start + to
		}
		i = end - 1
	}
	if last == 0 {
		return text
	}
	out.WriteString(text[last:])
	return out.String()
}

// passwordIn is where the ":password" of an authority's userinfo lies, the
// colon included, when it has one that is not empty.
func passwordIn(authority string) (from, to int, ok bool) {
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return 0, 0, false
	}
	colon := strings.IndexByte(authority[:at], ':')
	if colon < 0 || colon+1 == at {
		return 0, 0, false
	}
	return colon, at, true
}

// standardURL is raw, a URL, without the password the URL Standard reads in
// it, and whether its scheme is special: any slashes and backslashes, or none,
// before its authority, which ends at "/", "\\", "?" or "#". The password goes
// with its colon, an empty one too, and what is left is spelt as it was given.
// A tab or a newline in it, or a space before it, the Standard passes over;
// Go reads no such URL, so URL takes all before its last "@" anyway.
func standardURL(raw string) (string, bool) {
	n := specialAt(raw, 0)
	if n == 0 {
		return raw, false
	}
	start := n
	for start < len(raw) && (raw[start] == '/' || raw[start] == '\\') {
		start++
	}
	end := start + strings.IndexAny(raw[start:], "/\\?#")
	if end < start {
		end = len(raw)
	}
	authority := raw[start:end]
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return raw, true
	}
	colon := strings.IndexByte(authority[:at], ':')
	if colon < 0 {
		return raw, true
	}
	return raw[:start+colon] + raw[start+at:], true
}

// Value is a header field's value, or what is left of it once the secret is
// out.
func Value(name, value string) string {
	switch lower := strings.ToLower(name); {
	case lower == "cookie":
		pairs := strings.Split(value, ";")
		for i, pair := range pairs {
			pairs[i] = maskAfter(strings.TrimSpace(pair), "=")
		}
		return strings.Join(pairs, "; ")
	case lower == "set-cookie":
		// The attributes stay. Whether a cookie was scoped to the right domain
		// is what a session that will not stick usually turns on.
		pair, attributes, _ := strings.Cut(value, ";")
		if attributes != "" {
			attributes = ";" + attributes
		}
		return maskAfter(pair, "=") + attributes
	case lower == "authorization", lower == "proxy-authorization":
		return maskAfter(value, " ")
	case sensitive(lower):
		// Nobody's standard, and where an API key usually travels.
		return Masked
	case carriesURL(lower):
		// A URL's query is where a token often travels: HTTP/2 writes the
		// request's own as :path, and a Referer or Location quotes another's.
		return queries(value)
	}
	return value
}

// carriesURL names the fields whose value is a URL, or the path and query of
// one: an access token in its query is masked as in any URL written down.
func carriesURL(lower string) bool {
	switch lower {
	case ":path", "referer", "location", "content-location":
		return true
	}
	return false
}

// maskAfter keeps what comes before a separator and masks the rest. With no
// separator there is no telling the name from the secret, so all of it goes.
func maskAfter(value, separator string) string {
	name, _, found := strings.Cut(value, separator)
	if !found {
		return Masked
	}
	return name + separator + Masked
}

// sensitive is shared by header values and decoded query parameter names.
func sensitive(name string) bool {
	lower := strings.ToLower(name)
	return lower == "x-auth" || lower == "authorization" || lower == "proxy-authorization" || lower == "x-authorization" ||
		strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "key")
}

// queries preserves spelling, order, repeated fields and non-secret values.
// It also works on quoted URLs in parse errors, including malformed URLs that
// cannot be passed through url.Parse. No request URL is changed by this helper.
func queries(text string) string {
	var out strings.Builder
	for {
		start := strings.IndexByte(text, '?')
		if start < 0 {
			out.WriteString(text)
			return out.String()
		}
		out.WriteString(text[:start+1])
		text = text[start+1:]
		end := strings.IndexFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r == '#' })
		if end < 0 {
			end = len(text)
		}
		fields := strings.Split(text[:end], "&")
		for i, field := range fields {
			name, _, found := strings.Cut(field, "=")
			decoded, err := url.QueryUnescape(name)
			if found && err == nil && sensitive(decoded) {
				fields[i] = name + "=" + Masked
			}
		}
		out.WriteString(strings.Join(fields, "&"))
		text = text[end:]
	}
}
