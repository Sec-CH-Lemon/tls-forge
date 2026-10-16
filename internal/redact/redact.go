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
	if raw == "" || !strings.Contains(raw, "@") {
		return raw
	}
	parsed := raw
	schemeLess := !strings.Contains(raw, "://")
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
// A URL is a "://" and what follows it up to a "/" or a space. Its userinfo is
// everything before the last "@" in that, and the password what follows the
// first ":" of the userinfo. Quotes are not where a URL ends, since a password
// may hold one, escaped.
func Text(text string) string {
	if !strings.Contains(text, "://") || !strings.Contains(text, "@") {
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
	case strings.Contains(lower, "token"), strings.Contains(lower, "secret"),
		strings.Contains(lower, "password"), strings.Contains(lower, "key"):
		// Nobody's standard, and where an API key usually travels.
		return Masked
	}
	return value
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
