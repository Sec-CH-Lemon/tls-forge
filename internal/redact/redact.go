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
// taken out of it.
//
// Needed on top of URL because a proxy's URL turns up inside error messages:
// url.Parse quotes back the whole string it could not parse, so a mistyped
// proxy writes its own password into the text that was just cleaned of it.
func Error(err error, proxy string) string {
	text := err.Error()
	safe := URL(proxy)
	if safe != proxy {
		text = strings.ReplaceAll(text, proxy, safe)
		// The message may quote a normalised form rather than the string as
		// given, so the credentials are replaced in that shape too.
		if u, parseErr := url.Parse(proxy); parseErr == nil && u.User != nil {
			if _, ok := u.User.Password(); ok {
				text = strings.ReplaceAll(text, u.User.String()+"@",
					url.User(u.User.Username()).String()+"@")
			}
		}
	}
	return text
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
