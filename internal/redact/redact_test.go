package redact

import (
	"errors"
	"testing"
)

func TestURL(t *testing.T) {
	for _, tc := range []struct{ name, given, want string }{
		{"empty", "", ""},
		{"no credentials", "http://proxy.example:8080", "http://proxy.example:8080"},
		{"username only", "http://alice@proxy.example:8080", "http://alice@proxy.example:8080"},
		{"password", "http://alice:s3cr3t@proxy.example:8080", "http://alice@proxy.example:8080"},
		{"empty password", "http://alice:@proxy.example:8080", "http://alice@proxy.example:8080"},
		{"socks5", "socks5://bob:hunter2@127.0.0.1:1080", "socks5://bob@127.0.0.1:1080"},
		{"encoded password", "http://alice:p%40ss@proxy.example:8080", "http://alice@proxy.example:8080"},
		{"scheme-less password", "alice:s3cr3t@proxy.example:8080", "alice@proxy.example:8080"},
		{"scheme-less username", "alice@proxy.example:8080", "alice@proxy.example:8080"},
		// Carries an "@" but will not parse. Everything before the last one goes,
		// rather than guessing at the shape and printing a password by accident.
		{"unparseable", "://alice:s3cr3t@bad", "[redacted]@bad"},
		// An "@" in the path is not a credential, and rewriting it would corrupt
		// a perfectly good URL.
		{"at sign in path", "http://proxy.example:8080/pa@th", "http://proxy.example:8080/pa@th"},
	} {
		if got := URL(tc.given); got != tc.want {
			t.Errorf("%s: URL(%q) = %q, want %q", tc.name, tc.given, got, tc.want)
		}
	}
}

func TestError(t *testing.T) {
	for _, tc := range []struct{ name, err, proxy, want string }{
		{"the URL as given", `parse "://alice:s3cr3t@bad": missing protocol scheme`, "://alice:s3cr3t@bad",
			`parse "[redacted]@bad": missing protocol scheme`},
		// Quoted in a normalised form, its credentials are replaced in that shape.
		{"normalised", "dial http://alice:s3cr3t@proxy.example:8080: refused", "http://alice:s3cr3t@proxy.example:8080/",
			"dial http://alice@proxy.example:8080: refused"},
		{"no password to take out", "dial http://alice@proxy.example: refused", "http://alice@proxy.example",
			"dial http://alice@proxy.example: refused"},
		{"no proxy", "refused", "", "refused"},
	} {
		if got := Error(errors.New(tc.err), tc.proxy); got != tc.want {
			t.Errorf("%s: Error = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestValue(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		// The names stay, because which cookie went out is the question.
		{"Cookie", "a=1; b=two=2;c=3", "a=***; b=***; c=***"},
		{"cookie", "", "***"},
		// So do the attributes: how a cookie was scoped is the other question.
		{"set-cookie", "sid=abc; Domain=example.com; Secure", "sid=***; Domain=example.com; Secure"},
		{"Set-Cookie", "sid=abc", "sid=***"},
		{"Set-Cookie", "malformed", "***"},
		// The scheme stays, since Basic and Bearer fail for different reasons.
		{"Authorization", "Bearer abc.def", "Bearer ***"},
		{"proxy-authorization", "Basic dXNlcjpwYXNz", "Basic ***"},
		{"Authorization", "bare-credential", "***"},
		// Nobody's standard, and where an API key usually travels.
		{"X-Api-Key", "abc", "***"},
		{"x-csrf-token", "abc", "***"},
		{"X-Client-Secret", "abc", "***"},
		{"X-Password", "abc", "***"},
		// Everything else is what a log is for.
		{"User-Agent", "Mozilla/5.0", "Mozilla/5.0"},
		{":path", "/search?q=token", "/search?q=token"},
		{"Keep-Alive", "timeout=5", "timeout=5"},
		{"upgrade-insecure-requests", "1", "1"},
	} {
		if got := Value(tc.name, tc.value); got != tc.want {
			t.Errorf("Value(%q, %q) = %q, want %q", tc.name, tc.value, got, tc.want)
		}
	}
}
