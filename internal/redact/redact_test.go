package redact

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
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

func TestText(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"nothing to take out", "dial tcp 127.0.0.1:8080: connect: connection refused",
			"dial tcp 127.0.0.1:8080: connect: connection refused"},
		{"a URL without a password", `Get "https://example.test/a@b": EOF`, `Get "https://example.test/a@b": EOF`},
		{"a username only", "ssh://git@example.test/repo", "ssh://git@example.test/repo"},
		{"an empty password", "http://alice:@proxy.test", "http://alice:@proxy.test"},
		// What url.Parse quotes back of a proxy it could not read.
		{"a URL that will not parse", `parse "http://alice:s3cr3t@[bad": missing ']' in host`,
			`parse "http://alice@[bad": missing ']' in host`},
		{"a password with an @ in it", "http://alice:p@ss@proxy.test:8080/x", "http://alice@proxy.test:8080/x"},
		{"a password escaped", "http://alice:p%40ss@proxy.test", "http://alice@proxy.test"},
		{"a password with a quote, quoted", `parse "http://alice:se\"cret@[bad": invalid`,
			`parse "http://alice@[bad": invalid`},
		{"two URLs", "http://a:1@one.test and socks5://b:2@two.test:1080",
			"http://a@one.test and socks5://b@two.test:1080"},
		{"at the end", "via http://a:secret@p.test", "via http://a@p.test"},
		{"over lines", "first http://a:x@one.test\nsecond https://b:y@two.test",
			"first http://a@one.test\nsecond https://b@two.test"},
		{"an @ after the authority", "http://p.test/user:pw@x", "http://p.test/user:pw@x"},
		// Without "://" nothing reads as a URL. Error masks a proxy given so.
		{"no scheme", "invalid url `alice:s3cr3t@proxy.test`", "invalid url `alice:s3cr3t@proxy.test`"},
	} {
		if got := Text(tc.text); got != tc.want {
			t.Errorf("%s: Text(%q) = %q, want %q", tc.name, tc.text, got, tc.want)
		}
	}
}

func TestErr(t *testing.T) {
	if Err(nil, "http://a:b@p") != nil {
		t.Error("Err(nil) is not nil")
	}
	// Nothing to take out: the error itself, not a copy of it.
	plain := errors.New("connection refused")
	if Err(plain, "http://alice:s3cr3t@proxy.test") != plain {
		t.Error("an error with nothing to mask was wrapped")
	}

	// A proxy without a scheme is known by what was given, and any URL by
	// its shape; what it was is underneath, for errors.Is and errors.As.
	cause := &url.Error{Op: "parse", URL: "http://bob:hunter2@[bad", Err: errors.New("missing ']' in host")}
	wrapped := fmt.Errorf("tlsforge: invalid url `alice:s3cr3t@proxy.test`: %w", cause)
	masked := Err(wrapped, "alice:s3cr3t@proxy.test", "")
	want := "tlsforge: invalid url `alice@proxy.test`: parse \"http://bob@[bad\": missing ']' in host"
	if masked.Error() != want {
		t.Errorf("Err() = %q, want %q", masked.Error(), want)
	}
	var asURL *url.Error
	if !errors.Is(masked, cause) || !errors.As(masked, &asURL) || asURL != cause {
		t.Error("the cause is not underneath the masked error")
	}
	if errors.Unwrap(masked) != wrapped {
		t.Error("the masked error does not unwrap to the error it masks")
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

func TestSecretQueryAndAdditionalAuthFields(t *testing.T) {
	for _, raw := range []string{
		"https://example.test/x?access_token=never-keep&ok=1&access_token=never-keep#fragment",
		"https://u:never-keep@example.test/?%61ccess%5ftoken=never-keep&ok=1",
		"https://example.test/?X-Auth=never-keep&api_key=never-keep&ok=1",
	} {
		for _, safe := range []string{URL(raw), Text(`parse "` + raw + `": broken`), Text("prefix " + raw + " suffix")} {
			if strings.Contains(safe, "never-keep") || !strings.Contains(safe, "ok=1") {
				t.Errorf("unsafe or corrupted: %s", safe)
			}
		}
	}
	for _, name := range []string{"X-Authorization", "x-auth", "ACCESS_TOKEN"} {
		if got := Value(name, "never-keep rest"); strings.Contains(got, "never-keep") {
			t.Errorf("%s leaked: %s", name, got)
		}
	}
}

func TestQueryRedactionDoesNotStopInsideQuotedSecret(t *testing.T) {
	for _, raw := range []string{`https://example.test/?access_token=part'never-keep`, `https://example.test/?access_token=part"never-keep`, `https://example.test/?access_token=part\never-keep`} {
		for _, safe := range []string{URL(raw), Text(`parse "` + raw + `": invalid`)} {
			if strings.Contains(safe, "never-keep") {
				t.Errorf("quoted query leaked: %s", safe)
			}
		}
	}
}
