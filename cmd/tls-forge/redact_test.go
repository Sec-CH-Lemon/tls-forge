package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRedactProxy(t *testing.T) {
	cases := []struct {
		name  string
		given string
		want  string
	}{
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redactProxy(c.given); got != c.want {
				t.Errorf("redactProxy(%q) = %q, want %q", c.given, got, c.want)
			}
		})
	}
}

// TestResultJSONHasNoProxyPassword covers the sink people keep: the JSON lines
// are appended across runs and read back by other tools.
func TestResultJSONHasNoProxyPassword(t *testing.T) {
	r := result{URL: "https://example.com/", Proxy: "http://alice:s3cr3t@proxy.example:8080"}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "s3cr3t") {
		t.Errorf("the proxy password is in the JSON output: %s", encoded)
	}
	// The username survives, because it is what tells two proxies apart.
	if !strings.Contains(string(encoded), "alice") {
		t.Errorf("the proxy username was dropped: %s", encoded)
	}

	// The record itself keeps the URL as given: it is the key the client pool
	// and the exit lookup are filed under.
	if r.Proxy != "http://alice:s3cr3t@proxy.example:8080" {
		t.Errorf("marshalling changed the record: %q", r.Proxy)
	}
}

func TestResultLineHasNoProxyPassword(t *testing.T) {
	r := result{URL: "https://example.com/", Proxy: "http://alice:s3cr3t@proxy.example:8080"}
	if line := verboseLine(r); strings.Contains(line, "s3cr3t") {
		t.Errorf("the proxy password is in the terminal line: %s", line)
	}
}

// TestSetErrorHasNoProxyPassword covers the second way the password reached the
// output: url.Parse quotes back the whole string it could not parse, so a
// mistyped proxy wrote its own password into the error field.
func TestSetErrorHasNoProxyPassword(t *testing.T) {
	r := result{URL: "https://example.com/", Proxy: "://alice:s3cr3t@bad"}
	r.setError(errors.New(`tlsforge: parse "://alice:s3cr3t@bad": missing protocol scheme`))
	if strings.Contains(r.Error, "s3cr3t") {
		t.Errorf("the proxy password is in the error field: %s", r.Error)
	}

	// A normalised spelling of the same credentials is caught too.
	r = result{Proxy: "http://alice:s3cr3t@proxy.example:8080"}
	r.setError(errors.New(`dial http://alice:s3cr3t@proxy.example:8080: refused`))
	if strings.Contains(r.Error, "s3cr3t") {
		t.Errorf("the proxy password is in the error field: %s", r.Error)
	}

	// An error with no proxy in it is passed through unchanged.
	r = result{Proxy: "http://proxy.example:8080"}
	r.setError(errors.New("connection refused"))
	if r.Error != "connection refused" {
		t.Errorf("setError changed an unrelated message: %q", r.Error)
	}
}

// TestReportHasNoProxyPassword covers the sink the report was most exposed by:
// it is written to be mailed to someone.
func TestReportHasNoProxyPassword(t *testing.T) {
	records := []result{{
		URL:    "https://example.com/",
		Proxy:  "http://alice:s3cr3t@proxy.example:8080",
		Status: 200,
	}}
	totals := summarise(records, 0, nil)

	var out strings.Builder
	if err := renderReport(&out, records, totals, nil); err != nil {
		t.Fatalf("renderReport: %v", err)
	}
	if strings.Contains(out.String(), "s3cr3t") {
		t.Error("the proxy password is in the HTML report")
	}
	if !strings.Contains(out.String(), "alice") {
		t.Error("the proxy username is missing, so proxies cannot be told apart")
	}
}
