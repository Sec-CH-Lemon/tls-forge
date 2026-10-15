package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

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
	var out strings.Builder
	if err := renderReport(&out, inputOf(records)); err != nil {
		t.Fatalf("renderReport: %v", err)
	}
	if strings.Contains(out.String(), "s3cr3t") {
		t.Error("the proxy password is in the HTML report")
	}
	if !strings.Contains(out.String(), "alice") {
		t.Error("the proxy username is missing, so proxies cannot be told apart")
	}
}
