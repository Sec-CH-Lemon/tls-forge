package tlsforge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func writeRules(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	return path
}

// TestRulesReachTheWire is the feature where it counts: on the bytes, for the
// host named and for no other.
func TestRulesReachTheWire(t *testing.T) {
	server := startEcho(t)
	path := writeRules(t, `{"rules": [
		{"host": "*.example.com", "after": "accept",
		 "headers": [{"name": "X-Api-Version", "value": "3"}]},
		{"host": "*.google.com", "remove": ["x-client-data"]},
		{"host": "/^shop[0-9]+\\.example\\.net$/",
		 "headers": [{"name": "x-shop", "value": "yes"}]}
	]}`)

	client := newTestClient(t,
		WithProfileValue(googleProfile(t)),
		WithHeaderRulesFile(path),
		WithProxy(loopbackProxy(t, server.Addr())))

	sent := func(target string) []string {
		t.Helper()
		res, err := client.Get(target + "/api/all")
		if err != nil {
			t.Fatalf("Get %s: %v", target, err)
		}
		var got capture.Capture
		if err := json.Unmarshal(res.Body, &got); err != nil {
			t.Fatalf("reading the echo: %v", err)
		}
		return got.HTTP2.HeaderOrder
	}

	order := strings.Join(sent("https://www.example.com"), ",")
	if !strings.Contains(order, "accept,x-api-version,") {
		t.Errorf("the rule's header did not go where it was told:\n%s", order)
	}

	// A subdomain of the domain named, and only that domain.
	if order := strings.Join(sent("https://example.net"), ","); strings.Contains(order, "x-api-version") {
		t.Errorf("example.com's header went to example.net:\n%s", order)
	}
	if order := strings.Join(sent("https://shop7.example.net"), ","); !strings.Contains(order, "x-shop") {
		t.Errorf("the regular expression did not match:\n%s", order)
	}

	// A rule can unsend what this library adds by itself.
	order = strings.Join(sent("https://news.google.com"), ",")
	if strings.Contains(order, "x-client-data") {
		t.Errorf("remove did not remove:\n%s", order)
	}
	if !strings.Contains(order, "x-browser-channel") {
		t.Errorf("remove took the rest of the block with it:\n%s", order)
	}
}

func TestRuleReplacesInPlaceAndAddsAtTheEnd(t *testing.T) {
	base := NewHeader("accept", "*/*", "user-agent", "ua", "priority", "u=0")

	// A header the profile already has keeps its position: moving it would
	// change the order that is the point of the profile.
	replaced := Rules{mustCompile(t, Rule{Host: "example.com",
		Headers: []profile.Field{{Name: "user-agent", Value: "mine"}}})}.
		apply(base, "example.com")
	if got := strings.Join(replaced.Names(), ","); got != "accept,user-agent,priority" {
		t.Errorf("order = %s", got)
	}
	if got := replaced.Get("user-agent"); got != "mine" {
		t.Errorf("user-agent = %q", got)
	}

	// A header it does not have, and no anchor: the end.
	added := Rules{mustCompile(t, Rule{Host: "example.com",
		Headers: []profile.Field{{Name: "x-new", Value: "1"}}})}.
		apply(base, "example.com")
	if got := added.Names()[len(added)-1]; got != "x-new" {
		t.Errorf("a header with no anchor went to %q", got)
	}

	// An anchor naming a header that is not there: the end, rather than nowhere.
	stray := Rules{mustCompile(t, Rule{Host: "example.com", After: "nonesuch",
		Headers: []profile.Field{{Name: "x-new", Value: "1"}}})}.
		apply(base, "example.com")
	if got := stray.Names()[len(stray)-1]; got != "x-new" {
		t.Errorf("a header with a missing anchor went to %q", got)
	}

	// A rule for somebody else changes nothing.
	elsewhere := Rules{mustCompile(t, Rule{Host: "other.com",
		Headers: []profile.Field{{Name: "x-new", Value: "1"}}})}
	if got := elsewhere.apply(base, "example.com"); len(got) != len(base) {
		t.Errorf("a rule for another host applied: %v", got.Names())
	}
}

func mustCompile(t *testing.T, rule Rule) Rule {
	t.Helper()
	compiled, err := compileRules(Rules{rule})
	if err != nil {
		t.Fatalf("compiling %+v: %v", rule, err)
	}
	return compiled[0]
}

func TestRuleHostForms(t *testing.T) {
	for _, c := range []struct {
		pattern string
		host    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false},
		{"example.com", "EXAMPLE.COM", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "notexample.com", false},
		{"*.example.com", "example.com.evil.net", false},
		{"/^shop[0-9]+\\.example\\.net$/", "shop7.example.net", true},
		{"/^shop[0-9]+\\.example\\.net$/", "shopx.example.net", false},
		{" example.com ", "example.com", true},
	} {
		// Through apply, so what is tested is what a request goes through, not
		// a matcher a request might not reach.
		rules := Rules{mustCompile(t, Rule{Host: c.pattern,
			Headers: []profile.Field{{Name: "x-hit", Value: "1"}}})}
		applied := rules.apply(Header{}, c.host).Has("x-hit")
		if applied != c.want {
			t.Errorf("%q against %q = %v, want %v", c.pattern, c.host, applied, c.want)
		}
	}
}

func TestParseRules(t *testing.T) {
	if _, err := ParseRules([]byte("not json")); err == nil {
		t.Error("unparseable JSON was accepted")
	}
	// A file with no rules is a file pointed at by mistake.
	if _, err := ParseRules([]byte(`{}`)); err == nil {
		t.Error("a file with no rules was accepted")
	}
	if _, err := ParseRules([]byte(`{"rules": [{"headers": []}]}`)); err == nil {
		t.Error("a rule with no host was accepted")
	}
	if _, err := ParseRules([]byte(`{"rules": [{"host": "/([/"}]}`)); err == nil {
		t.Error("a broken regular expression was accepted")
	}

	rules, err := ParseRules([]byte(`{"rules": [
		{"host": "example.com", "headers": [{"name": "X-One", "value": "1"}], "remove": ["X-Two"]}
	]}`))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	// Lower-cased on the way in: HPACK needs it, and the order list is matched
	// lower-cased, so "X-One" and "x-one" must not be two headers.
	if rules[0].Headers[0].Name != "x-one" || rules[0].Remove[0] != "x-two" {
		t.Errorf("names were not lower-cased: %+v", rules[0])
	}
}

func TestReadRules(t *testing.T) {
	if _, err := ReadRules(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("a missing file was accepted")
	}
	rules, err := ReadRules(writeRules(t, `{"rules": [{"host": "example.com"}]}`))
	if err != nil {
		t.Fatalf("ReadRules: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("read %d rules", len(rules))
	}
}

func TestRulesComeFromTheEnvironmentWhenNoFileIsNamed(t *testing.T) {
	t.Setenv(RulesEnv, writeRules(t, `{"rules": [
		{"host": "example.com", "headers": [{"name": "x-from-env", "value": "1"}]}
	]}`))

	client := newTestClient(t)
	if len(client.rules) != 1 {
		t.Fatalf("the environment was not read: %+v", client.rules)
	}

	// Naming a file — even an empty name — is an answer, so the environment is
	// not consulted behind it.
	quiet := newTestClient(t, WithHeaderRulesFile(""))
	if len(quiet.rules) != 0 {
		t.Errorf("naming no file still read the environment: %+v", quiet.rules)
	}
}

func TestRulesFromCodeComeAfterTheFile(t *testing.T) {
	path := writeRules(t, `{"rules": [
		{"host": "example.com", "headers": [{"name": "x-who", "value": "file"}]}
	]}`)
	client := newTestClient(t,
		WithHeaderRulesFile(path),
		WithHeaderRules(Rule{Host: "example.com",
			Headers: []profile.Field{{Name: "x-who", Value: "code"}}}))

	got := client.rules.apply(Header{}, "example.com")
	if got.Get("x-who") != "code" {
		t.Errorf("x-who = %q; a rule passed in should override one from a file", got.Get("x-who"))
	}
}

func TestClientRejectsRulesItCannotUse(t *testing.T) {
	if _, err := New(WithHeaderRulesFile("/no/such/rules.json")); err == nil {
		t.Error("a missing rules file did not stop the client being built")
	}
	if _, err := New(WithHeaderRules(Rule{Host: "/([/"})); err == nil {
		t.Error("a broken rule did not stop the client being built")
	}
}

func TestHeadersSetOnTheClientBeatARule(t *testing.T) {
	path := writeRules(t, `{"rules": [
		{"host": "example.com", "headers": [{"name": "accept-language", "value": "de-DE"}]}
	]}`)
	server := startEcho(t)
	client := newTestClient(t,
		WithHeaderRulesFile(path),
		WithHeaders(NewHeader("accept-language", "fr-FR")),
		WithProxy(loopbackProxy(t, server.Addr())))

	res, err := client.Get("https://example.com/api/all")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	var got capture.Capture
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	for _, f := range got.HTTP2.Headers {
		if f.Name == "accept-language" && f.Value != "fr-FR" {
			t.Errorf("accept-language = %q; the client's own header should win", f.Value)
		}
	}
}
