package tlsforge

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// Headers one destination gets and no other.
//
// The block Chrome shows Google is one instance of a general shape: a
// destination, some headers it is sent, and where in the browser's order they
// go. This is that shape written down, so a site expecting a header nobody here
// has heard of does not need anybody here to hear of it.
//
// It is a file rather than a flag because the useful version is a list, and a
// list of headers per host on a command line is a shell-quoting exercise:
//
//	{
//	  "rules": [
//	    {
//	      "host": "*.example.com",
//	      "after": "accept",
//	      "headers": [
//	        { "name": "x-api-version", "value": "3" }
//	      ]
//	    },
//	    {
//	      "host": "/^cdn[0-9]+\\.example\\.net$/",
//	      "remove": ["x-client-data"]
//	    }
//	  ]
//	}
//
// Rules are applied in the order written, over the profile and over the Google
// block, and under anything the caller set for this client or this request. A
// file is a default for a destination; an argument is a decision about one
// request, and the decision wins.

// RulesEnv names the file to read when no rules are given in code or on the
// command line. It is how a rules file reaches the Python and Node clients,
// which start this binary rather than call this package.
const RulesEnv = "TLSFORGE_HEADER_RULES"

// Rule is the headers one destination gets.
type Rule struct {
	// Host is which destinations this applies to:
	//
	//	example.com                    that host and nothing else
	//	*.example.com                  that host and every subdomain of it
	//	/^shop[0-9]+\.example\.com$/   a regular expression
	//
	// The star form covers the bare domain as well as its subdomains, which is
	// how a browser's own match patterns read and what people mean when they
	// write it. Matching is against the hostname alone, lower-cased: no scheme,
	// no port, no path — a rule is about who is being talked to, not about what
	// is being asked for.
	//
	// The plain form is exact on purpose. A pattern that quietly matched
	// subdomains would send a site's headers to whatever it hosts for other
	// people, and the star is one character.
	Host string `json:"host"`

	// After names the header these go behind, for the ones being added rather
	// than replaced. Omitted, they go on the end — where a header the browser
	// never sends belongs, since there is no observed position to put it in.
	//
	// A header the profile already carries ignores this: it keeps the browser's
	// own place in the order, because moving it would change the fingerprint
	// that is the point of the profile.
	After string `json:"after,omitempty"`

	// Headers are added, or replaced in place if the profile already has them.
	Headers []profile.Field `json:"headers,omitempty"`

	// Remove names headers this destination should not be sent. It is the only
	// way to unsend something this library adds by itself — the Google block,
	// say — and a way to drop a header for one host without dropping it for the
	// profile.
	Remove []string `json:"remove,omitempty"`

	// match is Host compiled. Unexported, so it never reaches the JSON and can
	// never be half of a rule that was loaded without being checked.
	match func(string) bool
}

// Rules are rules in the order they were written.
type Rules []Rule

// ParseRules reads a rules file.
func ParseRules(data []byte) (Rules, error) {
	var file struct {
		Rules Rules `json:"rules"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("tlsforge: reading header rules: %w", err)
	}
	// Nought rules is not a rules file. Pointing at the wrong file, or writing
	// "rule" for "rules", otherwise produces a run that silently sends nothing
	// extra — and looks exactly like a run where the rules did not match.
	if len(file.Rules) == 0 {
		return nil, fmt.Errorf("tlsforge: no rules in this file; it needs a \"rules\" list")
	}
	return compileRules(file.Rules)
}

// ReadRules reads a rules file from disk.
func ReadRules(path string) (Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlsforge: header rules: %w", err)
	}
	return ParseRules(data)
}

// compileRules turns every Host into something that can answer about a host,
// and rejects the whole set if any of them cannot be. Half-loaded rules are
// worse than none: the run would work, and be wrong for one destination.
func compileRules(rules Rules) (Rules, error) {
	out := make(Rules, len(rules))
	copy(out, rules)
	for i := range out {
		if err := out[i].compile(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *Rule) compile() error {
	// Lower-cased here rather than at every comparison. HPACK requires lower
	// case on the wire anyway, and the order list is matched lower-cased, so a
	// rule saying "X-Api-Version" has to arrive as one name, not two.
	for i := range r.Headers {
		r.Headers[i].Name = strings.ToLower(r.Headers[i].Name)
	}
	for i := range r.Remove {
		r.Remove[i] = strings.ToLower(r.Remove[i])
	}

	pattern := strings.TrimSpace(r.Host)
	switch {
	case pattern == "":
		return fmt.Errorf("tlsforge: a header rule needs a host")

	case len(pattern) > 2 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/"):
		expression, err := regexp.Compile(pattern[1 : len(pattern)-1])
		if err != nil {
			return fmt.Errorf("tlsforge: header rule %s: %w", pattern, err)
		}
		r.match = expression.MatchString

	case strings.HasPrefix(pattern, "*."):
		domain := strings.ToLower(pattern[2:])
		r.match = func(host string) bool {
			return host == domain || strings.HasSuffix(host, "."+domain)
		}

	default:
		exact := strings.ToLower(pattern)
		r.match = func(host string) bool { return host == exact }
	}
	return nil
}

// apply layers every rule that matches over a header list.
func (rs Rules) apply(base Header, host string) Header {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	out := base
	for _, rule := range rs {
		if rule.match != nil && rule.match(host) {
			out = rule.applyTo(out)
		}
	}
	return out
}

func (r Rule) applyTo(base Header) Header {
	out := base.Clone()
	for _, name := range r.Remove {
		out.Del(name)
	}

	var added Header
	for _, f := range r.Headers {
		if out.Has(f.Name) {
			// In place: a header the browser sends has a position, and the
			// position is part of what the profile is for.
			out.Set(f.Name, f.Value)
			continue
		}
		added = append(added, f)
	}
	if len(added) == 0 {
		return out
	}

	at := -1
	for i, f := range out {
		if f.Name == r.After {
			at = i + 1
		}
	}
	if at < 0 {
		return append(out, added...)
	}
	return append(out[:at:at], append(added, out[at:]...)...)
}

// resolveRules is where a client's rules come from: a file, then whatever was
// passed in code — in that order, so an argument overrides a file.
//
// The environment is consulted only when no file was named. It is there for the
// clients that start this binary rather than import this package, and a caller
// that named a file has already answered the question.
func resolveRules(cfg *config) (Rules, error) {
	path := cfg.rulesFile
	if !cfg.rulesFileSet {
		path = os.Getenv(RulesEnv)
	}

	var out Rules
	if path != "" {
		fromFile, err := ReadRules(path)
		if err != nil {
			return nil, err
		}
		out = fromFile
	}
	if len(cfg.rules) == 0 {
		return out, nil
	}
	compiled, err := compileRules(cfg.rules)
	if err != nil {
		return nil, err
	}
	return append(out, compiled...), nil
}
