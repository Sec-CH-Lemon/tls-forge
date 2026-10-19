package main

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// machineFields are the values a profile keeps that the machine it was
// captured on decides, rather than the browser: the languages its person
// reads, and, of the client hints a Chromium browser sends when a server asks,
// the system's version, its processor and how many bits it has, its model,
// whether it runs 32-bit code on 64, and its form. Every request with the
// profile says them, so capture shows them, and --set changes them.
var machineFields = []string{
	"accept-language", "sec-ch-ua-platform-version", "sec-ch-ua-arch", "sec-ch-ua-bitness",
	"sec-ch-ua-model", "sec-ch-ua-wow64", "sec-ch-ua-form-factors",
}

// setting is a value --set gives the profile kept.
type setting struct{ name, value string }

// settingsOf reads capture's --set NAME=VALUE: a name of machineFields, once,
// and a value as the header carries it (valueProblem).
func settingsOf(given []string) ([]setting, error) {
	var out []setting
	for _, item := range given {
		name, value, ok := strings.Cut(item, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		switch {
		case !ok || !slices.Contains(machineFields, name):
			return nil, badValue("--set", item, "NAME=VALUE, NAME one of "+strings.Join(machineFields, ", "))
		case slices.ContainsFunc(out, func(s setting) bool { return s.name == name }):
			return nil, badValue("--set", item, "each name once")
		}
		if want := valueProblem(name, value); want != "" {
			return nil, badValue("--set", item, want)
		}
		out = append(out, setting{name, value})
	}
	return out, nil
}

// valueProblem says what value name takes, when value is none: a header
// value for accept-language; ?0 or ?1 for wow64; Structured Field strings,
// quoted (RFC 8941), for the form factors, a list of them; one for the rest.
func valueProblem(name, value string) string {
	switch name {
	case "accept-language":
		if value == "" || !httpguts.ValidHeaderFieldValue(value) {
			return "a header value, as en-US,en;q=0.9"
		}
	case "sec-ch-ua-wow64":
		if value != "?0" && value != "?1" {
			return "?0 or ?1"
		}
	case "sec-ch-ua-form-factors":
		for _, item := range strings.Split(value, ",") {
			if !structuredString(strings.TrimSpace(item)) {
				return `strings, quoted, as "Desktop"`
			}
		}
	default:
		if !structuredString(value) {
			return `a string, quoted, as "15.0.0"`
		}
	}
	return ""
}

// structuredString says s is a Structured Field string: printable ASCII in
// double quotes, a backslash inside only before a quote or a backslash.
func structuredString(s string) bool {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		switch c := s[i]; {
		case c < 0x20 || c > 0x7e || c == '"':
			return false
		case c == '\\':
			if i+1 == len(s)-1 || s[i+1] != '"' && s[i+1] != '\\' {
				return false
			}
			i++
		}
	}
	return true
}

// applySettings gives a profile the values --set says: the accept-language of
// its requests, and of its HTTP/1.1 ones where it says one of its own, and a
// client hint it has. One it has not, its browser does not send: a browser
// that sends no client hints, or one whose capture gave it none, is not given
// one by a flag.
func applySettings(p *profile.Profile, settings []setting) error {
	for _, s := range settings {
		set := func(fields []profile.Field) bool {
			found := false
			for i := range fields {
				if strings.EqualFold(fields[i].Name, s.name) {
					fields[i].Value, found = s.value, true
				}
			}
			return found
		}
		found := set(p.ClientHints)
		if s.name == "accept-language" {
			found = set(p.Headers)
			if p.HTTP1 != nil {
				set(p.HTTP1.Headers)
			}
		}
		if !found {
			return fmt.Errorf("capture: the browser measured sends no %s, and --set gives a profile none", s.name)
		}
	}
	return nil
}

// machineValues are what a profile keeps of the machine it was captured on,
// in machineFields' order: names and values.
func machineValues(p *profile.Profile) [][2]string {
	var out [][2]string
	for _, name := range machineFields {
		for _, field := range slices.Concat(p.Headers, p.ClientHints) {
			if strings.EqualFold(field.Name, name) {
				out = append(out, [2]string{name, field.Value})
				break
			}
		}
	}
	return out
}
