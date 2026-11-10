package main

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// machineFields are the values a profile keeps that the machine it was
// captured on decides, rather than the browser: the languages its person
// reads, and, of the client hints a Chromium browser sends when a server asks,
// the system's version, its processor and how many bits it has, its model,
// whether it runs 32-bit code on 64, its form, memory, geometry and preferences.
// These can be an explicit virtual persona. Hints require the origin's opt-in;
// capture inventories their saved values, and --set edits them.
var machineFields = []string{
	"accept-language", "sec-ch-ua-platform-version", "sec-ch-ua-arch", "sec-ch-ua-bitness",
	"sec-ch-ua-model", "sec-ch-ua-wow64", "sec-ch-ua-form-factors",
	"device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr",
	"viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height",
	"sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency",
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
		if slices.ContainsFunc(out, func(s setting) bool {
			return machineFieldGroup(s.name) == machineFieldGroup(name) && s.value != value
		}) {
			return nil, badValue("--set", item, "the same value for both names of an alias hint")
		}
		out = append(out, setting{name, value})
	}
	return out, nil
}

// valueProblem says what value name takes, when value is none: a header
// value for accept-language; ?0 or ?1 for wow64; Structured Field strings,
// quoted (RFC 8941), for the UA fields; bounded numeric memory/geometry and
// the preference keywords actually carried by the hints.
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
	case "device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr":
		n, ok := positiveMachineNumber(value)
		if !ok {
			return "a positive number with at most12 integer and3 fractional digits"
		}
		if machineFieldGroup(name) == "device-memory" {
			if fraction, _ := math.Frexp(n); fraction != 0.5 {
				return "a positive power of two in GiB, as8 or0.5"
			}
		}
	case "viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height":
		if len(value) == 0 || len(value) > 15 || !asciiDigits(value) {
			return "an unsigned Structured Field integer (0..999999999999999)"
		}
	case "sec-ch-prefers-color-scheme":
		if value != "light" && value != "dark" {
			return "light or dark"
		}
	case "sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency":
		if value != "no-preference" && value != "reduce" {
			return "no-preference or reduce"
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

// positiveMachineNumber accepts the number syntax used by the observed hint
// fields, including an integral spelling. Limits are Structured Fields wire
// bounds, not browser-specific device or viewport defaults.
func positiveMachineNumber(value string) (float64, bool) {
	whole, fractional, decimal := strings.Cut(value, ".")
	if len(whole) == 0 || len(whole) > 12 || !asciiDigits(whole) ||
		decimal && (len(fractional) == 0 || len(fractional) > 3 || !asciiDigits(fractional)) {
		return 0, false
	}
	n, _ := strconv.ParseFloat(value, 64) // the bounded digit syntax cannot overflow
	return n, n > 0
}

func asciiDigits(value string) bool {
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// These wire names denote the same input. An edit changes every existing
// alias, without inventing a hint the profile does not support.
func machineFieldGroup(name string) string {
	switch name {
	case "sec-ch-device-memory":
		return "device-memory"
	case "sec-ch-dpr":
		return "dpr"
	case "sec-ch-viewport-width":
		return "viewport-width"
	}
	return name
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
				if machineFieldGroup(strings.ToLower(fields[i].Name)) == machineFieldGroup(s.name) {
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
