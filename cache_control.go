package tlsforge

import (
	"strings"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/utls/behavior"
)

// A directive retains its field, order, spelling and value. Commas inside
// quoted strings are data; even malformed fields are not split by a map.
type cacheDirective struct {
	Field            int
	Raw, Name, Value string
	Quoted, Valid    bool
}
type cacheControl []cacheDirective

func cacheDirectives(h fhttp.Header) cacheControl {
	var out cacheControl
	for field, value := range fieldValues(h, "cache-control") {
		start, quoted, escaped := 0, false, false
		for i := 0; i <= len(value); i++ {
			if i == len(value) || value[i] == ',' && !quoted {
				out = append(out, parseCacheDirective(field, value[start:i]))
				start = i + 1
				continue
			}
			b := value[i]
			if escaped {
				escaped = false
			} else if quoted && b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = !quoted
			}
		}
	}
	return out
}

func cacheToken(s string) bool {
	if s == "" {
		return false
	}
	for _, b := range s {
		if !tokenByte(b) {
			return false
		}
	}
	return true
}

func parseCacheDirective(field int, raw string) cacheDirective {
	d := cacheDirective{Field: field, Raw: raw}
	text := strings.Trim(raw, " \t")
	name, value, hasValue := strings.Cut(text, "=")
	d.Name = strings.ToLower(strings.Trim(name, " \t"))
	d.Value = value
	if !cacheToken(name) {
		return d
	}
	if !hasValue {
		d.Valid = true
		return d
	}
	if !strings.HasPrefix(value, "\"") {
		d.Valid = cacheToken(value)
		return d
	}
	d.Quoted = true
	var decoded strings.Builder
	for i := 1; i < len(value); i++ {
		b := value[i]
		if b == '"' {
			d.Valid = i == len(value)-1
			d.Value = decoded.String()
			return d
		}
		if b == '\\' {
			i++
			if i == len(value) {
				return d
			}
			b = value[i]
		}
		if b != '\t' && (b < 32 || b == 127) {
			return d
		}
		decoded.WriteByte(b)
	}
	return d
}

func (d cacheControl) has(name string) bool {
	for _, v := range d {
		if v.Valid && v.Name == name {
			return true
		}
	}
	return false
}

// Saturation is selected by the profile's representable limit; the registry
// bounds it so converting to a duration cannot overflow. Keep scanning after
// saturation: a huge number followed by a letter is still invalid syntax.
func cacheDelta(value string, limit uint64) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	var n uint64
	for _, b := range value {
		if b < '0' || b > '9' {
			return 0, false
		}
		digit := uint64(b - '0')
		if n > limit/10 || n == limit/10 && digit > limit%10 {
			n = limit
		} else {
			n = n*10 + digit
		}
	}
	return time.Duration(n) * time.Second, true
}

func (d cacheControl) seconds(name string, p behavior.Policy) (time.Duration, bool) {
	count := 0
	for _, v := range d {
		if v.Name == name {
			count++
		}
	}
	if count > 1 && p.Text("cache.duplicate_freshness_policy") == "stale" {
		return 0, true
	}
	for _, v := range d {
		if v.Name != name {
			continue
		}
		if v.Valid && (!v.Quoted || p.Flag("cache.freshness_quoted_values")) {
			if value, ok := cacheDelta(v.Value, p.Uint("cache.delta_seconds_limit")); ok {
				return value, true
			}
		}
		if p.Text("cache.invalid_freshness_policy") == "stale" {
			return 0, true
		}
	}
	return 0, false
}
