package networkquality

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"unicode/utf8"
)

// connectionTypes are supported physical connection classes, not ECT labels.
// They identify input capabilities; their estimates always come from JSON.
var connectionTypes = []string{"unknown", "ethernet", "wifi", "2g", "3g", "4g", "5g", "none", "bluetooth"}

// Context identifies a network epoch without ready-made RTT or throughput.
// A nil Signal is unavailable, distinct from known signal strength zero.
type Context struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
	Signal     *int   `json:"signal" descriptor:"nullable"`
}

// Validate checks the typed cross-SDK representation before state or I/O.
func (c Context) Validate() error {
	if !slices.Contains(connectionTypes, c.Type) || len(c.ID) > 4096 || !utf8.ValidString(c.ID) || c.Generation > 1<<53-1 {
		return fmt.Errorf("invalid network context type, identity or generation")
	}
	if c.Signal != nil && (*c.Signal < 0 || *c.Signal > 4) {
		return fmt.Errorf("network signal must be null or0..4")
	}
	return nil
}

// Clone isolates the optional input from later caller mutation.
func (c Context) Clone() Context {
	if c.Signal != nil {
		value := *c.Signal
		c.Signal = &value
	}
	return c
}
func (c Context) signal() int {
	if c.Signal == nil {
		return -1
	}
	return *c.Signal
}

// UnmarshalJSON rejects unknown, duplicate and case-folded fields instead of
// allowing an old daemon or a typo to apply only part of a network transition.
func (c *Context) UnmarshalJSON(raw []byte) error {
	if len(raw) > 32768 || !utf8.Valid(raw) {
		return fmt.Errorf("network context requires bounded UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil {
		return e
	}
	if token != json.Delim('{') {
		return fmt.Errorf("network context must be an object")
	}
	seen := map[string]bool{}
	var candidate Context
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return e
		}
		name := key.(string)
		if !slices.Contains([]string{"type", "id", "generation", "signal"}, name) || seen[name] {
			return fmt.Errorf("unknown or duplicate network context field %q", name)
		}
		seen[name] = true
		var value json.RawMessage
		if e := d.Decode(&value); e != nil {
			return e
		}
		if name != "signal" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("network %s must not be null", name)
		}
		switch name {
		case "type", "id":
			if !validContextStringEscapes(value) {
				return fmt.Errorf("network %s contains invalid Unicode surrogate", name)
			}
			target := &candidate.ID
			if name == "type" {
				target = &candidate.Type
			}
			if e := json.Unmarshal(value, target); e != nil {
				return e
			}
		case "generation":
			if e := json.Unmarshal(value, &candidate.Generation); e != nil {
				return e
			}
		case "signal":
			if e := json.Unmarshal(value, &candidate.Signal); e != nil {
				return e
			}
		}
	}
	if _, e := d.Token(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("network context requires exactly one object")
	}
	if len(seen) != 4 {
		return fmt.Errorf("network context requires type, id, generation and signal")
	}
	if e := candidate.Validate(); e != nil {
		return e
	}
	*c = candidate
	return nil
}

// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD. An opaque
// network identity must retain its bytes; a genuine U+FFFD remains legal.
func validContextStringEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		code, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, _ := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
