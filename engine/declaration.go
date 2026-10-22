package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// DeclaredMajor reads exact, unambiguous compatibility metadata. It never
// infers a declaration from schema, names, version strings or defaults.
func DeclaredMajor(data []byte) (*int, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, fmt.Errorf("expected a JSON object")
	}
	var result *int
	seen := false
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key := token.(string)
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		if !strings.EqualFold(key, "engine_major") {
			continue
		}
		if key != "engine_major" {
			return nil, fmt.Errorf("invalid engine_major spelling %q", key)
		}
		if seen {
			return nil, fmt.Errorf("duplicate engine_major")
		}
		seen = true
		var n int
		if bytes.Equal(raw, []byte("null")) {
			return nil, fmt.Errorf("engine_major is null")
		}
		if err := json.Unmarshal(raw, &n); err != nil || n < 0 {
			return nil, fmt.Errorf("invalid engine_major %s", raw)
		}
		result = &n
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("extra data after JSON object")
	}
	return result, nil
}

// CheckMajor rejects an absent or incompatible declaration before any I/O.
func CheckMajor(subject string, declared *int) error {
	if declared == nil {
		return fmt.Errorf("%s: engine_major is required; running engine major %d", subject, Major())
	}
	if *declared < 0 {
		return fmt.Errorf("%s: invalid engine_major %d; running engine major %d", subject, *declared, Major())
	}
	if *declared != Major() {
		return fmt.Errorf("%s: engine_major %d is incompatible with running engine major %d", subject, *declared, Major())
	}
	return nil
}
