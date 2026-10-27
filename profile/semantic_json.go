package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// Go's struct decoder folds key spelling and accepts null for numeric fields.
// Refuse ambiguous executable representations before that information is lost.
// Offline Inspect remains separate and never grants execution permission.
func validateProfileJSON(data []byte) error {
	var named struct{ Name string }
	_ = json.Unmarshal(data, &named)
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(string) error
	value = func(path string) error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		if strings.HasPrefix(path, "http2.") {
			field := path[strings.LastIndexByte(path, '.')+1:]
			var scalar any
			switch field {
			case "id":
				scalar = Setting{}.ID
			case "value":
				scalar = Setting{}.Value
			case "connection_flow":
				scalar = HTTP2{}.ConnectionFlow
			case "stream_id":
				scalar = Priority{}.StreamID
			case "depends_on":
				scalar = Priority{}.DependsOn
			case "weight":
				scalar = Priority{}.Weight
			case "exclusive":
				if _, ok := token.(bool); !ok {
					return fmt.Errorf("%s = %v: requires a boolean", path, token)
				}
			}
			if scalar != nil {
				bits := reflect.TypeOf(scalar).Bits()
				n, ok := token.(json.Number)
				if !ok {
					return fmt.Errorf("%s = %v (%T): requires an unsigned %d-bit integer", path, token, token, bits)
				}
				if _, err := strconv.ParseUint(string(n), 10, bits); err != nil {
					return fmt.Errorf("%s = %s: requires 0..%d (unsigned %d-bit integer)", path, n, uint64(1)<<bits-1, bits)
				}
			}
			if (path == "http2.settings" || path == "http2.priorities" || path == "http2.pseudo_header_order") && token != nil && token != json.Delim('[') {
				return fmt.Errorf("%s = %v: requires an array", path, token)
			}
			if path == "http2.header_priority" && token != nil && token != json.Delim('{') {
				return fmt.Errorf("%s = %v: requires an object or null", path, token)
			}
		}
		record := strings.HasPrefix(path, "http2.settings[") && strings.HasSuffix(path, "]")
		if (path == "http2" || record) && token != json.Delim('{') {
			return fmt.Errorf("%s = %v: requires an object", path, token)
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name := strings.ToLower(strings.Map(func(r rune) rune {
					for {
						next := unicode.SimpleFold(r)
						if next <= r {
							return next
						}
						r = next
					}
				}, key.(string)))
				child := name
				if path != "" {
					child = path + "." + name
				}
				if seen[name] {
					kind := "duplicate JSON field"
					if strings.HasPrefix(child, "behavior.") {
						kind = "duplicate behavior field"
					}
					return fmt.Errorf("%s %s: requires one unambiguous value", kind, child)
				}
				seen[name] = true
				if err := value(child); err != nil {
					return err
				}
			}
			if record && (!seen["id"] || !seen["value"]) {
				return fmt.Errorf("%s: requires both id and value", path)
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for i := 0; d.More(); i++ {
				if err := value(fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(""); err != nil {
		return fmt.Errorf("profile %q: %w", named.Name, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("profile %q: extra JSON data", named.Name)
	}
	return nil
}
