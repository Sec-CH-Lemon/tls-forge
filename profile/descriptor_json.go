package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

// decodeDescriptorData rejects omitted, null, misspelled and unknown parameters rather
// than letting encoding/json's case folding and zero defaults choose behavior.
func decodeDescriptorData(data []byte, target any) error {
	if err := validateProfileJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	// Types and unknown fields are checked above. Shape validation additionally
	// rejects JSON null, omitted fields and encoding/json's case-folded names.
	return checkDescriptorShape(data, reflect.TypeOf(target).Elem())
}

func checkDescriptorShape(data []byte, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("descriptor data must not be null")
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil // The extension primitive checks its own parameter object.
	}
	if t.Kind() == reflect.Slice {
		if t.Elem().Kind() == reflect.Uint8 && bytes.HasPrefix(bytes.TrimSpace(data), []byte(`"`)) {
			return nil
		} // encoding/json accepts base64 byte strings.
		var values []json.RawMessage
		_ = json.Unmarshal(data, &values) // The typed decoder already accepted this slice.
		for _, raw := range values {
			if err := checkDescriptorShape(raw, t.Elem()); err != nil {
				return err
			}
		}
		return nil
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields) // The typed decoder already accepted this object.
	if fields == nil || len(fields) != t.NumField() {
		return fmt.Errorf("requires every declared parameter exactly once")
	}
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Tag.Get("json")
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("requires non-null %s", name)
		}
		if err := checkDescriptorShape(raw, t.Field(i).Type); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}
