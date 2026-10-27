package profile

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed catalogue.json
var catalogueTemplate []byte

// Policy choices and compatibility are pinned in JSON for every known backend
// entry. A new dependency preset needs an explicit data entry, never inference.
func catalogueProfile(name string) (*Profile, error) {
	var inventory struct {
		Entries   map[string]string          `json:"entries"`
		Templates map[string]json.RawMessage `json:"templates"`
	}
	decoder := json.NewDecoder(bytes.NewReader(catalogueTemplate))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return nil, err
	}
	key, ok := inventory.Entries[name]
	if !ok {
		return nil, fmt.Errorf("profile %q: no explicit engine-compatible catalogue policy", name)
	}
	if err := checkMajorJSON(inventory.Templates[key]); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	if err := validateProfileJSON(inventory.Templates[key]); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	// checkMajorJSON read the template as one JSON object: it unmarshals, and
	// its fields marshal again.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(inventory.Templates[key], &fields)
	fields["name"], _ = json.Marshal(name)
	fields["base"], _ = json.Marshal(name)
	data, _ := json.Marshal(fields)
	return Load(data)
}
