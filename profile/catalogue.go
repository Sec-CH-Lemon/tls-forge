package profile

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed catalogue.json
var catalogueTemplate []byte

var catalogueCache struct {
	sync.Mutex
	hash    [32]byte
	entries map[string]json.RawMessage
}

func catalogueEntries() (map[string]json.RawMessage, error) {
	catalogueCache.Lock()
	defer catalogueCache.Unlock()
	hash := sha256.Sum256(catalogueTemplate)
	if catalogueCache.entries != nil && catalogueCache.hash == hash {
		return catalogueCache.entries, nil
	}

	if err := validateProfileJSON(catalogueTemplate); err != nil {
		return nil, err
	}
	var inventory struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	decoder := json.NewDecoder(bytes.NewReader(catalogueTemplate))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return nil, err
	}
	catalogueCache.hash, catalogueCache.entries = hash, inventory.Entries
	return inventory.Entries, nil
}
func catalogueProfile(name string) (*Profile, error) {
	entries, err := catalogueEntries()
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	data, ok := entries[name]
	if !ok {
		return nil, fmt.Errorf("profile %q: no explicit engine-compatible catalogue policy", name)
	}
	// Catalogue descriptors cannot refer back to catalogue aliases. Reject
	// recursive/cyclic data before executable validation follows the base.
	var identity struct {
		Base string `json:"base"`
	}
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("catalogue %q: %w", name, err)
	}
	if identity.Base != "" {
		return nil, fmt.Errorf("catalogue %q: base indirection is forbidden; require a complete descriptor", name)
	}
	p, err := Load(data)
	if err != nil {
		return nil, fmt.Errorf("catalogue %q: %w", name, err)
	}
	if p.Name != name {
		return nil, fmt.Errorf("catalogue %q: entry name %q differs from its alias", name, p.Name)
	}
	p.catalogue = true
	return p, nil
}
