package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type a13Derivation struct {
	Fields            map[string]FieldOrigin `json:"fields"`
	BeforeSHA         string                 `json:"before_sha256"`
	AfterSHA          string                 `json:"after_sha256"`
	BeforeSemanticSHA string                 `json:"before_semantic_sha256"`
	Added             []string               `json:"added_policy_keys"`
}

func a13SHA(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func a13DerivationOf(t *testing.T, path string) a13Derivation {
	t.Helper()
	raw, err := os.ReadFile("provenance/a13-quic-ownership.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema   int                      `json:"schema"`
		Major    int                      `json:"engine_major"`
		Profiles map[string]a13Derivation `json:"profiles"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Major != 1 || len(doc.Profiles) != 21 {
		t.Fatal("incomplete derivation inventory")
	}
	row, ok := doc.Profiles[path]
	if !ok {
		t.Fatal("missing profile derivation", path)
	}
	return row
}
func checkA13Derivation(raw []byte, row a13Derivation, originalSHA string) error {
	if err := validateProfileJSON(raw); err != nil {
		return err
	}
	actualSHA := a13SHA(raw)
	if bytes.Contains(raw, []byte(`"headers.network_hints"`)) {
		var err error
		raw, actualSHA, err = unwindA13NetworkDerivation(raw, row.AfterSHA)
		if err != nil {
			return err
		}
	}
	if row.BeforeSHA != originalSHA || row.AfterSHA != actualSHA {
		return fmt.Errorf("profile byte/source digest mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	policy, ok := value["behavior"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing behavior")
	}
	if len(row.Added) != 16 {
		return fmt.Errorf("unexpected migration choice count")
	}
	for _, key := range row.Added {
		if _, ok := policy[key]; !ok {
			return fmt.Errorf("missing added choice %s", key)
		}
		delete(policy, key)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if a13SHA(canonical) != row.BeforeSemanticSHA {
		return fmt.Errorf("old profile fields changed")
	}
	return nil
}
func assertA13Derivation(t *testing.T, path string, raw []byte, originalSHA string) {
	t.Helper()
	if err := checkA13Derivation(raw, a13DerivationOf(t, path), originalSHA); err != nil {
		t.Fatal(err)
	}
}
func TestA13ProfileDerivationRejectsChangesOutsideNewChoices(t *testing.T) {
	path := "profile/data/chrome_156/macos.json"
	raw, err := os.ReadFile("data/chrome_156/macos.json")
	if err != nil {
		t.Fatal(err)
	}
	row := a13DerivationOf(t, path)
	if err = checkA13Derivation(raw, row, row.BeforeSHA); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["user_agent"] = json.RawMessage(`"negative-control"`)
	bad, _ := json.Marshal(fields)
	changed := row
	changed.AfterSHA = a13SHA(bad)
	if err = checkA13Derivation(bad, changed, row.BeforeSHA); err == nil {
		t.Fatal("changing an existing browser field hidden by refreshed after hash")
	}
	changed = row
	changed.BeforeSHA = "foreign"
	if err = checkA13Derivation(raw, changed, row.BeforeSHA); err == nil {
		t.Fatal("foreign source accepted")
	}
}
