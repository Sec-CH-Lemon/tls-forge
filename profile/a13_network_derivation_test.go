package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type networkRemovedField struct {
	Index int             `json:"index"`
	Field json.RawMessage `json:"field"`
}
type networkDerivation struct {
	Mode              string                           `json:"mode"`
	BeforeSHA         string                           `json:"before_sha256"`
	BeforeSemanticSHA string                           `json:"before_semantic_sha256"`
	AfterSHA          string                           `json:"after_sha256"`
	Removed           map[string][]networkRemovedField `json:"removed_fields"`
}

func networkDerivations() (map[string]networkDerivation, error) {
	raw, e := os.ReadFile("provenance/a13-network-hints.json")
	if e != nil {
		return nil, e
	}
	var doc struct {
		Schema   int                          `json:"schema"`
		Major    int                          `json:"engine_major"`
		Profiles map[string]networkDerivation `json:"profiles"`
	}
	if e = json.Unmarshal(raw, &doc); e != nil {
		return nil, e
	}
	if doc.Schema != 1 || doc.Major != 1 || len(doc.Profiles) != 21 {
		return nil, fmt.Errorf("incomplete network derivation inventory")
	}
	return doc.Profiles, nil
}

// Verify the exact new bytes and undo ONLY this documented derivative before
// checking the earlier immutable QUIC derivation. Earlier hashes are unchanged.
func unwindA13NetworkDerivation(raw []byte, beforeSHA string) ([]byte, string, error) {
	var refreshErr error
	raw, refreshErr = unwindPolicyAdditions(raw)
	if refreshErr != nil {
		return nil, "", refreshErr
	}
	raw, refreshErr = unwindHintBuildDerivations(raw)
	if refreshErr != nil {
		return nil, "", refreshErr
	}
	rows, e := networkDerivations()
	if e != nil {
		return nil, "", e
	}
	for _, row := range rows {
		if row.BeforeSHA != beforeSHA {
			continue
		}
		if a13SHA(raw) != row.AfterSHA {
			return nil, "", fmt.Errorf("network derivative byte digest mismatch")
		}
		var value map[string]json.RawMessage
		if e = json.Unmarshal(raw, &value); e != nil {
			return nil, "", e
		}
		delete(value, "network_hints")
		var policy map[string]json.RawMessage
		if e = json.Unmarshal(value["behavior"], &policy); e != nil {
			return nil, "", e
		}
		delete(policy, "headers.network_hints")
		value["behavior"], _ = json.Marshal(policy)
		for key, removed := range row.Removed {
			var fields []json.RawMessage
			if e = json.Unmarshal(value[key], &fields); e != nil {
				return nil, "", e
			}
			for _, r := range removed {
				if r.Index < 0 || r.Index > len(fields) {
					return nil, "", fmt.Errorf("invalid removed field index")
				}
				fields = append(fields, nil)
				copy(fields[r.Index+1:], fields[r.Index:])
				fields[r.Index] = r.Field
			}
			value[key], _ = json.Marshal(fields)
		}
		restored, _ := json.Marshal(value)
		var v any
		d := json.NewDecoder(bytes.NewReader(restored))
		d.UseNumber()
		if e = d.Decode(&v); e != nil {
			return nil, "", e
		}
		canonical, _ := json.Marshal(v)
		if a13SHA(canonical) != row.BeforeSemanticSHA {
			return nil, "", fmt.Errorf("network derivative changed an unrelated historical field")
		}
		return canonical, row.BeforeSHA, nil
	}
	return nil, "", fmt.Errorf("missing network derivative for %s", beforeSHA)
}

func TestA13NetworkDerivationsPreserveAllEarlierFields(t *testing.T) {
	rows, e := networkDerivations()
	if e != nil {
		t.Fatal(e)
	}
	for path, row := range rows {
		t.Run(path, func(t *testing.T) {
			raw, e := os.ReadFile("../" + path)
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e = unwindA13NetworkDerivation(raw, row.BeforeSHA); e != nil {
				t.Fatal(e)
			}
			p, e := Load(raw)
			if e != nil {
				t.Fatal(e)
			}
			if row.Mode == "none" {
				if p.NetworkHints != nil || p.Behavior.Text("headers.network_hints") != "none" {
					t.Fatal("historical profile acquired unmeasured network hints")
				}
			} else {
				if p.NetworkHints == nil || p.NetworkHints.Mode != "estimated" || p.NetworkHints.Policy.Environment.Identity != "connection-type" {
					t.Fatal("missing source-derived generator")
				}
				want := "headers"
				if strings.Contains(path, "chrome_152/") {
					want = "next-step"
				}
				if p.NetworkHints.Policy.Compute.HeaderDelivery != want || p.NetworkHints.Policy.Compute.TransactionStart != want {
					t.Fatal("source header delivery changed")
				}
				for _, fields := range p.networkHintFields() {
					for _, f := range fields {
						if networkHintName(f.Name) {
							t.Fatal("captured production network literal", f)
						}
					}
				}
			}

			bad := bytes.Replace(raw, []byte(`"user_agent":`), []byte(`"foreign":`), 1)
			if _, _, e = unwindA13NetworkDerivation(bad, row.BeforeSHA); e == nil {
				t.Fatal("unrelated mutation hidden")
			}
		})
	}
}
