package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// A policyAddition is a later data change that adds policy values alone: the
// values, where they come from, and each profile's bytes before and after.
// Unwinding takes them out again, through Save, and must give the bytes
// before exactly, so that the earlier layers' checks see the bytes they were
// made of. Layers are appended; an earlier one is never changed.
type policyAddition struct {
	Name     string                     `json:"name"`
	Source   string                     `json:"source"`
	Added    map[string]json.RawMessage `json:"added_policy"`
	Profiles map[string]struct {
		Before string `json:"before_sha256"`
		After  string `json:"after_sha256"`
	} `json:"profiles"`
}

func policyAdditions() ([]policyAddition, error) {
	raw, err := os.ReadFile("provenance/policy-additions.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Schema int              `json:"schema"`
		Major  int              `json:"engine_major"`
		Layers []policyAddition `json:"layers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Schema != 1 || doc.Major != 1 || len(doc.Layers) == 0 {
		return nil, fmt.Errorf("invalid policy-addition inventory")
	}
	for _, layer := range doc.Layers {
		if layer.Name == "" || layer.Source == "" || len(layer.Added) == 0 || len(layer.Profiles) != 21 {
			return nil, fmt.Errorf("incomplete policy-addition layer %q", layer.Name)
		}
	}
	return doc.Layers, nil
}

// unwindPolicyAdditions takes out every layer the bytes are the result of,
// the latest first, and returns the bytes of before the first. Bytes no layer
// made come back as they are, for the earlier layers to judge.
func unwindPolicyAdditions(raw []byte) ([]byte, error) {
	layers, err := policyAdditions()
	if err != nil {
		return nil, err
	}
	for range len(layers) + 1 {
		sum, matched := a13SHA(raw), false
		for _, layer := range layers {
			for _, row := range layer.Profiles {
				if row.After != sum {
					continue
				}
				if raw, err = undoPolicyAddition(raw, layer, row.Before); err != nil {
					return nil, err
				}
				matched = true
				break
			}
			if matched {
				break
			}
		}
		if !matched {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("cyclic policy-addition provenance")
}

func undoPolicyAddition(raw []byte, layer policyAddition, before string) ([]byte, error) {
	p, err := Load(raw)
	if err != nil {
		return nil, err
	}
	for key, want := range layer.Added {
		got, ok := p.Behavior[key]
		if !ok || !sameJSON(got, want) {
			return nil, fmt.Errorf("%s: %s is not the value the layer added", layer.Name, key)
		}
		delete(p.Behavior, key)
	}
	out, err := p.Save()
	if err != nil {
		return nil, err
	}
	if a13SHA(out) != before {
		return nil, fmt.Errorf("%s changed another profile field", layer.Name)
	}
	return out, nil
}

func sameJSON(a, b json.RawMessage) bool {
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}

// policyAdded says which layer added a key, for the origin tests.
func policyAdded(t *testing.T, key string) (policyAddition, bool) {
	t.Helper()
	layers, err := policyAdditions()
	if err != nil {
		t.Fatal(err)
	}
	for _, layer := range layers {
		if _, ok := layer.Added[key]; ok {
			return layer, true
		}
	}
	return policyAddition{}, false
}

// Every layer leaves the 21 Chrome profiles what Save writes, adds what it
// says and nothing else, and is anchored on the bytes the layer before it, or
// the release hints and network derivation before them, left.
func TestPolicyAdditionsPreserveEveryEarlierLayer(t *testing.T) {
	layers, err := policyAdditions()
	if err != nil {
		t.Fatal(err)
	}
	network, err := networkDerivations()
	if err != nil {
		t.Fatal(err)
	}
	hints, err := hintBuildDerivations()
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]string{}
	for path, row := range network {
		anchors[path] = row.AfterSHA
	}
	for _, row := range hints {
		if anchors[row.Path] == row.BeforeSHA {
			anchors[row.Path] = row.AfterSHA
		}
	}
	seen := map[string]bool{}
	for _, layer := range layers {
		for path, row := range layer.Profiles {
			if anchors[path] != row.Before {
				t.Fatalf("%s: %s is not anchored on the layer before it", layer.Name, path)
			}
			anchors[path] = row.After
		}
		for key := range layer.Added {
			if seen[key] {
				t.Fatalf("%s is added twice", key)
			}
			seen[key] = true
		}
	}
	for path, after := range anchors {
		raw, err := os.ReadFile("../" + path)
		if err != nil {
			t.Fatal(err)
		}
		if a13SHA(raw) != after {
			t.Fatalf("%s differs from its latest layer", path)
		}
		before, err := unwindPolicyAdditions(raw)
		if err != nil {
			t.Fatal(path, err)
		}
		if want := layers[0].Profiles[path].Before; a13SHA(before) != want {
			t.Fatalf("%s did not unwind to the bytes before the first layer", path)
		}

		// A field the layers do not name, changed with the hashes made to
		// match, is not hidden.
		p, err := Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		p.UserAgent += " foreign"
		bad, err := p.Save()
		if err != nil {
			t.Fatal(err)
		}
		last := layers[len(layers)-1]
		if _, err := undoPolicyAddition(bad, last, last.Profiles[path].Before); err == nil || !strings.Contains(err.Error(), "another profile field") {
			t.Fatalf("%s: an unrelated change was hidden: %v", path, err)
		}
		// A value other than the layer's is not taken for it.
		for key, value := range last.Added {
			changed := p.Clone()
			changed.UserAgent = strings.TrimSuffix(changed.UserAgent, " foreign")
			changed.Behavior[key] = otherValue(t, value)
			other, err := changed.Save()
			if err != nil {
				t.Fatal(key, err)
			}
			if _, err := undoPolicyAddition(other, last, last.Profiles[path].Before); err == nil || !strings.Contains(err.Error(), "not the value the layer added") {
				t.Fatalf("%s: another %s was taken for the layer's: %v", path, key, err)
			}
		}
	}
}

// otherValue is a value of the same kind as v the registry takes too.
func otherValue(t *testing.T, v json.RawMessage) json.RawMessage {
	t.Helper()
	var x any
	if err := json.Unmarshal(v, &x); err != nil {
		t.Fatal(err)
	}
	switch x := x.(type) {
	case bool:
		x = !x
		out, _ := json.Marshal(x)
		return out
	case float64:
		out, _ := json.Marshal(x + 1)
		return out
	case string:
		out, _ := json.Marshal(x + " Again.")
		return out
	}
	t.Fatalf("no other value of %s", v)
	return nil
}
