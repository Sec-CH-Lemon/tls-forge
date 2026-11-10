package profile

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v2/engine"
	"strings"
)

//go:embed engine-migration.json
var migrationData []byte

// Major declares compatibility explicitly when constructing a profile in Go.
func Major(n int) *int { return &n }

// ValidateEngine checks the actual compiled execution contract, not Schema or Name.
func (p *Profile) ValidateEngine() error { return p.validateEngineMajor(engine.Major()) }
func (p *Profile) validateEngineMajor(running int) error {
	name := "<nil>"
	if p != nil {
		name = p.Name
	}
	if p == nil || p.EngineMajor == nil {
		return fmt.Errorf("profile %q: engine_major is required; running engine major %d", name, running)
	}
	if *p.EngineMajor < 0 {
		return fmt.Errorf("profile %q: invalid engine_major %d; running engine major %d", name, *p.EngineMajor, running)
	}
	if *p.EngineMajor != running {
		return fmt.Errorf("profile %q: engine_major %d is incompatible with running engine major %d", name, *p.EngineMajor, running)
	}
	return nil
}

// Inspect decodes an archived profile for offline inspection. It does not grant
// permission to execute, nor add or change engine_major. Execution uses Load/New.
func Inspect(data []byte) (*Profile, error) { return decodeProfile(data, false) }

// Migrate explicitly creates a separately identified current-engine candidate.
// It preserves the source and capture provenance. The caller must perform the
// relevant browser/wire acceptance; this operation is not an equivalence claim.
func (p *Profile) Migrate(name string) (*Profile, error) {
	if p == nil || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("profile: migration needs a source and explicit destination name")
	}
	out := p.Clone()
	out.Name = name
	out.EngineMajor = Major(engine.Major())
	// Explicit migration alone applies the current data-owned additions. Offline
	// Inspect/Save and ordinary Load never complete or retag archived profiles.
	// An older schema without a behavior of its own gets them as it runs with
	// them, when it is saved below as a profile of this engine.
	if out.Behavior == nil {
		out.Behavior = p.RuntimeBehavior().Clone()
	}
	if out.Behavior != nil {
		for key, value := range p.rulesOfItsKind() {
			if !out.Behavior.Has(key) {
				out.Behavior[key] = append(json.RawMessage(nil), value...)
			}
		}
		var defaults struct {
			EngineMajor  *int                       `json:"engine_major"`
			Behavior     map[string]json.RawMessage `json:"behavior"`
			NetworkHints struct {
				WithLiterals    *NetworkHintsPolicy `json:"with_literals"`
				WithoutLiterals string              `json:"without_literals"`
			} `json:"network_hints"`
		}
		if err := json.Unmarshal(migrationData, &defaults); err != nil {
			return nil, err
		}
		if err := engine.CheckMajor("migration defaults", defaults.EngineMajor); err != nil {
			return nil, err
		}
		for key, value := range defaults.Behavior {
			if !out.Behavior.Has(key) {
				out.Behavior[key] = append(json.RawMessage(nil), value...)
			}
		}
		if !out.Behavior.Has("headers.network_hints") {
			selected := defaults.NetworkHints.WithoutLiterals
			if out.NetworkHints == nil {
				for _, fields := range out.networkHintFields() {
					for _, field := range fields {
						if networkHintName(field.Name) {
							out.NetworkHints = defaults.NetworkHints.WithLiterals.clone()
							break
						}
					}
					if out.NetworkHints != nil {
						break
					}
				}
			}
			if out.NetworkHints != nil {
				if err := out.validateNetworkHints(); err != nil {
					return nil, err
				}
				selected = out.NetworkHints.Mode
				if selected == "estimated" {
					selected = out.NetworkHints.Policy.Algorithm
				}
			}
			out.Behavior["headers.network_hints"], _ = json.Marshal(selected)
		}

	}
	if err := out.migrateQUICData(p.chromium()); err != nil {
		return nil, err
	}
	out.Notes += fmt.Sprintf("\nExplicit engine migration to %s (major %d) from profile %q; capture provenance retained; browser acceptance must be rechecked.", engine.Version(), engine.Major(), p.Name)
	data, err := out.Save()
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// checkMajorJSON rejects duplicate/invalid metadata before it can select a
// runtime. Decode the ordinary fields separately so offline inspection remains
// distinct from accepting an execution contract.
func checkMajorJSON(data []byte) error {
	var named struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(data, &named)
	major, err := engine.DeclaredMajor(data)
	if err != nil {
		return fmt.Errorf("profile %q: %w; running engine major %d", named.Name, err, engine.Major())
	}
	return engine.CheckMajor(fmt.Sprintf("profile %q", named.Name), major)
}
