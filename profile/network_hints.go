package profile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/networkquality"
)

// NetworkHintsPolicy makes literal network persona data distinct from an actual
// estimator. Estimated mode has no captured production hint values; its policy
// describes selection, measurement, generation and lifecycle mechanisms.
type NetworkHintsPolicy struct {
	Mode   string                 `json:"mode"`
	Policy *networkquality.Policy `json:"policy,omitempty"`
}

// UnmarshalJSON rejects missing, duplicate, unknown, case-folded or null choices.
func (p *NetworkHintsPolicy) UnmarshalJSON(raw []byte) error {
	var tag struct {
		Mode string `json:"mode"`
	}
	if e := json.Unmarshal(raw, &tag); e != nil {
		return e
	}
	switch tag.Mode {
	case "literal":
		var value struct {
			Mode string `json:"mode"`
		}
		if e := decodeDescriptorData(raw, &value); e != nil {
			return e
		}
		*p = NetworkHintsPolicy{Mode: value.Mode}
	case "estimated":
		var value struct {
			Mode   string                `json:"mode"`
			Policy networkquality.Policy `json:"policy"`
		}
		if e := decodeDescriptorData(raw, &value); e != nil {
			return e
		}
		if e := value.Policy.Validate(); e != nil {
			return e
		}
		*p = NetworkHintsPolicy{Mode: value.Mode, Policy: &value.Policy}
	default:
		return fmt.Errorf("unsupported network_hints mode %q", tag.Mode)
	}
	return nil
}
func (p *NetworkHintsPolicy) clone() *NetworkHintsPolicy {
	if p == nil {
		return nil
	}
	out := *p
	if p.Policy != nil {
		policy := p.Policy.Clone()
		out.Policy = &policy
	}
	return &out
}
func (p *Profile) validateNetworkHints() error {
	if p.NetworkHints == nil {
		return nil
	}
	switch p.NetworkHints.Mode {
	case "literal":
		if p.NetworkHints.Policy != nil {
			return fmt.Errorf("literal network_hints must not carry an estimator")
		}
		for _, fields := range p.networkHintFields() {
			for _, field := range fields {
				if err := validateLiteralNetworkHint(field); err != nil {
					return err
				}
			}
		}
	case "estimated":
		if p.NetworkHints.Policy == nil {
			return fmt.Errorf("estimated network_hints requires policy")
		}
		if e := p.NetworkHints.Policy.Validate(); e != nil {
			return e
		}
		for _, fields := range p.networkHintFields() {
			for _, f := range fields {
				switch strings.ToLower(f.Name) {
				case "rtt", "downlink", "ect":
					return fmt.Errorf("estimated network_hints conflicts with literal %s", f.Name)
				}
			}
		}
	default:
		return fmt.Errorf("unsupported network_hints mode %q", p.NetworkHints.Mode)
	}
	return nil
}

// The mandatory registry choice also makes earlier same-major engine snapshots
// reject this capability. Inspect/Save keep archives without adding the choice.
func (p *Profile) validateNetworkHintCapability() error {
	selected := p.RuntimeBehavior().Text("headers.network_hints")
	if p.NetworkHints == nil {
		if selected != "none" {
			return fmt.Errorf("network_hints requires explicit configuration for %s", selected)
		}
		for _, fields := range p.networkHintFields() {
			for _, field := range fields {
				if networkHintName(field.Name) {
					return fmt.Errorf("literal %s requires explicit literal network_hints", field.Name)
				}
			}
		}
		return nil
	}
	want := p.NetworkHints.Mode
	if want == "estimated" {
		want = p.NetworkHints.Policy.Algorithm
	}
	if selected != want {
		return fmt.Errorf("network_hints mode %s conflicts with capability %s", p.NetworkHints.Mode, selected)
	}
	return nil
}

func networkHintName(name string) bool {
	switch strings.ToLower(name) {
	case "rtt", "downlink", "ect":
		return true
	}
	return false
}

func validateLiteralNetworkHint(field Field) error {
	name, value := strings.ToLower(field.Name), field.Value
	valid := true
	switch name {
	case "rtt":
		valid = hintDigits(value, 15)
	case "downlink":
		integer, fraction, dot := strings.Cut(value, ".")
		// Chromium also serializes integral Mbps without a decimal point. Keep
		// that measured wire form distinct from a strict Structured Decimal.
		valid = hintDigits(integer, 12) && (!dot || hintDigits(fraction, 3))
	case "ect":
		valid = value == "slow-2g" || value == "2g" || value == "3g" || value == "4g"
	}
	if !valid {
		return fmt.Errorf("invalid literal network hint %s=%q", name, value)
	}
	return nil
}

func hintDigits(value string, maxDigits int) bool {
	if len(value) == 0 || len(value) > maxDigits {
		return false
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// HTTP/1 overrides are executable fields too; they cannot bypass the generator.
func (p *Profile) networkHintFields() [][]Field {
	fields := [][]Field{p.Headers, p.ClientHints}
	if p.HTTP1 != nil {
		fields = append(fields, p.HTTP1.Headers)
	}
	return fields
}
