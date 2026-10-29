package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

// FieldOrigin describes provenance, not executable policy or a browser verdict.
type FieldOrigin struct {
	Class  string `json:"class"`
	Source string `json:"source"`
}

// CaptureProvenance is separate from the runnable browser profile. Its hashes
// bind the final profile, the full policy basis and the original capture.
// Capturing a field does not establish its invariance or browser acceptance.
type CaptureProvenance struct {
	Schema           int                    `json:"provenance_schema"`
	ProfileSHA256    string                 `json:"profile_sha256"`
	CaptureSHA256    string                 `json:"capture_canonical_sha256"`
	BasisName        string                 `json:"basis_name"`
	BasisSHA256      string                 `json:"basis_sha256"`
	Browser          *capture.Navigator     `json:"browser,omitempty"`
	BrowserMode      string                 `json:"browser_mode"`
	Fields           map[string]FieldOrigin `json:"fields"`
	DrawObservations *Drawn                 `json:"draw_observations,omitempty"`
	Acceptance       string                 `json:"acceptance"`
}

func canonicalHash(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ProvenanceForCapture binds a completed candidate after any explicit caller
// edits. It does not select policy, mutate inputs or mark inherited data measured.
func ProvenanceForCapture(candidate, basis *Profile, c *capture.Capture, mode string) (*CaptureProvenance, error) {
	if candidate == nil || basis == nil || c == nil {
		return nil, fmt.Errorf("profile: provenance requires candidate, basis and capture")
	}
	result := &CaptureProvenance{Schema: 1, BasisName: basis.Name, BrowserMode: mode, Fields: map[string]FieldOrigin{}, Acceptance: "candidate; browser/wire acceptance not established by capture"}
	var err error
	candidateBytes, err := candidate.Save()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(candidateBytes)
	result.ProfileSHA256 = hex.EncodeToString(sum[:])
	if result.BasisSHA256, err = canonicalHash(basis); err != nil {
		return nil, err
	}
	if err := basis.Validate(); err != nil {
		return nil, err
	}
	if result.CaptureSHA256, err = canonicalHash(c); err != nil {
		return nil, err
	}
	if c.Navigator != nil {
		b, _ := json.Marshal(c.Navigator)
		_ = json.Unmarshal(b, &result.Browser)
	}
	for key := range basis.Behavior {
		result.Fields["behavior."+key] = FieldOrigin{"inherited", "policy basis"}
	}
	for _, field := range basis.ClientHints {
		result.Fields["client_hints."+field.Name] = FieldOrigin{"inherited", "policy basis; context/persona values not remeasured"}
	}
	result.Fields["client_hello.template"] = FieldOrigin{"measured", "capture raw ClientHello; public changing bytes retained as provenance only"}
	result.Fields["client_hello.generated_fields"] = FieldOrigin{"generated/stateful", "basis generation rules and live engine connection/session state; never replay captured keys, randoms or tickets"}
	result.Fields["per_connection"] = FieldOrigin{"inherited", "basis generation constraints; finite draw observations are not a complete distribution"}
	result.Fields["headers"] = FieldOrigin{"inherited", "policy basis"}
	if c.HTTP2 != nil && len(c.HTTP2.Headers) > 0 {
		result.Fields["headers"] = FieldOrigin{"measured", "capture HTTP/2 fields; request-specific fields excluded"}
	}
	result.Fields["http2"] = FieldOrigin{"inherited", "policy basis; no complete H2 prelude observed"}
	if c.HTTP2 != nil && len(c.HTTP2.PseudoHeaderOrder) > 0 {
		result.Fields["http2"] = FieldOrigin{"measured", "capture SETTINGS, flow and header representation; unobserved initial stream choice inherited"}
	}
	if c.HTTP1 != nil && (len(c.HTTP1.Headers) > 0 || len(c.HTTP1.HeaderNames) > 0) {
		result.Fields["http1"] = FieldOrigin{"measured", "capture HTTP/1 fields"}
	} else {
		result.Fields["http1"] = FieldOrigin{"inherited", "policy basis"}
	}
	for _, field := range capturedPersonaHints(c) {
		result.Fields["client_hints."+field.Name] = FieldOrigin{"measured", "capture UA hint/persona field; original value retained, not a constancy claim"}
	}

	result.DrawObservations, err = DrawnOf(c)
	if err != nil {
		return nil, err
	}
	return result, nil
}
