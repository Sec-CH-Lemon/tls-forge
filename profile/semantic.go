package profile

import (
	"fmt"
	"math"

	"github.com/igor-lemon/fhttp/http2"
)

// Validate accepts an executable identity before any request-related I/O.
// Inspect and Save preserve representable archives without this permission.
// Engine compatibility remains an independent, mandatory first gate.
func (p *Profile) Validate() error {
	_, err := p.validate()
	return err
}

// validate returns the same data-backed base that it checked. Adapter creation
// must not independently resolve a second representation after validation.
func (p *Profile) validate() (*Profile, error) {
	if err := p.ValidateEngine(); err != nil {
		return nil, err
	}
	if p.Name == "" {
		return nil, fmt.Errorf("profile: name is required")
	}
	if err := p.validateBehavior(); err != nil {
		return nil, err
	}
	if (p.RuntimeBehavior().Text("quic.tls_source") == "independent") != (p.QUICTLSSpec != nil) {
		return nil, fmt.Errorf("profile %q: independent QUIC TLS source and quic_tls_spec must be selected together", p.Name)
	}
	if len(p.ClientHello) > 0 && p.TLSSpec == nil && p.PerConnection == nil {
		return nil, fmt.Errorf("profile %q: raw client_hello requires explicit per_connection generation rules", p.Name)
	}
	if err := p.validateFields(); err != nil {
		return nil, err
	}
	var base *Profile
	if p.BareBase() {
		h := p.HTTP2
		if h.ConnectionFlow != 0 || h.StreamID != 0 || len(h.Priorities) != 0 || h.HeaderPriority != nil || len(h.PseudoHeaderOrder) != 0 {
			return nil, p.invalid("http2", h, "a full explicit HTTP2 profile to override a bare catalogue base")
		}
		var err error
		base, err = catalogueProfile(p.Base)
		if err != nil {
			return nil, p.invalid("base", p.Base, "an available pinned catalogue identity: "+err.Error())
		}
	}
	return base, p.validateHTTP2(base)
}

// RFC 9113 leaves SETTINGS_HEADER_TABLE_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE
// open, and the transport sizes its HPACK decoder by them: what a server may
// make the client keep is bounded here, as HTTP/3's QPACK table is in the
// registry. The unlimited advertised sentinel still uses the decoder's 16 MiB
// default; it does not permit unbounded allocation.
const (
	maxHeaderTableBytes = 1 << 20
	maxHeaderListBytes  = 16 << 20
)

func (p *Profile) invalid(path string, value any, requirement string) error {
	return fmt.Errorf("profile %q: %s = %v: requires %s", p.Name, path, value, requirement)
}

func (p *Profile) validateHTTP2(base *Profile) error {
	h := p.HTTP2
	if base != nil {
		h = base.HTTP2
	}
	// The peer's initial maximum frame payload is 16384 before its SETTINGS.
	if len(h.Settings) > 16384/6 {
		return p.invalid("http2.settings", len(h.Settings), "an initial SETTINGS payload no larger than 16384 bytes")
	}
	seen := map[uint16]bool{}
	for i, s := range h.Settings {
		if seen[s.ID] {
			return p.invalid(fmt.Sprintf("http2.settings[%d].id", i), s.ID, "one occurrence; repeated SETTINGS representation is unsupported (not an RFC prohibition)")
		}
		seen[s.ID] = true
		if err := (http2.Setting{ID: http2.SettingID(s.ID), Val: s.Value}).Valid(); err != nil {
			constraint := "the HTTP/2 setting's protocol range"
			switch s.ID {
			case 2, 8, 9:
				constraint = "0 or 1"
			case 4:
				constraint = "0..2147483647"
			case 5:
				constraint = "16384..16777215"
			}
			return p.invalid(fmt.Sprintf("http2.settings[%d].value", i), s.Value, constraint)
		}
		switch {
		case s.ID == 9 && s.Value > 1:
			return p.invalid(fmt.Sprintf("http2.settings[%d].value", i), s.Value, "0 or 1 (RFC9218)")
		case s.ID == 1 && s.Value > maxHeaderTableBytes:
			return p.invalid(fmt.Sprintf("http2.settings[%d].value", i), s.Value, "at most 1048576, the engine's bound on the HPACK table a server can fill")
		// fhttp maps its all-ones backend sentinel to Framer's zero, which
		// enforces its 16 MiB default. Other large values bypass that
		// safety bound and remain forbidden.
		case s.ID == 6 && s.Value > maxHeaderListBytes && s.Value != math.MaxUint32:
			return p.invalid(fmt.Sprintf("http2.settings[%d].value", i), s.Value, "at most 16777216, the engine's bound on a header list a server can send")
		}
	}
	if h.StreamID > math.MaxInt32 || h.StreamID != 0 && h.StreamID%2 == 0 {
		return p.invalid("http2.stream_id", h.StreamID, "0 (initial/default state) or an odd client stream ID in 1..2147483647")
	}
	first := h.StreamID
	if first == 0 {
		first = 1
	}
	for i, pr := range h.Priorities {
		path := fmt.Sprintf("http2.priorities[%d]", i)
		if pr.StreamID == 0 || pr.StreamID%2 == 0 || pr.StreamID > math.MaxInt32-2 {
			return p.invalid(path+".stream_id", pr.StreamID, "an odd client stream ID in 1..2147483645, leaving room for the initial request")
		}
		if err := p.validateDependency(path, pr, pr.StreamID); err != nil {
			return err
		}
		first = pr.StreamID + 2 // the existing transport starts after its final PRIORITY
	}
	if h.HeaderPriority != nil {
		if h.HeaderPriority.StreamID > math.MaxInt32 || h.HeaderPriority.StreamID != 0 && h.HeaderPriority.StreamID%2 == 0 {
			return p.invalid("http2.header_priority.stream_id", h.HeaderPriority.StreamID, "0 or an observed odd 31-bit client stream ID; the live HEADERS stream is request-derived")
		}
		if err := p.validateDependency("http2.header_priority", *h.HeaderPriority, first); err != nil {
			return err
		}
		dep := h.HeaderPriority.DependsOn
		if p.RuntimeBehavior().Text("h2.priority_dependency") != "nearest-weight" && dep%2 == 1 && dep >= first {
			return p.invalid("http2.header_priority.depends_on", dep, "a fixed client-stream dependency preceding the first request; a future request must not depend on itself")
		}
	}
	if h.ConnectionFlow > math.MaxInt32-65535 {
		return p.invalid("http2.connection_flow", h.ConnectionFlow, "an increment no greater than 2147418112; initial 65535 plus increment must fit the 31-bit window")
	}
	return nil
}

func (p *Profile) validateDependency(path string, pr Priority, stream uint32) error {
	if pr.DependsOn > math.MaxInt32 || pr.DependsOn == stream {
		return p.invalid(path+".depends_on", pr.DependsOn, fmt.Sprintf("0..2147483647 and a dependency other than stream %d", stream))
	}
	return nil
}
