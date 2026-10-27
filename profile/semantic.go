package profile

import (
	"fmt"
	"math"

	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/tls-client/profiles"
)

// Validate accepts an executable identity before any request-related I/O.
// Inspect and Save preserve representable archives without this permission.
// Engine compatibility remains an independent, mandatory first gate.
func (p *Profile) Validate() error {
	if err := p.ValidateEngine(); err != nil {
		return err
	}
	if err := p.validateBehavior(); err != nil {
		return err
	}
	if err := p.validateFields(); err != nil {
		return err
	}
	return p.validateHTTP2()
}

func (p *Profile) invalid(path string, value any, requirement string) error {
	return fmt.Errorf("profile %q: %s = %v: requires %s", p.Name, path, value, requirement)
}

func (p *Profile) validateHTTP2() error {
	h := p.HTTP2
	if p.BareBase() {
		// Bare bases use the pinned catalogue identity, not an invented copy of
		// its defaults. Refuse own fields that this representation would ignore.
		if h.ConnectionFlow != 0 || h.StreamID != 0 || len(h.Priorities) != 0 || h.HeaderPriority != nil || len(h.PseudoHeaderOrder) != 0 {
			return p.invalid("http2", h, "a full explicit HTTP2 profile to override a bare catalogue base")
		}
		base, ok := profiles.MappedTLSClients[p.Base]
		if !ok {
			return p.invalid("base", p.Base, "an available pinned catalogue identity")
		}
		h = HTTP2{ConnectionFlow: base.GetConnectionFlow(), StreamID: base.GetStreamID()}
		for _, id := range base.GetSettingsOrder() {
			h.Settings = append(h.Settings, Setting{uint16(id), base.GetSettings()[id]})
		}
		for _, pr := range base.GetPriorities() {
			h.Priorities = append(h.Priorities, Priority{pr.StreamID, pr.PriorityParam.Exclusive, pr.PriorityParam.StreamDep, pr.PriorityParam.Weight})
		}
		if pr := base.GetHeaderPriority(); pr != nil {
			h.HeaderPriority = &Priority{DependsOn: pr.StreamDep, Exclusive: pr.Exclusive, Weight: pr.Weight}
		}
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
		if s.ID == 9 && s.Value > 1 {
			return p.invalid(fmt.Sprintf("http2.settings[%d].value", i), s.Value, "0 or 1 (RFC9218)")
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
