package networkquality

import (
	"fmt"
	"net/netip"
)

// AddressRule is one ordered network eligibility rule; Chromium's coarse
// IPv6 allowlist and consolidated IPv4 reservations are profile data.
type AddressRule struct {
	Prefix string `json:"prefix"`
	Public bool   `json:"public"`
}

// AddressPolicy selects ordered eligibility rules and explicit resolution fallbacks.
type AddressPolicy struct {
	Rules                   []AddressRule `json:"rules"`
	UnmapIPv4               bool          `json:"unmap_ipv4"`
	DefaultPublic           bool          `json:"default_public"`
	MissingResolutionPublic bool          `json:"missing_resolution_public"`
	LocalhostPublic         bool          `json:"localhost_public"`
}

// Validate rejects undefined, duplicate, noncanonical or unbounded prefix data.
func (p AddressPolicy) Validate() error {
	if len(p.Rules) < 1 || len(p.Rules) > 4096 {
		return fmt.Errorf("invalid network address rule count")
	}
	seen := map[string]bool{}
	for _, rule := range p.Rules {
		prefix, err := netip.ParsePrefix(rule.Prefix)
		if err != nil || prefix.Masked().String() != rule.Prefix || seen[rule.Prefix] {
			return fmt.Errorf("invalid/duplicate/canonical network prefix %q", rule.Prefix)
		}
		seen[rule.Prefix] = true
	}
	return nil
}

// Public matches actual addresses only. Unavailable peers cannot invent samples.
func (p AddressPolicy) Public(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if p.UnmapIPv4 {
		ip = ip.Unmap()
	}
	for _, rule := range p.Rules {
		prefix, err := netip.ParsePrefix(rule.Prefix)
		if err != nil {
			return false
		}
		if prefix.Contains(ip) {
			return rule.Public
		}
	}
	return p.DefaultPublic
}
