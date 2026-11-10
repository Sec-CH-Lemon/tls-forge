package main

import (
	"crypto/rand"
	"fmt"
	"maps"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v2/networkquality"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

type networkHintSample struct {
	Scenario string      `json:"scenario"`
	Protocol string      `json:"protocol"`
	Request  int         `json:"request"`
	URL      string      `json:"url"`
	Headers  [][2]string `json:"headers"`
}

type networkHintValidation struct {
	Normalization string                     `json:"normalization"`
	Noise         networkquality.NoisePolicy `json:"noise"`
	ECT           []networkquality.ECTRule   `json:"ect"`
	Samples       []networkHintSample        `json:"samples"`
}

// Keep original normalized fields, including order/spelling, even on success.
func estimatedHintSamples(p *profile.Profile, got map[string]harness.MeasuredScenario) *networkHintValidation {
	if p.NetworkHints == nil || p.NetworkHints.Mode != "estimated" {
		return nil
	}
	out := &networkHintValidation{Normalization: "network-dependent equality only; require declared generator, presence, canonical encoding, JSON bounds/quantization/ECT vocabulary",
		Noise: p.NetworkHints.Policy.Noise, ECT: slices.Clone(p.NetworkHints.Policy.ECT), Samples: []networkHintSample{}}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		for _, proto := range []string{"h2", "h1"} {
			requests := got[id].H2
			if proto == "h1" {
				requests = got[id].H1
			}
			for i, request := range requests {
				sample := networkHintSample{Scenario: id, Protocol: proto, Request: i + 1, URL: request.URL}
				for _, header := range request.Headers {
					switch strings.ToLower(header[0]) {
					case "rtt", "downlink", "ect":
						sample.Headers = append(sample.Headers, header)
					}
				}
				if len(sample.Headers) > 0 {
					out.Samples = append(out.Samples, sample)
				}
			}
		}
	}
	return out
}

// comparisonValues includes actual output of a declared, implemented generator.
// These generated values establish availability; the existing byMachine rule
// compares presence, since Chrome and the client observe different networks.
// No captured network literals or dummy values are added to a profile.
func comparisonValues(p *profile.Profile) (map[string]string, error) {
	values := valuesOf(p)
	if p.NetworkHints == nil || p.NetworkHints.Mode != "estimated" {
		return values, nil
	}
	policy := p.NetworkHints.Policy
	if policy == nil || p.RuntimeBehavior().Text("headers.network_hints") != policy.Algorithm {
		return nil, fmt.Errorf("pinned: estimated network hints require their declared generator capability")
	}
	state, err := networkquality.NewState(*policy, policy.Environment.Fallback, time.Now, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pinned: network hint generator: %w", err)
	}
	maps.Copy(values, state.Hints(""))
	return values, nil
}

// estimatedHintDifferences strengthens presence-only comparison with the
// selected renderer's numeric bounds, quantization and ECT vocabulary. Raw
// browser values remain in the result; only network-dependent equality is
// normalized, exactly as it was for literal network personas.
func estimatedHintDifferences(p *profile.Profile, got map[string]harness.MeasuredScenario) []string {
	if p.NetworkHints == nil || p.NetworkHints.Mode != "estimated" {
		return nil
	}
	policy := p.NetworkHints.Policy
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(got)) {
		for _, proto := range []string{"h2", "h1"} {
			requests := got[id].H2
			if proto == "h1" {
				requests = got[id].H1
			}
			for i, request := range requests {
				for _, header := range request.Headers {
					if !validEstimatedHint(policy, strings.ToLower(header[0]), header[1]) {
						diff = append(diff, fmt.Sprintf("%s over %s, request %d: %s=%q violates the profile's network hint renderer", id, proto, i+1, header[0], header[1]))
					}
				}
			}
		}
	}
	return diff
}

func validEstimatedHint(p *networkquality.Policy, name, value string) bool {
	n := p.Noise
	switch name {
	case "rtt":
		number, err := strconv.ParseInt(value, 10, 64)
		maximum := int64(math.Round(float64(n.RTTCapMS)/float64(n.RTTQuantumMS))) * n.RTTQuantumMS
		return err == nil && strconv.FormatInt(number, 10) == value && number >= 0 && number <= maximum && number%n.RTTQuantumMS == 0
	case "downlink":
		number, err := strconv.ParseFloat(value, 64)
		if err != nil || strings.HasPrefix(value, "-") || math.IsNaN(number) || math.IsInf(number, 0) || strconv.FormatFloat(number, 'f', -1, 64) != value {
			return false
		}
		// Exact rational arithmetic keeps decimal quantization independent of
		// float representation (for example1.45 Mbps /50 Kbps).
		// The canonical finite decimal accepted above is always a rational.
		ratio, _ := new(big.Rat).SetString(value)
		ratio.Mul(ratio, big.NewRat(1000, n.DownlinkQuantumKbps))
		maximum := int64(math.Round(float64(n.DownlinkCapKbps) / float64(n.DownlinkQuantumKbps)))
		return ratio.IsInt() && ratio.Sign() >= 0 && ratio.Cmp(big.NewRat(maximum, 1)) <= 0
	case "ect":
		return value == n.MissingECT || slices.ContainsFunc(p.ECT, func(rule networkquality.ECTRule) bool { return rule.Label == value })
	default:
		return true
	}
}
