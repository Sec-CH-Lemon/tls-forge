package networkquality

import (
	"math"
	"strings"
	"testing"
)

func TestPolicyRejectsUnsupportedAmbiguousAndUnboundedChoices(t *testing.T) {
	for name, edit := range map[string]func(*Policy){
		"header-delivery":                     func(p *Policy) { p.Compute.HeaderDelivery = "guess" },
		"ect-label":                           func(p *Policy) { p.ECT[0].Label = "made-up" },
		"ect-rtt-overflow":                    func(p *Policy) { p.ECT[0].TypicalHTTPMS = math.MaxInt32 + 1 },
		"ect-transport-overflow":              func(p *Policy) { p.ECT[0].TypicalTransportMS = math.MaxInt32 + 1 },
		"ect-downlink-overflow":               func(p *Policy) { p.ECT[0].TypicalKbps = math.MaxInt32 + 1 },
		"ect-threshold-overflow":              func(p *Policy) { p.ECT[0].MinHTTPMS = math.MaxInt32 + 1 },
		"offline-label":                       func(p *Policy) { p.OfflineECT = "made-up" },
		"unknown-label":                       func(p *Policy) { p.UnknownECT = "made-up" },
		"missing-ect-label":                   func(p *Policy) { p.Noise.MissingECT = "made-up" },
		"empty-method":                        func(p *Policy) { p.Methods = []string{""} },
		"invalid-method":                      func(p *Policy) { p.Methods = []string{"GET\r\n"} },
		"long-method":                         func(p *Policy) { p.Methods = []string{strings.Repeat("a", 257)} },
		"duplicate-method":                    func(p *Policy) { p.Methods = []string{"GET", "GET"} },
		"metadata-source":                     func(p *Policy) { p.Environment.Source = "guessed" },
		"metadata-missing":                    func(p *Policy) { p.Environment.Missing = "ignore" },
		"metadata-fallback":                   func(p *Policy) { p.Environment.Fallback.Type = "made-up" },
		"metadata-identity":                   func(p *Policy) { p.Environment.Identity = "captured-ssid" },
		"metadata-family-missing":             func(p *Policy) { p.Environment.Families = nil },
		"metadata-family-duplicate":           func(p *Policy) { p.Environment.Families = []string{"ipv4", "ipv4"} },
		"metadata-family-unknown":             func(p *Policy) { p.Environment.Families = []string{"ipv7"} },
		"salt-lifecycle":                      func(p *Policy) { p.Noise.Scope = "per-header" },
		"start-delivery":                      func(p *Policy) { p.Compute.TransactionStart = "made-up" },
		"algorithm":                           func(p *Policy) { p.Algorithm = "unknown" },
		"duplicate-metric":                    func(p *Policy) { p.Metrics = append(p.Metrics, p.Metrics[0]) },
		"metric-missing":                      func(p *Policy) { p.Metrics = p.Metrics[:3] },
		"metric-capacity":                     func(p *Policy) { p.Metrics[0].Buffer.Capacity = 65537 },
		"negative-recent-window":              func(p *Policy) { p.Metrics[0].RecentMS = -1 },
		"percentile":                          func(p *Policy) { p.Metrics[0].Percentile = 101 },
		"source":                              func(p *Policy) { p.Sources[0].Name = "made-up" },
		"duplicate-source":                    func(p *Policy) { p.Sources = append(p.Sources, p.Sources[0]) },
		"source-missing":                      func(p *Policy) { p.Sources = p.Sources[:7] },
		"category":                            func(p *Policy) { p.Sources[0].Categories = []string{"made-up"} },
		"duplicate-category":                  func(p *Policy) { p.Sources[0].Categories = []string{"http", "http"} },
		"no-categories":                       func(p *Policy) { p.Sources[0].Categories = nil },
		"seed-unavailable-with-nonzero-value": func(p *Policy) { p.Seeds[0].HTTP = Metric{Value: 1} },
		"seed-outside-int32":                  func(p *Policy) { p.Seeds[0].HTTP.Value = math.MaxInt32 + 1 },
		"duplicate-seed":                      func(p *Policy) { p.Seeds = append(p.Seeds, p.Seeds[0]) },
		"no-unknown-network-seed":             func(p *Policy) { p.Seeds = p.Seeds[1:] },
		"no-ect":                              func(p *Policy) { p.ECT = nil },
		"unordered-ect":                       func(p *Policy) { p.ECT[1].MinHTTPMS = p.ECT[0].MinHTTPMS },
		"no-fastest-threshold":                func(p *Policy) { p.ECT[3].MinHTTPMS = 1 },
		"negative-duration":                   func(p *Policy) { p.Compute.IntervalMS = -1 },
		"unbounded-duration":                  func(p *Policy) { p.Compute.IntervalMS = math.MaxInt32 + 1 },
		"nan-multiplier":                      func(p *Policy) { p.Compute.EndUpper = math.NaN() },
		"infinite-multiplier":                 func(p *Policy) { p.Compute.EndUpper = math.Inf(1) },
		"invalid-growth":                      func(p *Policy) { p.Compute.GrowthRatio = .5 },
		"no-hanging-reference":                func(p *Policy) { p.Compute.MissingRTTMS = 0 },
		"no-minimum-inflight":                 func(p *Policy) { p.Throughput.MinInflight = 0 },
		"capacity-smaller-than-minimum":       func(p *Policy) { p.Throughput.MinInflight = p.Throughput.MaxRequests + 1 },
		"unbounded-cache":                     func(p *Policy) { p.Cache.Capacity = 65537 },
		"unbounded-socket-history":            func(p *Policy) { p.Socket.Capacity = 65537 },
		"tcp-source":                          func(p *Policy) { p.Socket.TCPSource = "made-up" },
		"cache-key":                           func(p *Policy) { p.Cache.Key = "made-up" },
		"hash":                                func(p *Policy) { p.Noise.Hash = "made-up" },
		"noise-integer-width":                 func(p *Policy) { p.Noise.SumBits = 24 },
		"empty-salt-range":                    func(p *Policy) { p.Noise.SaltMax = 0 },
		"unbounded-salt-range":                func(p *Policy) { p.Noise.SaltMax = 65536 },
		"zero-quantum":                        func(p *Policy) { p.Noise.RTTQuantumMS = 0 },
		"fallback-outside-cap":                func(p *Policy) { p.Noise.MissingRTTMS = p.Noise.RTTCapMS + 1 },
		"methods":                             func(p *Policy) { p.Methods = nil },
		"missing-label":                       func(p *Policy) { p.Noise.MissingECT = "" },
	} {
		t.Run(name, func(t *testing.T) {
			p := candidatePolicy(t)
			edit(&p)
			if e := p.Validate(); e == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}

func TestMethodFilterUsesHTTPTokenGrammarAndOwnsMutableMetadata(t *testing.T) {
	p := candidatePolicy(t)
	p.Methods = []string{"custom!#$%&'*+-.^_`|~0123"}
	v := 0
	p.Environment.Fallback.Signal = &v
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	copy := p.Clone()
	*copy.Environment.Fallback.Signal = 4
	copy.Environment.Families[0] = "ipv6"
	copy.Addresses.Rules[0].Public = true
	if *p.Environment.Fallback.Signal != 0 || p.Environment.Families[0] != "ipv4" || p.Addresses.Rules[0].Public {
		t.Fatal("mutable metadata/address policy aliases caller")
	}
}

func TestPolicySelectsMetadataIdentityAndObservationDeliveryIndependently(t *testing.T) {
	for _, identity := range []string{"connection-type", "route-interface-addresses"} {
		for _, start := range []string{"request", "headers", "next-step"} {
			for _, headers := range []string{"headers", "next-step"} {
				p := candidatePolicy(t)
				p.Environment.Identity = identity
				p.Compute.TransactionStart = start
				p.Compute.HeaderDelivery = headers
				if err := p.Validate(); err != nil {
					t.Fatal(identity, start, headers, err)
				}
			}
		}
	}
}
