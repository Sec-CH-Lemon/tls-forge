package networkquality

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

// Metric is an estimate with explicit availability; zero remains a real value.
type Metric struct {
	Value     int64 `json:"value"`
	Available bool  `json:"available"`
}

// Quality preserves separate HTTP, transport, end-to-end and throughput estimates.
type Quality struct {
	HTTP      Metric `json:"http_ms"`
	Transport Metric `json:"transport_ms"`
	EndToEnd  Metric `json:"end_to_end_ms"`
	Downlink  Metric `json:"downlink_kbps"`
	ECT       string `json:"ect"`
}

// MetricPolicy selects one bounded history and its query window.
type MetricPolicy struct {
	Name        string       `json:"name"`
	Buffer      BufferPolicy `json:"buffer"`
	RecentMS    int64        `json:"recent_ms"`
	FallbackAll bool         `json:"fallback_all"`
	Percentile  int          `json:"percentile"`
}

// SourceRule maps an implemented source to categories and recompute behavior.
type SourceRule struct {
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
	Default    bool     `json:"default"`
	Cached     bool     `json:"cached"`
	Recompute  bool     `json:"recompute"`
}

// NetworkSeed is explicit initial data for a connection type, not measured state.
type NetworkSeed struct {
	Type      string `json:"type"`
	HTTP      Metric `json:"http_ms"`
	Transport Metric `json:"transport_ms"`
	Downlink  Metric `json:"downlink_kbps"`
}

// ECTRule is one ordered HTTP RTT threshold and its typical cache-fill values.
type ECTRule struct {
	Label              string `json:"label"`
	MinHTTPMS          int64  `json:"min_http_ms"`
	TypicalHTTPMS      int64  `json:"typical_http_ms"`
	TypicalTransportMS int64  `json:"typical_transport_ms"`
	TypicalKbps        int64  `json:"typical_kbps"`
	ClampDownlink      bool   `json:"clamp_downlink"`
}

// ComputePolicy selects recomputation, RTT correction and hanging-request rules.
type ComputePolicy struct {
	TransactionStart    string  `json:"transaction_start"`
	UseEnd              bool    `json:"use_end"`
	IntervalMS          int64   `json:"interval_ms"`
	GrowthRatio         float64 `json:"growth_ratio"`
	NewSamples          int     `json:"new_samples"`
	Navigation          bool    `json:"navigation"`
	MinTransportSamples int     `json:"min_transport_samples"`
	MinEndSamples       int     `json:"min_end_samples"`
	TransportLower      float64 `json:"transport_lower"`
	EndLower            float64 `json:"end_lower"`
	EndUpper            float64 `json:"end_upper"`
	SparseRTTCapMS      int64   `json:"sparse_rtt_cap_ms"`
	CacheGraceMS        int64   `json:"cache_grace_ms"`
	DownlinkTypicalCap  float64 `json:"downlink_typical_cap"`
	HangingHTTP         float64 `json:"hanging_http"`
	HangingTransport    float64 `json:"hanging_transport"`
	HangingMinMS        int64   `json:"hanging_min_ms"`
	MissingRTTMS        int64   `json:"missing_rtt_ms"`
}

// ThroughputPolicy defines an aggregate receive-counter window.
type ThroughputPolicy struct {
	MinInflight           int     `json:"min_inflight"`
	MinTransferBytes      int64   `json:"min_transfer_bytes"`
	MaxRequests           int     `json:"max_requests"`
	HangingCWNDBytes      int64   `json:"hanging_cwnd_bytes"`
	HangingCWNDMultiplier float64 `json:"hanging_cwnd_multiplier"`
	HangingRTTMultiplier  float64 `json:"hanging_rtt_multiplier"`
	HangingMinMS          int64   `json:"hanging_min_ms"`
	MissingHTTPMS         int64   `json:"missing_http_ms"`
	SweepMS               int64   `json:"sweep_ms"`
}

// SocketPolicy selects notification filtering and bounded connection history.
type SocketPolicy struct {
	TCPSource     string `json:"tcp_source"`
	Capacity      int    `json:"capacity"`
	PerSocketMS   int64  `json:"per_socket_ms"`
	GlobalMS      int64  `json:"global_ms"`
	MinRTTUS      int64  `json:"min_rtt_us"`
	AllowPrivate  bool   `json:"allow_private"`
	SkipFirstQUIC bool   `json:"skip_first_quic"`
}

// PublicationPolicy defines when newly computed metrics become available to headers.
type PublicationPolicy struct {
	LatencyDifference   int64   `json:"latency_difference"`
	BandwidthDifference int64   `json:"bandwidth_difference"`
	Ratio               float64 `json:"ratio"`
}

// CachePolicy defines network partitioning and the startup cache-read phase.
type CachePolicy struct {
	Capacity           int    `json:"capacity"`
	Key                string `json:"key"`
	Enabled            bool   `json:"enabled"`
	ReadAfterBootstrap bool   `json:"read_after_bootstrap"`
}

// NoisePolicy selects a hash, browser-instance salt and quantization mechanism.
type NoisePolicy struct {
	Scope               string  `json:"scope"`
	Hash                string  `json:"hash"`
	SumBits             int     `json:"sum_bits"`
	SaltMin             int64   `json:"salt_min"`
	SaltMax             int64   `json:"salt_max"`
	Buckets             uint64  `json:"buckets"`
	Base                float64 `json:"base"`
	Step                float64 `json:"step"`
	RTTCapMS            int64   `json:"rtt_cap_ms"`
	RTTQuantumMS        int64   `json:"rtt_quantum_ms"`
	MissingRTTMS        int64   `json:"missing_rtt_ms"`
	DownlinkCapKbps     int64   `json:"downlink_cap_kbps"`
	DownlinkQuantumKbps int64   `json:"downlink_quantum_kbps"`
	MissingDownlinkKbps int64   `json:"missing_downlink_kbps"`
	MissingECT          string  `json:"missing_ect"`
}

// EnvironmentPolicy selects metadata input and its explicit unavailable-input contract.
type EnvironmentPolicy struct {
	Source   string   `json:"source"`
	Missing  string   `json:"missing"`
	Fallback Context  `json:"fallback"`
	Families []string `json:"families"`
	Identity string   `json:"identity"`
}

// Policy owns every data choice of the supported weighted-observation mechanism.
type Policy struct {
	Addresses      AddressPolicy     `json:"addresses"`
	Environment    EnvironmentPolicy `json:"environment"`
	Algorithm      string            `json:"algorithm"`
	Metrics        []MetricPolicy    `json:"metrics"`
	Sources        []SourceRule      `json:"sources"`
	Seeds          []NetworkSeed     `json:"seeds"`
	ECT            []ECTRule         `json:"ect"`
	Compute        ComputePolicy     `json:"compute"`
	Throughput     ThroughputPolicy  `json:"throughput"`
	Socket         SocketPolicy      `json:"socket"`
	Publication    PublicationPolicy `json:"publication"`
	Cache          CachePolicy       `json:"cache"`
	Noise          NoisePolicy       `json:"noise"`
	Methods        []string          `json:"methods"`
	ExcludePrivate bool              `json:"exclude_private"`
	ExcludeCached  bool              `json:"exclude_cached"`
	OfflineECT     string            `json:"offline_ect"`
	UnknownECT     string            `json:"unknown_ect"`
}

// Validate checks capabilities and hard resource/numeric bounds without adding defaults.
func (p Policy) Validate() error {
	if err := p.Addresses.Validate(); err != nil {
		return err
	}
	if p.Environment.Source != "context" && p.Environment.Source != "system" {
		return fmt.Errorf("unsupported network metadata source")
	}
	if p.Environment.Missing != "fallback" && p.Environment.Missing != "reject" {
		return fmt.Errorf("unsupported missing network metadata policy")
	}
	if p.Environment.Identity != "route-interface-addresses" {
		return fmt.Errorf("unsupported network identity rule")
	}
	if len(p.Environment.Families) < 1 || len(p.Environment.Families) > 2 {
		return fmt.Errorf("requires ordered metadata address families")
	}
	seenFamilies := map[string]bool{}
	for _, family := range p.Environment.Families {
		if family != "ipv4" && family != "ipv6" || seenFamilies[family] {
			return fmt.Errorf("invalid/duplicate metadata address family")
		}
		seenFamilies[family] = true
	}
	if e := p.Environment.Fallback.Validate(); e != nil {
		return e
	}
	if p.Algorithm != "weighted-observations" {
		return fmt.Errorf("unsupported network estimator %q", p.Algorithm)
	}
	metricNames := []string{"http", "transport", "end", "downlink"}
	seen := map[string]bool{}
	for _, m := range p.Metrics {
		if !slices.Contains(metricNames, m.Name) || seen[m.Name] {
			return fmt.Errorf("invalid/duplicate metric %q", m.Name)
		}
		seen[m.Name] = true
		if e := m.Buffer.Validate(); e != nil {
			return e
		}
		if m.RecentMS < 0 || m.RecentMS > math.MaxInt32 || m.Percentile < 0 || m.Percentile > 100 {
			return fmt.Errorf("invalid metric query")
		}
	}
	if len(seen) != len(metricNames) {
		return fmt.Errorf("requires all metric policies")
	}
	sourceNames := []string{"http", "tcp", "quic", "h2-ping", "seed-http", "seed-transport", "cache-http", "cache-transport"}
	seen = map[string]bool{}
	for _, s := range p.Sources {
		if !slices.Contains(sourceNames, s.Name) || seen[s.Name] {
			return fmt.Errorf("invalid/duplicate source %q", s.Name)
		}
		seen[s.Name] = true
		cats := map[string]bool{}
		for _, c := range s.Categories {
			if !slices.Contains(metricNames[:3], c) || cats[c] {
				return fmt.Errorf("invalid/duplicate category %q", c)
			}
			cats[c] = true
		}
		if len(cats) == 0 {
			return fmt.Errorf("empty source categories")
		}
	}
	if len(seen) != len(sourceNames) {
		return fmt.Errorf("requires all source rules")
	}
	seen = map[string]bool{}
	validMetric := func(m Metric) bool { return m.Value >= 0 && m.Value <= math.MaxInt32 && (m.Available || m.Value == 0) }
	for _, s := range p.Seeds {
		if !slices.Contains(connectionTypes, s.Type) || seen[s.Type] || !validMetric(s.HTTP) || !validMetric(s.Transport) || !validMetric(s.Downlink) {
			return fmt.Errorf("invalid network seed")
		}
		seen[s.Type] = true
	}
	if len(seen) != len(connectionTypes) {
		return fmt.Errorf("requires explicit seed for every connection class")
	}
	if len(p.ECT) < 1 || len(p.ECT) > 32 {
		return fmt.Errorf("invalid ECT rule count")
	}
	seen = map[string]bool{}
	previous := int64(math.MaxInt64)
	for _, r := range p.ECT {
		if !slices.Contains([]string{"slow-2g", "2g", "3g", "4g"}, r.Label) || seen[r.Label] || r.MinHTTPMS < 0 || r.MinHTTPMS > math.MaxInt32 || r.MinHTTPMS >= previous || r.TypicalHTTPMS < 0 || r.TypicalHTTPMS > math.MaxInt32 || r.TypicalTransportMS < 0 || r.TypicalTransportMS > math.MaxInt32 || r.TypicalKbps < 0 || r.TypicalKbps > math.MaxInt32 {
			return fmt.Errorf("invalid ordered ECT rule")
		}
		seen[r.Label] = true
		previous = r.MinHTTPMS
	}
	if previous != 0 {
		return fmt.Errorf("final ECT threshold must be zero")
	}
	c := p.Compute
	if c.TransactionStart != "request" && c.TransactionStart != "headers" {
		return fmt.Errorf("unsupported transaction start delivery")
	}
	t := p.Throughput
	s := p.Socket
	n := p.Noise
	for _, x := range []int64{c.IntervalMS, c.SparseRTTCapMS, c.CacheGraceMS, c.HangingMinMS, c.MissingRTTMS, t.MinTransferBytes, t.HangingCWNDBytes, t.HangingMinMS, t.MissingHTTPMS, t.SweepMS, s.PerSocketMS, s.GlobalMS, s.MinRTTUS, p.Publication.LatencyDifference, p.Publication.BandwidthDifference, n.RTTCapMS, n.MissingRTTMS, n.DownlinkCapKbps, n.MissingDownlinkKbps} {
		if x < 0 || x > math.MaxInt32 {
			return fmt.Errorf("network numeric parameter outside engine bounds")
		}
	}
	for _, x := range []float64{c.GrowthRatio, c.TransportLower, c.EndLower, c.EndUpper, c.DownlinkTypicalCap, c.HangingHTTP, c.HangingTransport, t.HangingCWNDMultiplier, t.HangingRTTMultiplier, p.Publication.Ratio, n.Base, n.Step} {
		if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 || x > 1e6 {
			return fmt.Errorf("invalid finite multiplier")
		}
	}
	if c.GrowthRatio < 1 || c.NewSamples < 1 || c.NewSamples > 65536 || c.MinTransportSamples < 1 || c.MinEndSamples < 1 || c.MinTransportSamples > 65536 || c.MinEndSamples > 65536 || c.HangingHTTP == 0 || c.HangingTransport == 0 || c.MissingRTTMS == 0 || t.HangingRTTMultiplier == 0 || t.MissingHTTPMS == 0 || t.SweepMS == 0 || p.Publication.Ratio < 1 {
		return fmt.Errorf("invalid estimator thresholds")
	}
	if t.MaxRequests < 1 || t.MaxRequests > 65536 || t.MinInflight < 1 || t.MinInflight > t.MaxRequests || s.Capacity < 1 || s.Capacity > 65536 || p.Cache.Capacity < 1 || p.Cache.Capacity > 65536 {
		return fmt.Errorf("invalid estimator allocation bounds")
	}
	if s.TCPSource != "none" && s.TCPSource != "kernel-tcp-info" {
		return fmt.Errorf("unsupported TCP RTT source")
	}
	if p.Cache.Key != "connection-type" && p.Cache.Key != "identity" {
		return fmt.Errorf("unsupported network cache key")
	}
	if n.Scope != "browser-instance" {
		return fmt.Errorf("unsupported network salt lifecycle")
	}
	if n.Hash != "libcxx-city64-le-abi1" && n.Hash != "libcxx-city64-le-abi2" || n.SumBits != 32 && n.SumBits != 64 || n.SaltMin < 1 || n.SaltMax < n.SaltMin || n.SaltMax > 65535 || n.Buckets < 1 || n.Buckets > 65536 || n.RTTQuantumMS < 1 || n.DownlinkQuantumKbps < 1 || n.RTTQuantumMS > math.MaxInt32 || n.DownlinkQuantumKbps > math.MaxInt32 || n.MissingRTTMS > n.RTTCapMS || n.MissingDownlinkKbps > n.DownlinkCapKbps {
		return fmt.Errorf("invalid network noise rule")
	}
	if len(p.Methods) == 0 || p.OfflineECT != "offline" || p.UnknownECT != "unknown" || !slices.Contains([]string{"slow-2g", "2g", "3g", "4g"}, n.MissingECT) {
		return fmt.Errorf("requires explicit network filters/fallback labels")
	}
	seenMethods := map[string]bool{}
	for _, method := range p.Methods {
		if !httpMethodToken(method) || seenMethods[method] {
			return fmt.Errorf("invalid/duplicate network method filter")
		}
		seenMethods[method] = true
	}
	return nil
}
func httpMethodToken(method string) bool {
	if len(method) == 0 || len(method) > 256 {
		return false
	}
	for _, c := range []byte(method) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// Clone isolates every mutable policy vector from later caller edits.
func (p Policy) Clone() Policy {
	p.Addresses.Rules = slices.Clone(p.Addresses.Rules)
	p.Environment.Fallback = p.Environment.Fallback.Clone()
	p.Environment.Families = slices.Clone(p.Environment.Families)
	p.Metrics = slices.Clone(p.Metrics)
	p.Sources = slices.Clone(p.Sources)
	for i := range p.Sources {
		p.Sources[i].Categories = slices.Clone(p.Sources[i].Categories)
	}
	p.Seeds = slices.Clone(p.Seeds)
	p.ECT = slices.Clone(p.ECT)
	p.Methods = slices.Clone(p.Methods)
	return p
}
