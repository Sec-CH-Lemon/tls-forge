// Package networkquality implements bounded observation mechanisms. Policies
// supply their parameters; this package contains no browser-name defaults.
package networkquality

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// BufferPolicy is the explicit weighting and storage rule for one metric.
// HalfLifeSeconds defines exponential age decay; SignalWeight is the weight
// multiplier for each signal-strength level of difference.
type BufferPolicy struct {
	Capacity        int     `json:"capacity"`
	HalfLifeSeconds float64 `json:"half_life_seconds"`
	SignalWeight    float64 `json:"signal_weight"`
}

// Validate checks supported numeric rules and the engine's allocation ceiling.
func (p BufferPolicy) Validate() error {
	if p.Capacity < 1 || p.Capacity > 65536 {
		return fmt.Errorf("observation capacity must be1..65536")
	}
	if math.IsNaN(p.HalfLifeSeconds) || math.IsInf(p.HalfLifeSeconds, 0) || p.HalfLifeSeconds <= 0 {
		return fmt.Errorf("observation half_life_seconds must be finite and positive")
	}
	if math.IsNaN(p.SignalWeight) || p.SignalWeight < 0 || p.SignalWeight > 1 {
		return fmt.Errorf("observation signal_weight must be0..1")
	}
	return nil
}

// Observation preserves its actual timestamp, value, source and signal context.
// Signal is -1 when no strength is known, otherwise0..4. The enclosing state
// validates input units and source eligibility before inserting observations.
type Observation struct {
	At     time.Time
	Value  int64
	Signal int
	Source string
}

// Buffer retains observations in nondecreasing timestamp order. Its enclosing
// estimator owns synchronization, avoiding a second lock around computations.
type Buffer struct {
	policy          BufferPolicy
	weightPerSecond float64
	observations    []Observation
}

// NewBuffer constructs a bounded metric history without supplying defaults.
func NewBuffer(policy BufferPolicy) (*Buffer, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Buffer{policy: policy, weightPerSecond: math.Pow(0.5, 1/policy.HalfLifeSeconds), observations: make([]Observation, 0, policy.Capacity)}, nil
}

// Add inserts an observation and returns the evicted one, including an incoming
// observation older than the oldest entry of an already-full buffer.
func (b *Buffer) Add(o Observation) *Observation {
	var evicted *Observation
	if len(b.observations) == b.policy.Capacity {
		if o.At.Before(b.observations[0].At) {
			return &o
		}
		old := b.observations[0]
		evicted = &old
		copy(b.observations, b.observations[1:])
		b.observations = b.observations[:len(b.observations)-1]
	}
	i := sort.Search(len(b.observations), func(i int) bool { return b.observations[i].At.After(o.At) })
	b.observations = append(b.observations, Observation{})
	copy(b.observations[i+1:], b.observations[i:])
	b.observations[i] = o
	return evicted
}

// Percentile computes the value-weighted percentile and eligible sample count.
// Age is truncated to whole seconds, then strength and age weights multiply.
// Absent signal strength does not imply a known strength of zero.
func (b *Buffer) Percentile(now, begin time.Time, signal, percentile int) (value int64, count int, available bool) {
	type weighted struct {
		value  int64
		weight float64
	}
	rows := make([]weighted, 0, len(b.observations))
	total := 0.0
	for _, o := range b.observations {
		if o.At.Before(begin) {
			continue
		}
		seconds := int64(now.Sub(o.At) / time.Second)
		weight := math.Pow(b.weightPerSecond, float64(seconds))
		if signal >= 0 && o.Signal >= 0 {
			difference := signal - o.Signal
			if difference < 0 {
				difference = -difference
			}
			weight *= math.Pow(b.policy.SignalWeight, float64(difference))
		}
		// Match the normalized binary64 floor used by the supported mechanism;
		// arithmetic safety is not a captured browser parameter or a zero sample.
		weight = min(1, max(math.Float64frombits(0x0010000000000000), weight))
		total += weight
		rows = append(rows, weighted{o.Value, weight})
	}
	if len(rows) == 0 {
		return 0, 0, false
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].value < rows[j].value })
	desired := float64(percentile) / 100 * total
	cumulative := 0.0
	for _, row := range rows {
		cumulative += row.weight
		if cumulative >= desired {
			return row.value, len(rows), true
		}
	}
	return rows[len(rows)-1].value, len(rows), true
}

// RemoveSources discards obsolete seeded/cached source classes without changing
// other observations or the configured capacity.
func (b *Buffer) RemoveSources(sources map[string]bool) {
	kept := b.observations[:0]
	for _, o := range b.observations {
		if !sources[o.Source] {
			kept = append(kept, o)
		}
	}
	clear(b.observations[len(kept):])
	b.observations = kept
}

// Clear removes network-specific observations; it does not change the policy.
func (b *Buffer) Clear() { clear(b.observations); b.observations = b.observations[:0] }
