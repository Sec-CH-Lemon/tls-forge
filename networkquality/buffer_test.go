package networkquality

import (
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"
)

func TestWeightedBufferMatchesPinnedIndependentOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/weighted-buffer-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Policy       BufferPolicy `json:"policy"`
			Now          int64        `json:"now_ms"`
			Begin        int64        `json:"begin_ms"`
			Signal       int          `json:"signal"`
			Percentile   int          `json:"percentile"`
			Observations []struct {
				At     int64 `json:"at_ms"`
				Value  int64 `json:"value"`
				Signal int   `json:"signal"`
			} `json:"observations"`
			Expected struct {
				Available bool  `json:"available"`
				Value     int64 `json:"value"`
				Count     int   `json:"count"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 128 {
		t.Fatal("oracle denominator", len(fixture.Cases))
	}
	for i, tc := range fixture.Cases {
		b, err := NewBuffer(tc.Policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range tc.Observations {
			b.Add(Observation{At: time.UnixMilli(o.At), Value: o.Value, Signal: o.Signal})
		}
		got, count, available := b.Percentile(time.UnixMilli(tc.Now), time.UnixMilli(tc.Begin), tc.Signal, tc.Percentile)
		if got != tc.Expected.Value || count != tc.Expected.Count || available != tc.Expected.Available {
			t.Errorf("case%d got%d/%d/%v want%+v", i, got, count, available, tc.Expected)
		}
	}
}

func TestBufferRejectsUnboundedOrUndefinedPolicies(t *testing.T) {
	valid := BufferPolicy{Capacity: 3, HalfLifeSeconds: 60, SignalWeight: 1}
	for _, edit := range []func(*BufferPolicy){
		func(p *BufferPolicy) { p.Capacity = 0 }, func(p *BufferPolicy) { p.Capacity = 65537 },
		func(p *BufferPolicy) { p.HalfLifeSeconds = 0 }, func(p *BufferPolicy) { p.HalfLifeSeconds = math.NaN() }, func(p *BufferPolicy) { p.HalfLifeSeconds = math.Inf(1) },
		func(p *BufferPolicy) { p.SignalWeight = -1 }, func(p *BufferPolicy) { p.SignalWeight = 2 }, func(p *BufferPolicy) { p.SignalWeight = math.NaN() },
	} {
		p := valid
		edit(&p)
		if _, err := NewBuffer(p); err == nil {
			t.Fatal("accepted undefined policy", p)
		}
	}
}

func TestBufferEvictsByTimestampAndPreservesZeroAndSource(t *testing.T) {
	b, err := NewBuffer(BufferPolicy{Capacity: 2, HalfLifeSeconds: 60, SignalWeight: 1})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(100, 0)
	if b.Add(Observation{At: at, Value: 0, Signal: -1, Source: "seed"}) != nil {
		t.Fatal("early eviction")
	}
	b.Add(Observation{At: at.Add(time.Second), Value: 20, Signal: 0, Source: "actual"})
	old := Observation{At: at.Add(-time.Second), Value: 99, Signal: -1, Source: "old"}
	if evicted := b.Add(old); evicted == nil || *evicted != old {
		t.Fatal("older incoming observation not evicted")
	}
	value, count, ok := b.Percentile(at, at.Add(-time.Hour), -1, 0)
	if !ok || value != 0 || count != 2 {
		t.Fatal("zero conflated with missing", value, count, ok)
	}
	evicted := b.Add(Observation{At: at.Add(2 * time.Second), Value: 40, Signal: 0, Source: "actual"})
	if evicted == nil || evicted.Source != "seed" {
		t.Fatal("wrong eviction", evicted)
	}
	evicted.Value = 999
	b.RemoveSources(map[string]bool{"seed": true})
	value, _, _ = b.Percentile(at, at.Add(-time.Hour), -1, 0)
	if value != 20 {
		t.Fatal("eviction aliases live buffer", value)
	}
	b.RemoveSources(map[string]bool{"actual": true})
	if _, n, ok := b.Percentile(at, at, -1, 50); ok || n != 0 {
		t.Fatal("sources not removed")
	}
	b.Add(Observation{At: at, Value: 1, Signal: -1})
	b.Clear()
	if _, n, ok := b.Percentile(at, at, -1, 50); ok || n != 0 {
		t.Fatal("network reset did not clear history")
	}
}

func TestBufferAgeAndStrengthAreObservedRules(t *testing.T) {
	at := time.Unix(100, 0)
	b, _ := NewBuffer(BufferPolicy{Capacity: 3, HalfLifeSeconds: 1, SignalWeight: 0})
	b.Add(Observation{At: at, Value: 10, Signal: 0})
	b.Add(Observation{At: at, Value: 90, Signal: 4})
	value, _, _ := b.Percentile(at, at, 4, 50)
	if value != 90 {
		t.Fatal("strength ignored", value)
	}
	value, _, _ = b.Percentile(at, at, -1, 50)
	if value != 10 {
		t.Fatal("missing strength treated as known", value)
	}
	b, _ = NewBuffer(BufferPolicy{Capacity: 3, HalfLifeSeconds: 1, SignalWeight: 1})
	b.Add(Observation{At: at, Value: 10, Signal: -1})
	b.Add(Observation{At: at.Add(time.Second), Value: 90, Signal: -1})
	value, _, _ = b.Percentile(at.Add(time.Second), at, -1, 50)
	if value != 90 {
		t.Fatal("age ignored", value)
	}
}

// Exact powers of two make insertion-order and value-order accumulation differ
// by one ULP. The100th percentile still returns the actual largest value.
func TestBufferHundredthPercentileSurvivesAccumulationRounding(t *testing.T) {
	b, err := NewBuffer(BufferPolicy{Capacity: 4, HalfLifeSeconds: 1, SignalWeight: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	b.Add(Observation{At: now.Add(-52 * time.Second), Value: 3, Signal: -1})
	b.Add(Observation{At: now.Add(-52 * time.Second), Value: 4, Signal: -1})
	b.Add(Observation{At: now, Value: 1, Signal: -1})
	b.Add(Observation{At: now, Value: 2, Signal: -1})
	value, count, ok := b.Percentile(now, time.Unix(0, 0), -1, 100)
	if !ok || count != 4 || value != 4 {
		t.Fatal("rounding lost the largest observation", value, count, ok)
	}
}
