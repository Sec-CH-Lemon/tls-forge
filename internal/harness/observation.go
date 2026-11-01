package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"time"
)

// ObservationWindows contains explicit fixture observation windows, in
// milliseconds. It changes only how long a page is observed, never its content
// or the comparison. A silent browser still fails the opening-page barrier.
type ObservationWindows map[string]int

// UnmarshalJSON refuses ambiguous windows before they can select a bench run.
func (w *ObservationWindows) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if !json.Valid(data) || len(data) == 0 || data[0] != '{' {
		return fmt.Errorf("observation_ms must be an object")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	_, _ = d.Token() // json.Valid and the opening brace were checked above.
	out := ObservationWindows{}
	for d.More() {
		key, _ := d.Token()
		id := key.(string)
		if _, exists := out[id]; exists {
			return fmt.Errorf("duplicate observation_ms scenario %q", id)
		}
		var ms int
		if err := d.Decode(&ms); err != nil {
			return fmt.Errorf("observation_ms %q: %w", id, err)
		}
		out[id] = ms
	}
	*w = out
	return nil
}

func observedCatalogue(windows ObservationWindows) (map[string]scenario, error) {
	out := maps.Clone(catalogue)
	for id, ms := range windows {
		sc, ok := out[id]
		if !ok {
			return nil, fmt.Errorf("observation_ms names unknown request scenario %q", id)
		}
		window := time.Duration(ms) * time.Millisecond
		if ms < int(measured.limit/time.Millisecond) || ms > 60000 || window < sc.settle {
			return nil, fmt.Errorf("observation_ms %q must retain at least %s and the original window, at most 60s", id, measured.limit)
		}
		sc.wait, sc.settle = "/never", window
		out[id] = sc
	}
	return out, nil
}

// MeasureObserved measures the complete catalogue, or only the explicit
// diagnostic selection, with the fixture's observation windows. Empty windows
// preserve Measure exactly; neither path passes over platform differences.
func MeasureObserved(ctx context.Context, b Browser, only []string, windows ObservationWindows,
	progress io.Writer) (map[string]MeasuredScenario, error) {
	scenarios, err := observedCatalogue(windows)
	if err != nil {
		return nil, err
	}
	return measure(ctx, b, scenarios, only, measured, progress)
}
