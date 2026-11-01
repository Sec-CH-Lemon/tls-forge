package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestObservationWindowsRejectAmbiguousOrShortenedRuns(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `1`, `{`, `{"auth-digest-negotiate":15000,"auth-digest-negotiate":20000}`,
		`{"auth-digest-negotiate":"15000"}`, `{"auth-digest-negotiate":1.5}`,
		`{"auth-digest-negotiate":null}`, `{"auth-digest-negotiate":0}`,
		`{"auth-digest-negotiate":14999}`, `{"auth-digest-negotiate":60001}`, `{"unknown":15000}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var windows ObservationWindows
			err := json.Unmarshal([]byte(raw), &windows)
			if err == nil {
				_, err = observedCatalogue(windows)
			}
			if err == nil {
				t.Fatal("accepted ambiguous, unknown or shortened observation")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"observation_ms":{"unknown":15000}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRequests(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("LoadRequests must reject before measurement: %v", err)
	}
	if _, err := MeasureObserved(context.Background(), &fake{}, nil, ObservationWindows{"unknown": 15000}, nil); err == nil {
		t.Fatal("invalid programmatic window reached measurement")
	}
}

func TestObservationWindowsPreserveAllScenesAndTheirRequests(t *testing.T) {
	id := "auth-digest-negotiate"
	before := catalogue[id]
	scenarios, err := observedCatalogue(ObservationWindows{id: 15000})
	if err != nil {
		t.Fatal(err)
	}
	want := before
	want.wait, want.settle = "/never", 15*time.Second
	if len(scenarios) != len(catalogue) || !reflect.DeepEqual(scenarios[id], want) || !reflect.DeepEqual(catalogue[id], before) {
		t.Fatal("observation changed or removed scene data or mutated the catalogue")
	}
	for name, original := range catalogue {
		if name != id && !reflect.DeepEqual(scenarios[name], original) {
			t.Fatalf("changed other scenario %s", name)
		}
	}
	// A selected diagnostic still uses the real server and refuses a browser
	// that cannot open its page. No error is converted into a finished fixture.
	if _, err := MeasureObserved(context.Background(), &fake{fail: "/"}, []string{id}, ObservationWindows{id: 15000}, nil); err == nil || !strings.Contains(err.Error(), "would not open") {
		t.Fatalf("opening error: %v", err)
	}
	// Exercise the same plan with a short test-only clock. An actual opening
	// request is mandatory; a silent process cannot pass by waiting it out.
	sc := scenarios[id]
	sc.settle = 35 * time.Millisecond
	b := &fake{}
	start := time.Now()
	got, err := measure(context.Background(), b, map[string]scenario{id: sc}, nil, quick, nil)
	if err != nil || len(got[id].Unfinished) != 0 || len(got[id].H2) != 1 || len(got[id].H1) != 1 || time.Since(start) < 70*time.Millisecond {
		t.Fatalf("fixed observation: %+v, %v", got, err)
	}
	timing := quick
	timing.limit = 35 * time.Millisecond
	if _, err := measure(context.Background(), &fake{silent: true}, map[string]scenario{id: sc}, nil, timing, nil); err == nil {
		t.Fatal("silent browser passed the opening barrier")
	}
	f := &RequestsFixture{ObservationMS: ObservationWindows{id: 15000}, Scenarios: got}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := f.Write(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRequests(path)
	if err != nil || !reflect.DeepEqual(f, loaded) {
		t.Fatalf("fixture did not preserve observation metadata: %+v, %v", loaded, err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte(`"observation_ms"`)) {
		t.Fatal("observation window lost")
	}
}
