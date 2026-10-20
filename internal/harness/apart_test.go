package harness

import (
	"slices"
	"testing"
)

func TestWhatIsApartOnAPlatformIsAScenarioOfTheBench(t *testing.T) {
	for platform, scenarios := range apart {
		if !slices.Contains([]string{"macos", "linux", "windows"}, platform) {
			t.Errorf("%s is no platform a profile is filed under", platform)
		}
		for id, why := range scenarios {
			if _, ok := catalogue[id]; !ok || why == "" {
				t.Errorf("%s on %s: %q, a scenario of the bench %v", id, platform, why, ok)
			}
		}
	}
	// What a caller is given is its own.
	got := Apart("windows")
	clear(got)
	if len(Apart("windows")) == 0 || len(Apart("macos")) != 0 {
		t.Errorf("windows %v, macos %v", Apart("windows"), Apart("macos"))
	}
}
