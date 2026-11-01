package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestWindowsReleaseReferenceRetainsAllCommonScenarios(t *testing.T) {
	original, err := LoadRequests(requestsFixture)
	if err != nil {
		t.Fatal(err)
	}
	path := "../../testdata/chrome156-windows-requests.json"
	windows, err := LoadRequests(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows.Scenarios) != len(original.Scenarios) || len(windows.Scenarios) != 228 ||
		!reflect.DeepEqual(windows.ObservationMS, ObservationWindows{"auth-digest-negotiate": 15000}) {
		t.Fatal("release fixture changed the scenario inventory or observation window")
	}
	changed := 0
	for id, sc := range original.Scenarios {
		got, ok := windows.Scenarios[id]
		if !ok {
			t.Fatalf("lost %s", id)
		}
		if id != "auth-digest-negotiate" && id != "auth-digest-ntlm" {
			if !reflect.DeepEqual(sc, got) {
				t.Fatalf("changed common scenario %s", id)
			}
			continue
		}
		changed++
		if len(got.H1) != 2 || len(got.H2) != 2 || len(got.Unfinished) != 0 {
			t.Fatalf("incomplete auth reference %s", id)
		}
	}
	if changed != 2 {
		t.Fatal("auth selection changed")
	}
	// The provenance binds both independent raw cohorts and the immutable old
	// fixture to this complete reference. Rewriting the old fixture is no fix.
	var provenance struct {
		Original struct {
			SHA string `json:"sha256"`
		} `json:"original_fixture"`
		Output struct {
			SHA string `json:"sha256"`
		} `json:"output_fixture"`
		Cohorts []struct {
			Requests string `json:"requests_sha256"`
		} `json:"cohorts"`
	}
	data, err := os.ReadFile("../../testdata/chrome156-windows-auth-provenance.json")
	if err != nil || json.Unmarshal(data, &provenance) != nil {
		t.Fatalf("provenance: %v", err)
	}
	for file, want := range map[string]string{requestsFixture: provenance.Original.SHA, path: provenance.Output.SHA} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("fixture hash changed %s", file)
		}
	}
	if len(provenance.Cohorts) != 2 || provenance.Cohorts[0].Requests == "" || provenance.Cohorts[1].Requests == "" {
		t.Fatal("independent cohort identities lost")
	}
}

func TestWindowsAuthReferenceRejectsActualWireMutations(t *testing.T) {
	f, err := LoadRequests("../../testdata/chrome156-windows-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	id := "auth-digest-ntlm"
	want := map[string]MeasuredScenario{id: f.Scenarios[id]}
	if diff := Compare(want, want, nil); len(diff) != 0 {
		t.Fatal(diff)
	}
	for _, kind := range []string{"token", "missing", "extra", "order", "body", "unfinished"} {
		t.Run(kind, func(t *testing.T) {
			encoded, _ := json.Marshal(want)
			var got map[string]MeasuredScenario
			_ = json.Unmarshal(encoded, &got)
			sc := got[id]
			switch kind {
			case "token":
				found := false
				for i, h := range sc.H1[1].Headers {
					if strings.EqualFold(h[0], "authorization") {
						sc.H1[1].Headers[i][1] = h[1][:len(h[1])-1] + "A"
						found = true
					}
				}
				if !found {
					t.Fatal("fixture has no authentication message")
				}
			case "missing":
				sc.H1 = sc.H1[:1]
			case "extra":
				sc.H1 = append(sc.H1, sc.H1[1])
			case "order":
				sc.H1[1].Headers[0], sc.H1[1].Headers[1] = sc.H1[1].Headers[1], sc.H1[1].Headers[0]
			case "body":
				sc.H1[1].Body = "unexpected"
			case "unfinished":
				sc.Unfinished = []string{"over h1: timed out"}
			}
			got[id] = sc
			if diff := Compare(want, got, nil); len(diff) == 0 {
				t.Fatalf("accepted %s mutation", kind)
			}
		})
	}
	// Request order and the complete Type1 bytes remain exact even when the
	// existing machine/build-value normalization is active.
	got := f.Scenarios[id]
	got.H1 = slices.Clone(got.H1)
	got.H1[0], got.H1[1] = got.H1[1], got.H1[0]
	if diff := Compare(want, map[string]MeasuredScenario{id: got}, OwnValues(want)); len(diff) == 0 {
		t.Fatal("normalized request reordering")
	}
}
