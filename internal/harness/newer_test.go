package harness

import (
	"maps"
	"slices"
	"testing"
)

func TestANewerBuildIsHeldToItsOwnValues(t *testing.T) {
	got := map[string]MeasuredScenario{
		"b": {H2: []Request{{Headers: [][2]string{{"sec-ch-ua", "b"}, {"accept", "x"}}}}},
		"a": {
			H2: []Request{{Headers: [][2]string{{"Sec-CH-UA", "a"}, {"user-agent", "u"}, {"rtt", "50"}}},
				{Headers: [][2]string{{"sec-ch-ua", "later"}, {"sec-ch-ua-platform", "p"}}}},
			H1: []Request{{Headers: [][2]string{{"Sec-Ch-Ua-Mobile", "?0"}, {"Host", "h"}}}},
		},
	}
	want := map[string]string{"sec-ch-ua": "a", "user-agent": "u", "rtt": "50", "sec-ch-ua-platform": "p",
		"sec-ch-ua-mobile": "?0"}
	if own := OwnValues(got); !maps.Equal(own, want) {
		t.Errorf("OwnValues = %v, want %v", own, want)
	}
	if own := OwnValues(nil); own == nil || len(own) != 0 {
		t.Errorf("of nothing: %v", own)
	}
	// Held to them, a version the fixture's is not is no difference; a
	// request that says another than the others is.
	fixture := map[string]MeasuredScenario{"a": {H2: []Request{{Headers: [][2]string{{"sec-ch-ua", "155"}}}}}}
	newer := map[string]MeasuredScenario{"a": {H2: []Request{{Headers: [][2]string{{"sec-ch-ua", "156"}}}}}}
	if diff := Compare(fixture, newer, OwnValues(newer)); diff != nil {
		t.Errorf("a newer version: %q", diff)
	}
	if diff := Compare(fixture, newer, nil); len(diff) != 1 {
		t.Errorf("held to the fixture: %q", diff)
	}
	fixture["a"] = MeasuredScenario{H2: []Request{{Headers: [][2]string{{"sec-ch-ua", "155"}}},
		{Headers: [][2]string{{"sec-ch-ua", "155"}}}}}
	newer["a"] = MeasuredScenario{H2: []Request{{Headers: [][2]string{{"sec-ch-ua", "156"}}},
		{Headers: [][2]string{{"sec-ch-ua", "157"}}}}}
	if diff := Compare(fixture, newer, OwnValues(newer)); !slices.Equal(diff,
		[]string{`a over h2, request 2: sec-ch-ua: "157", the profile's "156"`}) {
		t.Errorf("two versions: %q", diff)
	}
}

func TestANewerBuildsHeadsAreHeldAsMuchLongerAsItsFirst(t *testing.T) {
	scenario := func(records ...[]string) RecordsScenario {
		out := RecordsScenario{Note: "n"}
		for _, r := range records {
			out.Requests = append(out.Requests, RecordedRequest{Method: "GET", URL: "u", Records: r})
		}
		return out
	}
	fixture := map[string]RecordsScenario{
		"whole":    scenario([]string{"R718"}, []string{"R593"}),
		"split":    scenario([]string{"R700"}, []string{"r16384", "r14215"}),
		"merged":   scenario([]string{"R700"}, []string{"R695+B705"}, []string{"R600", "B706"}),
		"body":     scenario([]string{"R700"}, []string{"R680", "b16384", "b1"}),
		"lost":     scenario([]string{"R700"}),
		"none":     scenario(),
		"unknown":  scenario([]string{"R700"}, []string{"x+R", "Rx", ""}),
		"measured": scenario([]string{"R700"}),
	}
	newer := map[string]RecordsScenario{
		"whole":   scenario([]string{"R717"}, []string{"R592"}),
		"split":   scenario([]string{"R701"}, []string{"r16384", "r14216"}),
		"merged":  scenario([]string{"R701"}, []string{"R696+B705"}, []string{"R601", "B706"}),
		"body":    scenario([]string{"R699"}, []string{"R679", "b16384", "b1"}),
		"none":    scenario([]string{"R700"}),
		"unknown": scenario([]string{"R701"}, []string{"x+R", "Rx", ""}),
		"extra":   scenario([]string{"R700"}),
	}
	if diff := CompareRecordsNewer(fixture, newer); !slices.Equal(diff, []string{
		"lost was not measured", "measured was not measured", "none: 1 requests, want 0",
		"extra was measured, and the fixture has no such scenario"}) {
		t.Errorf("CompareRecordsNewer: %q", diff)
	}
	// Held as they are, every head that moved is a difference.
	if diff := CompareRecords(fixture, newer); len(diff) != 14 {
		t.Errorf("CompareRecords: %d differences, %q", len(diff), diff)
	}
	// A head on the boundary that crosses it says so.
	crossing := map[string]RecordsScenario{"merged": scenario([]string{"R701"}, []string{"R696", "B705"}, []string{"R601", "B706"})}
	if diff := CompareRecordsNewer(map[string]RecordsScenario{"merged": fixture["merged"]}, crossing); len(diff) != 1 {
		t.Errorf("a crossing: %q", diff)
	}
	if n := headLength([]string{"r16384", "r100+B5", "b9"}); n != 16484 {
		t.Errorf("headLength = %d", n)
	}
	for part, want := range map[string]int{"R12": 12, "r3": 3, "B5": 0, "R": 0, "": 0, "Rx": 0} {
		if size, ok := headPart(part); size != want || ok != (want != 0) {
			t.Errorf("headPart(%q) = %d, %v", part, size, ok)
		}
	}
}
