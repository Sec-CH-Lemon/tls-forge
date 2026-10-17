package harness

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	requestsFixture = "../../testdata/chrome155-requests.json"
	decodingFixture = "../../testdata/chrome155-decoding.json"
)

func TestTheCatalogueHasEveryScenarioTheFixtureHas(t *testing.T) {
	fixture, err := LoadRequests(requestsFixture)
	if err != nil {
		t.Fatalf("LoadRequests: %v", err)
	}
	if got, want := slices.Sorted(maps.Keys(catalogue)), slices.Sorted(maps.Keys(fixture.Scenarios)); !slices.Equal(got, want) {
		t.Fatalf("the catalogue has %v,\nthe fixture %v", got, want)
	}
	for id, sc := range catalogue {
		if sc.note != fixture.Scenarios[id].Note {
			t.Errorf("%s: the catalogue says %q, the fixture %q", id, sc.note, fixture.Scenarios[id].Note)
		}
	}
}

// placeholder is one of the catalogue's that fill would have filled in.
var placeholder = regexp.MustCompile(`\{(A|S|X|C|U|W|H|L|ID)\}`)

func TestEveryScenarioIsPlannedWithEveryPlaceFilledIn(t *testing.T) {
	o := origins(8443, 8080)
	for id, sc := range catalogue {
		p := sc.planned(id, o)
		for _, text := range []string{p.start, p.wait, p.pre, fill(sc.html, id, o), fill(sc.script, id, o)} {
			if placeholder.MatchString(text) {
				t.Errorf("%s: %q is not filled in", id, text)
			}
		}
		if !strings.HasPrefix(p.start, "http") || !strings.HasPrefix(p.wait, "/") {
			t.Errorf("%s: starts at %q and waits for %q", id, p.start, p.wait)
		}
		// A scenario waits for a page, or for a time, and not for both.
		if p.settle > 0 && !strings.HasPrefix(p.wait, "/never") {
			t.Errorf("%s waits for %s and for %s", id, p.wait, p.settle)
		}
	}
}

func TestAScenarioRunsOnItsPageUnlessToldOtherwise(t *testing.T) {
	o := origins(8443, 8080)
	if p := (scenario{}).planned("x", o); p != (plan{start: "https://www.example.com:8443/run/x", wait: "/done/x"}) {
		t.Errorf("planned %+v", p)
	}
	p := scenario{start: "{L}/run/{ID}", wait: "/p/{ID}", pre: "{X}/p/set", settle: time.Second}.planned("y", o)
	if p != (plan{start: "http://localhost:8080/run/y", wait: "/p/y", pre: "https://www.example.net:8443/p/set", settle: time.Second}) {
		t.Errorf("planned %+v", p)
	}
	if got := origins(1, 2); got["C"] != "https://u:p@www.example.net:1" || got["U"] != "https://u:p@www.example.com:1" ||
		got["W"] != "https://u:x@www.example.com:1" || got["H"] != "http://www.example.com:2" || len(got) != 8 {
		t.Errorf("origins %v", got)
	}
}

func TestAFormIsWrittenWithItsEncodingWhenItHasOne(t *testing.T) {
	if got := formHTML("post", "/a", ""); got != `<form id=f method=post action="/a" ><input name=a value=1><input name=b value="x y"></form>` {
		t.Errorf("formHTML %q", got)
	}
	if got := formHTML("get", "/b", "text/plain"); !strings.Contains(got, `method=get action="/b" enctype="text/plain">`) {
		t.Errorf("formHTML %q", got)
	}
}

func TestTheEndlessChainEndsAtItsTwentiethRequest(t *testing.T) {
	fixture, err := LoadRequests(requestsFixture)
	if err != nil {
		t.Fatalf("LoadRequests: %v", err)
	}
	// The fixture leaves out the reload of the error page, so the scenario is
	// over once its last request is asked for.
	chain := fixture.Scenarios["redir-nav-chain"]
	last := pathOf(chain.H2[len(chain.H2)-1].URL)
	if p := catalogue["redir-nav-chain"].planned("redir-nav-chain", origins(1, 2)); p.wait != last || len(chain.H2) != 20 || len(chain.H1) != 20 {
		t.Errorf("waits for %q, the fixture's last is %q of %d", p.wait, last, len(chain.H2))
	}
}
