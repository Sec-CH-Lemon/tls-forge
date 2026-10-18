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
	requestsFixture    = "../../testdata/chrome155-requests.json"
	connectionsFixture = "../../testdata/chrome155-connections.json"
	decodingFixture    = "../../testdata/chrome155-decoding.json"
)

func TestTheCatalogueHasEveryScenarioTheFixtureHas(t *testing.T) {
	for path, scenarios := range map[string]map[string]scenario{requestsFixture: catalogue, connectionsFixture: connectionCatalogue} {
		fixture, err := LoadRequests(path)
		if err != nil {
			t.Fatalf("LoadRequests: %v", err)
		}
		if got, want := slices.Sorted(maps.Keys(scenarios)), slices.Sorted(maps.Keys(fixture.Scenarios)); !slices.Equal(got, want) {
			t.Fatalf("the catalogue has %v,\n%s %v", got, path, want)
		}
		for id, sc := range scenarios {
			if sc.note != fixture.Scenarios[id].Note {
				t.Errorf("%s: the catalogue says %q, %s %q", id, sc.note, path, fixture.Scenarios[id].Note)
			}
		}
	}
}

func TestEveryScenarioOfConnectionsStartsAtTheLobbyAndNoOtherDoes(t *testing.T) {
	for id, sc := range connectionCatalogue {
		if !sc.connections || sc.start != lobby || sc.pre != "" || sc.settle != 0 {
			t.Errorf("%s: %+v", id, sc)
		}
		if _, ok := catalogue[id]; ok {
			t.Errorf("%s is a scenario of requests too", id)
		}
	}
	for id, sc := range catalogue {
		if sc.connections {
			t.Errorf("%s is a scenario of connections", id)
		}
	}
	// The run page comes two seconds after the lobby has loaded.
	if p := connectionCatalogue["conn-fetch"].planned("conn-fetch", origins(8443, 8080)); p.start !=
		"https://www.example.com:8443/p/lobby?after=2&next=/run/conn-fetch" || p.wait != "/done/conn-fetch" {
		t.Errorf("planned %+v", p)
	}
}

// placeholder is one of the catalogue's that fill would have filled in.
var placeholder = regexp.MustCompile(`\{(A|S|X|C|U|W|H|L|ID)\}`)

func TestEveryScenarioIsPlannedWithEveryPlaceFilledIn(t *testing.T) {
	o := origins(8443, 8080)
	every := maps.Clone(catalogue)
	maps.Copy(every, connectionCatalogue)
	for id, sc := range every {
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
	if p := (scenario{}).planned("x", o); p != (plan{start: "https://www.example.com:8443/run/x", wait: "/done/x", times: 1}) {
		t.Errorf("planned %+v", p)
	}
	p := scenario{start: "{L}/run/{ID}", wait: "/p/{ID}", pre: "{X}/p/set", settle: time.Second}.planned("y", o)
	if p != (plan{start: "http://localhost:8080/run/y", wait: "/p/y", pre: "https://www.example.net:8443/p/set", times: 1,
		settle: time.Second}) {
		t.Errorf("planned %+v", p)
	}
	if p := (scenario{wait: "/p/{ID}", times: 3}).planned("z", o); p.wait != "/p/z" || p.times != 3 {
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

func TestAPageThatIsNeverTakenEndsAtTheThirtySecondRequest(t *testing.T) {
	fixture, err := LoadRequests(requestsFixture)
	if err != nil {
		t.Fatalf("LoadRequests: %v", err)
	}
	// Every request is for the page waited for, so the scenario is over once
	// it has been asked for as often as Chrome asks for it.
	stale := fixture.Scenarios["auth-digest-stale-forever"]
	p := catalogue["auth-digest-stale-forever"].planned("auth-digest-stale-forever", origins(1, 2))
	for _, requests := range [][]Request{stale.H2, stale.H1} {
		if len(requests) != p.times || p.times != 32 {
			t.Errorf("waits for %d, the fixture has %d", p.times, len(requests))
		}
		for _, r := range requests {
			if pathOf(r.URL) != p.wait {
				t.Errorf("%s, not %s", r.URL, p.wait)
			}
		}
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
