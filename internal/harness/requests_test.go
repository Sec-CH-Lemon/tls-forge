package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// opening is a page a fake was asked to open, and with which profile.
type opening struct{ url, dir string }

// fake is a browser that asks for the page it opens, and then, in the order
// given, for what then says it would ask for there, each by a path or a URL.
// It fails to open what fail names; silent, it asks for nothing; garbling, it
// also sends a line that is no request.
type fake struct {
	mu       sync.Mutex
	opened   []opening
	then     func(url string) []string
	fail     string
	silent   bool
	garbling bool
	dump     func(url string, res *http.Response, body []byte) []byte
	// quiet are the opens, counted from 0, it asks nothing on; stopped, when
	// each open was stopped.
	quiet   map[int]bool
	stopped []time.Time
	// reloads are the opens, counted from 0, whose page comes as a reload, as
	// Chrome's error page asks again for a navigation its start broke:
	// "instead" of the page, "again" after it, or "alone", nothing after it.
	reloads map[int]string
	// trusted are the keys it was told to take as a site's, in order.
	trusted []string
}

func (f *fake) trusting(spki string) Browser {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trusted = append(f.trusted, spki)
	return f
}

// untrusting is a browser that cannot be told to take a key as a site's.
type untrusting struct{ Browser }

func (f *fake) Open(_ context.Context, page, dir string) (func(), error) {
	f.mu.Lock()
	f.opened = append(f.opened, opening{page, dir})
	quiet := f.silent || f.quiet[len(f.opened)-1]
	reload := f.reloads[len(f.opened)-1]
	f.mu.Unlock()
	if f.fail != "" && strings.Contains(page, f.fail) {
		return nil, errors.New("the fake would not open " + page)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if quiet {
			return
		}
		if reload != "instead" {
			ask(page)
		}
		if reload != "" {
			askReloading(page)
		}
		if reload == "alone" {
			return
		}
		if f.garbling {
			garble(page)
		}
		if f.then != nil {
			base, _ := url.Parse(page)
			for _, next := range f.then(page) {
				to, _ := base.Parse(next)
				ask(to.String())
			}
		}
	}()
	return func() {
		<-done
		f.mu.Lock()
		f.stopped = append(f.stopped, time.Now())
		f.mu.Unlock()
	}, nil
}

func (f *fake) DumpDOM(_ context.Context, page string) ([]byte, error) {
	res, err := client().Get(page)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	var body bytes.Buffer
	_, _ = body.ReadFrom(res.Body)
	return f.dump(page, res, body.Bytes()), nil
}

// garble sends a line that is no request to where page is, over TLS that
// offers HTTP/1.1 alone.
func garble(page string) {
	u, _ := url.Parse(page)
	conn, err := tls.Dial("tcp", "127.0.0.1:"+u.Port(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // the bench's own
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("BREW\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(make([]byte, 1))
}

// ask asks for page, and reads the answer.
func ask(page string) {
	res, err := client().Get(page)
	if err == nil {
		_ = res.Body.Close()
	}
}

// askReloading asks for page as a browser reloading it does, with a
// Cache-Control, and reads the answer.
func askReloading(page string) {
	req, _ := http.NewRequest(http.MethodGet, page, nil)
	req.Header.Set("Cache-Control", "max-age=0")
	res, err := client().Do(req)
	if err == nil {
		_ = res.Body.Close()
	}
}

// quick is a timing a test can wait out.
var quick = timing{poll: 5 * time.Millisecond, limit: 2 * time.Second, after: 50 * time.Millisecond, persist: 20 * time.Millisecond}

func TestAScenarioIsKeptWithoutTheScenesItSetOrThePortsItRanOn(t *testing.T) {
	scenarios := map[string]scenario{
		// A page that sets cookies before the run page, the run page, what it
		// asks for, a favicon and its done.
		"set": {note: "set", start: "{X}/r/302/set?cookie=1&to={A}/run/{ID}", script: "1"},
		// A typed navigation, which has no run page to leave out.
		"typed": {note: "typed", start: "{A}/p/typed?x=1:2", wait: "/p/typed"},
	}
	b := &fake{then: func(page string) []string {
		if !strings.Contains(page, "/r/302/set") {
			return nil
		}
		// What the run page, where the redirect led, asks for.
		u, _ := url.Parse(page)
		run := "https://www.example.com:" + u.Port()
		return []string{run + "/p/after-set", run + "/favicon.ico", run + "/done/set"}
	}}
	var progress bytes.Buffer
	got, err := measure(context.Background(), b, scenarios, nil, quick, &progress)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	for _, proto := range []string{"h2", "h1"} {
		set, typed := got["set"].H2, got["typed"].H2
		if proto == "h1" {
			set, typed = got["set"].H1, got["typed"].H1
		}
		if len(set) != 1 || set[0].URL != "https://www.example.com/p/after-set" || set[0].Method != "GET" {
			t.Errorf("set over %s: %+v", proto, set)
		}
		if len(typed) != 1 || typed[0].URL != "https://www.example.com/p/typed?x=1:2" {
			t.Errorf("typed over %s: %+v", proto, typed)
		}
		for _, r := range append(set, typed...) {
			for _, h := range r.Headers {
				if strings.EqualFold(h[0], "host") || h[0] == ":authority" {
					if h[1] != "www.example.com" {
						t.Errorf("%s over %s: %s %q", r.URL, proto, h[0], h[1])
					}
				}
			}
		}
	}
	if got["set"].Note != "set" || got["typed"].Note != "typed" {
		t.Errorf("notes %+v", got)
	}
	if got := progress.String(); got != "h2 set: 1 requests\nh2 typed: 1 requests\nh1 set: 1 requests\nh1 typed: 1 requests\n" {
		t.Errorf("progress %q", got)
	}
	// HTTP/2 over the port that offers it, HTTP/1.1 alone over the other.
	if !slices.ContainsFunc(got["typed"].H2[0].Headers, func(h [2]string) bool { return h[0] == ":method" }) ||
		slices.ContainsFunc(got["typed"].H1[0].Headers, func(h [2]string) bool { return h[0] == ":method" }) {
		t.Errorf("h2 %v, h1 %v", got["typed"].H2[0].Headers, got["typed"].H1[0].Headers)
	}
}

func TestAFirstVisitIsMadeInTheProfileTheScenarioRunsIn(t *testing.T) {
	scenarios := map[string]scenario{"again": {note: "again", pre: "{A}/p/first", start: "{A}/p/again", wait: "/p/again"}}
	b := &fake{}
	// Left open long enough for the browser to write down what it keeps.
	slow := quick
	slow.persist = 150 * time.Millisecond
	start := time.Now()
	got, err := measure(context.Background(), b, scenarios, nil, slow, nil)
	if len(b.stopped) == 0 || b.stopped[0].Sub(start) < slow.persist {
		t.Errorf("the first visit was stopped after %v", b.stopped[0].Sub(start))
	}
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	// What the first visit asked for is no part of it.
	if len(got["again"].H2) != 1 || got["again"].H2[0].URL != "https://www.example.com/p/again" {
		t.Errorf("kept %+v", got["again"].H2)
	}
	if len(b.opened) != 4 || b.opened[0].dir != b.opened[1].dir || b.opened[1].dir == b.opened[2].dir ||
		!strings.HasSuffix(b.opened[0].url, "/p/first") || !strings.HasSuffix(b.opened[1].url, "/p/again") {
		t.Errorf("opened %+v", b.opened)
	}
	// And the profile is gone with the scenario.
	if _, err := os.Stat(b.opened[0].dir); !os.IsNotExist(err) {
		t.Errorf("the profile is still there: %v", err)
	}
}

func TestAScenarioWaitsForItsPageToBeAskedForAsOftenAsItSays(t *testing.T) {
	again := func(string) []string { return []string{"/p/again", "/p/again"} }
	thrice := map[string]scenario{"thrice": {note: "thrice", start: "{A}/p/again", wait: "/p/again", times: 3}}
	got, err := measure(context.Background(), &fake{then: again}, thrice, nil, quick, nil)
	if err != nil || len(got["thrice"].H2) != 3 {
		t.Errorf("measure: %+v, %v", got, err)
	}
	// Asked for once less, it is not over: what it asked is kept, and said not
	// to be finished.
	four := map[string]scenario{"four": {start: "{A}/p/again", wait: "/p/again", times: 4}}
	got, err = measure(context.Background(), &fake{then: again}, four, nil, quick, nil)
	if err != nil || len(got["four"].H2) != 3 || len(got["four"].Unfinished) != 2 {
		t.Errorf("measure: %+v, %v", got, err)
	}
}

func TestAScenarioTheBrowserBeganAndDidNotFinishIsWhatItDid(t *testing.T) {
	// It asked for its first page and never for the one it ends at, as Chrome
	// on Windows a page offering Negotiate: what it asked is kept, said to be
	// unfinished over each protocol, and the next scenario is measured.
	scenarios := map[string]scenario{
		"a-stuck": {note: "stuck", start: "{A}/p/stuck", wait: "/p/elsewhere"},
		"b-next":  {note: "next", start: "{A}/p/next", wait: "/p/next"},
	}
	var progress strings.Builder
	short := quick
	short.limit = 300 * time.Millisecond
	got, err := measure(context.Background(), &fake{}, scenarios, nil, short, &progress)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	stuck := got["a-stuck"]
	if want := []string{"over h2: /p/elsewhere was not asked for within 300ms", "over h1: /p/elsewhere was not asked for within 300ms"}; !slices.Equal(stuck.Unfinished, want) ||
		len(stuck.H2) != 1 || stuck.H2[0].URL != "https://www.example.com/p/stuck" || len(stuck.H1) != 1 || stuck.Note != "stuck" {
		t.Errorf("stuck: %+v", stuck)
	}
	if next := got["b-next"]; next.Unfinished != nil || len(next.H2) != 1 {
		t.Errorf("next: %+v", next)
	}
	if !strings.Contains(progress.String(), "h2 a-stuck: 1 requests, /p/elsewhere was not asked for within 300ms\n") ||
		!strings.Contains(progress.String(), "h2 b-next: 1 requests\n") {
		t.Errorf("progress:\n%s", progress.String())
	}
	// Its context ending is no difference of the browser's: nothing is kept.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := measure(ctx, &fake{}, map[string]scenario{"a-stuck": scenarios["a-stuck"]}, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "harness: a-stuck over h2: /p/elsewhere was not asked for: context deadline exceeded") {
		t.Errorf("measure: %v", err)
	}
}

func TestAScenarioThatSettlesIsLeftThatLong(t *testing.T) {
	scenarios := map[string]scenario{"settles": {note: "settles", start: "{A}/p/settles", wait: "/never", settle: 30 * time.Millisecond}}
	got, err := measure(context.Background(), &fake{}, scenarios, nil, quick, nil)
	if err != nil || len(got["settles"].H1) != 1 {
		t.Errorf("measure: %+v, %v", got, err)
	}
}

func TestAScenarioThatAsksNothingOnceOthersLoadedIsTriedOnceMore(t *testing.T) {
	// A browser slow to start once, as Chrome on a Windows runner may be:
	// tried again in a fresh profile, it is measured. Asking nothing twice,
	// it is a scenario not finished, nothing kept, and the next is measured.
	scenarios := map[string]scenario{
		"a-loads": {note: "a", start: "{A}/p/a", wait: "/p/a"},
		"b-quiet": {note: "b", start: "{A}/p/b", wait: "/p/b"},
	}
	short := quick
	short.limit = 300 * time.Millisecond
	once := &fake{quiet: map[int]bool{1: true}}
	got, err := measure(context.Background(), once, scenarios, nil, short, nil)
	if err != nil || got["b-quiet"].Unfinished != nil || len(got["b-quiet"].H2) != 1 || len(once.opened) != 5 ||
		once.opened[1].url != once.opened[2].url || once.opened[1].dir == once.opened[2].dir {
		t.Errorf("once quiet: %+v, %v, opened %+v", got, err, once.opened)
	}
	twice := &fake{quiet: map[int]bool{1: true, 2: true}}
	got, err = measure(context.Background(), twice, scenarios, nil, short, nil)
	if quiet := got["b-quiet"]; err != nil || len(quiet.H2) != 0 || len(quiet.H1) != 1 ||
		!slices.Equal(quiet.Unfinished, []string{"over h2: /p/b was not asked for within 300ms"}) {
		t.Errorf("twice quiet: %+v, %v", got, err)
	}
	if len(twice.opened) != 5 {
		t.Errorf("opened %d times", len(twice.opened))
	}
}

func TestAScenarioWhosePageCameAsAReloadIsRunAgain(t *testing.T) {
	// Its first page asked for with a Cache-Control, instead of as a browser
	// opens it or after it: Chrome's error page, as when its start broke the
	// navigation. Run again in a fresh profile, it is measured as it ran then,
	// and said to be run again; a lobby it starts at as well.
	scenarios := map[string]scenario{
		"typed": {note: "typed", start: "{A}/p/typed", wait: "/p/typed"},
		"lobby": {note: "lobby", start: "{A}/p/lobby?next=/run/{ID}", script: "1"},
	}
	lobby := func(page string) []string {
		if strings.Contains(page, "/p/lobby") {
			return []string{"/run/lobby", "/done/lobby"}
		}
		return nil
	}
	for _, tc := range []struct {
		name    string
		reloads map[int]string
		id      string
		page    string
	}{
		{"instead of the page", map[int]string{0: "instead"}, "typed", "/p/typed"},
		{"after the page", map[int]string{0: "again"}, "typed", "/p/typed"},
		{"its lobby", map[int]string{0: "instead"}, "lobby", "/p/lobby"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &fake{reloads: tc.reloads, then: lobby}
			var progress bytes.Buffer
			got, err := measure(context.Background(), b, scenarios, []string{tc.id}, quick, &progress)
			said := tc.id + ": " + tc.page + " came as a reload, run again\n"
			if err != nil || got[tc.id].Unfinished != nil || !strings.HasPrefix(progress.String(), said) ||
				strings.Count(progress.String(), "run again") != 1 || len(b.opened) != 3 ||
				b.opened[0].url != b.opened[1].url || b.opened[0].dir == b.opened[1].dir {
				t.Errorf("measure: %+v, %v, said %q, opened %+v", got, err, progress.String(), b.opened)
			}
			for _, r := range append(got[tc.id].H2, got[tc.id].H1...) {
				if slices.ContainsFunc(r.Headers, func(h [2]string) bool { return strings.EqualFold(h[0], "cache-control") }) {
					t.Errorf("kept a reload: %+v", r)
				}
			}
		})
	}
}

func TestAScenarioThatDidNotFinishAfterAReloadIsRunAgain(t *testing.T) {
	// The reload asked for nothing more within the time it had: run again,
	// it is measured. Trouble with what it sent is no reload's, and ends it.
	scenarios := map[string]scenario{"start": {note: "start", start: "{A}/p/start", wait: "/p/end"}}
	then := func(page string) []string {
		if strings.Contains(page, "/p/start") {
			return []string{"/p/end"}
		}
		return nil
	}
	short := quick
	short.limit = 300 * time.Millisecond
	b := &fake{then: then, reloads: map[int]string{0: "alone"}}
	got, err := measure(context.Background(), b, scenarios, nil, short, nil)
	if err != nil || got["start"].Unfinished != nil || len(got["start"].H2) != 2 || len(b.opened) != 3 {
		t.Errorf("measure: %+v, %v, opened %d", got, err, len(b.opened))
	}
	garbled := &fake{then: then, garbling: true, reloads: map[int]string{0: "instead"}}
	if _, err := measure(context.Background(), garbled, scenarios, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), `a request line that is not one: "BREW"`) || len(garbled.opened) != 1 {
		t.Errorf("measure: %v, opened %d", err, len(garbled.opened))
	}
}

func TestAScenarioWhosePageCameAsAReloadEveryTimeDidNotFinish(t *testing.T) {
	// Its last run kept, and what it asked; the next protocol measured.
	scenarios := map[string]scenario{"typed": {note: "typed", start: "{A}/p/typed", wait: "/p/typed"}}
	b := &fake{reloads: map[int]string{0: "instead", 1: "instead", 2: "instead"}}
	var progress bytes.Buffer
	got, err := measure(context.Background(), b, scenarios, nil, quick, &progress)
	typed := got["typed"]
	if err != nil || len(b.opened) != 4 || len(typed.H2) != 1 || len(typed.H1) != 1 ||
		!slices.Equal(typed.Unfinished, []string{"over h2: /p/typed came as a reload in each of 3 runs"}) ||
		strings.Count(progress.String(), "typed: /p/typed came as a reload, run again\n") != 2 ||
		!strings.Contains(progress.String(), "h2 typed: 1 requests, /p/typed came as a reload in each of 3 runs\n") {
		t.Errorf("measure: %+v, %v, said %q, opened %d", got, err, progress.String(), len(b.opened))
	}
}

func TestAPageIsAReloadWhenItIsAskedForWithACacheControl(t *testing.T) {
	p := scenario{start: "{A}/p/lobby?after=2&next=/run/{ID}"}.planned("x", origins(8443, 8080))
	get := func(target string, headers ...[2]string) Entry {
		return Entry{Method: http.MethodGet, Target: target, Headers: headers}
	}
	for _, tc := range []struct {
		name    string
		entries []Entry
		page    string
	}{
		{"none", nil, ""},
		{"pages opened", []Entry{get("https://www.example.com:8443/p/lobby?after=2", [2]string{"accept", "text/html"}),
			get("https://www.example.com:8443/run/x")}, ""},
		{"its start, over HTTP/2", []Entry{get("https://www.example.com:8443/p/lobby?after=2", [2]string{"cache-control", "max-age=0"})},
			"/p/lobby"},
		{"its run page, over HTTP/1.1", []Entry{get("https://www.example.com:8443/p/lobby"),
			get("https://www.example.com:8443/run/x", [2]string{"Cache-Control", "max-age=0"})}, "/run/x"},
		{"another page", []Entry{get("https://www.example.com:8443/p/x-end", [2]string{"cache-control", "max-age=0"})}, ""},
		{"another scenario's run page", []Entry{get("https://www.example.com:8443/run/y", [2]string{"cache-control", "max-age=0"})}, ""},
		{"a form's POST", []Entry{{Method: http.MethodPost, Target: "https://www.example.com:8443/run/x",
			Headers: [][2]string{{"cache-control", "max-age=0"}}}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if page, again := reloaded(tc.entries, p, "x"); page != tc.page || again != (tc.page != "") {
				t.Errorf("reloaded: %q, %v, want %q", page, again, tc.page)
			}
		})
	}
}

func TestAScenarioThatDoesNotFinishIsNoMeasurement(t *testing.T) {
	for _, tc := range []struct {
		name      string
		scenarios map[string]scenario
		b         *fake
		says      string
	}{
		{"never begins", map[string]scenario{"stuck": {start: "{A}/p/stuck", wait: "/p/stuck"}}, &fake{silent: true},
			"harness: stuck over h2: /p/stuck was not asked for within 2s"},
		{"never makes its first visit", map[string]scenario{"first": {pre: "{A}/p/first", start: "{A}/p/x", wait: "/p/x"}},
			&fake{silent: true}, "the first visit, https://www.example.com:"},
		{"the browser will not open", map[string]scenario{"closed": {start: "{A}/p/closed", wait: "/p/closed"}}, &fake{fail: "closed"},
			"the fake would not open"},
		{"the browser will not open the first visit", map[string]scenario{"closed": {pre: "{A}/p/pre", start: "{A}/p/x"}},
			&fake{fail: "/p/pre"}, "the fake would not open"},
		{"what it sends cannot be read", map[string]scenario{"garbled": {start: "{A}/p/garbled", wait: "/p/garbled"}},
			&fake{garbling: true}, `a request line that is not one: "BREW"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := measure(context.Background(), tc.b, tc.scenarios, nil, quick, nil)
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Errorf("measure: %v, want %q", err, tc.says)
			}
		})
	}
}

func TestOnlyTheScenariosNamedAreMeasuredAndAnUnknownOneIsRefused(t *testing.T) {
	scenarios := map[string]scenario{
		"a": {start: "{A}/p/a", wait: "/p/a"}, "b": {start: "{A}/p/b", wait: "/p/b"}, "c": {start: "{A}/p/c", wait: "/p/c"},
	}
	var progress bytes.Buffer
	got, err := measure(context.Background(), &fake{}, scenarios, []string{"c", "a"}, quick, &progress)
	if err != nil || len(got) != 2 || got["a"].H2 == nil || got["c"].H1 == nil {
		t.Errorf("measure: %+v, %v", got, err)
	}
	// By name, whatever order they were named in.
	if progress.String() != "h2 a: 1 requests\nh2 c: 1 requests\nh1 a: 1 requests\nh1 c: 1 requests\n" {
		t.Errorf("progress %q", progress.String())
	}
	if _, err := measure(context.Background(), &fake{}, scenarios, []string{"a", "z"}, quick, nil); err == nil ||
		err.Error() != "harness: there is no scenario z" {
		t.Errorf("measure of an unknown scenario: %v", err)
	}
}

func TestAFirstVisitIsWaitedForAnewInEachScenario(t *testing.T) {
	// The first scenario asks for the page the second visits first; the second
	// makes no first visit at all, which the first's request must not stand in
	// for.
	scenarios := map[string]scenario{
		"a": {start: "{A}/p/first", wait: "/p/first"},
		"b": {pre: "{A}/p/first", start: "{A}/p/b", wait: "/p/b"},
	}
	_, err := measure(context.Background(), &fake{quiet: map[int]bool{1: true}}, scenarios, nil, quick, nil)
	if err == nil || !strings.Contains(err.Error(), "b over h2: the first visit") {
		t.Errorf("measure: %v", err)
	}
}

func TestAMeasurementStopsWhenItsContextDoes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scenarios := map[string]scenario{"a": {start: "{A}/p/a", wait: "/p/never"}, "b": {pre: "{A}/p/b", start: "{A}/p/b", wait: "/p/b"}}
	for _, id := range []string{"a", "b"} {
		_, err := measure(ctx, &fake{}, scenarios, []string{id}, quick, nil)
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("%s: %v", id, err)
		}
	}
	// A settle that a done context cuts short is no measurement either.
	settles := map[string]scenario{"s": {start: "{A}/p/s", wait: "/never", settle: time.Hour}}
	if _, err := measure(ctx, &fake{}, settles, nil, quick, nil); err == nil {
		t.Error("a scenario settled past its context")
	}
	// Measure is measure of the catalogue, at the fixture's pace.
	if _, err := Measure(ctx, &fake{fail: "/"}, []string{"nav-direct"}, nil); err == nil ||
		!strings.Contains(err.Error(), "the fake would not open") {
		t.Errorf("Measure: %v", err)
	}
}

// tempNowhere points every variable the system's temporary directory is read
// from at one that is not there: TMPDIR on Unix, TMP and TEMP on Windows.
func tempNowhere(t *testing.T) {
	t.Helper()
	none := filepath.Join(t.TempDir(), "none")
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, none)
	}
}

func TestAMeasurementNeedsAPlaceForItsProfiles(t *testing.T) {
	tempNowhere(t)
	scenarios := map[string]scenario{"a": {start: "{A}/p/a", wait: "/p/a"}}
	if _, err := measure(context.Background(), &fake{}, scenarios, nil, quick, nil); err == nil {
		t.Error("measured with nowhere to keep a profile")
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := measure(context.Background(), &fake{}, scenarios, nil, quick, nil); !errors.Is(err, failing) {
		t.Errorf("measure with no server: %v", err)
	}
}

func TestKeptLeavesOutTheScenesAndThePorts(t *testing.T) {
	s := &Server{H2: 1111, H1: 2222, Plain: 3333}
	entries := []Entry{
		{Method: "GET", Target: "https://www.example.net:1111/r/302/set?cookie=1"},
		{Method: "GET", Target: "https://www.example.com:1111/run/x"},
		{Method: "POST", Target: "https://www.example.com:1111/p/x", Body: "b",
			Headers: [][2]string{{"origin", "https://www.example.com:1111"}, {"referer", "http://localhost:3333/a:11112"},
				{"date", "10:30:00"}}, Priority: &[3]uint32{1, 0, 219}},
		{Method: "GET", Target: "https://www.example.com:1111/favicon.ico"},
		{Method: "GET", Target: "https://www.example.com:1111/done/x"},
		{Method: "GET", Target: "http://www.example.com:2222/p/y"},
	}
	got := s.kept(entries, false)
	want := []Request{
		{Method: "POST", URL: "https://www.example.com/p/x", Body: "b", Priority: []uint32{1, 0, 219},
			Headers: [][2]string{{"origin", "https://www.example.com"}, {"referer", "http://localhost/a:11112"}, {"date", "10:30:00"}}},
		{Method: "GET", URL: "http://www.example.com/p/y"},
	}
	if len(got) != len(want) {
		t.Fatalf("kept %+v", got)
	}
	for i := range want {
		if got[i].Method != want[i].Method || got[i].URL != want[i].URL || got[i].Body != want[i].Body ||
			!slices.Equal(got[i].Priority, want[i].Priority) || !slices.Equal(got[i].Headers, want[i].Headers) {
			t.Errorf("request %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if got := s.kept(nil, false); got == nil || len(got) != 0 {
		t.Errorf("kept of nothing: %#v", got)
	}
	for _, r := range got {
		if r.Conn != 0 || r.Resumed {
			t.Errorf("%s says a connection: %d, %v", r.URL, r.Conn, r.Resumed)
		}
	}
	if pathOf("http://a/%zz") != "" || pathOf("https://a/b?c") != "/b" {
		t.Error("pathOf")
	}
}

func TestAScenarioOfConnectionsKeepsItsPageAndNumbersItsConnectionsByFirstUse(t *testing.T) {
	s := &Server{H2: 1111, H1: 2222, Plain: 3333}
	entries := []Entry{
		{Method: "GET", Target: "https://www.example.com:1111/p/lobby?next=/run/x", Conn: 3},
		{Method: "GET", Target: "https://www.example.com:1111/run/x", Conn: 5, Resumed: true},
		{Method: "GET", Target: "https://www.example.com:1111/favicon.ico", Conn: 4},
		{Method: "GET", Target: "https://www.example.com:1111/p/omit", Conn: 9},
		{Method: "GET", Target: "https://www.example.net:1111/cors/x", Conn: 5, Resumed: true},
		{Method: "GET", Target: "https://www.example.net:1111/cors/y", Conn: 7},
		{Method: "GET", Target: "https://www.example.com:1111/p/omit-again", Conn: 9},
		{Method: "GET", Target: "https://www.example.com:1111/done/x", Conn: 8},
	}
	type kept struct {
		url     string
		conn    int
		resumed bool
	}
	want := []kept{
		{"https://www.example.com/run/x", 1, true},
		{"https://www.example.com/p/omit", 2, false},
		{"https://www.example.net/cors/x", 1, true},
		{"https://www.example.net/cors/y", 3, false},
		{"https://www.example.com/p/omit-again", 2, false},
	}
	got := s.kept(entries, true)
	if len(got) != len(want) {
		t.Fatalf("kept %+v", got)
	}
	for i, w := range want {
		if g := got[i]; g.URL != w.url || g.Conn != w.conn || g.Resumed != w.resumed {
			t.Errorf("request %d: %s on %d, resumed %v; want %+v", i, g.URL, g.Conn, g.Resumed, w)
		}
	}
	// Without its run page, a scenario of connections keeps all it has.
	if got := s.kept(entries[2:4], true); len(got) != 1 || got[0].Conn != 1 || got[0].URL != "https://www.example.com/p/omit" {
		t.Errorf("kept %+v", got)
	}
}

func TestAScenarioOfConnectionsIsMeasuredTakingTheServersKeyAsASites(t *testing.T) {
	scenarios := map[string]scenario{
		"c": {note: "c", start: "{A}/p/lobby?next=/run/{ID}", connections: true},
		"r": {note: "r", start: "{A}/p/r", wait: "/p/r"},
	}
	lobby := func(page string) []string {
		if !strings.Contains(page, "/p/lobby") {
			return nil
		}
		return []string{"/run/c", "/p/c", "/done/c"}
	}
	b := &fake{then: lobby}
	got, err := measure(context.Background(), b, scenarios, nil, quick, nil)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	// Over each protocol, the scenario of connections and no other.
	if len(b.trusted) != 2 || b.trusted[0] != b.trusted[1] || len(b.trusted[0]) != 44 {
		t.Errorf("trusted %q", b.trusted)
	}
	for _, requests := range [][]Request{got["c"].H2, got["c"].H1} {
		// The fake asks each on a connection of its own.
		if len(requests) != 2 || requests[0].URL != "https://www.example.com/run/c" || requests[0].Conn != 1 ||
			requests[1].Conn != 2 {
			t.Errorf("kept %+v", requests)
		}
	}
	if r := got["r"].H2; len(r) != 1 || r[0].Conn != 0 {
		t.Errorf("kept %+v", r)
	}
	// A browser that cannot be told to is measured as it is.
	got, err = measure(context.Background(), untrusting{&fake{then: lobby}}, scenarios, []string{"c"}, quick, nil)
	if err != nil || len(got["c"].H1) != 2 {
		t.Errorf("measure: %+v, %v", got, err)
	}
	// MeasureConnections is measure of the catalogue of connections.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := MeasureConnections(ctx, &fake{fail: "/"}, []string{"conn-fetch"}, nil); err == nil ||
		!strings.Contains(err.Error(), "conn-fetch over h2: the fake would not open") {
		t.Errorf("MeasureConnections: %v", err)
	}
}

func TestAFixtureOfRequestsIsWrittenAsItIsKept(t *testing.T) {
	out := filepath.Join(t.TempDir(), "requests.json")
	var fixture *RequestsFixture
	for _, path := range []string{requestsFixture, connectionsFixture} {
		committed, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if fixture, err = LoadRequests(path); err != nil {
			t.Fatalf("LoadRequests: %v", err)
		}
		if err := fixture.Write(out); err != nil {
			t.Fatalf("Write: %v", err)
		}
		written, _ := os.ReadFile(out)
		if !bytes.Equal(written, committed) {
			t.Errorf("%s read and written again is not the fixture", path)
		}
	}
	if _, err := LoadRequests(filepath.Join(t.TempDir(), "none.json")); !os.IsNotExist(err) {
		t.Errorf("LoadRequests of nothing: %v", err)
	}
	broken := filepath.Join(t.TempDir(), "broken.json")
	_ = os.WriteFile(broken, []byte(`{"scenarios":`), 0o644)
	if _, err := LoadRequests(broken); err == nil || !strings.Contains(err.Error(), "broken.json") {
		t.Errorf("LoadRequests of a broken file: %v", err)
	}
	if err := fixture.Write(filepath.Join(t.TempDir(), "none", "x.json")); err == nil {
		t.Error("written where there is no directory")
	}
	if err := writeJSON(out, map[string]any{"x": make(chan int)}); err == nil {
		t.Error("wrote what JSON cannot say")
	}
}

func TestNoRequestChromeSentInAFixtureIsAReload(t *testing.T) {
	// The rule would run every scenario measured again were Chrome to ask
	// for a page it begins with with a Cache-Control as it should: none of
	// the requests, connections, header blocks and ALPS it was measured to
	// send is one.
	o := origins(8443, 8080)
	held := 0
	hold := func(id string, sc scenario, entries []Entry) {
		t.Helper()
		if page, again := reloaded(entries, sc.planned(id, o), id); again {
			t.Errorf("%s: %s came as a reload", id, page)
		}
		held++
	}
	for path, scenarios := range map[string]map[string]scenario{requestsFixture: catalogue, connectionsFixture: connectionCatalogue} {
		fixture, err := LoadRequests(path)
		if err != nil {
			t.Fatalf("LoadRequests: %v", err)
		}
		for id, measured := range fixture.Scenarios {
			for _, r := range append(measured.H2, measured.H1...) {
				hold(id, scenarios[id], []Entry{{Method: r.Method, Target: r.URL, Headers: r.Headers}})
			}
		}
	}
	written := func(conns [][]WrittenRequest) []Entry {
		var out []Entry
		for _, conn := range conns {
			for _, r := range conn {
				e := Entry{Method: r.Method, Target: r.URL}
				for _, field := range r.Fields {
					name, _, _ := strings.Cut(strings.TrimPrefix(field, ":"), ":")
					e.Headers = append(e.Headers, [2]string{name, ""})
				}
				out = append(out, e)
			}
		}
		return out
	}
	hpack, err := LoadHPACK(hpackFixture)
	if err != nil {
		t.Fatalf("LoadHPACK: %v", err)
	}
	for id, measured := range hpack.Scenarios {
		hold(id, hpackCatalogue[id], written(measured.Connections))
	}
	alps, err := LoadALPS(alpsFixture)
	if err != nil {
		t.Fatalf("LoadALPS: %v", err)
	}
	for id, measured := range alps.Scenarios {
		hold(id, alpsCatalogue[id], written(measured.Connections))
	}
	if held < 700 {
		t.Errorf("held %d requests and blocks", held)
	}
	// The way blocks are read: a field with the name, as a run page's
	// reload writes it.
	if _, again := reloaded(written([][]WrittenRequest{{{Method: "GET", URL: "https://www.example.com/run/x",
		Fields: []string{":method: indexed static 2", "cache-control: with indexing, name static 24, value huffman"}}}}),
		scenario{}.planned("x", o), "x"); !again {
		t.Error("a run page's block with cache-control is no reload")
	}
}
