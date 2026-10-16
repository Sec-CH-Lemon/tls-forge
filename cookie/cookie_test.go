package cookie

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestLoadTheFilesOwnShape(t *testing.T) {
	file, err := Load([]byte(`{
	  "version": 1,
	  "sets": [
	    {"id": "warm-eu", "note": "logged in", "cookies": [
	      {"name": "session", "value": "eu-1", "domain": "example.com", "path": "/",
	       "secure": true, "http_only": true, "expires": "2030-01-02T03:04:05Z"}
	    ]}
	  ]
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(file.Sets) != 1 || file.Sets[0].ID != "warm-eu" {
		t.Fatalf("sets: %+v", file.Sets)
	}
	got := file.Sets[0].Cookies[0]
	if got.Name != "session" || got.Value != "eu-1" || got.Domain != "example.com" {
		t.Errorf("cookie: %+v", got)
	}
	// The flags are part of what the server set, and a session is not portable
	// without them.
	if !got.Secure || !got.HTTPOnly {
		t.Errorf("the flags were lost: %+v", got)
	}
	if got.Expires.Year() != 2030 {
		t.Errorf("expiry: %v", got.Expires)
	}
}

func TestLoadABareArrayOfSets(t *testing.T) {
	file, err := Load([]byte(`[{"id":"a","cookies":[{"name":"s","value":"1"}]},
	                           {"cookies":[{"name":"s","value":"2"}]}]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Every set gets an id, so one can always be asked for by name.
	if ids := file.IDs(); len(ids) != 2 || ids[0] != "a" || ids[1] != "2" {
		t.Errorf("ids = %v", ids)
	}
}

func TestLoadABareArrayWithAnEmptySet(t *testing.T) {
	file, err := Load([]byte(`[{"id":"empty","cookies":[]}]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(file.Sets) != 1 || file.Sets[0].ID != "empty" || len(file.Sets[0].Cookies) != 0 {
		t.Fatalf("sets: %+v", file.Sets)
	}
}

func TestLoadAnEmptyArrayAsAnEmptyFile(t *testing.T) {
	file, err := Load([]byte(`[]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(file.Sets) != 0 {
		t.Fatalf("sets: %+v", file.Sets)
	}
}

func TestLoadABrowserExport(t *testing.T) {
	// What an extension writes: a flat array, camelCase flag, expiry as seconds
	// since the epoch with a fraction. A warmed session usually arrives this
	// way and nobody should have to rewrite it.
	file, err := Load([]byte(`[
	  {"name":"session","value":"abc","domain":".example.com","path":"/",
	   "secure":true,"httpOnly":true,"expirationDate":1893456245.5,"sameSite":"lax"},
	  {"name":"other","value":"x"}
	]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(file.Sets) != 1 || len(file.Sets[0].Cookies) != 2 {
		t.Fatalf("sets: %+v", file.Sets)
	}
	got := file.Sets[0].Cookies[0]
	if !got.HTTPOnly {
		t.Error("httpOnly was not read")
	}
	if got.Expires.Unix() != 1893456245 {
		t.Errorf("expiry = %v", got.Expires)
	}
	// A field this format does not know is not a reason to reject a file that
	// came out of a browser.
	if file.Sets[0].Cookies[1].Name != "other" {
		t.Errorf("cookies: %+v", file.Sets[0].Cookies)
	}
}

func TestLoadRejectsWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"nothing at all", "   "},
		{"not JSON", "<html>"},
		{"an object with a key this format does not know", `{"sets":[],"colour":"red"}`},
		{"a cookie with no name", `[{"value":"x"}]`},
		{"a cookie with no name in the file shape", `{"sets":[{"id":"a","cookies":[{"value":"x"}]}]}`},
		{"a cookie with no name in a set array", `[{"id":"a","cookies":[{"value":"x"}]}]`},
		{"a set array with an unknown field", `[{"id":"a","cookies":[],"colour":"red"}]`},
		{"duplicate set ids", `{"sets":[{"id":"a","cookies":[]},{"id":"a","cookies":[]}]}`},
		{"more than one JSON value", `{"sets":[]} {"sets":[]}`},
		{"garbage after a JSON object", `{"sets":[]} trailing`},
		// An array that is neither a list of sets nor a list of cookies.
		{"an array of numbers", `[1, 2, 3]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load([]byte(tc.body)); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestLoadFillsInWhatAFileLeavesOut(t *testing.T) {
	// No version and no ids: both are this format's to supply, so a file written
	// by hand is still one a run can ask a set of.
	file, err := Load([]byte(`{"sets":[{"cookies":[{"name":"s","value":"1"}]}]}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if file.Version != currentVersion || file.Sets[0].ID != "1" {
		t.Errorf("got version %d, ids %v", file.Version, file.IDs())
	}
}

func TestLoadABrowserExportWithAnRFC3339Expiry(t *testing.T) {
	// Not every exporter writes the date as seconds since the epoch.
	file, err := Load([]byte(`[{"name":"s","value":"1","expires":"2030-06-01T12:00:00Z"}]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := file.Sets[0].Cookies[0].Expires; got.Year() != 2030 || got.Month() != time.June {
		t.Errorf("expiry = %v", got)
	}
}

func TestEncodeLeavesOutAWarmingDateThatWasNeverSet(t *testing.T) {
	data := (&File{Sets: []Set{{ID: "a"}}}).Encode()
	if strings.Contains(string(data), "warmed") {
		t.Errorf("a set that was never dated carries one:\n%s", data)
	}
	dated := (&File{Sets: []Set{{ID: "a", Warmed: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}}).Encode()
	if !strings.Contains(string(dated), "2030-01-01") {
		t.Errorf("a real warming date was dropped:\n%s", dated)
	}
}

func TestPick(t *testing.T) {
	file := &File{Sets: []Set{{ID: "a"}, {ID: "b"}, {ID: "c"}}}
	pick := rand.New(rand.NewSource(1))

	if set, err := file.Pick("b", pick); err != nil || set.ID != "b" {
		t.Errorf("by name: %+v, %v", set, err)
	}

	// Random rather than the first: a file of warmed sessions exists to be
	// spread over.
	seen := map[string]bool{}
	for range 200 {
		set, err := file.Pick("", pick)
		if err != nil {
			t.Fatalf("Pick: %v", err)
		}
		seen[set.ID] = true
	}
	if len(seen) != 3 {
		t.Errorf("only %v were ever chosen", seen)
	}

	// One set needs no seed to be repeatable.
	single := &File{Sets: []Set{{ID: "only"}}}
	if set, _ := single.Pick("", pick); set.ID != "only" {
		t.Errorf("a file of one: %+v", set)
	}
	if _, err := file.Pick("", nil); err == nil {
		t.Error("multiple sets without a random source should be rejected")
	}
}

func TestPickErrors(t *testing.T) {
	pick := rand.New(rand.NewSource(1))
	if _, err := (&File{}).Pick("", pick); err == nil {
		t.Error("an empty file should be rejected")
	}
	// The message names what is there, or the reader is left guessing.
	_, err := (&File{Sets: []Set{{ID: "warm-eu"}, {ID: "warm-us"}}}).Pick("nope", pick)
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"nope", "warm-eu", "warm-us"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestLive(t *testing.T) {
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	set := Set{Cookies: []Cookie{
		{Name: "session"}, // no date: a session cookie
		{Name: "fresh", Expires: now.Add(time.Hour)},
		{Name: "due", Expires: now},
		{Name: "stale", Expires: now.Add(-time.Hour)},
	}}
	live := set.Live(now)
	if len(live.Cookies) != 2 {
		t.Fatalf("kept %+v", live.Cookies)
	}
	for _, c := range live.Cookies {
		if c.Name == "stale" || c.Name == "due" {
			t.Error("an expired cookie was kept")
		}
	}
	// The original is untouched, so a caller can still see what expired.
	if len(set.Cookies) != 4 {
		t.Error("Live changed the set it was given")
	}
}

func TestAddGivesEverySetAnIDOfItsOwn(t *testing.T) {
	// --cookie-set takes an id: two sets answering to the same name make the
	// flag a coin toss. Two runs can finish inside one second.
	file := &File{}
	for range 3 {
		file.Add(Set{ID: "2026-08-16-09-08-21"})
	}
	file.Add(Set{})
	want := []string{"2026-08-16-09-08-21", "2026-08-16-09-08-21-2", "2026-08-16-09-08-21-3", "1"}
	got := file.IDs()
	if len(got) != len(want) {
		t.Fatalf("ids = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ids = %v, want %v", got, want)
			break
		}
	}
}

func TestEncodeLeavesOutAnExpiryThatWasNeverSet(t *testing.T) {
	// omitempty has no opinion about a struct, so a session cookie would
	// otherwise be written down as expiring in the year one.
	file := &File{Sets: []Set{{ID: "a", Cookies: []Cookie{
		{Name: "session", Value: "x"},
		{Name: "dated", Value: "y", Expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
	}}}}
	data := file.Encode()
	if strings.Contains(string(data), "0001-01-01") {
		t.Errorf("a session cookie was given a date:\n%s", data)
	}
	if !strings.Contains(string(data), "2030-01-01") {
		t.Errorf("a real expiry was dropped:\n%s", data)
	}

	// And what was written comes back the same.
	again, err := Load(data)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if len(again.Sets[0].Cookies) != 2 || !again.Sets[0].Cookies[0].Expires.IsZero() {
		t.Errorf("round trip: %+v", again.Sets[0].Cookies)
	}
	if again.Version != currentVersion {
		t.Errorf("version = %d", again.Version)
	}
}

func TestEncodeIsValidJSON(t *testing.T) {
	data := (&File{Sets: []Set{{ID: "a", Cookies: []Cookie{{Name: "n", Value: "v"}}}}}).Encode()
	var any map[string]any
	if err := json.Unmarshal(data, &any); err != nil {
		t.Fatalf("what was written is not JSON: %v", err)
	}
}

func TestParse(t *testing.T) {
	got, err := Parse(" session = abc123 ")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Name != "session" || got.Value != "abc123" {
		t.Errorf("got %+v", got)
	}
	// A value may hold anything, including the separator.
	if got, _ := Parse("jwt=a=b=c"); got.Value != "a=b=c" {
		t.Errorf("value = %q", got.Value)
	}
	if got, _ := Parse("empty="); got.Name != "empty" || got.Value != "" {
		t.Errorf("got %+v", got)
	}

	for _, bad := range []string{"no-equals-sign", "=novalue", " = "} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestAFileKeepsWhichCookiesAreTheirHostsAlone(t *testing.T) {
	file := &File{Sets: []Set{{ID: "s", Cookies: []Cookie{
		{Name: "host", Value: "1", Domain: "example.com", HostOnly: true, SameSite: "lax"},
		{Name: "domain", Value: "2", Domain: "example.com", SameSite: "none"},
	}}}}
	data := file.Encode()
	if !strings.Contains(string(data), `"version": 2`) || !strings.Contains(string(data), `"host_only": true`) ||
		!strings.Contains(string(data), `"same_site": "lax"`) {
		t.Fatalf("the scope or the SameSite was not written:\n%s", data)
	}
	if strings.Count(string(data), "host_only") != 1 {
		t.Errorf("a domain's cookie was written as its host's:\n%s", data)
	}
	again, err := Load(data)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	got := again.Sets[0].Cookies
	if !got[0].HostOnly || got[1].HostOnly || got[0].SameSite != "lax" || got[1].SameSite != "none" {
		t.Errorf("round trip lost the scope or the SameSite: %+v", got)
	}
	if again.Unscoped() {
		t.Error("a file written now says it does not keep scope")
	}
}

func TestAnOlderFileSaysItDidNotKeepScope(t *testing.T) {
	// Version 1 wrote every cookie without its scope, so a host's cookie reads
	// as its domain's; the file says so, and is read as it was then.
	old, err := Load([]byte(`{"version":1,"sets":[{"id":"a","cookies":[{"name":"s","value":"1","domain":"example.com"}]}]}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !old.Unscoped() || old.Sets[0].Cookies[0].HostOnly {
		t.Errorf("version 1: unscoped %v, cookie %+v", old.Unscoped(), old.Sets[0].Cookies[0])
	}
	// Written again, it is this version, and says nothing of the sort.
	again, err := Load(old.Encode())
	if err != nil || again.Unscoped() || again.Version != currentVersion {
		t.Errorf("rewritten: %v, unscoped %v, version %d", err, again.Unscoped(), again.Version)
	}
	for _, body := range []string{`{"sets":[]}`, `[]`, "example.com\tTRUE\t/\tFALSE\t0\tn\tv\n"} {
		file, err := Load([]byte(body))
		if err != nil || file.Unscoped() {
			t.Errorf("%q: %v, unscoped %v", body, err, file.Unscoped())
		}
	}
}

func TestABrowserExportKeepsScopeLifetimeAndSameSite(t *testing.T) {
	file, err := Load([]byte(`[
	  {"name":"a","value":"1","domain":"example.com","hostOnly":true,"session":true,
	   "expirationDate":1893553445,"sameSite":"no_restriction"},
	  {"name":"b","value":"2","domain":".example.com","hostOnly":false,"sameSite":"lax",
	   "expirationDate":1893553445},
	  {"name":"c","value":"3","domain":"example.com","sameSite":"unspecified"},
	  {"name":"d","value":"4","domain":"example.com","host_only":true,"same_site":"Strict"}
	]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := file.Sets[0].Cookies
	for i, want := range []struct {
		hostOnly bool
		session  bool
		sameSite string
	}{
		// A session cookie has no expiry, whatever date the export wrote beside it.
		{true, true, "none"},
		{false, false, "lax"},
		{false, true, ""},
		{true, true, "strict"},
	} {
		if got[i].HostOnly != want.hostOnly || got[i].Expires.IsZero() != want.session || got[i].SameSite != want.sameSite {
			t.Errorf("cookie %s: host only %v, expires %v, SameSite %q; want %v, session %v, %q",
				got[i].Name, got[i].HostOnly, got[i].Expires, got[i].SameSite, want.hostOnly, want.session, want.sameSite)
		}
	}
}
