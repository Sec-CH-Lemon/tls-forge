package harness

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// recordsFixture is the fixture of records, from the package's directory.
const recordsFixture = "../../testdata/chrome155-records.json"

func TestRecordsAreMeasuredOverHTTP1(t *testing.T) {
	scenarios := map[string]scenario{"two": {note: "two", script: "1", wait: "/p/a", quiet: true}}
	b := &oneConnection{then: func(string) []string { return []string{"/p/a"} }}
	var progress bytes.Buffer
	got, err := measureRecords(context.Background(), b, scenarios, nil, quick, &progress)
	if err != nil {
		t.Fatalf("measureRecords: %v", err)
	}
	if progress.String() != "h1 two: 2 requests\n" {
		t.Errorf("progress %q", progress.String())
	}
	two := got["two"]
	if two.Note != "two" || len(two.Requests) != 2 || two.Requests[1].Method != "GET" ||
		two.Requests[1].URL != "https://www.example.com/p/a" || len(two.Requests[1].Records) != 1 ||
		!strings.HasPrefix(two.Requests[1].Records[0], "R") {
		t.Errorf("two: %+v", two)
	}
	// Measured with nothing to say it to.
	if _, err := measureRecords(context.Background(), b, scenarios, nil, quick, nil); err != nil {
		t.Errorf("measureRecords: %v", err)
	}
}

func TestARecordsMeasurementSaysWhyItIsNone(t *testing.T) {
	scenarios := map[string]scenario{"b": {note: "b", script: "1", wait: "/run/b"}}
	if _, err := measureRecords(context.Background(), &oneConnection{}, scenarios, []string{"c"}, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "there is no scenario c") {
		t.Errorf("an unknown scenario: %v", err)
	}
	if _, err := measureRecords(context.Background(), &oneConnection{fail: true}, scenarios, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "b over http/1.1: the browser would not open") {
		t.Errorf("a browser that does not open: %v", err)
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := MeasureRecords(context.Background(), &oneConnection{}, nil, nil); !errors.Is(err, failing) {
		t.Errorf("measured with no server: %v", err)
	}
	if _, err := StartRecordsServer(); !errors.Is(err, failing) {
		t.Errorf("started with no port: %v", err)
	}
}

func TestTheRecordsServerServesHTTP1OverTLS(t *testing.T) {
	s, err := StartRecordsServer()
	if err != nil {
		t.Fatalf("StartRecordsServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	res, _ := get(t, "GET", "https://www.example.com:"+strconv.Itoa(s.H1)+"/p/a", nil)
	entries := requests(t, s)
	if res.Proto != "HTTP/1.1" || len(entries) != 1 || entries[0].Records == nil {
		t.Errorf("answered %s, kept %+v", res.Proto, entries)
	}
}

func TestOnlyHTTP1RequestsOverTLSAreRecorded(t *testing.T) {
	s := started(t, catalogue)
	port := strconv.Itoa(s.H1)
	entries := []Entry{
		{Proto: "h2", Method: "GET", Target: "https://www.example.com:" + port + "/a"},
		{Proto: "http/1.1", Method: "GET", Target: "http://www.example.com/b"},
		{Proto: "http/1.1", Method: "POST", Target: "https://www.example.com:" + port + "/c", Body: "abc", Records: []string{"R10+B3"}},
	}
	if got := s.Recorded(entries); !slices.EqualFunc(got, []RecordedRequest{{Method: "POST", URL: "https://www.example.com/c",
		Body: 3, Records: []string{"R10+B3"}}}, func(a, b RecordedRequest) bool {
		return a.Method == b.Method && a.URL == b.URL && a.Body == b.Body && slices.Equal(a.Records, b.Records)
	}) {
		t.Errorf("recorded %+v", got)
	}
	if got := s.Recorded(nil); got == nil || len(got) != 0 {
		t.Errorf("recorded of none %#v", got)
	}
}

func TestEveryDifferenceInHowRecordsCarriedRequestsIsSaid(t *testing.T) {
	request := func(method, url string, body int, records ...string) RecordedRequest {
		return RecordedRequest{Method: method, URL: url, Body: body, Records: records}
	}
	want := RecordsScenario{Requests: []RecordedRequest{request("GET", "https://a/1", 0, "R100"),
		request("POST", "https://a/2", 3, "R120+B3")}}
	for _, tc := range []struct {
		name string
		got  []RecordedRequest
		diff []string
	}{
		{"the same", want.Requests, nil},
		{"a request fewer", want.Requests[:1], []string{"1 requests, want 2"}},
		{"another request", []RecordedRequest{want.Requests[0], request("PUT", "https://a/2", 3, "R120+B3")},
			[]string{"request 2: PUT https://a/2, want POST https://a/2"}},
		{"another URL", []RecordedRequest{request("GET", "https://a/3", 0, "R100"), want.Requests[1]},
			[]string{"request 1: GET https://a/3, want GET https://a/1"}},
		{"in records otherwise", []RecordedRequest{want.Requests[0], request("POST", "https://a/2", 3, "R120", "B3")},
			[]string{"request 2, POST https://a/2: a body of 3 in records [R120 B3], want 3 in [R120+B3]"}},
		{"another body", []RecordedRequest{want.Requests[0], request("POST", "https://a/2", 4, "R120+B3")},
			[]string{"request 2, POST https://a/2: a body of 4 in records [R120+B3], want 3 in [R120+B3]"}},
	} {
		if diff := DiffRecords(want, RecordsScenario{Requests: tc.got}); !slices.Equal(diff, tc.diff) {
			t.Errorf("%s: %q, want %q", tc.name, diff, tc.diff)
		}
	}
	other := RecordsScenario{Requests: want.Requests[:1]}
	got := CompareRecords(map[string]RecordsScenario{"a": want, "b": want, "c": want},
		map[string]RecordsScenario{"a": want, "c": other, "d": want})
	if !slices.Equal(got, []string{"b was not measured", "c: 1 requests, want 2",
		"d was measured, and the fixture has no such scenario"}) {
		t.Errorf("CompareRecords: %q", got)
	}
}

func TestAFixtureOfRecordsIsWrittenAsItIsKept(t *testing.T) {
	committed, err := os.ReadFile(recordsFixture)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fixture, err := LoadRecords(recordsFixture)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	path := filepath.Join(t.TempDir(), "records.json")
	if err := fixture.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if wrote, _ := os.ReadFile(path); !bytes.Equal(wrote, committed) {
		t.Errorf("wrote it otherwise:\n%s", wrote)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(fixture.Scenarios)), slices.Sorted(maps.Keys(recordsCatalogue))) {
		t.Errorf("the fixture's scenarios: %v", slices.Sorted(maps.Keys(fixture.Scenarios)))
	}
}
