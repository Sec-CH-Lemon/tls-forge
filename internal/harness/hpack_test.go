package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// hpackFixture is the fixture of header blocks, from the package's directory.
const hpackFixture = "../../testdata/chrome155-hpack.json"

// oneConnection is a browser that asks for the page it opens, and then for
// what then says it would ask for there, on one HTTP/2 connection, written by
// Go's own encoder with a table as large as the server allows, up to table.
// The first split times it is opened, it asks for what follows the page on a
// connection of its own.
type oneConnection struct {
	then   func(page string) []string
	table  uint32
	fail   bool
	split  int
	opened int
}

// connection is a client of a connection of its own.
func (b *oneConnection) connection() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the bench's own certificate
		ForceAttemptHTTP2: true,
		HTTP2:             &http.HTTP2Config{MaxEncoderHeaderTableSize: int(max(b.table, 4096))},
	}}
}

func (b *oneConnection) Open(_ context.Context, page, _ string) (func(), error) {
	if b.fail {
		return nil, errors.New("the browser would not open " + page)
	}
	b.opened++
	first := b.connection()
	ask := func(c *http.Client, url string) {
		if res, err := c.Get(url); err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
	}
	ask(first, page)
	then := first
	if b.opened <= b.split {
		then = b.connection()
	}
	if b.then != nil {
		base, _ := url.Parse(page)
		for _, next := range b.then(page) {
			to, _ := base.Parse(next)
			ask(then, to.String())
		}
	}
	first.CloseIdleConnections()
	then.CloseIdleConnections()
	return func() {}, nil
}

func (b *oneConnection) DumpDOM(context.Context, string) ([]byte, error) { return nil, nil }

func TestHPACKIsMeasuredConnectionByConnection(t *testing.T) {
	scenarios := map[string]scenario{
		"two":    {note: "two", script: "1", wait: "/p/a", quiet: true},
		"tabled": {note: "tabled", script: "1", wait: "/p/a", table: 1024},
	}
	b := &oneConnection{then: func(string) []string { return []string{"/p/a", "/p/a"} }}
	var progress bytes.Buffer
	got, err := measureHPACK(context.Background(), b, scenarios, nil, quick, &progress)
	if err != nil {
		t.Fatalf("measureHPACK: %v", err)
	}
	if progress.String() != "h2 tabled: 1 connections\nh2 two: 1 connections\n" {
		t.Errorf("progress %q", progress.String())
	}
	two := got["two"]
	if two.Note != "two" || two.Table != 0 || len(two.Connections) != 1 || len(two.Connections[0]) != 3 {
		t.Fatalf("two: %+v", two)
	}
	first, again := two.Connections[0][1], two.Connections[0][2]
	if first.Method != "GET" || first.URL != "https://www.example.com/p/a" || !slices.Contains(first.Fields, ":method: indexed static 2") {
		t.Errorf("the first /p/a: %+v", first)
	}
	// Asked again on the connection, every field but :path is found whole.
	for _, field := range again.Fields {
		if !strings.Contains(field, "indexed") {
			t.Errorf("asked again, %q", field)
		}
	}
	if got := got["tabled"]; got.Table != 1024 || len(got.Connections) != 1 || !slices.Contains(got.Connections[0][1].Fields, "size update 1024") {
		t.Errorf("tabled: %+v", got)
	}
}

func TestAnHPACKMeasurementSaysWhyItIsNone(t *testing.T) {
	scenarios := map[string]scenario{"b": {note: "b", script: "1", wait: "/run/b"}}
	if _, err := measureHPACK(context.Background(), &oneConnection{}, scenarios, []string{"c"}, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "there is no scenario c") {
		t.Errorf("an unknown scenario: %v", err)
	}
	if _, err := measureHPACK(context.Background(), &oneConnection{fail: true}, scenarios, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "b over h2: the browser would not open") {
		t.Errorf("a browser that does not open: %v", err)
	}
	// A block written for a larger table than the scenario's server allows:
	// that of a's server, whose port the browser keeps from a's page, and
	// asks of in b's.
	scenarios["a"] = scenario{note: "a", wait: "/run/a", table: 65536}
	var table string
	b := &oneConnection{table: 65536, then: func(page string) []string {
		u, _ := url.Parse(page)
		if table == "" {
			table = u.Port()
			return nil
		}
		return []string{"https://www.example.com:" + table + "/p/a", "https://www.example.com:" + table + "/p/b"}
	}}
	if _, err := measureHPACK(context.Background(), b, scenarios, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "b over h2: harness: GET https://www.example.com/p/b on connection") {
		t.Errorf("a table larger than allowed: %v", err)
	}
	if got, err := measureHPACK(context.Background(), &oneConnection{}, nil, nil, quick, nil); err != nil || len(got) != 0 {
		t.Errorf("nothing to measure: %v, %v", got, err)
	}
	// MeasureHPACK is measureHPACK of the HPACK catalogue, at the fixture's
	// pace.
	if _, err := MeasureHPACK(context.Background(), &oneConnection{fail: true}, []string{"hpack-fetch"}, nil); err == nil ||
		!strings.Contains(err.Error(), "hpack-fetch over h2: the browser would not open") {
		t.Errorf("MeasureHPACK: %v", err)
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := measureHPACK(context.Background(), &oneConnection{}, scenarios, nil, quick, nil); !errors.Is(err, failing) {
		t.Errorf("measured with no server: %v", err)
	}
}

func TestAScenarioWhoseOriginTookTwoConnectionsIsRunAgain(t *testing.T) {
	// Run again while an origin's requests went on more than one
	// connection, at most runs times.
	scenarios := map[string]scenario{"a": {note: "a", wait: "/p/a"}}
	then := func(string) []string { return []string{"/p/a"} }
	b := &oneConnection{then: then, split: runs - 1}
	var progress bytes.Buffer
	got, err := measureHPACK(context.Background(), b, scenarios, nil, quick, &progress)
	if err != nil || len(got["a"].Connections) != 1 || b.opened != runs {
		t.Fatalf("measured %+v in %d runs: %v", got, b.opened, err)
	}
	again := "h2 a: an origin's requests on more than one connection, run again\n"
	if want := strings.Repeat(again, runs-1) + "h2 a: 1 connections\n"; progress.String() != want {
		t.Errorf("progress %q, want %q", progress.String(), want)
	}
	b = &oneConnection{then: then, split: runs}
	if _, err := measureHPACK(context.Background(), b, scenarios, nil, quick, nil); err == nil || b.opened != runs ||
		!strings.Contains(err.Error(), "a over h2: an origin's requests went on more than one connection in each of 5 runs") {
		t.Errorf("in %d runs: %v", b.opened, err)
	}
	// Each origin on a connection of its own is one each; a target that is
	// no URL is an origin of its own.
	for _, tc := range []struct {
		entries []Entry
		one     bool
	}{
		{[]Entry{{Proto: "h2", Conn: 1, Target: "https://a/1"}, {Proto: "h2", Conn: 2, Target: "https://b/1"}, {Proto: "h2", Conn: 1, Target: "https://a/2"}}, true},
		{[]Entry{{Proto: "h2", Conn: 1, Target: "https://a/1"}, {Proto: "h2", Conn: 2, Target: "https://a/2"}}, false},
		{[]Entry{{Proto: "h2", Conn: 1, Target: "https://a/1"}, {Proto: "http/1.1", Conn: 2, Target: "https://a/2"}}, true},
		{[]Entry{{Proto: "h2", Conn: 1, Target: "%zz"}, {Proto: "h2", Conn: 2, Target: "%zz"}}, false},
		{[]Entry{{Proto: "h2", Conn: 1, Target: "%zz"}, {Proto: "h2", Conn: 2, Target: "%zy"}}, true},
	} {
		if got := oneEach(tc.entries); got != tc.one {
			t.Errorf("oneEach(%+v) = %v", tc.entries, got)
		}
	}
}

func TestAServerWithTablesThatCannotStartSaysWhy(t *testing.T) {
	failing := errors.New("no")
	old := listen
	t.Cleanup(func() { listen = old })
	calls := 0
	listen = func(network, addr string) (net.Listener, error) {
		// The first four are had, and the fifth, the second table's, is not.
		if calls++; calls < 5 {
			return net.Listen(network, addr)
		}
		return nil, failing
	}
	if _, err := startServer(hpackCatalogue); !errors.Is(err, failing) {
		t.Errorf("startServer: %v", err)
	}
}

// blocksOf are the header blocks of each list of fields, names and values, as
// one HPACK encoder writes them one after another on a connection.
func blocksOf(lists ...[]string) [][]byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	var out [][]byte
	for _, fields := range lists {
		buf.Reset()
		for i := 0; i < len(fields); i += 2 {
			_ = enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
		}
		out = append(out, slices.Clone(buf.Bytes()))
	}
	return out
}

func TestWrittenReadsEachConnectionAgainstItsOwnTable(t *testing.T) {
	s := &Server{H2: 1111, H1: 2222, Plain: 3333, Tables: map[uint32]int{1024: 4444}}
	one := blocksOf([]string{":method", "GET", "x-a", "1"}, []string{":method", "GET", "x-a", "1"})
	// Another connection's table holds another field: read against the
	// first's, its index would name it.
	two := blocksOf([]string{":method", "GET", "x-b", "2"})
	entries := []Entry{
		{Proto: "h2", Conn: 1, Method: "GET", Target: "https://www.example.com:1111/a", Block: one[0]},
		{Proto: "http/1.1", Conn: 2, Method: "GET", Target: "https://www.example.com:2222/b"},
		{Proto: "h2", Conn: 3, Method: "GET", Target: "https://www.example.com:4444/c", Block: two[0]},
		{Proto: "h2", Conn: 1, Method: "GET", Target: "https://www.example.com:1111/d", Block: one[1]},
	}
	got, err := s.Written(entries, 1024)
	if err != nil {
		t.Fatalf("Written: %v", err)
	}
	want := [][]WrittenRequest{
		{{Method: "GET", URL: "https://www.example.com/a", Fields: []string{":method: indexed static 2", "x-a: with indexing, new name, value plain"}},
			{Method: "GET", URL: "https://www.example.com/d", Fields: []string{":method: indexed static 2", "x-a: indexed dynamic 62"}}},
		{{Method: "GET", URL: "https://www.example.com/c", Fields: []string{":method: indexed static 2", "x-b: with indexing, new name, value plain"}}},
	}
	if diff := DiffHPACK(HPACKScenario{Connections: want}, HPACKScenario{Connections: got}); diff != nil {
		t.Errorf("%q", diff)
	}
	// A table as large as the server allowed is read, and one larger is not.
	bigger := []Entry{{Proto: "h2", Conn: 1, Method: "GET", Target: "https://a/", Block: []byte{0x3f, 0xe1, 0xff, 0x03}}}
	if got, err := s.Written(bigger, 65536); err != nil || got[0][0].Fields[0] != "size update 65536" {
		t.Errorf("a table the server allowed: %v, %v", got, err)
	}
	if _, err := s.Written(bigger, 0); err == nil {
		t.Error("a table larger than the server allowed was read")
	}
	// A block that does not read is said, by its request and connection.
	entries[3].Block = []byte{0xff}
	if _, err := s.Written(entries, 0); err == nil || err.Error() !=
		"harness: GET https://www.example.com/d on connection 1: fingerprint: an HPACK integer cut short" {
		t.Errorf("an unreadable block: %v", err)
	}
	// A request with no field written has none, not nil, as JSON says it.
	if got, err := s.Written([]Entry{{Proto: "h2", Conn: 1}}, 0); err != nil || got[0][0].Fields == nil {
		t.Errorf("an empty block: %#v, %v", got, err)
	}
	if got, err := s.Written(nil, 0); err != nil || got != nil {
		t.Errorf("nothing: %v, %v", got, err)
	}
}

func TestEveryDifferenceInHowRequestsWentIntoHPACKIsSaid(t *testing.T) {
	request := func(method, url string, fields ...string) WrittenRequest {
		return WrittenRequest{Method: method, URL: url, Fields: fields}
	}
	want := HPACKScenario{Connections: [][]WrittenRequest{
		{request("GET", "https://a/1", "x: indexed static 2"), request("GET", "https://a/2", "y: indexed dynamic 62")},
		{request("GET", "https://b/1")},
	}}
	for _, tc := range []struct {
		name string
		got  [][]WrittenRequest
		diff []string
	}{
		{"the same", want.Connections, nil},
		{"a connection fewer", want.Connections[:1], []string{"1 connections, want 2"}},
		{"a connection more", append(slices.Clone(want.Connections), want.Connections[1]), []string{"3 connections, want 2"}},
		{"a request fewer", [][]WrittenRequest{want.Connections[0][:1], want.Connections[1]},
			[]string{"connection 1: 1 requests, want 2"}},
		{"another request", [][]WrittenRequest{{want.Connections[0][0], request("PUT", "https://a/2")}, want.Connections[1]},
			[]string{"connection 1, request 2: PUT https://a/2, want GET https://a/2"}},
		{"another URL", [][]WrittenRequest{{want.Connections[0][0], request("GET", "https://a/3")}, want.Connections[1]},
			[]string{"connection 1, request 2: GET https://a/3, want GET https://a/2"}},
		{"written otherwise", [][]WrittenRequest{{want.Connections[0][0], request("GET", "https://a/2", "y: indexed dynamic 63")},
			want.Connections[1]},
			[]string{"connection 1, request 2, GET https://a/2:\n  written [\"y: indexed dynamic 63\"]\n  want    [\"y: indexed dynamic 62\"]"}},
		{"a field more", [][]WrittenRequest{want.Connections[0], {request("GET", "https://b/1", "z: indexed static 3")}},
			[]string{"connection 2, request 1, GET https://b/1:\n  written [\"z: indexed static 3\"]\n  want    []"}},
	} {
		if diff := DiffHPACK(want, HPACKScenario{Connections: tc.got}); !slices.Equal(diff, tc.diff) {
			t.Errorf("%s: %q, want %q", tc.name, diff, tc.diff)
		}
	}
	other := HPACKScenario{Connections: want.Connections[:1]}
	got := CompareHPACK(map[string]HPACKScenario{"a": want, "b": want, "c": want},
		map[string]HPACKScenario{"a": want, "c": other, "d": want})
	if !slices.Equal(got, []string{"b was not measured", "c: 1 connections, want 2",
		"d was measured, and the fixture has no such scenario"}) {
		t.Errorf("CompareHPACK: %q", got)
	}
}

func TestTheHPACKScenariosAreServedFromTheirTables(t *testing.T) {
	s, err := StartHPACKServer()
	if err != nil {
		t.Fatalf("StartHPACKServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.PortFor(0) != s.H2 || s.PortFor(1024) == 0 || s.PortFor(65536) == 0 || s.PortFor(1024) == s.PortFor(65536) ||
		len(s.Tables) != 2 {
		t.Fatalf("ports: h2 %d, tables %v", s.H2, s.Tables)
	}
	for _, id := range slices.Sorted(maps.Keys(hpackCatalogue)) {
		sc := hpackCatalogue[id]
		p := sc.planned(id, origins(s.PortFor(sc.table), s.Plain))
		res, body := get(t, http.MethodGet, p.start, nil)
		if res.StatusCode != http.StatusOK || !strings.Contains(body, quietIcon) {
			t.Errorf("%s: %d %s", id, res.StatusCode, body)
		}
	}
	// A page asked to be quiet names an icon, and one that is not does not.
	quiet := "https://www.example.com:" + strconv.Itoa(s.H2) + "/p/a?quiet"
	if _, body := get(t, http.MethodGet, quiet, nil); !strings.Contains(body, quietIcon) {
		t.Errorf("quiet: %s", body)
	}
	if _, body := get(t, http.MethodGet, strings.TrimSuffix(quiet, "?quiet"), nil); strings.Contains(body, "icon") {
		t.Errorf("not quiet: %s", body)
	}
	// ?big=N sets a cookie of N bytes, and nothing that is not a size does.
	for big, want := range map[string][]string{
		"10": {"big=xxxxxxxxxx; Max-Age=3600; Path=/"},
		"0":  nil,
		"x":  nil,
	} {
		res, _ := get(t, http.MethodGet, "https://www.example.com:"+strconv.Itoa(s.H2)+"/p/a?big="+big, nil)
		if got := res.Header.Values("Set-Cookie"); !slices.Equal(got, want) {
			t.Errorf("?big=%s set %q", big, got)
		}
	}
}

func TestAFixtureOfHeaderBlocksIsWrittenAsItIsKept(t *testing.T) {
	committed, err := os.ReadFile(hpackFixture)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fixture, err := LoadHPACK(hpackFixture)
	if err != nil {
		t.Fatalf("LoadHPACK: %v", err)
	}
	out := filepath.Join(t.TempDir(), "hpack.json")
	if err := fixture.Write(out); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written, _ := os.ReadFile(out); !bytes.Equal(written, committed) {
		t.Error("the fixture read and written again is not the fixture")
	}
	// Every scenario of the catalogue is in it, and nothing else.
	if !slices.Equal(slices.Sorted(maps.Keys(fixture.Scenarios)), slices.Sorted(maps.Keys(hpackCatalogue))) {
		t.Errorf("the fixture's scenarios: %v", slices.Sorted(maps.Keys(fixture.Scenarios)))
	}
}

func TestAConnectionHeldWritesOnlyOnceLetGo(t *testing.T) {
	// What is written waits for held, and gives up when the connection is
	// closed before.
	for _, letGo := range []bool{true, false} {
		ours, theirs := net.Pipe()
		held := make(chan struct{})
		conn := newTeeConn(ours, func([]byte) {}, held)
		wrote := make(chan error, 1)
		go func() {
			_, err := conn.Write([]byte("x"))
			wrote <- err
		}()
		select {
		case err := <-wrote:
			t.Fatalf("wrote before it was let go: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		if letGo {
			close(held)
			got := make([]byte, 1)
			if _, err := io.ReadFull(theirs, got); err != nil || got[0] != 'x' || <-wrote != nil {
				t.Errorf("let go: read %q, %v", got, err)
			}
		} else if err := conn.Close(); err != nil || !errors.Is(<-wrote, net.ErrClosed) {
			t.Errorf("closed: %v", err)
		}
		_ = conn.Close()
		_ = theirs.Close()
	}
}

func TestATableServerSaysItsSizeOnceTheFirstHeaderBlockHasCome(t *testing.T) {
	s := started(t, map[string]scenario{"t": {table: 1024}})
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.Tables[1024]),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // the bench's own
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fr := http2.NewFramer(conn, conn)
	_, _ = conn.Write([]byte(http2.ClientPreface))
	_ = fr.WriteSettings()
	// Nothing comes before a request has.
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if f, err := fr.ReadFrame(); err == nil {
		t.Fatalf("before a request, %v", f)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i, path := range []string{"/p/a", "/p/b"} {
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(1 + 2*i), EndStream: true, EndHeaders: true,
			BlockFragment: block(":method", "GET", ":scheme", "https", ":authority", "www.example.com", ":path", path)})
	}
	f, err := fr.ReadFrame()
	settings, ok := f.(*http2.SettingsFrame)
	if err != nil || !ok {
		t.Fatalf("first, %v, %v", f, err)
	}
	if size, ok := settings.Value(http2.SettingHeaderTableSize); !ok || size != 1024 {
		t.Errorf("the table's size said %d, %v", size, ok)
	}
	for answered := 0; answered < 2; {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if h, ok := f.(*http2.HeadersFrame); ok && h.StreamID%2 == 1 {
			answered++
		}
	}
	if got := requests(t, s); len(got) != 2 || got[1].Target != "https://www.example.com/p/b" || len(got[1].Block) == 0 {
		t.Errorf("kept %+v", got)
	}
}
