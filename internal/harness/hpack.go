package harness

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/v5/fingerprint"
)

// HPACKFixture is what testdata/chrome155-hpack.json holds: how a browser wrote
// the header blocks of each connection of each scenario into HPACK.
type HPACKFixture struct {
	// Browser says which browser was measured, how it was run and where.
	Browser string `json:"browser"`
	// Measured are the dates it was, and How says how.
	Measured  string                   `json:"measured"`
	How       string                   `json:"how"`
	Scenarios map[string]HPACKScenario `json:"scenarios"`
}

// HPACKScenario is how the requests of a scenario went into HPACK: those of
// each connection, the connections in the order they were first written on,
// and on each the requests in the order they were.
type HPACKScenario struct {
	Note string `json:"note"`
	// Table is the size of the HPACK table the server's SETTINGS let the
	// browser have, when it is not the 4096 bytes they say by default, and
	// Frame the largest frame they let it send, when it is not Go's 1 MiB.
	Table uint32 `json:"table,omitempty"`
	Frame uint32 `json:"frame,omitempty"`
	// Records says each request's DATA frames and TLS records are kept.
	Records     bool               `json:"records,omitempty"`
	Connections [][]WrittenRequest `json:"connections"`
}

// WrittenRequest is a request as it went into HPACK: its method, its URL with
// no port, and how each field of its header block was written against the
// dynamic table the requests before it on its connection left, as
// fingerprint.Representation.Named says it; and, for a header block that took
// more than one frame, the payload length of each, HEADERS first, as on the
// wire. In a scenario of records, Data are the payload lengths of its DATA
// frames and Records how the TLS records carried its frames (Entry.Records);
// in a fixture of ALPS, Priority is its HEADERS frame's priority, as
// Request.Priority says it.
type WrittenRequest struct {
	Method   string   `json:"method"`
	URL      string   `json:"url"`
	Fields   []string `json:"fields"`
	Frames   []int    `json:"frames,omitempty"`
	Data     []int    `json:"data,omitempty"`
	Records  []string `json:"records,omitempty"`
	Priority []uint32 `json:"priority,omitempty"`
}

// LoadHPACK reads a fixture of header blocks.
func LoadHPACK(path string) (*HPACKFixture, error) { return load[HPACKFixture](path) }

// Write writes the fixture to path as it is kept, as the fixture of requests
// is.
func (f *HPACKFixture) Write(path string) error { return writeJSON(path, f) }

// hpackCatalogue is every scenario the HPACK of later requests was measured in,
// by its name in the fixture: a page, over HTTP/2, and what its script asked
// for, each page naming an icon of its own (quiet), so that no /favicon.ico
// comes between. URLs are as in catalogue.
var hpackCatalogue = map[string]scenario{
	"hpack-fetch": {note: "a page, then fetch() of its origin",
		script: "fetch('{A}/p/hpack-fetch').then(done);", quiet: true},
	"hpack-fetch-again": {note: "a page, then fetch() of its origin three times, the third of the first's URL",
		script: "fetch('{A}/p/hpack-a').then(()=>fetch('{A}/p/hpack-b')).then(()=>fetch('{A}/p/hpack-a')).then(done);", quiet: true},
	"hpack-navigation": {note: "a page, then location.href to a page of its origin",
		script: "location.href='{A}/p/hpack-navigation?quiet';", wait: "/p/hpack-navigation", quiet: true},
	"hpack-cookies": {note: "a page whose answer set two cookies, then fetch() of its origin and location.href to a page of it, which carry them",
		start: "{A}/run/{ID}?cookie=1", script: "fetch('{A}/p/hpack-cookies-fetch').then(()=>{location.href='{A}/p/hpack-cookies?quiet';});",
		wait: "/p/hpack-cookies", quiet: true},
	"hpack-methods": {note: "a page, then fetch() of its origin with PUT, DELETE, PATCH and POST",
		script: "fetch('{A}/p/hpack-put',{method:'PUT',body:'x'}).then(()=>fetch('{A}/p/hpack-delete',{method:'DELETE'})).then(()=>fetch('{A}/p/hpack-patch',{method:'PATCH',body:'y'})).then(()=>fetch('{A}/p/hpack-post',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).then(done);",
		quiet:  true},
	"hpack-preflight": {note: "a page, then fetch() of another origin of its site, CORS simple, then one with X-Foo, which a preflight asks about",
		script: "fetch('{S}/cors/hpack-simple').then(()=>fetch('{S}/cors/hpack-preflighted?maxage=0',{headers:{'X-Foo':'bar'}})).then(done);",
		quiet:  true},
	"hpack-big-cookie": {note: "a page whose answer set a cookie larger than the dynamic table, then fetch() of its origin twice, which carry it",
		start: "{A}/run/{ID}?big=4080", script: "fetch('{A}/p/hpack-big-1').then(()=>fetch('{A}/p/hpack-big-2')).then(done);", quiet: true},
	"hpack-table-64k": {note: "a page, then fetch() of its origin, from a server whose SETTINGS let the dynamic table be 65536 bytes",
		script: "fetch('{A}/p/hpack-table-64k').then(done);", table: 65536, quiet: true},
	"hpack-table-1k": {note: "a page, then fetch() of its origin, from a server whose SETTINGS let the dynamic table be 1024 bytes",
		script: "fetch('{A}/p/hpack-table-1k').then(done);", table: 1024, quiet: true},
	"hpack-records-header": {note: "a page, then fetch() of its origin with an X-Foo of 8,000 letters, a header block of about 5 KB",
		script: "fetch('{A}/p/hpack-records-header',{headers:{'X-Foo':'a'.repeat(8000)}}).then(done);", records: true, quiet: true},
	"hpack-records-post-1k": {note: "a page, then fetch() POST of 1,000 letters to its origin",
		script: "fetch('{A}/p/hpack-records-post-1k',{method:'POST',body:'a'.repeat(1000)}).then(done);", records: true, quiet: true},
	"hpack-records-post-64k": {note: "a page, then fetch() POST of 65,536 letters to its origin",
		script: "fetch('{A}/p/hpack-records-post-64k',{method:'POST',body:'a'.repeat(65536)}).then(done);", records: true, quiet: true},
	"hpack-records-long-url": {note: "a page, then fetch() of a URL of its origin whose query is 8,000 letters, a :path of about 8 KB",
		script: "fetch('{A}/p/hpack-records-long-url?'+'a'.repeat(8000)).then(done);", records: true, quiet: true},
	"hpack-records-big-header": {note: "a page, then fetch() of its origin with an X-Foo of 30,000 letters, a header block in a HEADERS and a CONTINUATION frame",
		script: "fetch('{A}/p/hpack-records-big-header',{headers:{'X-Foo':'a'.repeat(30000)}}).then(done);", records: true, quiet: true},
	"hpack-records-cookie-2k": {note: "a page whose answer set a cookie of 2,048 bytes with its name, then fetch() of its origin, which carries it",
		start: "{A}/run/{ID}?big=2044", script: "fetch('{A}/p/hpack-records-cookie-2k').then(done);", records: true, quiet: true},
	"hpack-records-cookie-4k": {note: "a page whose answer set a cookie of 4,096 bytes with its name, then fetch() of its origin, which carries it",
		start: "{A}/run/{ID}?big=4092", script: "fetch('{A}/p/hpack-records-cookie-4k').then(done);", records: true, quiet: true},
	"hpack-records-cookie-16k": {note: "a page whose answer set four cookies of 4,096 bytes with their names, 16 KiB, then fetch() of its origin, which carries them",
		start: "{A}/run/{ID}?big=4091&bigs=4", script: "fetch('{A}/p/hpack-records-cookie-16k').then(done);", records: true, quiet: true},
	"hpack-records-post-16k": {note: "a page, then fetch() POST of 16,376 letters to its origin, a DATA frame's 16,375 and one more",
		script: "fetch('{A}/p/hpack-records-post-16k',{method:'POST',body:'a'.repeat(16376)}).then(done);", records: true, quiet: true},
	"hpack-big-header": {note: "a page, then fetch() of its origin with an X-Foo of 30,000 letters, a header block of more than one frame",
		script: "fetch('{A}/p/hpack-big-header',{headers:{'X-Foo':'a'.repeat(30000)}}).then(done);", quiet: true},
	"hpack-bigger-header": {note: "a page, then fetch() of its origin with an X-Foo of 60,000 letters",
		script: "fetch('{A}/p/hpack-bigger-header',{headers:{'X-Foo':'a'.repeat(60000)}}).then(done);", quiet: true},
	"hpack-big-header-16k": {note: "the same as hpack-big-header, from a server whose SETTINGS let a frame be 16384 bytes",
		script: "fetch('{A}/p/hpack-big-header-16k',{headers:{'X-Foo':'a'.repeat(30000)}}).then(done);", frame: 16384, quiet: true},
	"hpack-bigger-header-16k": {note: "the same as hpack-bigger-header, from a server whose SETTINGS let a frame be 16384 bytes",
		script: "fetch('{A}/p/hpack-bigger-header-16k',{headers:{'X-Foo':'a'.repeat(60000)}}).then(done);", frame: 16384, quiet: true},
}

// MeasureHPACK is how b writes the requests of each scenario of the HPACK
// catalogue named in only, or of every one, into HPACK over HTTP/2: what the
// fixture holds for them. It says each scenario it ran to progress, when there
// is one.
func MeasureHPACK(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]HPACKScenario, error) {
	return measureHPACK(ctx, b, hpackCatalogue, only, measured, progress)
}

// runs is how often a scenario of the HPACK catalogue is run, at most, before
// its requests went to each origin on one connection. Chrome opens a spare
// connection beside the one a navigation goes on, and now and then sends the
// page's later requests on it: that run measures which connection Chrome
// takes, not how it writes a connection's requests.
const runs = 5

func measureHPACK(ctx context.Context, b Browser, scenarios map[string]scenario, only []string, t timing,
	progress io.Writer) (map[string]HPACKScenario, error) {
	ids, err := selected(scenarios, only)
	if err != nil {
		return nil, err
	}
	s, err := startServer(scenarios)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if progress == nil {
		progress = io.Discard
	}
	out := map[string]HPACKScenario{}
	for _, id := range ids {
		sc := scenarios[id]
		var written [][]WrittenRequest
		for run := 1; ; run++ {
			entries, err := s.run(ctx, b, id, sc, origins(s.PortFor(sc.settings()), s.Plain), t, progress)
			if err == nil {
				written, err = s.Written(entries, sc.table, sc.records)
			}
			if err == nil && !oneEach(entries) {
				if run < runs {
					_, _ = fmt.Fprintf(progress, "h2 %s: an origin's requests on more than one connection, run again\n", id)
					continue
				}
				err = fmt.Errorf("an origin's requests went on more than one connection in each of %d runs", runs)
			}
			if err != nil {
				return nil, fmt.Errorf("harness: %s over h2: %w", id, err)
			}
			break
		}
		out[id] = HPACKScenario{Note: sc.note, Table: sc.table, Frame: sc.frame, Records: sc.records, Connections: written}
		_, _ = fmt.Fprintf(progress, "h2 %s: %d connections\n", id, len(written))
	}
	return out, nil
}

// oneEach says whether the HTTP/2 requests of entries to each origin all went
// on one connection.
func oneEach(entries []Entry) bool {
	conns := map[string]int{}
	for _, e := range entries {
		if e.Proto != "h2" {
			continue
		}
		origin := e.Target
		if u, err := url.Parse(e.Target); err == nil {
			origin = u.Host
		}
		if conn, ok := conns[origin]; ok && conn != e.Conn {
			return false
		}
		conns[origin] = e.Conn
	}
	return true
}

// StartHPACKServer starts a Server answering the scenarios of the HPACK
// catalogue, each from the port its SETTINGS ask for (PortFor).
func StartHPACKServer() (*Server, error) { return startServer(hpackCatalogue) }

// PortFor is the port of the server's HTTP/2 whose SETTINGS say settings
// where they are not Go's: H2's for none.
func (s *Server) PortFor(settings H2Settings) int {
	if settings == (H2Settings{}) {
		return s.H2
	}
	return s.Settled[settings]
}

// Written is how the HTTP/2 requests of entries went into HPACK, connection by
// connection, each block read against the table the ones before it on its
// connection left, from a server whose SETTINGS let the table be table bytes,
// 4096 for none, with their DATA frames and TLS records when records says;
// no port of the server's is in a URL.
func (s *Server) Written(entries []Entry, table uint32, records bool) ([][]WrittenRequest, error) {
	if table == 0 {
		table = 4096
	}
	var out [][]WrittenRequest
	conns := map[int]int{}
	readers := map[int]*fingerprint.HeaderBlocks{}
	for _, e := range entries {
		if e.Proto != "h2" {
			continue
		}
		if _, ok := readers[e.Conn]; !ok {
			readers[e.Conn] = fingerprint.NewHeaderBlocks(table)
			conns[e.Conn] = len(out)
			out = append(out, nil)
		}
		representations, err := readers[e.Conn].Next(e.Block)
		if err != nil {
			return nil, fmt.Errorf("harness: %s %s on connection %d: %w", e.Method, s.bare(e.Target), e.Conn, err)
		}
		written := WrittenRequest{Method: e.Method, URL: s.bare(e.Target), Fields: []string{}}
		for _, r := range representations {
			written.Fields = append(written.Fields, r.Named())
		}
		if len(e.Frames) > 1 {
			written.Frames = e.Frames
		}
		if records {
			written.Data, written.Records = e.Data, e.Records
		}
		out[conns[e.Conn]] = append(out[conns[e.Conn]], written)
	}
	return out, nil
}

// DiffHPACK is how the requests of got went into HPACK otherwise than want's:
// a line for each difference, none when they went alike.
func DiffHPACK(want, got HPACKScenario) []string {
	if len(got.Connections) != len(want.Connections) {
		return []string{fmt.Sprintf("%d connections, want %d", len(got.Connections), len(want.Connections))}
	}
	var out []string
	for c, requests := range want.Connections {
		if len(got.Connections[c]) != len(requests) {
			out = append(out, fmt.Sprintf("connection %d: %d requests, want %d", c+1, len(got.Connections[c]), len(requests)))
			continue
		}
		for r, w := range requests {
			g := got.Connections[c][r]
			switch {
			case g.Method != w.Method || g.URL != w.URL:
				out = append(out, fmt.Sprintf("connection %d, request %d: %s %s, want %s %s", c+1, r+1, g.Method, g.URL,
					w.Method, w.URL))
			case !sameFields(g.Fields, w.Fields):
				out = append(out, fmt.Sprintf("connection %d, request %d, %s %s:\n  written %q\n  want    %q", c+1, r+1,
					w.Method, w.URL, g.Fields, w.Fields))
			case !sameCut(g.Frames, w.Frames):
				out = append(out, fmt.Sprintf("connection %d, request %d, %s %s: frames %v, want %v", c+1, r+1,
					w.Method, w.URL, g.Frames, w.Frames))
			case !slices.Equal(g.Data, w.Data) || !slices.Equal(g.Records, w.Records):
				out = append(out, fmt.Sprintf("connection %d, request %d, %s %s: DATA frames %v and records %v, want %v and %v",
					c+1, r+1, w.Method, w.URL, g.Data, g.Records, w.Data, w.Records))
			case !slices.Equal(g.Priority, w.Priority):
				out = append(out, fmt.Sprintf("connection %d, request %d, %s %s: priority %v, want %v", c+1, r+1,
					w.Method, w.URL, g.Priority, w.Priority))
			}
		}
	}
	return out
}

// platformDecided are the fields whose values the platform and the machine
// decide: the user agent, sec-ch-ua-platform and every client hint a server
// asks for. Chrome writes a value Huffman-coded only when that is shorter, as
// quiche's encoder does, so a value of another platform may go the other way:
// "Windows" goes Huffman-coded where "macOS" does not, and Linux's empty
// platform version plain where macOS's goes Huffman-coded.
var platformDecided = []string{
	"user-agent", "sec-ch-ua-platform",
	"device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr", "viewport-width", "sec-ch-viewport-width",
	"sec-ch-viewport-height", "rtt", "downlink", "ect", "sec-ch-ua-full-version", "sec-ch-ua-arch",
	"sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-bitness", "sec-ch-ua-wow64",
	"sec-ch-ua-full-version-list", "sec-ch-ua-form-factors",
	"sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency",
}

// sameFields says two header blocks were written alike, field by field: the
// coding of a value the platform decides set aside, the rest of how it was
// written held.
func sameFields(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] && withoutCoding(a[i]) != withoutCoding(b[i]) {
			return false
		}
	}
	return true
}

// withoutCoding is a field as written, without its value's coding when the
// platform decides its value.
func withoutCoding(field string) string {
	name, _, _ := strings.Cut(field, ": ")
	if !slices.Contains(platformDecided, name) {
		return field
	}
	for _, coding := range []string{", value huffman", ", value plain"} {
		if rest, ok := strings.CutSuffix(field, coding); ok {
			return rest
		}
	}
	return field
}

// sameCut says two header blocks went into frames alike: as many frames, each
// but the last as long. The last carries what is left of the block, whose
// length the bench's port changes by a byte from run to run (its digits
// Huffman-code to 5 or 6 bits); the fields say what the block is.
func sameCut(a, b []int) bool {
	return len(a) == len(b) && (len(a) == 0 || slices.Equal(a[:len(a)-1], b[:len(b)-1]))
}

// CompareHPACK is how what a browser wrote, got, differs from what the fixture
// holds, want, as Compare says it for requests: a scenario not measured, one
// the fixture has not, and every difference DiffHPACK finds in the others,
// after the scenario's name. Nothing when they are the same.
func CompareHPACK(want, got map[string]HPACKScenario) []string {
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(want)) {
		measured, ok := got[id]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s was not measured", id))
			continue
		}
		for _, d := range DiffHPACK(want[id], measured) {
			diff = append(diff, id+": "+d)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[id]; !ok {
			diff = append(diff, fmt.Sprintf("%s was measured, and the fixture has no such scenario", id))
		}
	}
	return diff
}
