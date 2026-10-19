package harness

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
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
	Table       uint32             `json:"table,omitempty"`
	Frame       uint32             `json:"frame,omitempty"`
	Connections [][]WrittenRequest `json:"connections"`
}

// WrittenRequest is a request as it went into HPACK: its method, its URL with
// no port, and how each field of its header block was written against the
// dynamic table the requests before it on its connection left, as
// fingerprint.Representation.Named says it; and, for a header block that took
// more than one frame, the payload length of each, HEADERS first, as on the
// wire.
type WrittenRequest struct {
	Method string   `json:"method"`
	URL    string   `json:"url"`
	Fields []string `json:"fields"`
	Frames []int    `json:"frames,omitempty"`
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
			entries, err := s.run(ctx, b, id, sc, origins(s.PortFor(sc.settings()), s.Plain), t)
			if err == nil {
				written, err = s.Written(entries, sc.table)
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
		out[id] = HPACKScenario{Note: sc.note, Table: sc.table, Frame: sc.frame, Connections: written}
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
// 4096 for none; no port of the server's is in a URL.
func (s *Server) Written(entries []Entry, table uint32) ([][]WrittenRequest, error) {
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
			case !slices.Equal(g.Fields, w.Fields):
				out = append(out, fmt.Sprintf("connection %d, request %d, %s %s:\n  written %q\n  want    %q", c+1, r+1,
					w.Method, w.URL, g.Fields, w.Fields))
			case !slices.Equal(g.Frames, w.Frames):
				out = append(out, fmt.Sprintf("connection %d, request %d, %s %s: frames %v, want %v", c+1, r+1,
					w.Method, w.URL, g.Frames, w.Frames))
			}
		}
	}
	return out
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
