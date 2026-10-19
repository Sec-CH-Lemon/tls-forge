package harness

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"time"
)

// alpsVariant is what the bench's ALPS server gives a client for h2: settings,
// made for the origin the client reached it at, none to give no ALPS; and the
// HPACK table the HTTP/2 server behind it lets the client have, when its
// settings say one larger than the 4096 bytes HPACK starts with.
type alpsVariant struct {
	settings func(origin string) []byte
	table    uint32
}

// h2Frame is an HTTP/2 frame of type typ and flags on stream, carrying payload.
func h2Frame(typ, flags byte, stream uint32, payload []byte) []byte {
	n := len(payload)
	frame := []byte{byte(n >> 16), byte(n >> 8), byte(n), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[5:], stream)
	return append(frame, payload...)
}

// settingsFrame is a SETTINGS frame of each identifier and value of pairs.
func settingsFrame(pairs ...uint32) []byte {
	var payload []byte
	for i := 0; i < len(pairs); i += 2 {
		payload = binary.BigEndian.AppendUint16(payload, uint16(pairs[i]))
		payload = binary.BigEndian.AppendUint32(payload, pairs[i+1])
	}
	return h2Frame(4, 0, 0, payload)
}

// acceptCHFrame is an ACCEPT_CH frame (type 0x89) asking origin for hints.
func acceptCHFrame(origin, hints string) []byte {
	payload := binary.BigEndian.AppendUint16(nil, uint16(len(origin)))
	payload = binary.BigEndian.AppendUint16(append(payload, origin...), uint16(len(hints)))
	return h2Frame(0x89, 0, 0, append(payload, hints...))
}

// askedHintsViaALPS are the client hints the accept-ch variant asks for.
const askedHintsViaALPS = "sec-ch-ua-platform-version, sec-ch-ua-full-version-list, sec-ch-ua-arch"

// alpsVariants are what the bench's ALPS server gives a client for h2, by the
// name a scenario gives: no ALPS, ALPS with nothing, SETTINGS, ACCEPT_CH, a
// frame of a type HTTP/2 does not have, a SETTINGS frame cut short, one that
// acknowledges, and a DATA frame, which ALPS may not carry.
var alpsVariants = map[string]alpsVariant{
	"none":  {},
	"empty": {settings: func(string) []byte { return []byte{} }},
	"settings": {settings: func(string) []byte {
		return settingsFrame(1, 65536, 3, 100, 4, 1<<20, 6, 65536, 0x8a8a, 1)
	}, table: 65536},
	"accept-ch": {settings: func(origin string) []byte {
		return append(settingsFrame(), acceptCHFrame(origin, askedHintsViaALPS)...)
	}},
	"unknown-frame":   {settings: func(string) []byte { return h2Frame(0xfa, 0, 0, []byte("x")) }},
	"malformed":       {settings: func(string) []byte { return settingsFrame(1, 65536)[:12] }},
	"settings-stream": {settings: func(string) []byte { return h2Frame(4, 0, 1, nil) }},
	"accept-ch-malformed": {settings: func(origin string) []byte {
		return h2Frame(0x89, 0, 0, append(binary.BigEndian.AppendUint16(nil, uint16(len(origin)+10)), origin...))
	}},
	"accept-ch-empty-origin": {settings: func(string) []byte { return acceptCHFrame("", askedHintsViaALPS) }},
	"settings-ack":           {settings: func(string) []byte { return h2Frame(4, 1, 0, nil) }},
	"data":                   {settings: func(string) []byte { return h2Frame(0, 0, 1, []byte("x")) }},
}

// alpsSettled is how long a scenario of a variant a browser may refuse runs,
// rather than waiting for a page it may never ask for.
const alpsSettled = 4 * time.Second

// alpsCatalogue is every scenario ALPS was measured in, by its name in the
// fixture: a page typed into the browser, from the bench's ALPS server of the
// variant the scenario names, over HTTP/2, and its fetch() of /done/ID; and
// for a variant the browser may refuse, whatever it asked in four seconds.
var alpsCatalogue = map[string]scenario{
	"alps-none":  {note: "no ALPS given, though the browser offers it", script: "done();", alps: "none", quiet: true},
	"alps-empty": {note: "ALPS given with no frames", script: "done();", alps: "empty", quiet: true},
	"alps-settings": {note: "ALPS giving SETTINGS: a table of 65536, 100 streams, a window of 1 MiB, a header list of 65536 and an unknown setting",
		script: "done();", alps: "settings", quiet: true},
	"alps-accept-ch": {note: "ALPS giving an empty SETTINGS frame and an ACCEPT_CH frame asking the page's origin for three hints",
		script: "done();", alps: "accept-ch", quiet: true},
	"alps-unknown-frame": {note: "ALPS giving a frame of type 0xfa", script: "done();", alps: "unknown-frame", quiet: true, settle: alpsSettled},
	"alps-malformed":     {note: "ALPS giving a SETTINGS frame cut short", script: "done();", alps: "malformed", quiet: true, settle: alpsSettled},
	"alps-settings-ack":  {note: "ALPS giving a SETTINGS frame that acknowledges", script: "done();", alps: "settings-ack", quiet: true, settle: alpsSettled},
	"alps-data":          {note: "ALPS giving a DATA frame", script: "done();", alps: "data", quiet: true, settle: alpsSettled},
	"alps-settings-stream": {note: "ALPS giving a SETTINGS frame on stream 1", script: "done();", alps: "settings-stream",
		quiet: true, settle: alpsSettled},
	"alps-accept-ch-malformed": {note: "ALPS giving an ACCEPT_CH frame whose origin is cut short", script: "done();",
		alps: "accept-ch-malformed", quiet: true, settle: alpsSettled},
	"alps-accept-ch-empty-origin": {note: "ALPS giving an ACCEPT_CH frame for an empty origin", script: "done();",
		alps: "accept-ch-empty-origin", quiet: true, settle: alpsSettled},
}

// ALPSFixture is what testdata/chrome155-alps.json holds: what a browser made
// of the bench's ALPS server in each scenario.
type ALPSFixture struct {
	// Browser says which browser was measured, how it was run and where.
	Browser string `json:"browser"`
	// Measured are the dates it was, and How says how.
	Measured  string                  `json:"measured"`
	How       string                  `json:"how"`
	Scenarios map[string]ALPSScenario `json:"scenarios"`
}

// ALPSScenario is what a browser made of the bench's ALPS server in a
// scenario: the handshake of each connection it spoke HTTP/2 on, in the order
// they were made (a spare connection it said nothing on is left out), and the
// requests of each, as they went into HPACK.
type ALPSScenario struct {
	Note        string             `json:"note"`
	Handshakes  []ALPSHandshake    `json:"handshakes"`
	Connections [][]WrittenRequest `json:"connections"`
}

// LoadALPS reads a fixture of ALPS.
func LoadALPS(path string) (*ALPSFixture, error) { return load[ALPSFixture](path) }

// Write writes the fixture to path as it is kept, as the fixture of requests
// is.
func (f *ALPSFixture) Write(path string) error { return writeJSON(path, f) }

// StartALPSServer starts the bench's server for the ALPS catalogue: the one its
// scenarios were measured on, for a client to be held to them.
func StartALPSServer() (*Server, error) { return startServer(alpsCatalogue) }

// MeasureALPS is what b makes of the bench's ALPS server in each scenario of
// the ALPS catalogue named in only, or in every one: what the fixture holds
// for them. It says each scenario it ran to progress, when there is one.
func MeasureALPS(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]ALPSScenario, error) {
	return measureALPS(ctx, b, alpsCatalogue, only, measured, progress)
}

func measureALPS(ctx context.Context, b Browser, scenarios map[string]scenario, only []string, t timing,
	progress io.Writer) (map[string]ALPSScenario, error) {
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
	out := map[string]ALPSScenario{}
	for _, id := range ids {
		sc := scenarios[id]
		for run := 1; ; run++ {
			entries, err := s.run(ctx, b, id, sc, origins(s.ALPS[sc.alps], s.Plain), t)
			if err == nil {
				out[id], err = s.ALPSOf(sc.note, sc.alps, entries)
			}
			if err == nil && !oneEach(entries) {
				if run < runs {
					_, _ = fmt.Fprintf(progress, "alps %s: an origin's requests on more than one connection, run again\n", id)
					continue
				}
				err = fmt.Errorf("an origin's requests went on more than one connection in each of %d runs", runs)
			}
			if err != nil {
				return nil, fmt.Errorf("harness: %s: %w", id, err)
			}
			break
		}
		_, _ = fmt.Fprintf(progress, "alps %s: %d connections\n", id, len(out[id].Handshakes))
	}
	return out, nil
}

// ALPSOf is what a client made of the bench's ALPS server of the variant
// named alps since the server started or was reset, entries being what it
// asked meanwhile: each connection's handshake, and how its requests went into
// HPACK.
func (s *Server) ALPSOf(note, alps string, entries []Entry) (ALPSScenario, error) {
	written, err := s.Written(entries, alpsVariants[alps].table, false)
	if err != nil {
		return ALPSScenario{}, err
	}
	spoken := []ALPSHandshake{}
	for _, h := range s.ALPSHandshakes() {
		asked := slices.ContainsFunc(entries, func(e Entry) bool { return e.Conn == h.Conn })
		if h.Settings != nil || asked {
			spoken = append(spoken, h)
		}
	}
	return ALPSScenario{Note: note, Handshakes: spoken, Connections: append([][]WrittenRequest{}, written...)}, nil
}

// ALPSHandshakes are the handshakes the bench's ALPS server made since it
// started or was reset, in the order they were made.
func (s *Server) ALPSHandshakes() []ALPSHandshake {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ALPSHandshake{}
	for _, h := range s.alpsSeen {
		c := *h
		c.Protocols, c.Flight, c.Settings = slices.Clone(h.Protocols), slices.Clone(h.Flight), slices.Clone(h.Settings)
		out = append(out, c)
	}
	return out
}

// DiffALPS is how got's handshakes and requests went otherwise than want's: a
// line for each difference, none when they went alike.
func DiffALPS(want, got ALPSScenario) []string {
	var out []string
	if len(got.Handshakes) != len(want.Handshakes) {
		out = append(out, fmt.Sprintf("%d handshakes, want %d", len(got.Handshakes), len(want.Handshakes)))
	} else {
		for i, w := range want.Handshakes {
			if g := got.Handshakes[i]; !sameHandshake(g, w) {
				out = append(out, fmt.Sprintf("handshake %d: %s, want %s", i+1, g, w))
			}
		}
	}
	return append(out, DiffHPACK(HPACKScenario{Connections: want.Connections}, HPACKScenario{Connections: got.Connections})...)
}

func sameHandshake(a, b ALPSHandshake) bool {
	return a.Codepoint == b.Codepoint && slices.Equal(a.Protocols, b.Protocols) && a.ALPN == b.ALPN &&
		a.Negotiated == b.Negotiated && a.ClientSettings == b.ClientSettings && slices.Equal(a.Flight, b.Flight) &&
		slices.Equal(a.Settings, b.Settings) && a.GoAway == b.GoAway
}

// String says a handshake as a difference shows it.
func (h ALPSHandshake) String() string {
	return fmt.Sprintf("ALPS %d for %v, %s, negotiated %v, client settings %q, flight %v, SETTINGS %v, GOAWAY %q",
		h.Codepoint, h.Protocols, h.ALPN, h.Negotiated, h.ClientSettings, h.Flight, h.Settings, h.GoAway)
}

// CompareALPS is how what a browser made of the bench's ALPS server, got,
// differs from what the fixture holds, want, as CompareHPACK says it.
func CompareALPS(want, got map[string]ALPSScenario) []string {
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(want)) {
		measured, ok := got[id]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s was not measured", id))
			continue
		}
		for _, d := range DiffALPS(want[id], measured) {
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

// settingsOf says the settings of a SETTINGS frame's payload, ID=value each.
func settingsOf(payload []byte) []string {
	out := []string{}
	for i := 0; i+6 <= len(payload); i += 6 {
		out = append(out, fmt.Sprintf("%d=%d", binary.BigEndian.Uint16(payload[i:]), binary.BigEndian.Uint32(payload[i+2:])))
	}
	return out
}

// alpsNames are the variants scenarios name, sorted.
func alpsNames(scenarios map[string]scenario) []string {
	var names []string
	for _, sc := range scenarios {
		if sc.alps != "" && !slices.Contains(names, sc.alps) {
			names = append(names, sc.alps)
		}
	}
	slices.Sort(names)
	return names
}

// originOf is the origin a client reaches the bench's ALPS server of port at.
func originOf(port int) string { return "https://www.example.com:" + strconv.Itoa(port) }
