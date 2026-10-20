package harness

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
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
func acceptCHFrame(origin, hints string) []byte { return acceptCH(0, 0, origin, hints) }

// acceptCH is an ACCEPT_CH frame on stream with flags, of an entry for each
// origin and value of pairs.
func acceptCH(stream uint32, flags byte, pairs ...string) []byte {
	return h2Frame(0x89, flags, stream, entries(pairs...))
}

// entries are each of values with its length in two bytes before it, as an
// ACCEPT_CH frame says an origin and a value.
func entries(values ...string) []byte {
	var out []byte
	for _, s := range values {
		out = append(binary.BigEndian.AppendUint16(out, uint16(len(s))), s...)
	}
	return out
}

// elsewhere is origin with www.example.net in place of www.example.com: an
// origin of another site on the same port.
func elsewhere(origin string) string {
	return strings.Replace(origin, "www.example.com", "www.example.net", 1)
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
	// How ACCEPT_CH is read where it says more than one thing, or says it
	// otherwise than it may.
	"accept-ch-two-entries": {settings: func(origin string) []byte {
		return acceptCH(0, 0, origin, "sec-ch-ua-arch", origin, "sec-ch-ua-platform-version")
	}},
	"accept-ch-other-origin": {settings: func(origin string) []byte {
		return acceptCH(0, 0, elsewhere(origin), "sec-ch-ua-arch", origin, "sec-ch-ua-platform-version")
	}},
	"accept-ch-two-frames": {settings: func(origin string) []byte {
		return append(acceptCH(0, 0, elsewhere(origin), "sec-ch-ua-arch"),
			acceptCH(0, 0, origin, "sec-ch-ua-platform-version")...)
	}},
	"accept-ch-capitals": {settings: func(origin string) []byte {
		return acceptCHFrame(strings.ToUpper(origin), askedHintsViaALPS)
	}},
	"accept-ch-stream": {settings: func(origin string) []byte { return acceptCH(1, 0, origin, askedHintsViaALPS) }},
	"accept-ch-flags":  {settings: func(origin string) []byte { return acceptCH(0, 1, origin, askedHintsViaALPS) }},
	"accept-ch-stream-then-good": {settings: func(origin string) []byte {
		return append(acceptCH(1, 0, origin, "sec-ch-ua-arch"), acceptCH(0, 0, origin, "sec-ch-ua-platform-version")...)
	}},
	"accept-ch-good-then-stream": {settings: func(origin string) []byte {
		return append(acceptCH(0, 0, origin, "sec-ch-ua-arch"), acceptCH(1, 0, origin, "sec-ch-ua-platform-version")...)
	}},
	"accept-ch-malformed-then-good": {settings: func(origin string) []byte {
		cut := h2Frame(0x89, 0, 0, binary.BigEndian.AppendUint16(entries(origin), 5))
		return append(cut, acceptCH(0, 0, origin, "sec-ch-ua-platform-version")...)
	}},
	"accept-ch-stream-flags": {settings: func(origin string) []byte { return acceptCH(1, 1, origin, askedHintsViaALPS) }},
	// Which of two things that do not read Chrome says, and which frames
	// it refuses.
	"settings-ack-then-cut": {settings: func(string) []byte {
		return append(h2Frame(4, 1, 0, nil), settingsFrame(1, 65536)[:12]...)
	}},
	"accept-ch-stream-then-ack": {settings: func(origin string) []byte {
		return append(acceptCH(1, 0, origin, "sec-ch-ua-arch"), h2Frame(4, 1, 0, nil)...)
	}},
	"accept-ch-stream-then-cut": {settings: func(origin string) []byte {
		return append(acceptCH(1, 0, origin, "sec-ch-ua-arch"), settingsFrame(1, 65536)[:12]...)
	}},
	"data-then-accept-ch-stream": {settings: func(origin string) []byte {
		return append(h2Frame(0, 0, 1, []byte("x")), acceptCH(1, 0, origin, "sec-ch-ua-arch")...)
	}},
	"settings-ack-payload": {settings: func(string) []byte { return h2Frame(4, 1, 0, make([]byte, 6)) }},
	"settings-odd":         {settings: func(string) []byte { return h2Frame(4, 0, 0, make([]byte, 5)) }},
	"unknown-frame-stream": {settings: func(string) []byte { return h2Frame(0xfa, 0xff, 1, []byte("x")) }},
	"altsvc": {settings: func(string) []byte {
		return h2Frame(0xa, 0, 0, append(entries(""), `h3=":443"`...))
	}},
	"priority-update":        {settings: func(string) []byte { return h2Frame(0x10, 0, 0, append([]byte{0, 0, 0, 1}, "u=1"...)) }},
	"origin-frame":           {settings: func(origin string) []byte { return h2Frame(0xc, 0, 0, entries(origin)) }},
	"data-then-settings-ack": {settings: func(string) []byte { return append(h2Frame(0, 0, 1, []byte("x")), h2Frame(4, 1, 0, nil)...) }},
	"data-then-cut": {settings: func(string) []byte {
		return append(h2Frame(0, 0, 1, []byte("x")), settingsFrame(1, 65536)[:12]...)
	}},
	// Each frame of a type HTTP/2 has, as it may be sent.
	"headers":       {settings: func(string) []byte { return h2Frame(1, 4, 1, []byte{0x82}) }},
	"priority":      {settings: func(string) []byte { return h2Frame(2, 0, 1, []byte{0, 0, 0, 0, 15}) }},
	"rst-stream":    {settings: func(string) []byte { return h2Frame(3, 0, 1, []byte{0, 0, 0, 8}) }},
	"push-promise":  {settings: func(string) []byte { return h2Frame(5, 4, 1, []byte{0, 0, 0, 2, 0x82}) }},
	"ping":          {settings: func(string) []byte { return h2Frame(6, 0, 0, make([]byte, 8)) }},
	"goaway":        {settings: func(string) []byte { return h2Frame(7, 0, 0, make([]byte, 8)) }},
	"window-update": {settings: func(string) []byte { return h2Frame(8, 0, 0, []byte{0, 0, 0, 1}) }},
	"continuation":  {settings: func(string) []byte { return h2Frame(9, 4, 1, []byte{0x82}) }},
	// SETTINGS whose values a SETTINGS frame may not say, or flags it has
	// no use for.
	"settings-flags":        {settings: func(string) []byte { return h2Frame(4, 0xfe, 0, settingsFrame(1, 65536)[9:]) }, table: 65536},
	"settings-window-large": {settings: func(string) []byte { return settingsFrame(4, 1<<31) }},
	"settings-push-2":       {settings: func(string) []byte { return settingsFrame(2, 2) }},
	"settings-frame-small":  {settings: func(string) []byte { return settingsFrame(5, 100) }},
	"settings-connect-2":    {settings: func(string) []byte { return settingsFrame(8, 2) }},
	"settings-priorities-2": {settings: func(string) []byte { return settingsFrame(9, 2) }},
	// Frames that do not read as their type says, and frames of more than
	// 16 KiB.
	"ping-stream":         {settings: func(string) []byte { return h2Frame(6, 0, 1, make([]byte, 8)) }},
	"ping-short":          {settings: func(string) []byte { return h2Frame(6, 0, 0, make([]byte, 7)) }},
	"data-stream-0":       {settings: func(string) []byte { return h2Frame(0, 0, 0, []byte("x")) }},
	"priority-short":      {settings: func(string) []byte { return h2Frame(2, 0, 1, []byte{0, 0, 0, 0}) }},
	"rst-stream-0":        {settings: func(string) []byte { return h2Frame(3, 0, 0, []byte{0, 0, 0, 8}) }},
	"goaway-stream":       {settings: func(string) []byte { return h2Frame(7, 0, 1, make([]byte, 8)) }},
	"window-update-zero":  {settings: func(string) []byte { return h2Frame(8, 0, 0, []byte{0, 0, 0, 0}) }},
	"window-update-short": {settings: func(string) []byte { return h2Frame(8, 0, 0, []byte{0, 0, 1}) }},
	"headers-bad-hpack":   {settings: func(string) []byte { return h2Frame(1, 4, 1, []byte{0xff, 0xff, 0xff}) }},
	"headers-open":        {settings: func(string) []byte { return h2Frame(1, 0, 1, []byte{0x82}) }},
	"headers-then-continuation": {settings: func(string) []byte {
		return append(h2Frame(1, 0, 1, []byte{0x82}), h2Frame(9, 4, 1, []byte{0x84})...)
	}},
	"headers-open-then-settings": {settings: func(string) []byte { return append(h2Frame(1, 0, 1, []byte{0x82}), settingsFrame()...) }},
	"headers-padded-bad":         {settings: func(string) []byte { return h2Frame(1, 0xc, 1, []byte{5, 0x82}) }},
	"unknown-large":              {settings: func(string) []byte { return h2Frame(0xfa, 0, 0, make([]byte, 20000)) }},
	"settings-large": {settings: func(string) []byte {
		pairs := []uint32{1, 65536}
		for range 3000 {
			pairs = append(pairs, 0x8a8a, 1)
		}
		return settingsFrame(pairs...)
	}, table: 65536},
	"settings-priorities-1":       {settings: func(string) []byte { return settingsFrame(9, 1) }},
	"settings-priorities-changed": {settings: func(string) []byte { return settingsFrame(9, 0, 9, 1) }},
	"settings-priorities-again":   {settings: func(string) []byte { return settingsFrame(9, 1, 9, 1) }},
	"settings-connect-1-0":        {settings: func(string) []byte { return settingsFrame(8, 1, 8, 0) }},
	"settings-connect-0-1":        {settings: func(string) []byte { return settingsFrame(8, 0, 8, 1) }},
	"settings-streams-0":          {settings: func(string) []byte { return settingsFrame(3, 0) }},
	"accept-ch-good-then-malformed": {settings: func(origin string) []byte {
		// The second entry's value says five bytes, and none follow.
		return h2Frame(0x89, 0, 0, binary.BigEndian.AppendUint16(entries(origin, "sec-ch-ua-arch", origin), 5))
	}},
	"settings-ack": {settings: func(string) []byte { return h2Frame(4, 1, 0, nil) }},
	"data":         {settings: func(string) []byte { return h2Frame(0, 0, 1, []byte("x")) }},
}

// alpsSettled is how long a scenario of a variant a browser may refuse runs,
// rather than waiting for a page it may never ask for.
const alpsSettled = 4 * time.Second

// alpsLobby is where a scenario of two navigations starts: a page over plain
// HTTP that goes on to the run page two seconds after it has loaded. Chrome
// closes the connections it holds each time its certificate verifier is told
// something new, which it is in the first few hundred milliseconds after it
// starts (lobby, in connections.go): a run page typed at once lost its
// connection under it, and the navigation after it went out on a new one.
const alpsLobby = "{H}/p/lobby?after=2&next={A}/run/{ID}"

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
	// What else the hints ACCEPT_CH asks for go with: a navigation from the
	// page, a form, a redirect, and a page whose Accept-CH asked for one.
	"alps-accept-ch-link": {note: "ALPS asking the page's origin for three hints, and location.href to a page of that origin",
		start: alpsLobby, script: "location.href='{A}/p/alps-accept-ch-link?quiet';", wait: "/p/alps-accept-ch-link",
		alps: "accept-ch", quiet: true},
	"alps-accept-ch-form": {note: "ALPS asking the page's origin for three hints, and a form posted to that origin",
		start: alpsLobby, html: formHTML("post", "{A}/p/alps-accept-ch-form?quiet", ""), script: submit,
		wait: "/p/alps-accept-ch-form", alps: "accept-ch", quiet: true},
	"alps-accept-ch-redirect": {note: "ALPS asking the page's origin for three hints, and location.href to a 302 to that origin",
		start: alpsLobby, wait: "/p/alps-accept-ch-redirected", alps: "accept-ch", quiet: true,
		script: "location.href='{A}/r/302/alps-accept-ch-redirect?to=/p/alps-accept-ch-redirected%3Fquiet';"},
	"alps-accept-ch-two-entries": {note: "ALPS giving an ACCEPT_CH frame of two entries for the page's origin, a hint each",
		script: "done();", alps: "accept-ch-two-entries", quiet: true},
	"alps-accept-ch-other-origin": {note: "ALPS giving an ACCEPT_CH frame of an entry for another site's origin, then one for the page's, a hint each",
		script: "done();", alps: "accept-ch-other-origin", quiet: true},
	"alps-accept-ch-two-frames": {note: "ALPS giving an ACCEPT_CH frame for another site's origin, then one for the page's, a hint each",
		script: "done();", alps: "accept-ch-two-frames", quiet: true},
	"alps-accept-ch-capitals": {note: "ALPS giving an ACCEPT_CH frame for the page's origin in capitals", script: "done();",
		alps: "accept-ch-capitals", quiet: true},
	"alps-accept-ch-stream": {note: "ALPS giving an ACCEPT_CH frame on stream 1", script: "done();", alps: "accept-ch-stream",
		quiet: true, settle: alpsSettled},
	"alps-accept-ch-flags": {note: "ALPS giving an ACCEPT_CH frame with a flag", script: "done();", alps: "accept-ch-flags",
		quiet: true, settle: alpsSettled},
	"alps-accept-ch-stream-then-good": {note: "ALPS giving an ACCEPT_CH frame on stream 1, then one on stream 0, a hint each",
		script: "done();", alps: "accept-ch-stream-then-good", quiet: true, settle: alpsSettled},
	"alps-accept-ch-good-then-stream": {note: "ALPS giving an ACCEPT_CH frame on stream 0, then one on stream 1, a hint each",
		script: "done();", alps: "accept-ch-good-then-stream", quiet: true, settle: alpsSettled},
	"alps-accept-ch-good-then-malformed": {note: "ALPS giving an ACCEPT_CH frame of an entry for the page's origin, then one cut short",
		script: "done();", alps: "accept-ch-good-then-malformed", quiet: true, settle: alpsSettled},
	"alps-accept-ch-malformed-then-good": {note: "ALPS giving an ACCEPT_CH frame whose entry is cut short, then one for the page's origin",
		script: "done();", alps: "accept-ch-malformed-then-good", quiet: true},
	"alps-accept-ch-stream-flags": {note: "ALPS giving an ACCEPT_CH frame on stream 1 with a flag", script: "done();",
		alps: "accept-ch-stream-flags", quiet: true, settle: alpsSettled},
	"alps-settings-ack-then-cut": {note: "ALPS giving a SETTINGS frame that acknowledges, then a SETTINGS frame cut short",
		script: "done();", alps: "settings-ack-then-cut", quiet: true, settle: alpsSettled},
	"alps-accept-ch-stream-then-ack": {note: "ALPS giving an ACCEPT_CH frame on stream 1, then a SETTINGS frame that acknowledges",
		script: "done();", alps: "accept-ch-stream-then-ack", quiet: true, settle: alpsSettled},
	"alps-accept-ch-stream-then-cut": {note: "ALPS giving an ACCEPT_CH frame on stream 1, then a SETTINGS frame cut short",
		script: "done();", alps: "accept-ch-stream-then-cut", quiet: true, settle: alpsSettled},
	"alps-data-then-accept-ch-stream": {note: "ALPS giving a DATA frame, then an ACCEPT_CH frame on stream 1", script: "done();",
		alps: "data-then-accept-ch-stream", quiet: true, settle: alpsSettled},
	"alps-settings-ack-payload": {note: "ALPS giving a SETTINGS frame that acknowledges and carries a setting", script: "done();",
		alps: "settings-ack-payload", quiet: true, settle: alpsSettled},
	"alps-settings-odd": {note: "ALPS giving a SETTINGS frame of five bytes", script: "done();", alps: "settings-odd",
		quiet: true, settle: alpsSettled},
	"alps-unknown-frame-stream": {note: "ALPS giving a frame of type 0xfa on stream 1, every flag set", script: "done();",
		alps: "unknown-frame-stream", quiet: true, settle: alpsSettled},
	"alps-altsvc": {note: "ALPS giving an ALTSVC frame", script: "done();", alps: "altsvc", quiet: true, settle: alpsSettled},
	"alps-priority-update": {note: "ALPS giving a PRIORITY_UPDATE frame", script: "done();", alps: "priority-update",
		quiet: true, settle: alpsSettled},
	"alps-origin-frame": {note: "ALPS giving an ORIGIN frame", script: "done();", alps: "origin-frame", quiet: true,
		settle: alpsSettled},
	"alps-data-then-settings-ack": {note: "ALPS giving a DATA frame, then a SETTINGS frame that acknowledges", script: "done();", alps: "data-then-settings-ack", quiet: true,
		settle: alpsSettled},
	"alps-data-then-cut": {note: "ALPS giving a DATA frame, then a SETTINGS frame cut short", script: "done();", alps: "data-then-cut", quiet: true,
		settle: alpsSettled},
	"alps-headers": {note: "ALPS giving a HEADERS frame on stream 1", script: "done();", alps: "headers", quiet: true,
		settle: alpsSettled},
	"alps-priority": {note: "ALPS giving a PRIORITY frame on stream 1", script: "done();", alps: "priority", quiet: true,
		settle: alpsSettled},
	"alps-rst-stream": {note: "ALPS giving a RST_STREAM frame on stream 1", script: "done();", alps: "rst-stream", quiet: true,
		settle: alpsSettled},
	"alps-push-promise": {note: "ALPS giving a PUSH_PROMISE frame on stream 1", script: "done();", alps: "push-promise", quiet: true,
		settle: alpsSettled},
	"alps-ping": {note: "ALPS giving a PING frame", script: "done();", alps: "ping", quiet: true,
		settle: alpsSettled},
	"alps-goaway": {note: "ALPS giving a GOAWAY frame", script: "done();", alps: "goaway", quiet: true,
		settle: alpsSettled},
	"alps-window-update": {note: "ALPS giving a WINDOW_UPDATE frame", script: "done();", alps: "window-update", quiet: true,
		settle: alpsSettled},
	"alps-continuation": {note: "ALPS giving a CONTINUATION frame on stream 1", script: "done();", alps: "continuation", quiet: true,
		settle: alpsSettled},
	"alps-settings-flags": {note: "ALPS giving a SETTINGS frame of a table of 65536, every flag set but ACK", script: "done();", alps: "settings-flags", quiet: true,
		settle: alpsSettled},
	"alps-settings-window-large": {note: "ALPS giving SETTINGS: a window of 2^31", script: "done();", alps: "settings-window-large", quiet: true,
		settle: alpsSettled},
	"alps-settings-push-2": {note: "ALPS giving SETTINGS: ENABLE_PUSH 2", script: "done();", alps: "settings-push-2", quiet: true,
		settle: alpsSettled},
	"alps-settings-frame-small": {note: "ALPS giving SETTINGS: frames of at most 100 bytes", script: "done();", alps: "settings-frame-small", quiet: true,
		settle: alpsSettled},
	"alps-settings-connect-2": {note: "ALPS giving SETTINGS: ENABLE_CONNECT_PROTOCOL 2", script: "done();", alps: "settings-connect-2", quiet: true,
		settle: alpsSettled},
	"alps-settings-priorities-2": {note: "ALPS giving SETTINGS: NO_RFC7540_PRIORITIES 2", script: "done();", alps: "settings-priorities-2", quiet: true,
		settle: alpsSettled},
	"alps-ping-stream": {note: "ALPS giving a PING frame on stream 1", script: "done();", alps: "ping-stream", quiet: true,
		settle: alpsSettled},
	"alps-ping-short": {note: "ALPS giving a PING frame of seven bytes", script: "done();", alps: "ping-short", quiet: true,
		settle: alpsSettled},
	"alps-data-stream-0": {note: "ALPS giving a DATA frame on stream 0", script: "done();", alps: "data-stream-0", quiet: true,
		settle: alpsSettled},
	"alps-priority-short": {note: "ALPS giving a PRIORITY frame of four bytes", script: "done();", alps: "priority-short", quiet: true,
		settle: alpsSettled},
	"alps-rst-stream-0": {note: "ALPS giving a RST_STREAM frame on stream 0", script: "done();", alps: "rst-stream-0", quiet: true,
		settle: alpsSettled},
	"alps-goaway-stream": {note: "ALPS giving a GOAWAY frame on stream 1", script: "done();", alps: "goaway-stream", quiet: true,
		settle: alpsSettled},
	"alps-window-update-zero": {note: "ALPS giving a WINDOW_UPDATE frame of nothing", script: "done();", alps: "window-update-zero", quiet: true,
		settle: alpsSettled},
	"alps-window-update-short": {note: "ALPS giving a WINDOW_UPDATE frame of three bytes", script: "done();", alps: "window-update-short", quiet: true,
		settle: alpsSettled},
	"alps-headers-bad-hpack": {note: "ALPS giving a HEADERS frame whose block does not decode", script: "done();", alps: "headers-bad-hpack", quiet: true,
		settle: alpsSettled},
	"alps-headers-open": {note: "ALPS giving a HEADERS frame without END_HEADERS", script: "done();", alps: "headers-open", quiet: true,
		settle: alpsSettled},
	"alps-headers-then-continuation": {note: "ALPS giving a HEADERS frame without END_HEADERS, then its CONTINUATION", script: "done();", alps: "headers-then-continuation", quiet: true,
		settle: alpsSettled},
	"alps-headers-open-then-settings": {note: "ALPS giving a HEADERS frame without END_HEADERS, then a SETTINGS frame", script: "done();", alps: "headers-open-then-settings", quiet: true,
		settle: alpsSettled},
	"alps-headers-padded-bad": {note: "ALPS giving a HEADERS frame padded by more than it carries", script: "done();", alps: "headers-padded-bad", quiet: true,
		settle: alpsSettled},
	"alps-unknown-large": {note: "ALPS giving a frame of type 0xfa of 20,000 bytes", script: "done();", alps: "unknown-large", quiet: true,
		settle: alpsSettled},
	"alps-settings-large": {note: "ALPS giving a SETTINGS frame of 18,006 bytes: a table of 65536 and an unknown setting 3,000 times", script: "done();", alps: "settings-large", quiet: true,
		settle: alpsSettled},
	"alps-settings-priorities-1": {note: "ALPS giving SETTINGS: NO_RFC7540_PRIORITIES 1", script: "done();", alps: "settings-priorities-1", quiet: true,
		settle: alpsSettled},
	"alps-settings-streams-0": {note: "ALPS giving SETTINGS: no stream at a time", script: "done();", alps: "settings-streams-0", quiet: true,
		settle: alpsSettled},
	"alps-settings-priorities-changed": {note: "ALPS giving SETTINGS: NO_RFC7540_PRIORITIES 0, then 1", script: "done();", alps: "settings-priorities-changed", quiet: true,
		settle: alpsSettled},
	"alps-settings-priorities-again": {note: "ALPS giving SETTINGS: NO_RFC7540_PRIORITIES 1, then 1", script: "done();", alps: "settings-priorities-again", quiet: true,
		settle: alpsSettled},
	"alps-settings-connect-1-0": {note: "ALPS giving SETTINGS: ENABLE_CONNECT_PROTOCOL 1, then 0", script: "done();", alps: "settings-connect-1-0", quiet: true,
		settle: alpsSettled},
	"alps-settings-connect-0-1": {note: "ALPS giving SETTINGS: ENABLE_CONNECT_PROTOCOL 0, then 1", script: "done();", alps: "settings-connect-0-1", quiet: true,
		settle: alpsSettled},
	"alps-accept-ch-asked": {note: "ALPS asking the page's origin for three hints, a page whose Accept-CH asked for one of them, and location.href to that origin",
		start: alpsLobby + "?accept=sec-ch-ua-arch", script: "location.href='{A}/p/alps-accept-ch-asked?quiet';",
		wait: "/p/alps-accept-ch-asked", alps: "accept-ch", quiet: true},
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
			entries, err := s.run(ctx, b, id, sc, origins(s.ALPS[sc.alps], s.Plain), t, progress)
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
// asked meanwhile: the handshake of each connection it asked on or refused,
// up to the first it ended with a GOAWAY, and how its requests went into
// HPACK. A connection it sent nothing on but its SETTINGS, if that, is one
// Chrome opened as it started, beside its navigation's, and the page never
// used: on GitHub's Linux runner one now and then outlived the start, and
// the scenario said 2 handshakes where Chrome had made 1 (2026-10-20,
// alps-accept-ch); no handshake of the fixture is one.
func (s *Server) ALPSOf(note, alps string, entries []Entry) (ALPSScenario, error) {
	written, err := s.Written(entries, alpsVariants[alps].table, false)
	if err != nil {
		return ALPSScenario{}, err
	}
	prioritized(entries, written)
	spoken := []ALPSHandshake{}
	for _, h := range s.ALPSHandshakes() {
		asked := slices.ContainsFunc(entries, func(e Entry) bool { return e.Conn == h.Conn })
		if asked || h.GoAway != "" {
			spoken = append(spoken, h)
		}
		if h.GoAway != "" {
			// The request whose connection's ALPS was refused failed with
			// it: what follows is the browser's error page, which Chrome
			// reloads by itself a second later, and what that asks.
			break
		}
	}
	return ALPSScenario{Note: note, Handshakes: spoken, Connections: append([][]WrittenRequest{}, written...)}, nil
}

// prioritized says in each request of written, which Written made of
// entries, the priority its HEADERS frame carried: a server's ALPS may tell a
// browser to send none.
func prioritized(entries []Entry, written [][]WrittenRequest) {
	at := map[int]int{}
	sent := map[int]int{}
	for _, e := range entries {
		if e.Proto != "h2" {
			continue
		}
		if _, ok := at[e.Conn]; !ok {
			at[e.Conn] = len(at)
		}
		if e.Priority != nil {
			written[at[e.Conn]][sent[e.Conn]].Priority = e.Priority[:]
		}
		sent[e.Conn]++
	}
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
