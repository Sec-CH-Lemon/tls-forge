package fingerprint

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// chromeHTTP2 is what a real Chrome 151 sends on a fresh connection, measured
// twice — once by tls.browserleaks.com and once by this library's echo server,
// which agreed. Its Raw is written as wire says.
func chromeHTTP2() *HTTP2 {
	h := chromeHTTP2Fields()
	h.Raw = preambleOf(h, wire{})
	return h
}

// wire is how preambleOf writes a preamble: as Chrome does, unless told
// otherwise.
type wire struct {
	// ackFirst acknowledges the server's SETTINGS before the request.
	ackFirst bool
	// priority sends a PRIORITY frame before the request.
	priority bool
	// noWindow sends no WINDOW_UPDATE.
	noWindow bool
	// sensitive is a field written never to be indexed.
	sensitive string
	// split cuts the header block into a HEADERS and a CONTINUATION.
	split bool
	// sizeUpdate begins the header block with a table size update.
	sizeUpdate bool
}

// preambleOf writes the frames a client sends before its first request is
// whole, with x/net's framer and encoder: neither the echo server's nor the
// transport's, so that a mistake in either cannot hide here.
func preambleOf(h *HTTP2, w wire) []byte {
	var out bytes.Buffer
	framer := http2.NewFramer(&out, nil)
	settings := make([]http2.Setting, len(h.Settings))
	for i, s := range h.Settings {
		settings[i] = http2.Setting{ID: http2.SettingID(s.ID), Val: s.Value}
	}
	_ = framer.WriteSettings(settings...)
	if !w.noWindow {
		_ = framer.WriteWindowUpdate(0, h.WindowUpdate)
	}
	if w.ackFirst {
		_ = framer.WriteSettingsAck()
	}
	if w.priority {
		_ = framer.WritePriority(3, http2.PriorityParam{Weight: 200})
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	if w.sizeUpdate {
		enc.SetMaxDynamicTableSize(2048)
	}
	for _, f := range h.Headers {
		_ = enc.WriteField(hpack.HeaderField{Name: f.Name, Value: f.Value, Sensitive: f.Name == w.sensitive})
	}
	fragment := block.Bytes()
	param := http2.HeadersFrameParam{StreamID: 1, EndStream: true, EndHeaders: !w.split,
		Priority: http2.PriorityParam{Exclusive: true, Weight: 255}}
	if w.split {
		param.BlockFragment, fragment = fragment[:4], fragment[4:]
		_ = framer.WriteHeaders(param)
		_ = framer.WriteContinuation(1, true, fragment)
	} else {
		param.BlockFragment = fragment
		_ = framer.WriteHeaders(param)
	}
	return out.Bytes()
}

func chromeHTTP2Fields() *HTTP2 {
	return &HTTP2{
		Settings: []Setting{
			{ID: 1, Value: 65536},
			{ID: 2, Value: 0},
			{ID: 4, Value: 6291456},
			{ID: 6, Value: 262144},
		},
		WindowUpdate: 15663105,
		Headers: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/"},
			{Name: "sec-ch-ua", Value: `"Chromium";v="151"`},
			{Name: "user-agent", Value: "Mozilla/5.0"},
			{Name: "accept", Value: "text/html"},
		},
		HeaderPriority: &Priority{StreamID: 1, Exclusive: true, Weight: 255},
	}
}

func TestAkamaiMatchesRealChrome(t *testing.T) {
	const want = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if got := chromeHTTP2().Akamai(); got != want {
		t.Errorf("Akamai = %s\nwant    %s", got, want)
	}
}

func TestAkamaiWithoutWindowUpdate(t *testing.T) {
	h := chromeHTTP2()
	h.WindowUpdate = 0
	// "00" rather than "0" is what the original implementation writes, and the
	// value is compared as a string against logs produced by it.
	const want = "1:65536;2:0;4:6291456;6:262144|00|0|m,a,s,p"
	if got := h.Akamai(); got != want {
		t.Errorf("Akamai = %s\nwant    %s", got, want)
	}
}

func TestAkamaiWithStandalonePriorityFrames(t *testing.T) {
	h := chromeHTTP2()
	h.Priorities = []Priority{
		{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 200},
		{StreamID: 5, Exclusive: true, DependsOn: 3, Weight: 100},
	}
	const want = "1:65536;2:0;4:6291456;6:262144|15663105|3:0:0:200,5:1:3:100|m,a,s,p"
	if got := h.Akamai(); got != want {
		t.Errorf("Akamai = %s\nwant    %s", got, want)
	}
}

func TestAkamaiOnAnEmptyConnection(t *testing.T) {
	if got, want := (&HTTP2{}).Akamai(), "|00|0|"; got != want {
		t.Errorf("Akamai = %q, want %q", got, want)
	}
}

func TestPseudoHeaderOrder(t *testing.T) {
	got := chromeHTTP2().PseudoHeaderOrder()
	if want := []string{"m", "a", "s", "p"}; !reflect.DeepEqual(got, want) {
		t.Errorf("PseudoHeaderOrder = %v, want %v", got, want)
	}
}

func TestPseudoHeaderOrderIgnoresABareColon(t *testing.T) {
	h := &HTTP2{Headers: []HeaderField{{Name: ":"}, {Name: ":path"}}}
	if got, want := h.PseudoHeaderOrder(), []string{"p"}; !reflect.DeepEqual(got, want) {
		t.Errorf("PseudoHeaderOrder = %v, want %v", got, want)
	}
}

func TestHeaderOrderExcludesPseudoHeaders(t *testing.T) {
	got := chromeHTTP2().HeaderOrder()
	want := []string{"sec-ch-ua", "user-agent", "accept"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("HeaderOrder = %v, want %v", got, want)
	}
}

func TestHeaderLookup(t *testing.T) {
	h := chromeHTTP2()
	if got, ok := h.Header("USER-AGENT"); !ok || got != "Mozilla/5.0" {
		t.Errorf("Header(USER-AGENT) = %q, %v", got, ok)
	}
	if _, ok := h.Header("cookie"); ok {
		t.Error("Header(cookie) reported a header that was not sent")
	}
}
