package fingerprint

import (
	"reflect"
	"testing"
)

// chromeHTTP2 is what a real Chrome 151 sends on a fresh connection, measured
// twice — once by tls.browserleaks.com and once by this library's echo server,
// which agreed.
func chromeHTTP2() *HTTP2 {
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
