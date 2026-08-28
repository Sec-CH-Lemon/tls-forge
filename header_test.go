package tlsforge

import (
	"reflect"
	"testing"
)

func TestNewHeader(t *testing.T) {
	h := NewHeader("Sec-CH-UA", `"Chromium";v="151"`, "User-Agent", "Mozilla/5.0")
	if got, want := h.Names(), []string{"sec-ch-ua", "user-agent"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	if got := h.Get("USER-AGENT"); got != "Mozilla/5.0" {
		t.Errorf("Get = %q", got)
	}
}

func TestNewHeaderWithAnOddNumberOfArguments(t *testing.T) {
	// Convenience syntax is not a place to lose a request over: the dangling
	// name is dropped rather than panicking or inventing an empty value.
	h := NewHeader("accept", "*/*", "dangling")
	if len(h) != 1 {
		t.Errorf("header = %v, want the complete pair only", h)
	}
}

func TestGetAndHas(t *testing.T) {
	h := NewHeader("accept", "*/*", "x-empty", "")
	if !h.Has("X-EMPTY") {
		t.Error("Has should find a header with an empty value")
	}
	if h.Has("cookie") {
		t.Error("Has found a header that is not there")
	}
	if got := h.Get("cookie"); got != "" {
		t.Errorf("Get = %q, want empty", got)
	}
}

func TestSetKeepsPosition(t *testing.T) {
	// The whole point: a Set that deleted and re-appended would move the header
	// to the end of the list and change the fingerprint, so overriding one value
	// of a browser profile would silently stop looking like that browser.
	h := NewHeader("sec-ch-ua", "a", "user-agent", "b", "accept", "c")
	h.Set("USER-AGENT", "replaced")

	if got, want := h.Names(), []string{"sec-ch-ua", "user-agent", "accept"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	if got := h.Get("user-agent"); got != "replaced" {
		t.Errorf("Get = %q", got)
	}
}

func TestSetAppendsWhatIsNotThere(t *testing.T) {
	h := NewHeader("accept", "*/*")
	h.Set("Referer", "https://example.com")
	if got, want := h.Names(), []string{"accept", "referer"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
}

func TestAddKeepsEveryValue(t *testing.T) {
	h := NewHeader("cookie", "a=1")
	h.Add("Cookie", "b=2")
	if got, want := h.Values("cookie"), []string{"a=1", "b=2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Values = %v, want %v", got, want)
	}
}

func TestDel(t *testing.T) {
	h := NewHeader("a", "1", "b", "2", "c", "3")
	h.Del("B")
	if got, want := h.Names(), []string{"a", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	h.Del("missing")
	if len(h) != 2 {
		t.Errorf("deleting an absent header changed the list: %v", h)
	}
}

func TestClone(t *testing.T) {
	original := NewHeader("a", "1")
	clone := original.Clone()
	clone.Set("a", "changed")
	clone.Set("b", "2")

	if original.Get("a") != "1" {
		t.Error("the clone shares storage with the original")
	}
	if len(original) != 1 {
		t.Errorf("original = %v, want one header", original)
	}
}

func TestMergeKeepsTheBaseOrder(t *testing.T) {
	// A caller setting `referer` should get the browser's order with referer in
	// the browser's slot, not a browser-shaped list with one header bolted on
	// the end.
	base := NewHeader("sec-ch-ua", "a", "user-agent", "b", "referer", "old", "accept", "c")
	merged := base.Merge(NewHeader("referer", "new", "x-extra", "1"))

	want := []string{"sec-ch-ua", "user-agent", "referer", "accept", "x-extra"}
	if got := merged.Names(); !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	if got := merged.Get("referer"); got != "new" {
		t.Errorf("referer = %q", got)
	}
	if base.Get("referer") != "old" {
		t.Error("Merge modified the base")
	}
}

func TestMergeWithNothing(t *testing.T) {
	base := NewHeader("a", "1")
	if got := base.Merge(nil); !reflect.DeepEqual(got, base) {
		t.Errorf("Merge(nil) = %v, want %v", got, base)
	}
}

func TestMergePreservesRepeatedOverrideValues(t *testing.T) {
	base := NewHeader("accept", "text/html", "x-after", "last")
	overrides := NewHeader("cookie", "a=1", "cookie", "b=2", "accept", "application/json")
	merged := base.Merge(overrides)

	if got, want := merged.Values("cookie"), []string{"a=1", "b=2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("cookie values = %v, want %v", got, want)
	}
	if got, want := merged.Names(), []string{"accept", "x-after", "cookie", "cookie"}; !reflect.DeepEqual(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}
	if got := merged.Get("accept"); got != "application/json" {
		t.Errorf("accept = %q", got)
	}
}
