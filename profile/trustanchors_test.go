package profile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

func TestATrustAnchorListInByteOrderGoesOutAsCaptured(t *testing.T) {
	// A browser that sorts its IDs sends them so every time: nothing drawn.
	drawn := false
	cache := newTrustAnchorPayloads(func(int, func(int, int)) { drawn = true })
	for _, captured := range [][]byte{
		{0, 6, 1, 1, 1, 2, 1, 3},
		// By the IDs' bytes, as Chromium sorts them: the shorter ID last, where
		// the length each record leads with would have put it first.
		{0, 7, 3, 0x82, 0xdf, 0x13, 2, 0xd6, 0x79},
		{0, 4, 1, 1, 1, 1},
		{0, 0},
	} {
		got, err := cache.payload(captured)
		if err != nil || !bytes.Equal(got, captured) {
			t.Errorf("payload(%x) = %x, %v; want it as captured", captured, got, err)
		}
		if len(got) > 3 {
			// The caller's own copy.
			got[3] ^= 0xff
			if again, _ := cache.payload(captured); !bytes.Equal(again, captured) {
				t.Errorf("payload(%x) after a caller changed its copy = %x", captured, again)
			}
		}
	}
	if drawn {
		t.Error("an order was drawn for a list in byte order")
	}
}

func TestAnyOtherTrustAnchorListIsDrawnOncePerProcess(t *testing.T) {
	reverse := func(n int, swap func(int, int)) {
		for left, right := 0, n-1; left < right; left, right = left+1, right-1 {
			swap(left, right)
		}
	}
	cache := newTrustAnchorPayloads(reverse)

	// Out of byte order, as a Chrome before 154 sent them: an order is drawn.
	first, err := cache.payload([]byte{0, 6, 1, 2, 1, 1, 1, 3})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 6, 1, 3, 1, 2, 1, 1}
	if !bytes.Equal(first, want) {
		t.Fatalf("first payload = %x, want %x", first, want)
	}

	// Another capture of the set in another order gets the order this process
	// drew for it, and callers do not receive the cached slice.
	first[3] = 0xff
	second, err := cache.payload([]byte{0, 6, 1, 3, 1, 1, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, want) {
		t.Fatalf("second payload = %x, want cached order %x", second, want)
	}

	// In the order of their records but not of their IDs' bytes is out of
	// byte order too.
	drawn := false
	other := newTrustAnchorPayloads(func(int, func(int, int)) { drawn = true })
	if _, err := other.payload([]byte{0, 7, 2, 0xd6, 0x79, 3, 0x82, 0xdf, 0x13}); err != nil || !drawn {
		t.Errorf("a shorter ID first drew no order: %v", err)
	}
}

func TestMalformedTrustAnchorPayloadsAreRejected(t *testing.T) {
	for _, payload := range [][]byte{
		nil,             // no uint16 list length
		{0, 1},          // declared list is absent
		{0, 1, 0},       // zero-length IDs are forbidden
		{0, 2, 2, 0xaa}, // ID extends beyond the list
	} {
		if _, err := splitTrustAnchors(payload); err == nil {
			t.Errorf("splitTrustAnchors(%x) succeeded", payload)
		}
	}

	raw := withRawExtension(t, chromeHelloBytes(t), fingerprint.ExtTrustAnchors, nil)
	if _, err := (&Profile{Name: "malformed", ClientHello: raw}).Spec(); err == nil ||
		!strings.Contains(err.Error(), "malformed trust_anchors") {
		t.Errorf("profile error = %v", err)
	}
}
