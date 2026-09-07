package profile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

func TestTrustAnchorPayloadOrderIsStableWithinAProcess(t *testing.T) {
	reverse := func(n int, swap func(int, int)) {
		for left, right := 0, n-1; left < right; left, right = left+1, right-1 {
			swap(left, right)
		}
	}
	cache := newTrustAnchorPayloads(reverse)

	first, err := cache.payload([]byte{0, 6, 1, 1, 1, 2, 1, 3})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 6, 1, 3, 1, 2, 1, 1}
	if !bytes.Equal(first, want) {
		t.Fatalf("first payload = %x, want %x", first, want)
	}

	// The second capture contains the same set in a different order. It must
	// reuse the process order, and callers must not receive the cached slice.
	first[3] = 0xff
	second, err := cache.payload([]byte{0, 6, 1, 2, 1, 1, 1, 3})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, want) {
		t.Fatalf("second payload = %x, want cached order %x", second, want)
	}

	empty, err := cache.payload([]byte{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, []byte{0, 0}) {
		t.Errorf("empty payload = %x", empty)
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
