package fingerprint

import (
	"reflect"
	"testing"
)

func TestIsGREASE(t *testing.T) {
	// The sixteen reserved values from RFC 8701, all of the form 0xNaNa.
	for _, value := range []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	} {
		if !IsGREASE(value) {
			t.Errorf("IsGREASE(%#04x) = false, want true", value)
		}
	}
	for _, value := range []uint16{
		0x0000, 0x1301, 0x0a0b, 0x0b0a, 0xabab, 0x0a1a, 0xfaaf, 0xffff,
	} {
		if IsGREASE(value) {
			t.Errorf("IsGREASE(%#04x) = true, want false", value)
		}
	}
}

func TestWithoutGREASEKeepsOrderAndCopies(t *testing.T) {
	original := []uint16{0x0a0a, 0x1301, 0x1a1a, 0x1302}
	filtered := withoutGREASE(original)

	if want := []uint16{0x1301, 0x1302}; !reflect.DeepEqual(filtered, want) {
		t.Errorf("withoutGREASE = %v, want %v", filtered, want)
	}

	// The result must not alias the input: JA4 sorts it, and sorting a slice
	// that aliased the parsed hello would scramble the record of what the client
	// actually sent — which the structural diff still needs.
	filtered[0] = 0xffff
	if original[1] != 0x1301 {
		t.Error("withoutGREASE returned a slice aliasing its input")
	}
}

func TestWithoutGREASEOnEmptyInput(t *testing.T) {
	if got := withoutGREASE(nil); len(got) != 0 {
		t.Errorf("withoutGREASE(nil) = %v, want empty", got)
	}
}
