package fingerprint

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

// chrome155Hello is one of the two hellos of one launch of Chrome 155, recorded
// off the wire: the cold one of its first connection, or the one it opened once
// it held a session ticket.
func chrome155Hello(t *testing.T, name string) *ClientHello {
	t.Helper()
	raw, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	hello, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return hello
}

func TestChrome155ResumesWithOneExtensionMore(t *testing.T) {
	cold := chrome155Hello(t, "chrome155-clienthello.bin")
	resumed := chrome155Hello(t, "chrome155-clienthello-resumed.bin")
	if got := cold.JA4(); got != "t13d1517h2_8daaf6152771_cb7bf5808d99" {
		t.Errorf("cold JA4 = %s", got)
	}
	if got := resumed.JA4(); got != "t13d1518h2_8daaf6152771_e2d80978ab2e" {
		t.Errorf("resumed JA4 = %s", got)
	}

	// pre_shared_key and nothing else is added, and it is the last extension,
	// after the second GREASE one, where nothing shuffles it.
	types := func(hello *ClientHello) []uint16 {
		var out []uint16
		for _, typ := range hello.ExtensionTypes() {
			if !IsGREASE(typ) {
				out = append(out, typ)
			}
		}
		slices.Sort(out)
		return out
	}
	added := slices.DeleteFunc(types(resumed), func(typ uint16) bool { return slices.Contains(types(cold), typ) })
	if !slices.Equal(added, []uint16{ExtPreSharedKey}) || len(types(resumed)) != len(types(cold))+1 {
		t.Errorf("resuming added %v to %v", added, types(cold))
	}
	all := resumed.ExtensionTypes()
	if all[len(all)-1] != ExtPreSharedKey || !IsGREASE(all[len(all)-2]) || !IsGREASE(cold.ExtensionTypes()[len(cold.ExtensionTypes())-1]) {
		t.Errorf("the resumed hello ends with %v, the cold one with %v", all[len(all)-3:], cold.ExtensionTypes()[len(cold.ExtensionTypes())-2:])
	}

	// What stays: the key exchange is psk_dhe_ke in both, session_ticket is
	// empty in both, and neither asks for early data.
	for _, hello := range []*ClientHello{cold, resumed} {
		if modes := hello.PSKKeyExchangeModes(); !bytes.Equal(modes, []byte{1}) {
			t.Errorf("psk_key_exchange_modes = %v", modes)
		}
		if ticket, ok := hello.Extension(ExtSessionTicket); !ok || len(ticket) != 0 {
			t.Errorf("session_ticket = %v, %v", ticket, ok)
		}
		if _, ok := hello.Extension(42); ok {
			t.Error("a hello asked for early data")
		}
	}
	// The raw JA4 differs by that extension alone.
	if got := strings.Replace(strings.Replace(resumed.JA4Raw(), "1518h2", "1517h2", 1), ",0029", "", 1); got != cold.JA4Raw() {
		t.Errorf("raw JA4s differ beyond pre_shared_key:\n%s\n%s", resumed.JA4Raw(), cold.JA4Raw())
	}
}
