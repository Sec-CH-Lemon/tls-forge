package fingerprint

import (
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"extension", ExtensionName(ExtServerName), "server_name"},
		{"ALPS, as Chrome 155 sends it", ExtensionName(ExtALPS), "application_settings"},
		{"ALPS, as Chrome sent it first", ExtensionName(ExtALPSOld), "application_settings_old"},
		{"trust anchors", ExtensionName(ExtTrustAnchors), "trust_anchors"},
		{"group", GroupName(4588), "X25519MLKEM768"},
		{"signature", SignatureName(0x0904), "mldsa44"},
		{"cipher", CipherName(0x1301), "TLS_AES_128_GCM_SHA256"},
		{"version", VersionName(0x0304), "TLS 1.3"},
		{"setting", SettingName(4), "INITIAL_WINDOW_SIZE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("= %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestNamesFallBackToHex(t *testing.T) {
	for _, got := range []string{
		ExtensionName(0x9999), GroupName(0x9999), SignatureName(0x9999),
		CipherName(0x9999), VersionName(0x9999), SettingName(0x9999),
	} {
		if got != "0x9999" {
			t.Errorf("unknown value rendered as %q, want 0x9999", got)
		}
	}
}

func TestNamesLabelGREASE(t *testing.T) {
	// GREASE has to be recognisable in a diff, or a reader spends time chasing
	// an "extension" that is deliberate noise.
	got := ExtensionName(0x1a1a)
	if !strings.HasPrefix(got, "GREASE") || !strings.Contains(got, "0x1a1a") {
		t.Errorf("ExtensionName(0x1a1a) = %q, want it to name GREASE and the value", got)
	}
	if !strings.HasPrefix(CipherName(0x0a0a), "GREASE") {
		t.Errorf("CipherName(0x0a0a) = %q, want a GREASE label", CipherName(0x0a0a))
	}
}

func TestNamesOf(t *testing.T) {
	got := namesOf([]uint16{0x1301, 0x1302}, CipherName)
	if len(got) != 2 || got[0] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("namesOf = %v", got)
	}
}

func TestTheOldALPSNamesKeepTheirValues(t *testing.T) {
	// A caller of the names that had them the wrong way round reads what it
	// read before: the values stay, and the right names are the new ones.
	for _, tc := range []struct{ got, want uint16 }{
		{ExtApplicationSettings, 17513}, {ExtALPSOld, 17513},
		{ExtApplicationSettingsOld, 17613}, {ExtALPS, 17613},
	} {
		if tc.got != tc.want {
			t.Errorf("%d, want %d", tc.got, tc.want)
		}
	}
	// A hello with both, which no browser sends, is read for the current one.
	hello := mustParse(t, newHello().withCiphers(0x1301).
		withExtension(ExtALPSOld, alpn("http/1.1")).withExtension(ExtALPS, alpn("h2")).records())
	if got := hello.ApplicationSettings(); len(got) != 1 || got[0] != "h2" {
		t.Errorf("ApplicationSettings = %q", got)
	}
}
