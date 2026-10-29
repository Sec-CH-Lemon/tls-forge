package tlsforge

import (
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	"testing"
)

func TestPlatformH3SettingsReachProductionWire(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			port, observed := greasePeer(t)
			p, err := profile.Get("chrome_155_" + platform)
			if err != nil {
				t.Fatal(err)
			}
			p.Name = "neutral_platform"
			p.UserAgent = "Metadata without browser identity"
			client := echClient(t, alpsNames(t), WithProfileValue(p))
			if body := came(t, client, "https://h3.h3.test:"+port+"/"); body != "ok" {
				t.Fatalf("H3 required: %s", body)
			}
			seen := greaseObservation(t, observed)
			settings := map[uint64]uint64{}
			for _, pair := range seen.pairs {
				settings[pair[0]] = pair[1]
			}
			if settings[1] != 65536 || settings[7] != 100 {
				t.Fatalf("platform QPACK SETTINGS lost: %v", seen.pairs)
			}
		})
	}
}
