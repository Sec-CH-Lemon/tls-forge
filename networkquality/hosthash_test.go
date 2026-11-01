package networkquality

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

func TestHostHashMatchesBothPinnedLibcxxVariants(t *testing.T) {
	raw, err := os.ReadFile("testdata/libcxx-hosthash-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Host  string `json:"host"`
			Fixed bool   `json:"fixed"`
			Value string `json:"value"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 180 {
		t.Fatal("missing oracle cases", len(fixture.Cases))
	}
	differences := 0
	for _, tc := range fixture.Cases {
		want, err := strconv.ParseUint(tc.Value, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := LibcxxHash64(tc.Host, tc.Fixed); got != want {
			t.Errorf("host%q fixed%v hash%d want%d", tc.Host, tc.Fixed, got, want)
		}
		if LibcxxHash64(tc.Host, false) != LibcxxHash64(tc.Host, true) {
			differences++
		}
	}
	if differences == 0 {
		t.Fatal("ABI branch not distinguished by short names")
	}
}
