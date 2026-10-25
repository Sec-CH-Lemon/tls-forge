package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// The published release is the anchor. More implementation commits in the
// same unpublished engine must not turn one pending release into majors2..7.
func TestReleaseAnchoredDevelopmentMajor(t *testing.T) {
	var release struct {
		Latest  string `json:"latest_released_version"`
		Status  string `json:"release_status"`
		Pending bool   `json:"pending_engine_change"`
	}
	if err := json.Unmarshal(metadata, &release); err != nil {
		t.Fatal(err)
	}
	previous := parse([]byte(`{"version":"` + release.Latest + `"}`))
	wantMajor := previous.major
	switch release.Status {
	case "unreleased":
		if release.Pending {
			wantMajor++
		}
	case "released":
		if release.Pending || Version() != release.Latest {
			t.Fatal("published identity must equal its release anchor")
		}
	default:
		t.Fatal("release status must explicitly distinguish published and unpublished versions")
	}
	if Major() != wantMajor {
		t.Fatalf("engine major%d must be%d, anchored to released%s; development iterations do not increment it", Major(), wantMajor, release.Latest)
	}
}

func TestCompiledIdentity(t *testing.T) {
	if Version() != "1.0.0" || Major() != 1 {
		t.Fatalf("wrong compiled identity: %s/%d", Version(), Major())
	}
	for _, v := range []string{"1.0.0", "v1.0.0"} {
		if err := CheckBuildVersion(v); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"dev", "v0.1.0", "v7.0.0", "v2.0.1", "v3.0.0", "v4.0.0", "v5.0.0", "v6.0.0", "v1.0.1", "v1.0.0-dirty"} {
		if CheckBuildVersion(v) == nil {
			t.Fatal(v)
		}
	}
	for _, v := range []string{`{}`, `x`, `{"version":"1.0"}`, `{"version":"01.0.0"}`, `{"version":"-1.0.0"}`} {
		t.Run(v, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid identity accepted")
				}
			}()
			parse([]byte(v))
		})
	}
}
func TestUnambiguousMajorJSON(t *testing.T) {
	for _, raw := range []string{"null", "-1", "1.0", "1.5", `"1"`, "true", "9999999999999999999999999"} {
		if _, err := DeclaredMajor([]byte(`{"engine_major":` + raw + `}`)); err == nil {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{`{"engine_major":1,"engine_major":1}`, `{"engine_major":0,"Engine_Major":1}`, `{"ENGINE_MAJOR":1}`, `[]`, `{} {}`, `{"engine_major":1,`} {
		if _, err := DeclaredMajor([]byte(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
		if err := CheckMajor("test", &n); (err == nil) != (n == Major()) {
			t.Fatal(n, err)
		}
	}
	if err := CheckMajor("profile x", nil); err == nil || !strings.Contains(err.Error(), "running engine major 1") {
		t.Fatal(err)
	}
	n := -1
	if CheckMajor("x", &n) == nil {
		t.Fatal("negative major")
	}
}

func TestADeclaredMajorIsReadExactlyOrRefused(t *testing.T) {
	one := 1
	for _, tc := range []struct {
		data string
		want *int
		err  string
	}{
		{`{"name":"x","engine_major":1,"behavior":{"a":[1,{"b":2}]}}`, &one, ""},
		{`{"name":"x"}`, nil, ""},
		{``, nil, "EOF"},
		{`[1]`, nil, "expected a JSON object"},
		{`{"name":}`, nil, "invalid character"},
		{`{"Engine_Major":1}`, nil, `invalid engine_major spelling "Engine_Major"`},
		{`{"engine_major":1,"engine_major":1}`, nil, "duplicate engine_major"},
		{`{"engine_major":null}`, nil, "engine_major is null"},
		{`{"engine_major":-1}`, nil, "invalid engine_major -1"},
		{`{"engine_major":1.5}`, nil, "invalid engine_major 1.5"},
		{`{"engine_major":1`, nil, "EOF"},
		{`{"engine_major":1} {}`, nil, "extra data after JSON object"},
	} {
		got, err := DeclaredMajor([]byte(tc.data))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: %v, %v; want %q", tc.data, got, err, tc.err)
			}
			continue
		}
		if err != nil || (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: %v, %v; want %v", tc.data, got, err, tc.want)
		}
	}
}
