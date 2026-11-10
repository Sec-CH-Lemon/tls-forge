package engine

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// The published release is the anchor. An unpublished engine is newer than
// it and keeps its major: the major goes up only when the profiles the
// release ran can no longer run as they are (owner, 2026-11-11), a loss the
// owner decides, which moves this test with the version. Implementation
// commits, a new fork release or a new toolchain never do, and never turn one
// pending release into majors 2..7.
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
		if !newerVersion(Version(), release.Latest) {
			t.Fatalf("unreleased %s is not newer than the release %s", Version(), release.Latest)
		}
	case "released":
		if release.Pending || Version() != release.Latest {
			t.Fatal("published identity must equal its release anchor")
		}
	default:
		t.Fatal("release status must explicitly distinguish published and unpublished versions")
	}
	if Major() != wantMajor {
		t.Fatalf("engine major %d must be %d, the major of the release %s: the profiles it ran still run", Major(), wantMajor, release.Latest)
	}
}

func TestCompiledIdentity(t *testing.T) {
	if Version() != "1.1.0" || Major() != 1 {
		t.Fatalf("wrong compiled identity: %s/%d", Version(), Major())
	}
	for _, v := range []string{"1.1.0", "v1.1.0"} {
		if err := CheckBuildVersion(v); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"dev", "v0.1.0", "v7.0.0", "v2.0.1", "v3.0.0", "v4.0.0", "v5.0.0", "v6.0.0", "v1.0.0", "v1.0.1", "v2.0.0", "v1.1.0-dirty"} {
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
		{`{"engine_major":1`, nil, "unexpected end of JSON input"},
		{`{"engine_major":1]`, nil, "invalid character ']'"},
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

// newerVersion says whether a, a version of three numbers, comes after b.
func newerVersion(a, b string) bool {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := range x {
		m, _ := strconv.Atoi(x[i])
		n, _ := strconv.Atoi(y[i])
		if m != n {
			return m > n
		}
	}
	return false
}

func TestANewerVersionIsNewerNumberByNumber(t *testing.T) {
	for _, tc := range []struct {
		a, b  string
		newer bool
	}{{"1.1.0", "1.0.1", true}, {"1.0.10", "1.0.9", true}, {"2.0.0", "1.9.9", true},
		{"1.0.1", "1.0.1", false}, {"1.0.0", "1.0.1", false}, {"0.9.9", "1.0.0", false}} {
		if got := newerVersion(tc.a, tc.b); got != tc.newer {
			t.Errorf("%s after %s: %v", tc.a, tc.b, got)
		}
	}
}
