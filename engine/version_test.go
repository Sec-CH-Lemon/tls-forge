package engine

import (
	"strings"
	"testing"
)

func TestCompiledIdentity(t *testing.T) {
	if Version() != "7.0.0" || Major() != 7 {
		t.Fatalf("wrong compiled identity: %s/%d", Version(), Major())
	}
	for _, v := range []string{"7.0.0", "v7.0.0"} {
		if err := CheckBuildVersion(v); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"dev", "v0.1.0", "v1.0.0", "v2.0.1", "v3.0.0", "v4.0.0", "v5.0.0", "v6.0.0", "v7.0.1", "v7.0.0-dirty"} {
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
	for _, raw := range []string{`{"engine_major":7,"engine_major":7}`, `{"engine_major":0,"Engine_Major":1}`, `{"ENGINE_MAJOR":1}`, `[]`, `{} {}`, `{"engine_major":7,`} {
		if _, err := DeclaredMajor([]byte(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
		if err := CheckMajor("test", &n); (err == nil) != (n == Major()) {
			t.Fatal(n, err)
		}
	}
	if err := CheckMajor("profile x", nil); err == nil || !strings.Contains(err.Error(), "running engine major 7") {
		t.Fatal(err)
	}
	n := -1
	if CheckMajor("x", &n) == nil {
		t.Fatal("negative major")
	}
}
