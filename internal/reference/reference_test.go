package reference

import (
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// zeros is a SHA-256 the manifest accepts, of nothing in particular.
var zeros = strings.Repeat("0", 64)

// manifest is a valid manifest with one field set as given, as JSON.
func manifest(t *testing.T, change func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"schema":  1,
		"version": "155.0.8059.80",
		"profile": "chrome_155",
		"launch":  map[string]any{"headless": false, "args": []any{"--no-sandbox"}},
		"builds": []any{
			map[string]any{"platform": "linux", "arch": "amd64", "installer": "google-chrome-stable_155.0.8059.80-1_amd64.deb",
				"installer_sha256": zeros, "binary": "opt/google/chrome/chrome", "binary_sha256": zeros},
			map[string]any{"platform": "macos", "arch": "arm64", "installer": "googlechrome-155.0.8059.80.dmg",
				"installer_sha256": zeros, "binary": "Google Chrome.app/Contents/MacOS/Google Chrome", "binary_sha256": zeros},
		},
	}
	if change != nil {
		change(m)
	}
	data, err := jsonMarshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// build sets a field of the manifest's first build.
func build(field string, value any) func(m map[string]any) {
	return func(m map[string]any) { m["builds"].([]any)[0].(map[string]any)[field] = value }
}

func TestAManifestIsReadStrictly(t *testing.T) {
	m, err := Load(manifest(t, nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Version != "155.0.8059.80" || m.Profile != "chrome_155" || m.Launch.Headless || len(m.Launch.Args) != 1 ||
		len(m.Builds) != 2 || m.Builds[1].Binary != "Google Chrome.app/Contents/MacOS/Google Chrome" {
		t.Errorf("read %+v", m)
	}
	for _, tc := range []struct {
		name   string
		change func(m map[string]any)
		want   string
	}{
		{"a field it does not have", func(m map[string]any) { m["channel"] = "stable" }, `unknown field "channel"`},
		{"another schema", func(m map[string]any) { m["schema"] = 2 }, "schema 2, and this reads 1"},
		{"no schema", func(m map[string]any) { delete(m, "schema") }, "schema 0"},
		{"a version Chrome has not", func(m map[string]any) { m["version"] = "155" }, `version "155" is not a full version`},
		{"no profile", func(m map[string]any) { m["profile"] = "" }, "no profile"},
		{"no build", func(m map[string]any) { m["builds"] = []any{} }, "no build"},
		{"a platform it is not", build("platform", "freebsd"), `platform "freebsd" is none of`},
		{"a machine it is not", build("arch", "386"), `arch "386" is none of`},
		{"no installer", build("installer", ""), `installer "" is not a file name`},
		{"an installer in a directory", build("installer", "a/b.deb"), `installer "a/b.deb"`},
		{"an installer in a Windows directory", build("installer", `a\b.exe`), `installer "a\\b.exe"`},
		{"the archive itself", build("installer", ".."), `installer ".."`},
		{"this directory", build("installer", "."), `installer "."`},
		{"a hash in capitals", build("installer_sha256", strings.ToUpper(strings.Repeat("a", 64))), "installer_sha256"},
		{"a hash too short", build("installer_sha256", "abc"), "installer_sha256"},
		{"no binary", build("binary", ""), `binary "" is not a clean relative path`},
		{"a binary from the root", build("binary", "/opt/chrome"), `binary "/opt/chrome"`},
		{"a binary outside", build("binary", "../chrome"), `binary "../chrome"`},
		{"a binary that is the parent", build("binary", ".."), `binary ".."`},
		{"a binary that is the directory", build("binary", "."), `binary "."`},
		{"a binary not clean", build("binary", "opt/../chrome"), `binary "opt/../chrome"`},
		{"a binary with backslashes", build("binary", `opt\chrome`), `binary "opt\\chrome"`},
		{"a binary hash in capitals", build("binary_sha256", strings.ToUpper(strings.Repeat("a", 64))), "binary_sha256"},
		{"one build twice", func(m map[string]any) {
			m["builds"] = append(m["builds"].([]any), m["builds"].([]any)[0])
		}, "linux/amd64 twice"},
	} {
		if _, err := Load(manifest(t, tc.change)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	for _, document := range []string{`{`, `[]`} {
		if _, err := Load([]byte(document)); err == nil {
			t.Errorf("%s was read", document)
		}
	}
	if _, err := Load(append(manifest(t, nil), []byte(" {}")...)); err == nil || !strings.Contains(err.Error(), "more after") {
		t.Errorf("more after the manifest: %v", err)
	}
}

func TestABuildIsFoundForItsPlatformAndMachine(t *testing.T) {
	m, err := Load(manifest(t, nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b, err := m.Build("macos", "arm64"); err != nil || b != &m.Builds[1] {
		t.Errorf("macos/arm64: %+v, %v", b, err)
	}
	if _, err := m.Build("windows", "amd64"); err == nil ||
		err.Error() != "reference: no build for windows/amd64; the reference is Google Chrome 155.0.8059.80 on "+
			"linux/amd64, macos/arm64" {
		t.Errorf("windows/amd64: %v", err)
	}
}

func TestAFileIsHeldToItsHash(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "installer")
	if err := os.WriteFile(name, []byte("chrome"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256([]byte("chrome"))
	if err := VerifyFile(name, hex.EncodeToString(sum[:])); err != nil {
		t.Errorf("the file itself: %v", err)
	}
	if err := VerifyFile(name, zeros); !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "hashes to") {
		t.Errorf("another file: %v", err)
	}
	if err := VerifyFile(filepath.Join(dir, "missing"), zeros); err == nil || errors.Is(err, ErrMismatch) {
		t.Errorf("no file: %v", err)
	}
	// A directory opens and does not read.
	if err := VerifyFile(dir, zeros); err == nil || !strings.Contains(err.Error(), "reading") {
		t.Errorf("a directory: %v", err)
	}
}

func TestTheBrowserMustSayItIsTheReference(t *testing.T) {
	m, err := Load(manifest(t, nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := m.CheckIdentity("Google Chrome 155.0.8059.80 \n"); err != nil {
		t.Errorf("the reference: %v", err)
	}
	for said, want := range map[string]string{
		"Google Chrome for Testing 155.0.8059.80": "is Chrome for Testing",
		"Chromium 155.0.8059.80":                  "is Chromium",
		"Google Chrome 155.0.8059.81":             `the browser says "Google Chrome 155.0.8059.81"`,
		"Google Chrome 155.0.8059.80 beta":        "the browser says",
		"":                                        `the browser says ""`,
	} {
		if err := m.CheckIdentity(said); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", said, err, want)
		}
	}
}

// executable writes bytes to a file and is its name.
func executable(t *testing.T, data []byte) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "browser")
	if err := os.WriteFile(name, data, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	return name
}

// elfHeader is the header of a 64-bit little-endian ELF executable for machine.
func elfHeader(machine elf.Machine) []byte {
	out := make([]byte, 64)
	copy(out, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(out[16:], 2) // an executable
	binary.LittleEndian.PutUint16(out[18:], uint16(machine))
	binary.LittleEndian.PutUint32(out[20:], 1)
	binary.LittleEndian.PutUint16(out[52:], 64)
	return out
}

// machoHeader is the header of a 64-bit Mach-O executable for cpu, with no
// load commands.
func machoHeader(cpu macho.Cpu) []byte {
	out := make([]byte, 32)
	binary.LittleEndian.PutUint32(out[0:], macho.Magic64)
	binary.LittleEndian.PutUint32(out[4:], uint32(cpu))
	binary.LittleEndian.PutUint32(out[12:], uint32(macho.TypeExec))
	return out
}

// fatHeader is a universal Mach-O holding an executable for each cpu.
func fatHeader(cpus ...macho.Cpu) []byte {
	out := make([]byte, 4096)
	binary.BigEndian.PutUint32(out[0:], macho.MagicFat)
	binary.BigEndian.PutUint32(out[4:], uint32(len(cpus)))
	for i, cpu := range cpus {
		offset := 1024 * (i + 1)
		entry := out[8+20*i:]
		binary.BigEndian.PutUint32(entry[0:], uint32(cpu))
		binary.BigEndian.PutUint32(entry[8:], uint32(offset))
		binary.BigEndian.PutUint32(entry[12:], 32)
		binary.BigEndian.PutUint32(entry[16:], 10)
		copy(out[offset:], machoHeader(cpu))
	}
	return out
}

// peHeader is a PE executable for machine, with no sections: as long as the
// 96 bytes of DOS header the reader takes first, and its own.
func peHeader(machine uint16) []byte {
	out := make([]byte, 256)
	copy(out, "MZ")
	binary.LittleEndian.PutUint32(out[0x3c:], 0x40)
	copy(out[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(out[0x44:], machine)
	return out
}

func TestAnExecutableSaysWhatItIsFor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     []byte
		platform string
		machines []string
	}{
		{"ELF for amd64", elfHeader(elf.EM_X86_64), "linux", []string{"amd64"}},
		{"ELF for arm64", elfHeader(elf.EM_AARCH64), "linux", []string{"arm64"}},
		{"ELF for a machine this does not name", elfHeader(elf.EM_386), "linux", []string{""}},
		{"Mach-O for arm64", machoHeader(macho.CpuArm64), "macos", []string{"arm64"}},
		{"universal Mach-O", fatHeader(macho.CpuAmd64, macho.CpuArm64), "macos", []string{"amd64", "arm64"}},
		{"PE for amd64", peHeader(pe.IMAGE_FILE_MACHINE_AMD64), "windows", []string{"amd64"}},
		{"PE for arm64", peHeader(pe.IMAGE_FILE_MACHINE_ARM64), "windows", []string{"arm64"}},
	} {
		platform, machines, err := Machine(executable(t, tc.data))
		if err != nil || platform != tc.platform || strings.Join(machines, ",") != strings.Join(tc.machines, ",") {
			t.Errorf("%s: %s %v, %v", tc.name, platform, machines, err)
		}
	}
	if _, _, err := Machine(executable(t, []byte("#!/bin/sh\n"))); err == nil ||
		!strings.Contains(err.Error(), "not ELF, Mach-O or PE") {
		t.Errorf("a script: %v", err)
	}
	// And this test binary is one, for this machine.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	platform, machines, err := Machine(self)
	want := map[string]string{"darwin": "macos"}[runtime.GOOS]
	if want == "" {
		want = runtime.GOOS
	}
	if err != nil || platform != want || machines[0] != runtime.GOARCH {
		t.Errorf("this binary: %s %v, %v", platform, machines, err)
	}
}

func TestAnExecutableIsHeldToItsBuild(t *testing.T) {
	b := &Build{Platform: "macos", Arch: "arm64"}
	if err := b.CheckMachine(executable(t, fatHeader(macho.CpuAmd64, macho.CpuArm64))); err != nil {
		t.Errorf("a universal binary: %v", err)
	}
	for name, data := range map[string][]byte{
		"another platform": elfHeader(elf.EM_AARCH64),
		"another machine":  machoHeader(macho.CpuAmd64),
	} {
		if err := b.CheckMachine(executable(t, data)); err == nil || !strings.Contains(err.Error(), "the build is macos/arm64") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := b.CheckMachine(executable(t, []byte("text"))); err == nil || !strings.Contains(err.Error(), "no executable") {
		t.Errorf("text: %v", err)
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
