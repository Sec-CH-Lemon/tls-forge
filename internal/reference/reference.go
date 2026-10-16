// Package reference is the Google Chrome a release is held to: which build,
// its installer as archived and what that hashes to, the browser it installs
// and what that hashes to, how it is launched, and the checks that the browser
// about to be measured is that build and no other. Not a newer one, not
// Chrome for Testing, not Chromium: a reference that could be swapped for
// whatever is at hand would hold a release to nothing.
//
// Google publishes no archive of past builds of Google Chrome, so whoever
// releases keeps the installers, privately, since their terms do not allow
// handing them on; the manifest, which says what they are, is committed.
package reference

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Schema is the version of the manifest format this package reads.
const Schema = 1

// Manifest says which build of Google Chrome is the reference.
type Manifest struct {
	Schema int `json:"schema"`
	// Version is Google Chrome's full version, as --version says it:
	// 155.0.8059.80.
	Version string `json:"version"`
	// Profile is the profile held to it.
	Profile string  `json:"profile"`
	Launch  Launch  `json:"launch"`
	Builds  []Build `json:"builds"`
}

// Launch is how the reference is started to be measured.
type Launch struct {
	Headless bool     `json:"headless"`
	Args     []string `json:"args,omitempty"`
}

// Build is the reference on one platform and machine.
type Build struct {
	// Platform is linux, macos or windows; Arch amd64 or arm64.
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	// Installer is the installer's file name in the archive, and
	// InstallerSHA256 what it hashes to.
	Installer       string `json:"installer"`
	InstallerSHA256 string `json:"installer_sha256"`
	// Binary is the browser's executable once installed, relative to where it
	// is installed, with forward slashes, and BinarySHA256 what it hashes to.
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binary_sha256"`
}

var (
	fullVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	platforms   = []string{"linux", "macos", "windows"}
	arches      = []string{"amd64", "arm64"}
)

// Load reads a manifest strictly: a field the format does not have, a schema
// it is not, or a build that could not be checked is an error.
func Load(data []byte) (*Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("reference: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("reference: more after the manifest")
	}
	switch {
	case m.Schema != Schema:
		return nil, fmt.Errorf("reference: schema %d, and this reads %d", m.Schema, Schema)
	case !fullVersion.MatchString(m.Version):
		return nil, fmt.Errorf("reference: version %q is not a full version of Chrome, such as 155.0.8059.80", m.Version)
	case m.Profile == "":
		return nil, errors.New("reference: no profile to hold to it")
	case len(m.Builds) == 0:
		return nil, errors.New("reference: no build")
	}
	seen := map[string]bool{}
	for _, b := range m.Builds {
		if err := b.check(); err != nil {
			return nil, fmt.Errorf("reference: %s/%s: %w", b.Platform, b.Arch, err)
		}
		if seen[b.Platform+"/"+b.Arch] {
			return nil, fmt.Errorf("reference: %s/%s twice", b.Platform, b.Arch)
		}
		seen[b.Platform+"/"+b.Arch] = true
	}
	return &m, nil
}

func (b Build) check() error {
	clean := path.Clean(b.Binary)
	switch {
	case !slices.Contains(platforms, b.Platform):
		return fmt.Errorf("platform %q is none of %v", b.Platform, platforms)
	case !slices.Contains(arches, b.Arch):
		return fmt.Errorf("arch %q is none of %v", b.Arch, arches)
	case b.Installer == "" || strings.ContainsAny(b.Installer, `/\`) || b.Installer == "." || b.Installer == "..":
		return fmt.Errorf("installer %q is not a file name", b.Installer)
	case !sha256Hex.MatchString(b.InstallerSHA256):
		return fmt.Errorf("installer_sha256 %q is not a SHA-256 in lower-case hex", b.InstallerSHA256)
	case b.Binary == "" || clean != b.Binary || path.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, "../") ||
		clean == ".." || strings.Contains(b.Binary, `\`):
		return fmt.Errorf("binary %q is not a clean relative path with forward slashes", b.Binary)
	case !sha256Hex.MatchString(b.BinarySHA256):
		return fmt.Errorf("binary_sha256 %q is not a SHA-256 in lower-case hex", b.BinarySHA256)
	}
	return nil
}

// Build is the reference build for a platform and machine.
func (m *Manifest) Build(platform, arch string) (*Build, error) {
	for i := range m.Builds {
		if m.Builds[i].Platform == platform && m.Builds[i].Arch == arch {
			return &m.Builds[i], nil
		}
	}
	return nil, fmt.Errorf("reference: no build for %s/%s; the reference is Google Chrome %s on %s",
		platform, arch, m.Version, m.platforms())
}

func (m *Manifest) platforms() string {
	var out []string
	for _, b := range m.Builds {
		out = append(out, b.Platform+"/"+b.Arch)
	}
	return strings.Join(out, ", ")
}

// ErrMismatch reports a file that is not what the manifest says it is.
var ErrMismatch = errors.New("reference: not the file the manifest names")

// VerifyFile checks that the file at name hashes to want.
func VerifyFile(name, want string) error {
	f, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("reference: %w", err)
	}
	defer func() { _ = f.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return fmt.Errorf("reference: reading %s: %w", name, err)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != want {
		return fmt.Errorf("%w: %s hashes to %s, and the manifest says %s", ErrMismatch, name, got, want)
	}
	return nil
}

// CheckIdentity holds what the browser says it is, its --version, to the
// reference: Google Chrome of exactly the version, and not Chrome for Testing,
// which shares its name and runs experiments real users do not have.
func (m *Manifest) CheckIdentity(said string) error {
	said = strings.TrimSpace(said)
	want := "Google Chrome " + m.Version
	switch {
	case said == want:
		return nil
	case strings.HasPrefix(said, "Google Chrome for Testing"):
		return fmt.Errorf("reference: %q is Chrome for Testing, which is not the reference, %s", said, want)
	case strings.HasPrefix(said, "Chromium"):
		return fmt.Errorf("reference: %q is Chromium, which is not the reference, %s", said, want)
	default:
		return fmt.Errorf("reference: the browser says %q, and the reference is %s", said, want)
	}
}

// Machine is the platform an executable is for, and the machines it runs on:
// one, or each of a universal Mach-O's.
func Machine(name string) (platform string, machines []string, err error) {
	if f, err := elf.Open(name); err == nil {
		defer func() { _ = f.Close() }()
		return "linux", []string{elfMachines[f.Machine]}, nil
	}
	if f, err := macho.Open(name); err == nil {
		defer func() { _ = f.Close() }()
		return "macos", []string{machoMachines[f.Cpu]}, nil
	}
	if f, err := macho.OpenFat(name); err == nil {
		defer func() { _ = f.Close() }()
		for _, arch := range f.Arches {
			machines = append(machines, machoMachines[arch.Cpu])
		}
		return "macos", machines, nil
	}
	if f, err := pe.Open(name); err == nil {
		defer func() { _ = f.Close() }()
		return "windows", []string{peMachines[f.Machine]}, nil
	}
	return "", nil, fmt.Errorf("reference: %s is no executable this reads: not ELF, Mach-O or PE", name)
}

var (
	elfMachines   = map[elf.Machine]string{elf.EM_X86_64: "amd64", elf.EM_AARCH64: "arm64"}
	machoMachines = map[macho.Cpu]string{macho.CpuAmd64: "amd64", macho.CpuArm64: "arm64"}
	peMachines    = map[uint16]string{pe.IMAGE_FILE_MACHINE_AMD64: "amd64", pe.IMAGE_FILE_MACHINE_ARM64: "arm64"}
)

// CheckMachine holds an executable's platform and machines to the build's.
func (b *Build) CheckMachine(name string) error {
	platform, machines, err := Machine(name)
	if err != nil {
		return err
	}
	if platform != b.Platform || !slices.Contains(machines, b.Arch) {
		return fmt.Errorf("reference: %s is for %s on %v, and the build is %s/%s", name, platform, machines,
			b.Platform, b.Arch)
	}
	return nil
}
