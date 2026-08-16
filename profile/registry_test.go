package profile

import (
	"strings"
	"testing"
)

func TestGetTheShippedProfile(t *testing.T) {
	// The measured Chrome that ships with the library. If this fails, the
	// embedded profile is missing or malformed, and every default client is
	// broken.
	p, err := Get("chrome_151")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(p.ClientHello) == 0 {
		t.Error("the shipped profile carries no captured ClientHello")
	}
	if !strings.Contains(p.UserAgent, "Chrome/") {
		t.Errorf("user agent = %q", p.UserAgent)
	}
	if len(p.Headers) == 0 {
		t.Error("the shipped profile carries no headers")
	}
}

func TestGetResolvesAFamilyNameToTheNewestMeasured(t *testing.T) {
	// "chrome" has to keep meaning the current Chrome after the next capture,
	// rather than pinning whichever one was current when the code was written.
	byFamily, err := Get("chrome")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.HasPrefix(byFamily.Name, "chrome_") {
		t.Errorf("Get(chrome) = %q, want a versioned profile", byFamily.Name)
	}
	if len(byFamily.ClientHello) == 0 {
		t.Error("Get(chrome) resolved to a catalogue entry rather than a measured profile")
	}
}

func TestGetFallsBackToTheCatalogue(t *testing.T) {
	p, err := Get("chrome_133")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Base != "chrome_133" {
		t.Errorf("Base = %q, want chrome_133", p.Base)
	}
	if len(p.ClientHello) != 0 {
		t.Error("a catalogue entry should not claim a captured hello")
	}
}

func TestGetErrors(t *testing.T) {
	if _, err := Get(""); err == nil {
		t.Error("an empty name should be reported")
	}
	_, err := Get("netscape_navigator_4")
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("error = %v, want an unknown-profile complaint", err)
	}
	// The message has to help: a bare "unknown" leaves the caller guessing.
	if !strings.Contains(err.Error(), "try one of") {
		t.Errorf("error = %q, want it to suggest alternatives", err)
	}
}

func TestRegisterTakesPrecedence(t *testing.T) {
	// A caller who captures their own browser and registers it under a name must
	// get theirs, not the one shipped here.
	registry := NewRegistry()
	mine := &Profile{Name: "chrome_151", UserAgent: "mine", Base: "chrome_133"}
	if err := registry.Register(mine); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := registry.Get("chrome_151")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserAgent != "mine" {
		t.Errorf("user agent = %q, want the registered profile's", got.UserAgent)
	}
}

func TestRegisterRejectsUnnamedProfiles(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(nil); err == nil {
		t.Error("registering nil should be reported")
	}
	if err := registry.Register(&Profile{}); err == nil {
		t.Error("registering a profile without a name should be reported")
	}
}

func TestNames(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(&Profile{Name: "my_browser", Base: "chrome_133"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	names := registry.Names()
	if len(names) < 2 {
		t.Fatalf("Names = %v, want the catalogue as well", names)
	}

	// Measured profiles come first: they are the ones worth reaching for.
	position := map[string]int{}
	for i, name := range names {
		position[name] = i
	}
	if position["my_browser"] > position["chrome_133"] {
		t.Errorf("registered profiles should be listed before catalogue entries: %v", names[:6])
	}
	if position["chrome_151"] == 0 && !registry.HasHandshake("chrome_151") {
		t.Error("the embedded profile should be listed and measured")
	}

	// No duplicates, even though a name can come from more than one source.
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Errorf("%q listed twice", name)
		}
		seen[name] = true
	}
}

func TestMeasured(t *testing.T) {
	if !Default.HasHandshake("chrome_151") {
		t.Error("the shipped Chrome profile should count as measured")
	}
	if Default.HasHandshake("chrome_133") {
		t.Error("a catalogue entry is not a measured profile")
	}
	if Default.HasHandshake("nothing_like_this") {
		t.Error("an unknown profile is not measured")
	}
}

func TestNewestInFamilyPrefersMeasuredOverNewer(t *testing.T) {
	// A catalogue entry for a later version still carries no headers, so
	// resolving the family name to it would trade a complete impersonation for a
	// handshake-only one — quietly, at the moment the catalogue moved ahead.
	registry := NewRegistry()
	if err := registry.Register(&Profile{
		Name: "acme_10", ClientHello: chromeHelloBytes(t),
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := registry.Register(&Profile{Name: "acme_99", Base: "chrome_133"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := registry.Get("acme")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "acme_10" {
		t.Errorf("Get(acme) = %q, want the measured acme_10", got.Name)
	}
}

func TestNewestInFamilyPicksTheHighestVersion(t *testing.T) {
	registry := NewRegistry()
	for _, name := range []string{"acme_9", "acme_120", "acme_37"} {
		if err := registry.Register(&Profile{Name: name, ClientHello: chromeHelloBytes(t)}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	// A suffix that is not a version is a distinct profile, not a candidate.
	if err := registry.Register(&Profile{Name: "acme_nightly", ClientHello: chromeHelloBytes(t)}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := registry.Get("acme")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "acme_120" {
		t.Errorf("Get(acme) = %q, want acme_120", got.Name)
	}
}

func TestNewestInFamilyFallsBackToTheCatalogue(t *testing.T) {
	// No measured Firefox ships with the library, so the family name has to
	// resolve to the catalogue rather than failing.
	got, err := Get("firefox")
	if err != nil {
		t.Fatalf("Get(firefox): %v", err)
	}
	if !strings.HasPrefix(got.Name, "firefox") {
		t.Errorf("Get(firefox) = %q", got.Name)
	}
}

func TestPackageLevelHelpersUseTheDefaultRegistry(t *testing.T) {
	if err := Register(&Profile{Name: "package_level_test", Base: "chrome_133"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := Get("package_level_test"); err != nil {
		t.Errorf("Get: %v", err)
	}
	if len(Names()) == 0 {
		t.Error("Names returned nothing")
	}
}

func TestFirstN(t *testing.T) {
	if got := firstN([]string{"a", "b"}, 5); len(got) != 2 {
		t.Errorf("firstN = %v, want the whole list", got)
	}
	got := firstN([]string{"a", "b", "c"}, 2)
	if len(got) != 3 || got[2] != "…" {
		t.Errorf("firstN = %v, want a truncation marker", got)
	}
}

func TestFirstNDoesNotClobberItsInput(t *testing.T) {
	// firstN appends to a slice of the caller's list; without a capacity limit
	// that append would overwrite the caller's third element.
	original := []string{"a", "b", "c", "d"}
	_ = firstN(original, 2)
	if original[2] != "c" {
		t.Errorf("firstN modified its input: %v", original)
	}
}
