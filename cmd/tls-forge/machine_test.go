package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

func TestSetTakesWhatAHeaderCarries(t *testing.T) {
	for _, tc := range []struct {
		given []string
		want  []setting
		says  string
	}{
		{[]string{"accept-language=de-DE,de;q=0.9", ` Sec-CH-UA-Platform-Version ="15.0.0"`, "sec-ch-ua-wow64=?1",
			`sec-ch-ua-form-factors="Desktop", "XR"`, `sec-ch-ua-model="a\"b\\c"`},
			[]setting{{"accept-language", "de-DE,de;q=0.9"}, {"sec-ch-ua-platform-version", `"15.0.0"`},
				{"sec-ch-ua-wow64", "?1"}, {"sec-ch-ua-form-factors", `"Desktop", "XR"`}, {"sec-ch-ua-model", `"a\"b\\c"`}}, ""},
		{nil, nil, ""},
		{[]string{"accept-language"}, nil, "NAME=VALUE"},
		{[]string{"user-agent=x"}, nil, "NAME one of accept-language"},
		{[]string{"accept-language=a", "accept-language=b"}, nil, "each name once"},
		{[]string{"accept-language="}, nil, "a header value"},
		{[]string{"accept-language=a\nb"}, nil, "a header value"},
		{[]string{"sec-ch-ua-wow64=?2"}, nil, "?0 or ?1"},
		{[]string{"sec-ch-ua-platform-version=15.0.0"}, nil, "a string, quoted"},
		{[]string{`sec-ch-ua-arch="a"b"`}, nil, "a string, quoted"},
		{[]string{`sec-ch-ua-arch="a\"`}, nil, "a string, quoted"},
		{[]string{`sec-ch-ua-arch="a\n"`}, nil, "a string, quoted"},
		{[]string{"sec-ch-ua-arch=\"\x01\""}, nil, "a string, quoted"},
		{[]string{`sec-ch-ua-arch="é"`}, nil, "a string, quoted"},
		{[]string{`sec-ch-ua-arch="`}, nil, "a string, quoted"},
		{[]string{`sec-ch-ua-form-factors="Desktop", Mobile`}, nil, "strings, quoted"},
	} {
		got, err := settingsOf(tc.given)
		switch {
		case tc.says == "" && (err != nil || !reflect.DeepEqual(got, tc.want)):
			t.Errorf("%q: %+v, %v", tc.given, got, err)
		case tc.says != "" && (err == nil || !strings.Contains(err.Error(), tc.says)):
			t.Errorf("%q: %v, want it to say %q", tc.given, err, tc.says)
		}
	}
}

func TestSetChangesWhatAProfileKeepsOfTheMachine(t *testing.T) {
	p := &profile.Profile{EngineMajor: profile.Major(2),
		Headers:     []profile.Field{{Name: "user-agent", Value: "u"}, {Name: "accept-language", Value: "ru-RU"}},
		HTTP1:       &profile.HTTP1{Headers: []profile.Field{{Name: "Accept-Language", Value: "ru-RU"}}},
		ClientHints: []profile.Field{{Name: "sec-ch-ua-arch", Value: `"arm"`}, {Name: "sec-ch-ua-wow64", Value: "?0"}},
	}
	if err := applySettings(p, []setting{{"accept-language", "de-DE"}, {"sec-ch-ua-arch", `"x86"`}}); err != nil {
		t.Fatal(err)
	}
	if p.Headers[1].Value != "de-DE" || p.HTTP1.Headers[0].Value != "de-DE" || p.ClientHints[0].Value != `"x86"` {
		t.Errorf("%+v %+v %+v", p.Headers, p.HTTP1.Headers, p.ClientHints)
	}
	if got := machineValues(p); !reflect.DeepEqual(got, [][2]string{{"accept-language", "de-DE"},
		{"sec-ch-ua-arch", `"x86"`}, {"sec-ch-ua-wow64", "?0"}}) {
		t.Errorf("machineValues = %q", got)
	}
	// One the browser does not send is not given; nor one without HTTP/1.1.
	if err := applySettings(p, []setting{{"sec-ch-ua-model", `""`}}); err == nil ||
		!strings.Contains(err.Error(), "the browser measured sends no sec-ch-ua-model") {
		t.Errorf("a hint it has not: %v", err)
	}
	if err := applySettings(&profile.Profile{EngineMajor: profile.Major(2)}, []setting{{"accept-language", "de"}}); err == nil {
		t.Error("an accept-language it has not")
	}
	if err := applySettings(&profile.Profile{EngineMajor: profile.Major(2), Headers: []profile.Field{{Name: "accept-language", Value: "x"}}},
		[]setting{{"accept-language", "de"}}); err != nil {
		t.Errorf("without HTTP/1.1: %v", err)
	}
}

func TestCaptureSetsWhatItKeepsOfTheMachine(t *testing.T) {
	// --set is for the profile kept, and is read before anything listens.
	for _, args := range [][]string{
		{"--manual", "--set", "accept-language=de"},
		{"--manual", "--save", t.TempDir(), "--set", "user-agent=x"},
	} {
		code, _, stderr := exec(t, append([]string{"capture"}, args...)...)
		if code != 2 || strings.Contains(stderr, "waiting for a browser") {
			t.Errorf("%q: exit code = %d\n%s", args, code, stderr)
		}
	}
	// --install keeps one too, and waits for its browser.
	keepProfilesIn(t)
	if code, _, stderr := exec(t, "capture", "--manual", "--install", "--set", "accept-language=de", "--timeout", "50ms"); code != 1 ||
		!strings.Contains(stderr, "no browser came") {
		t.Errorf("with --install: exit code = %d\n%s", code, stderr)
	}
	// A Chromium browser's hints, as it sends them when its page asks, are
	// kept as set, and what is kept of the machine is said.
	navigator := `{"full_version_list": [{"brand": "Google Chrome", "version": "155.0.8059.85"}],
		"ua_full_version": "155.0.8059.85", "architecture": "arm", "bitness": "64",
		"platform_version": "27.0.1", "form_factors": ["Desktop"]}`
	visited := aPersonVisitsAs(t, "chrome", aPerson{navigator: navigator, hints: []string{
		"sec-ch-ua-full-version", `"155.0.8059.85"`, "sec-ch-ua-arch", `"arm"`, "sec-ch-ua-platform-version", `"27.0.1"`,
		"sec-ch-ua-bitness", `"64"`, "sec-ch-ua-full-version-list", `"Google Chrome";v="155.0.8059.85"`,
		"sec-ch-ua-form-factors", `"Desktop"`,
	}})
	dir := t.TempDir()
	code, stdout, stderr := exec(t, "capture", "--manual", "--save", dir, "--timeout", "30s",
		"--set", "accept-language=de-DE,de;q=0.9", "--set", `sec-ch-ua-platform-version="15.7.4"`)
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if code != 0 || !strings.Contains(stdout, "kept of the machine it was captured on") ||
		!strings.Contains(stdout, `  sec-ch-ua-platform-version   "15.7.4"`) ||
		!strings.Contains(stdout, "  accept-language              de-DE,de;q=0.9") ||
		!strings.Contains(stdout, `  sec-ch-ua-arch               "arm"`) {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	version, platform := theVisitorsPlatform(t)
	data, err := os.ReadFile(filepath.Join(dir, version, platform+".json"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := profile.Load(data)
	if err != nil || machineValues(saved)[0][1] != "de-DE,de;q=0.9" {
		t.Errorf("saved %+v, %v", saved, err)
	}
	// A hint the browser gave none of is no value to set: nothing is kept.
	visited = aPersonVisits(t, "chrome")
	other := t.TempDir()
	code, _, stderr = exec(t, "capture", "--manual", "--save", other, "--timeout", "30s",
		"--set", `sec-ch-ua-arch="x86"`)
	if err := <-visited; err != nil {
		t.Fatalf("visiting: %v", err)
	}
	if entries, _ := os.ReadDir(other); code != 1 || !strings.Contains(stderr, "sends no sec-ch-ua-arch") || len(entries) != 0 {
		t.Errorf("exit code = %d, kept %v\n%s", code, entries, stderr)
	}
}
