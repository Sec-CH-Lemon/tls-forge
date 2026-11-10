package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v2"
	"github.com/Sec-CH-Lemon/tls-forge/v2/capture"
)

// What a terminal would obey (an escape sequence setting a window's title,
// clearing the screen, a carriage return writing over a line), in words a
// proxy, a server or a visiting browser said, reaches the terminal as text:
// in an error, a request's line, a capture's fields and a comparison's.
const obeyed = "\x1b]0;owned\x07\x1b[2J\rover"

const shown = `\x1b]0;owned\a\x1b[2J\rover`

func saysNothingObeyed(t *testing.T, where, said string) {
	t.Helper()
	if strings.ContainsAny(said, "\x1b\x07\r") || !strings.Contains(said, shown) {
		t.Errorf("%s: %q", where, said)
	}
}

func TestWhatATerminalWouldObeyIsShownAsText(t *testing.T) {
	saysNothingObeyed(t, "an error", prefixed(errors.New("fetch: proxy responded with non 200 code: 403 "+obeyed)))
	saysNothingObeyed(t, "a request's line", verboseLine(result{URL: "https://a.test/", Error: "403 " + obeyed}))

	var out bytes.Buffer
	printCapture(newPrinter(&out), &capture.Capture{Navigator: &capture.Navigator{UserAgent: "Mozilla/5.0 " + obeyed,
		Platform: "macOS" + obeyed, Languages: []string{"en" + obeyed}}})
	for _, label := range []string{"user-agent", "platform", "languages"} {
		for line := range strings.Lines(out.String()) {
			if strings.Contains(line, label) {
				saysNothingObeyed(t, "the capture's "+label, line)
			}
		}
	}

	out.Reset()
	(&diffPrinter{out: newPrinter(&out), labelAt: 10}).line("", "-", "user-agent", "Mozilla/5.0 "+obeyed, false)
	saysNothingObeyed(t, "a comparison's line", out.String())

	hello, err := os.ReadFile("../../testdata/chrome155-clienthello.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	ua := "Mozilla/5.0 " + obeyed
	browser := &capture.Capture{RawClientHello: hello, Navigator: &capture.Navigator{UserAgent: ua,
		Platform: "macOS" + obeyed, FullVersionList: []capture.Brand{{Brand: "Google Chrome", Version: "155"}}}}
	result, err := tlsforge.Compare(browser, &capture.Capture{RawClientHello: hello, Profile: "chrome"})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	out.Reset()
	printComparison(newPrinter(&out), result, palette{}, false)
	lines := strings.Split(out.String(), "\n")
	saysNothingObeyed(t, "the browser compared", lines[0])
	saysNothingObeyed(t, "what it is", lines[1])
}
