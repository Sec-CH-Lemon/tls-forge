package harness

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// byMachine are the values the machine decides, or its settings, its window or
// its network, not the browser: compared by presence alone. Every one but the
// user agent is a client hint.
var byMachine = []string{
	"user-agent", "rtt", "downlink", "ect", "device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr",
	"viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height", "sec-ch-prefers-color-scheme",
	"sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency", "sec-ch-ua-platform-version",
	"sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model", "sec-ch-ua-wow64",
}

// byBuild are the values the browser's build and its platform decide, which a
// profile says: held to the profile's when there is one.
var byBuild = []string{
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
	"sec-ch-ua-form-factors",
}

// OwnValues are the values the browser sent of each header its machine or its
// build decides, the first of each in the order of the scenarios' names: what
// a newer build is held to (Compare's profile), so that its version, which
// sec-ch-ua and the like say, is no difference from a fixture an older build
// wrote; that its own requests agree with each other still is.
func OwnValues(got map[string]MeasuredScenario) map[string]string {
	out := map[string]string{}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		for _, r := range append(slices.Clone(got[id].H2), got[id].H1...) {
			for _, h := range r.Headers {
				name := strings.ToLower(h[0])
				if _, seen := out[name]; !seen && (slices.Contains(byMachine, name) || slices.Contains(byBuild, name)) {
					out[name] = h[1]
				}
			}
		}
	}
	return out
}

// boundary is Chrome's multipart boundary, drawn anew for every form.
var boundary = regexp.MustCompile(`----WebKitFormBoundary[0-9A-Za-z]{16}`)

func withoutBoundary(text string) string {
	return boundary.ReplaceAllString(text, "----WebKitFormBoundary0000000000000000")
}

// digestDrawn are the parameters of a Digest answer Chrome draws for each:
// its client nonce, and the response worked out with it.
var digestDrawn = regexp.MustCompile(`\b(cnonce|response)="[^"]*"`)

// comparable is a header's value as it is compared: without what Chrome draws
// anew for each request, a multipart boundary, and the client nonce and
// response of a Digest answer.
func comparable(name, value string) string {
	value = withoutBoundary(value)
	if name == "authorization" && strings.HasPrefix(value, "Digest ") {
		value = digestDrawn.ReplaceAllString(value, `$1=""`)
	}
	return value
}

// Compare is how what a browser asked for, got, differs from what the fixture
// holds, want: nothing when they are the same. A scenario is the same when
// every request is, in the same order, over each protocol: its method, URL and
// body, the connection it came on and whether that one resumed a TLS session,
// its HTTP/2 priority (exclusive and weight: the stream it depends on is the
// connection's business), the names of its headers in order, spelt alike, and
// their values, but for what Chrome draws for each (comparable). A value
// the machine decides is compared by presence alone;
// one the build decides is held to profile, the values the profile sends by
// name, when there is one, and to the fixture's when there is not. With a
// profile, every value the browser sends that a profile gives has to be one it
// has.
func Compare(want, got map[string]MeasuredScenario, profile map[string]string) []string {
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(want)) {
		measured, ok := got[id]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s was not measured", id))
			continue
		}
		for _, why := range measured.Unfinished {
			diff = append(diff, fmt.Sprintf("%s did not finish %s", id, why))
		}
		for _, proto := range []string{"h2", "h1"} {
			w, g := want[id].H2, measured.H2
			if proto == "h1" {
				w, g = want[id].H1, measured.H1
			}
			diff = append(diff, compareScenario(id+" over "+proto, w, g, profile)...)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[id]; !ok {
			diff = append(diff, fmt.Sprintf("%s was measured, and the fixture has no such scenario", id))
		}
	}
	return diff
}

func compareScenario(where string, want, got []Request, profile map[string]string) []string {
	if len(got) != len(want) {
		urls := func(requests []Request) []string {
			var out []string
			for _, r := range requests {
				out = append(out, r.Method+" "+r.URL)
			}
			return out
		}
		return []string{fmt.Sprintf("%s: %d requests, the fixture %d\n  browser %v\n  fixture %v", where, len(got),
			len(want), urls(got), urls(want))}
	}
	var diff []string
	for i := range want {
		for _, d := range compareRequest(want[i], got[i], profile) {
			diff = append(diff, fmt.Sprintf("%s, request %d: %s", where, i+1, d))
		}
	}
	return diff
}

// connection says which connection a request came on, and whether that one
// resumed a TLS session.
func connection(r Request) string {
	said := "connection " + strconv.Itoa(r.Conn)
	if r.Resumed {
		said += ", resumed"
	}
	return said
}

func compareRequest(want, got Request, profile map[string]string) []string {
	var diff []string
	if got.Method != want.Method || got.URL != want.URL {
		diff = append(diff, fmt.Sprintf("%s %s, the fixture %s %s", got.Method, got.URL, want.Method, want.URL))
	}
	if withoutBoundary(got.Body) != withoutBoundary(want.Body) {
		diff = append(diff, fmt.Sprintf("body %q, the fixture's %q", got.Body, want.Body))
	}
	if got.Conn != want.Conn || got.Resumed != want.Resumed {
		diff = append(diff, fmt.Sprintf("%s, the fixture's %s", connection(got), connection(want)))
	}
	if (len(got.Priority) == 3) != (len(want.Priority) == 3) ||
		len(want.Priority) == 3 && (got.Priority[0] != want.Priority[0] || got.Priority[2] != want.Priority[2]) {
		diff = append(diff, fmt.Sprintf("priority %v, the fixture's %v", got.Priority, want.Priority))
	}
	names := func(headers [][2]string) []string {
		var out []string
		for _, h := range headers {
			out = append(out, h[0])
		}
		return out
	}
	if !slices.Equal(names(got.Headers), names(want.Headers)) {
		return append(diff, fmt.Sprintf("headers\n    browser %v\n    fixture %v", names(got.Headers), names(want.Headers)))
	}
	for i, h := range want.Headers {
		name, value := strings.ToLower(h[0]), got.Headers[i][1]
		said, says := profile[name]
		switch {
		case profile != nil && (slices.Contains(byMachine, name) || slices.Contains(byBuild, name)) && !says:
			diff = append(diff, fmt.Sprintf("%s: the profile has none, and the browser sends %q", h[0], value))
		case slices.Contains(byMachine, name):
		case slices.Contains(byBuild, name) && profile != nil:
			if value != said {
				diff = append(diff, fmt.Sprintf("%s: %q, the profile's %q", h[0], value, said))
			}
		case comparable(name, value) != comparable(name, h[1]):
			diff = append(diff, fmt.Sprintf("%s: %q, the fixture's %q", h[0], value, h[1]))
		}
	}
	return diff
}
