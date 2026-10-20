package harness

import (
	"slices"
	"strings"
	"testing"
)

// fetched is a request as Chrome sends fetch() of JSON to another site.
func fetched() Request {
	return Request{Method: "POST", URL: "https://www.example.net/cors/x", Priority: []uint32{1, 0, 219}, Body: "{}",
		Headers: [][2]string{
			{":method", "POST"}, {"content-type", "application/json"}, {"sec-ch-ua", `"Google Chrome";v="155"`},
			{"sec-ch-ua-platform", `"macOS"`}, {"user-agent", "HeadlessChrome/155"}, {"sec-ch-ua-arch", `"arm"`},
			{"rtt", "100"}, {"origin", "https://www.example.com"},
		}}
}

// changed is r with change made to a copy of it.
func changed(r Request, change func(*Request)) Request {
	r.Headers = slices.Clone(r.Headers)
	r.Priority = slices.Clone(r.Priority)
	change(&r)
	return r
}

func setHeader(r *Request, name, value string) {
	for i, h := range r.Headers {
		if h[0] == name {
			r.Headers[i][1] = value
		}
	}
}

func one(r Request) map[string]MeasuredScenario {
	return map[string]MeasuredScenario{"x": {H2: []Request{r}, H1: []Request{r}}}
}

func TestTheSameIsNoDifference(t *testing.T) {
	if diff := Compare(one(fetched()), one(fetched()), nil); diff != nil {
		t.Errorf("Compare: %v", diff)
	}
	profile := map[string]string{"sec-ch-ua": `"Google Chrome";v="155"`, "sec-ch-ua-platform": `"macOS"`,
		"user-agent": "Mozilla", "sec-ch-ua-arch": `"x86"`, "rtt": "50"}
	if diff := Compare(one(fetched()), one(fetched()), profile); diff != nil {
		t.Errorf("Compare with a profile: %v", diff)
	}
}

func TestWhatChromeDrawsForEachRequestIsNoDifference(t *testing.T) {
	digest := func(nonce, cnonce, response string) Request {
		return Request{Method: "GET", URL: "https://www.example.com/auth/x", Headers: [][2]string{{"authorization",
			`Digest username="u", realm="bench", nonce="` + nonce + `", uri="/auth/x", response="` + response +
				`", qop=auth, nc=00000001, cnonce="` + cnonce + `"`}, {"x-other", `response="` + response + `"`}}}
	}
	measured := digest("b3ec7d4c", "e00b1861ac9940bc", "f2b8b49dfa7b77a4c73ca8c344b9f86c")
	again := digest("b3ec7d4c", "4ea7e78b5ca12345", "a9fb8d19d2f7e12ce6f3aff2d7439188")
	again.Headers[1] = measured.Headers[1]
	if diff := Compare(one(measured), one(again), nil); diff != nil {
		t.Errorf("Compare of another client nonce: %v", diff)
	}
	// The server's nonce is the server's, and a response elsewhere than in a
	// Digest answer is a value like any other.
	for _, other := range []Request{digest("other", "e00b1861ac9940bc", "f2b8b49dfa7b77a4c73ca8c344b9f86c"),
		changed(measured, func(r *Request) { r.Headers[1][1] = `response="1"` })} {
		if diff := Compare(one(measured), one(other), nil); len(diff) != 2 {
			t.Errorf("Compare: %v", diff)
		}
	}
	bearer := changed(measured, func(r *Request) { r.Headers[0][1] = `Bearer response="1"` })
	if diff := Compare(one(bearer), one(changed(bearer, func(r *Request) { r.Headers[0][1] = `Bearer response="2"` })), nil); len(diff) != 2 {
		t.Errorf("Compare of another scheme: %v", diff)
	}
}

func TestWhatDiffersIsSaidByScenarioProtocolAndRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Request)
		says   string
	}{
		{"the method", func(r *Request) { r.Method = "PUT" }, "x over h2, request 1: PUT https://www.example.net/cors/x, the fixture POST"},
		{"the URL", func(r *Request) { r.URL += "?y" }, "/cors/x?y, the fixture POST https://www.example.net/cors/x"},
		{"the body", func(r *Request) { r.Body = "[]" }, `body "[]", the fixture's "{}"`},
		{"the connection", func(r *Request) { r.Conn = 2 }, "connection 2, the fixture's connection 0"},
		{"a resumed one", func(r *Request) { r.Resumed = true }, "connection 0, resumed, the fixture's connection 0"},
		{"exclusive", func(r *Request) { r.Priority[0] = 0 }, "priority [0 0 219], the fixture's [1 0 219]"},
		{"the weight", func(r *Request) { r.Priority[2] = 255 }, "priority [1 0 255]"},
		{"no priority", func(r *Request) { r.Priority = nil }, "priority [], the fixture's [1 0 219]"},
		{"the order of the headers", func(r *Request) { r.Headers[1], r.Headers[2] = r.Headers[2], r.Headers[1] },
			"headers\n    browser [:method sec-ch-ua content-type"},
		{"a header's spelling", func(r *Request) { r.Headers[7][0] = "Origin" }, "headers"},
		{"a value", func(r *Request) { setHeader(r, "origin", "null") }, `origin: "null", the fixture's "https://www.example.com"`},
		{"a value the build decides, with no profile", func(r *Request) { setHeader(r, "sec-ch-ua-platform", `"Linux"`) },
			`sec-ch-ua-platform: "\"Linux\"", the fixture's "\"macOS\""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diff := Compare(one(fetched()), one(changed(fetched(), tc.change)), nil)
			if len(diff) != 2 || !strings.Contains(diff[0], tc.says) || !strings.HasPrefix(diff[1], "x over h1, request 1: ") {
				t.Errorf("Compare: %q, want %q", diff, tc.says)
			}
		})
	}
	// The order of the headers differing, their values are not gone into.
	diff := Compare(one(fetched()), one(changed(fetched(), func(r *Request) {
		r.Headers = r.Headers[1:]
		r.Method = "GET"
	})), nil)
	if len(diff) != 4 || !strings.Contains(diff[1], "headers") {
		t.Errorf("Compare: %q", diff)
	}
	// A priority where the fixture has none is a difference too.
	diff = Compare(one(changed(fetched(), func(r *Request) { r.Priority = nil })), one(fetched()), nil)
	if len(diff) != 2 || !strings.Contains(diff[0], "priority [1 0 219], the fixture's []") {
		t.Errorf("Compare: %q", diff)
	}
}

func TestWhatTheMachineDecidesIsComparedByPresence(t *testing.T) {
	got := changed(fetched(), func(r *Request) {
		setHeader(r, "user-agent", "Mozilla/5.0 (X11; Linux x86_64)")
		setHeader(r, "sec-ch-ua-arch", `"x86"`)
		setHeader(r, "rtt", "250")
	})
	if diff := Compare(one(fetched()), one(got), nil); diff != nil {
		t.Errorf("Compare: %v", diff)
	}
}

func TestWhatTheBuildDecidesIsHeldToTheProfile(t *testing.T) {
	profile := map[string]string{"sec-ch-ua": `"Google Chrome";v="155"`, "sec-ch-ua-platform": `"Linux"`,
		"user-agent": "Mozilla", "sec-ch-ua-arch": `"arm"`, "rtt": "50"}
	// Chrome on another platform than the fixture's: held to the profile, not
	// to the fixture.
	linux := changed(fetched(), func(r *Request) { setHeader(r, "sec-ch-ua-platform", `"Linux"`) })
	if diff := Compare(one(fetched()), one(linux), profile); diff != nil {
		t.Errorf("Compare: %v", diff)
	}
	// What the profile says otherwise is a difference.
	diff := Compare(one(fetched()), one(fetched()), profile)
	if len(diff) != 2 || !strings.Contains(diff[0], `sec-ch-ua-platform: "\"macOS\"", the profile's "\"Linux\""`) {
		t.Errorf("Compare: %q", diff)
	}
	// And what it says nothing of, a client hint above all, is one it would
	// not send.
	for _, name := range []string{"rtt", "sec-ch-ua", "user-agent"} {
		without := map[string]string{}
		for k, v := range profile {
			if k != name {
				without[k] = v
			}
		}
		diff := Compare(one(fetched()), one(linux), without)
		if len(diff) != 2 || !strings.Contains(diff[0], name+": the profile has none, and the browser sends") {
			t.Errorf("without %s: %q", name, diff)
		}
	}
}

func TestAFormsBoundaryIsDrawnAnewAndNoDifference(t *testing.T) {
	form := func(boundary string) Request {
		return Request{Method: "POST", URL: "https://www.example.com/p/form", Body: "--" + boundary + "\r\na\r\n--" + boundary + "--",
			Headers: [][2]string{{"content-type", "multipart/form-data; boundary=" + boundary}}}
	}
	if diff := Compare(one(form("----WebKitFormBoundaryC1qAB56j0LZxNoh0")), one(form("----WebKitFormBoundaryZZZZ9999aaaa0000")), nil); diff != nil {
		t.Errorf("Compare: %v", diff)
	}
	// What is no such boundary is compared as it is.
	diff := Compare(one(form("----WebKitFormBoundaryC1qAB56j0LZxNoh0")), one(form("----WebKitFormBoundaryC1qA")), nil)
	if len(diff) != 4 {
		t.Errorf("Compare: %q", diff)
	}
}

func TestAScenarioMeasuredOrNotIsSaid(t *testing.T) {
	want := map[string]MeasuredScenario{"a": {H2: []Request{fetched()}, H1: []Request{fetched()}}, "b": {}}
	got := map[string]MeasuredScenario{"a": {H2: []Request{fetched(), fetched()}, H1: []Request{fetched()}}, "c": {}}
	diff := Compare(want, got, nil)
	if len(diff) != 3 ||
		!strings.HasPrefix(diff[0], "a over h2: 2 requests, the fixture 1\n  browser [POST https://www.example.net/cors/x POST") ||
		diff[1] != "b was not measured" || diff[2] != "c was measured, and the fixture has no such scenario" {
		t.Errorf("Compare: %q", diff)
	}
}

func TestAScenarioTheBrowserDidNotFinishIsADifference(t *testing.T) {
	// Said for each protocol it stopped short over, beside how what it asked
	// differs.
	unfinished := one(fetched())
	scenario := unfinished["x"]
	scenario.Unfinished = []string{"over h2: /p/end was not asked for within 15s"}
	scenario.H2 = nil
	unfinished["x"] = scenario
	diff := Compare(one(fetched()), unfinished, nil)
	if len(diff) != 2 || diff[0] != "x did not finish over h2: /p/end was not asked for within 15s" ||
		!strings.HasPrefix(diff[1], "x over h2: 0 requests, the fixture 1") {
		t.Errorf("%q", diff)
	}
}
