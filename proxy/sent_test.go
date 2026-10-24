package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
)

// subresources is testdata/chrome155-subresources.json: every request Chrome
// 155 made of a page with an image, a script, a style sheet, a font and a
// frame, fetch()es, an XHR and a form's POST, sent to the site over HTTP/2 and
// over HTTP/1.1, which a browser speaks to a proxy too.
type subresources struct {
	H2 []sentRequest `json:"h2"`
	H1 []sentRequest `json:"h1"`
}

type sentRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Headers  [][2]string `json:"headers"`
	Body     string      `json:"body"`
	Priority *struct {
		DependsOn uint32 `json:"depends_on"`
		Exclusive bool   `json:"exclusive"`
		Weight    uint8  `json:"weight"`
	} `json:"priority"`
}

func TestABrowsersRequestsReachTheSiteAsChromeSentThemThere(t *testing.T) {
	// What a browser sends the proxy over HTTP/1.1, which says what it is in
	// Sec-Fetch-*, reaches the site as Chrome sent the site that request
	// itself: over HTTP/2 every field in its place with its value, the
	// profile's own the browser's own here too, and its HEADERS frame's
	// priority; over HTTP/1.1 as the browser sent it, spelling and all.
	raw, err := os.ReadFile("../testdata/chrome155-subresources.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var chrome subresources
	if err := json.Unmarshal(raw, &chrome); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	destination, err := echo.Start()
	if err != nil {
		t.Fatalf("echo.Start: %v", err)
	}
	defer destination.Close()
	client, err := tlsforge.New(tlsforge.WithProfile("chrome_155_macos"), tlsforge.WithInsecureSkipVerify(),
		tlsforge.WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ca := newCAForTest(t)
	server, problems := startProxy(t, client, ca)
	browser := throughProxy(t, server, ca)
	for _, site := range []struct {
		proto, url string
		want       []sentRequest
	}{{"h2", destination.URL(), chrome.H2}, {"h1", destination.CaptureURL(), chrome.H1}} {
		for i, sent := range chrome.H1 {
			t.Run(site.proto+sent.URL, func(t *testing.T) {
				// The page's origin is the site's, as Chrome's was.
				placed := strings.NewReplacer("{A}", site.url)
				var body io.Reader
				if sent.Body != "" {
					body = strings.NewReader(sent.Body)
				}
				req, err := http.NewRequest(sent.Method, site.url+"/api/all", body)
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range sent.Headers {
					switch strings.ToLower(f[0]) {
					case "host", "connection", "content-length":
					default:
						req.Header.Add(f[0], placed.Replace(f[1]))
					}
				}
				// A connection of its own, whose first request the site says.
				client.CloseIdleConnections()
				res, err := browser.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				said, _ := io.ReadAll(res.Body)
				var measured capture.Capture
				if err := json.Unmarshal(said, &measured); err != nil {
					t.Fatalf("%d: %s", res.StatusCode, said)
				}
				want := site.want[i]
				unplaced := strings.NewReplacer(site.url, "{A}")
				var got [][2]string
				switch site.proto {
				case "h2":
					for _, f := range measured.HTTP2.Headers {
						if !strings.HasPrefix(f.Name, ":") {
							got = append(got, [2]string{f.Name, unplaced.Replace(f.Value)})
						}
					}
					p := measured.HTTP2.HeaderPriority
					if want.Priority == nil || p == nil || p.Exclusive != want.Priority.Exclusive ||
						p.Weight != want.Priority.Weight || p.DependsOn != want.Priority.DependsOn {
						t.Errorf("priority %+v, Chrome's %+v", p, want.Priority)
					}
				default:
					for j, f := range measured.HTTP1.Headers {
						got = append(got, [2]string{measured.HTTP1.HeaderNames[j], unplaced.Replace(f.Value)})
					}
				}
				var wanted [][2]string
				for _, f := range want.Headers {
					if !strings.EqualFold(f[0], "host") {
						wanted = append(wanted, f)
					}
				}
				got = slices.DeleteFunc(got, func(f [2]string) bool { return strings.EqualFold(f[0], "host") })
				if !slices.Equal(got, wanted) {
					t.Errorf("the site got\n%v\nChrome sent it\n%v", got, wanted)
				}
			})
		}
	}
	if reported := problems.list(); len(reported) != 0 {
		t.Errorf("proxy reported: %v", reported)
	}
}

func TestTheContextARequestSaysItWasSentIn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		header map[string]string
		want   *tlsforge.BrowserContext
	}{
		{"nothing of a browser", "GET", map[string]string{"Referer": "https://a.example/p"}, nil},
		{"a mode a proxy does not take", "GET", map[string]string{"Sec-Fetch-Mode": "websocket"}, nil},
		{"typed", "GET", map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "None"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindNavigation, Sent: true}},
		{"typed, from no page whatever the Referer says", "GET", map[string]string{"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Site": " none", "Referer": "https://a.example/p"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindNavigation, Sent: true}},
		{"a link", "GET", map[string]string{"Sec-Fetch-Mode": " Navigate ", "Sec-Fetch-Site": "same-origin",
			"Referer": "https://a.example/p"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindNavigation, Initiator: "https://a.example/p", Sent: true}},
		{"a form", "POST", map[string]string{"Sec-Fetch-Mode": "navigate", "Origin": "https://a.example"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindForm, Initiator: "https://a.example/", Sent: true}},
		{"fetch()", "POST", map[string]string{"Sec-Fetch-Mode": "cors", "Referer": "https://a.example/p",
			"Origin": "https://a.example"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Mode: "cors", Initiator: "https://a.example/p", Sent: true}},
		{"an image", "GET", map[string]string{"Sec-Fetch-Mode": "no-cors", "Origin": "null"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Mode: "no-cors", Sent: true}},
		{"with a cookie", "GET", map[string]string{"Sec-Fetch-Mode": "same-origin", "Cookie": "a=1"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Mode: "same-origin", Credentials: "include", Sent: true}},
		{"with an Authorization", "GET", map[string]string{"Sec-Fetch-Mode": "cors", "Authorization": "Bearer t"},
			&tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Mode: "cors", Credentials: "include", Sent: true}},
	} {
		req, _ := http.NewRequest(tc.method, "https://b.example/x", nil)
		for name, value := range tc.header {
			req.Header.Set(name, value)
		}
		got := sentContext(req)
		if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// refusing is a Client that cannot take what a browser sent: every request
// goes as one without a context.
type refusing struct {
	answering
}

func (*refusing) Validate(*tlsforge.Request) error { return errRequestTooLarge }

func TestARequestAClientCannotTakeAsABrowsersGoesWithoutAContext(t *testing.T) {
	for _, client := range []interface {
		Client
		requests() []*tlsforge.Request
	}{&answering{}, &refusing{}} {
		server, _ := startProxy(t, client, newCAForTest(t))
		r, _ := through(t, server, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n"+
			"Sec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nX-Keep: 1\r\n\r\n")
		if status, _ := headLines(t, r); status != "HTTP/1.1 200 OK" {
			t.Fatalf("answered %q", status)
		}
		asked := client.requests()
		if len(asked) != 1 || asked[0].Browser != nil || asked[0].Body != nil ||
			!bytes.Equal([]byte(asked[0].Header.Get("x-keep")), []byte("1")) {
			t.Errorf("%T sent %+v", client, asked)
		}
	}
}
