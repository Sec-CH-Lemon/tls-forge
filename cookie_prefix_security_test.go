package tlsforge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	tc "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/utls/behavior"
)

func TestCookiePrefixesMatchChrome156Witness(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Protocol string `json:"protocol"`
			Set      string `json:"set_cookie"`
			Cookie   string `json:"cookie"`
		} `json:"cookie_cases"`
	}
	data, err := os.ReadFile("testdata/chrome156-response-security.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 48 {
		t.Fatal("incomplete cookie witness")
	}
	for i, row := range fixture.Cases {
		t.Run(fmt.Sprintf("%s/%d", row.Protocol, i), func(t *testing.T) {
			protocol, scheme := row.Protocol, "https"
			if protocol == "http" {
				scheme = "http"
			}
			server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "no-store")
				if r.URL.Path == "/set" {
					w.Header().Set("Set-Cookie", row.Set)
					return
				}
				_, _ = w.Write([]byte(r.Header.Get("Cookie")))
			})
			client := newTestClient(t, server.dialing())
			for _, path := range []string{"/set", "/x/echo"} {
				response, err := client.Do(&Request{URL: scheme + "://probe.test" + path, Browser: &BrowserContext{Kind: KindFetch, Initiator: scheme + "://probe.test/"}})
				if err != nil {
					t.Fatal(err)
				}
				if path == "/x/echo" && string(response.Body) != row.Cookie {
					t.Fatalf("Set-Cookie %q: got %q, Chrome %q", row.Set, response.Body, row.Cookie)
				}
			}
		})
	}
}

func TestJSONOwnsCookiePrefixRules(t *testing.T) {
	guard := func(sensitive, nameless bool, attrs ...string) []behavior.CookiePrefix {
		if attrs == nil {
			attrs = []string{}
		}
		return []behavior.CookiePrefix{{Prefix: "__Guard-", CaseSensitive: sensitive, RejectNameless: nameless, Attributes: attrs}}
	}
	tests := []struct {
		rules     []behavior.CookiePrefix
		set, want string
	}{
		{guard(false, true, "secure", "http-only", "host-only", "root-path"), "__Guard-id=1; Secure; HttpOnly; Path=/", "__Guard-id=1"},
		{guard(false, true, "secure"), "__Guard-id=1; Path=/", ""},
		{guard(false, true, "http-only"), "__Guard-id=1; Path=/", ""},
		{guard(false, true, "host-only"), "__Guard-id=1; Domain=probe.test; Path=/", ""},
		{guard(false, true, "root-path"), "__Guard-id=1; Path=/x", ""},
		{guard(false, true), "__Guard-id=1; Path=/x", "__Guard-id=1"},
		{guard(false, true), "=__Guard-hidden=1; Secure; Path=/", ""},
		{guard(false, false), "=__Guard-hidden=1; Secure; Path=/", "__Guard-hidden=1"},
		{guard(false, true, "secure"), "__gUaRd-id=1; Path=/", ""},
		{guard(true, true, "secure"), "__gUaRd-id=1; Path=/", "__gUaRd-id=1"},
		{[]behavior.CookiePrefix{}, "__Host-id=1; Path=/x", "__Host-id=1"},
	}
	for _, protocol := range []string{"h1", "h2"} {
		server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
			i, err := strconv.Atoi(r.URL.Query().Get("case"))
			if err != nil || i < 0 || i >= len(tests) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			if r.URL.Path == "/set" {
				w.Header().Set("Set-Cookie", tests[i].set)
				return
			}
			_, _ = w.Write([]byte(r.Header.Get("Cookie")))
		})
		var wg sync.WaitGroup
		for i, row := range tests {
			p := policyFile(t, map[string]any{"cookie.prefixes": row.rules})
			p.Name, p.UserAgent = "renamed_non_chrome_999", "Metadata does not select cookie rules"
			client := newTestClient(t, WithProfileValue(p), server.dialing())
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, path := range []string{"/set", "/x/echo"} {
					response, err := client.Get(fmt.Sprintf("https://probe.test%s?case=%d", path, i))
					if err != nil {
						t.Error(err)
						return
					}
					if path == "/x/echo" && string(response.Body) != row.want {
						t.Errorf("%s case %d: got %q, want %q", protocol, i, response.Body, row.want)
					}
				}
			}()
		}
		wg.Wait()
	}
}

func TestInvalidCookiePrefixPolicyRejectedBeforeIO(t *testing.T) {
	for _, raw := range []string{"", `null`, `[{"prefix":"x","prefix":"y","case_sensitive":false,"reject_nameless":true,"attributes":[]}]`, `[{"prefix":"x","case_sensitive":false,"reject_nameless":true,"attributes":["unsupported"]}]`} {
		p := shippedProfile(t, "chrome_155_macos")
		if raw == "" {
			delete(p.Behavior, "cookie.prefixes")
		} else {
			p.Behavior["cookie.prefixes"] = json.RawMessage(raw)
		}
		var dials atomic.Int32
		_, err := New(WithProfileValue(p), WithTransportOption(tc.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, fmt.Errorf("unexpected dial")
		})))
		if err == nil || dials.Load() != 0 {
			t.Fatalf("invalid cookie policy reached I/O: %v, dials %d", err, dials.Load())
		}
	}
}

func TestAProfileOfAnOlderSchemaRunsOnlyWithItsCookieRules(t *testing.T) {
	// A profile that says an older schema but brings a behavior of its own
	// without cookie.prefixes used to run, and stored a __Host- cookie of
	// another path; it is refused before anything is sent. With the rules it
	// runs, and refuses that cookie as the shipped profile does.
	var asked atomic.Int32
	site := tlsSite(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if r.URL.Path == "/set" {
			w.Header().Add("Set-Cookie", "__Host-sid=attacker; Secure; Path=/x")
			return
		}
		_, _ = w.Write([]byte(r.Header.Get("Cookie")))
	}))
	shipped, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []int{0, 2} {
		without := shipped.Clone()
		without.Schema = schema
		delete(without.Behavior, "cookie.prefixes")
		if _, err := New(WithProfileValue(without), WithInsecureSkipVerify()); err == nil ||
			!strings.Contains(err.Error(), "requires cookie.prefixes") {
			t.Errorf("schema %d without cookie.prefixes: %v", schema, err)
		}
		if n := asked.Load(); n != 0 {
			t.Fatalf("schema %d: the site was asked %d times by a refused profile", schema, n)
		}
		with := shipped.Clone()
		with.Schema = schema
		client, err := New(WithProfileValue(with), WithInsecureSkipVerify())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Do(&Request{URL: site.URL + "/set"}); err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(&Request{URL: site.URL + "/x/echo"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(res.Body), "__Host-sid") {
			t.Errorf("schema %d with the rules kept %q", schema, res.Body)
		}
		_ = client.Close()
		asked.Store(0)
	}
}
