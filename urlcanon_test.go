package tlsforge

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v5/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v5/profile"
	tls_client "github.com/igor-lemon/tls-client"
)

// urlDiffers are the cases of the URL fixture that tls-forge does not send as
// Chrome did, and why.
var urlDiffers = map[string]string{
	"url-path-percent":        "a percent sign that escapes nothing, which a url.URL escapes once more",
	"url-redirect-bad-escape": "a percent sign that escapes nothing, which a url.URL escapes once more",
}

// urlUpgraded are the cases Chrome sent over https though they were http
// URLs: HTTPS-Upgrades tries https first for a navigation to a name on port
// 80, a page's, a redirect's or one typed, and tls-forge sends what it is
// asked for. The url-upgrade-fallback cases are sent as Chrome's went, over
// http, but Chrome tried https first: two TLS handshakes naming the host that
// failed, which the fixture does not hold.
var urlUpgraded = map[string]bool{"url-port-default-http": true, "url-upgrade-link": true, "url-upgrade-redirect": true,
	"url-upgrade-typed": true, "url-upgrade-userinfo": true}

// The ports the URL fixture's {P} and {Q} are said as here.
const (
	fixtureTLSPort   = "18443"
	fixturePlainPort = "18080"
)

// fixtureURL is a URL case's input with its ports filled in: a URL, or a
// Location, and the URL of the 302 that says it.
func fixtureURL(id string, c harness.URLCase) (input, base string) {
	input = strings.NewReplacer("{P}", fixtureTLSPort, "{Q}", fixturePlainPort).Replace(c.Input)
	if c.Redirect {
		base = "https://www.example.com:" + fixtureTLSPort + "/r/302/" + id + "?to=" + url.QueryEscape(input)
	}
	return input, base
}

// sentFor is what tls-forge sends for the URL u, said as the fixture says
// what Chrome sent: no port of the fixture's.
func sentFor(u *url.URL) harness.SentURL {
	authority := strings.NewReplacer(":"+fixtureTLSPort, "", ":"+fixturePlainPort, "").Replace(u.Host)
	sent := harness.SentURL{Scheme: u.Scheme, Authority: authority, Target: u.RequestURI()}
	if u.Scheme == "https" && !strings.HasPrefix(u.Host, "[") && strings.Trim(u.Hostname(), "0123456789.") != "" {
		sent.SNI = u.Hostname()
	}
	return sent
}

func TestEveryURLChromeWasGivenIsMadeAsChromeMadeIt(t *testing.T) {
	// Each URL Chrome 155 was given, as a page's location.href or a
	// redirect's Location, is made the URL Chrome sent a request for, its
	// target what went on the request line and in :path, its authority what
	// went in Host and :authority; and each it sent nothing for is refused.
	fixture, err := harness.LoadURLs("testdata/chrome155-urls.json")
	if err != nil {
		t.Fatalf("LoadURLs: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("the fixture has no cases")
	}
	for id, c := range fixture.Cases {
		t.Run(id, func(t *testing.T) {
			if c.H2 != c.H1 {
				t.Fatalf("Chrome sent %v over HTTP/2 and %v over HTTP/1.1", c.H2, c.H1)
			}
			input, rawBase := fixtureURL(id, c)
			var base *url.URL
			if rawBase != "" {
				var err error
				if base, err = requestURL(rawBase, nil); err != nil {
					t.Fatalf("the 302's URL: %v", err)
				}
			}
			got, err := requestURL(input, base)
			switch want := c.H2; {
			case urlDiffers[id] != "":
				if err == nil {
					t.Fatalf("sent %v; want a refusal: %s", sentFor(got), urlDiffers[id])
				}
			case want.Refused != "":
				if err == nil {
					t.Fatalf("sent %v; Chrome sent nothing (%s)", sentFor(got), want.Refused)
				}
			case err != nil:
				t.Fatalf("refused: %v; Chrome sent %v", err, want)
			default:
				sent := sentFor(got)
				if urlUpgraded[id] {
					if sent.Scheme != "http" {
						t.Errorf("scheme %q, want http as asked", sent.Scheme)
					}
					sent.Scheme, sent.SNI = want.Scheme, want.SNI
				}
				if sent != want {
					t.Errorf("sent %v\nChrome %v", sent, want)
				}
			}
		})
	}
	for id := range urlDiffers {
		if _, ok := fixture.Cases[id]; !ok {
			t.Errorf("urlDiffers names %s, which the fixture has not", id)
		}
	}
	for id := range urlUpgraded {
		if _, ok := fixture.Cases[id]; !ok {
			t.Errorf("urlUpgraded names %s, which the fixture has not", id)
		}
	}
}

func TestEveryURLGoesOutAsChromeSentIt(t *testing.T) {
	// Each URL Chrome 155 was given goes out from tls-forge to the server
	// Chrome was measured against, over HTTP/2 and over HTTP/1.1 alone, as
	// Chrome's went: the server name its TLS asked for, its scheme, its
	// :authority or Host, and its :path or request target, as the server read
	// them; and for a URL Chrome sent nothing for, nothing goes out, the 302
	// that names it aside.
	fixture, err := harness.LoadURLs("testdata/chrome155-urls.json")
	if err != nil {
		t.Fatalf("LoadURLs: %v", err)
	}
	server, err := harness.StartURLServer()
	if err != nil {
		t.Fatalf("StartURLServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	onEveryPlatform(t, func(t *testing.T, p *profile.Profile) { urlsAsChromeSentThem(t, p, server, fixture) })
}

// urlsAsChromeSentThem sends every URL of the fixture wearing p, one after
// another, over each protocol, and holds what the server read to Chrome's.
func urlsAsChromeSentThem(t *testing.T, p *profile.Profile, server *harness.URLServer, fixture *harness.URLsFixture) {
	for _, proto := range []string{"h2", "h1"} {
		for _, id := range slices.Sorted(maps.Keys(fixture.Cases)) {
			t.Run(proto+"/"+id, func(t *testing.T) {
				want := fixture.Cases[id].H2
				if proto == "h1" {
					want = fixture.Cases[id].H1
				}
				server.Reset()
				client := newTestClient(t, WithProfileValue(p),
					WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, network, server.Addr(addr, proto))
					})))
				target, err := server.URL(id, proto)
				if err != nil {
					t.Fatalf("URL: %v", err)
				}
				_, err = client.Get(target)
				got, sentErr := server.Sent(id)
				if sentErr != nil {
					t.Fatalf("Sent: %v", sentErr)
				}
				switch {
				case urlDiffers[id] != "" || want.Refused != "":
					if err == nil || got.Refused == "" {
						t.Errorf("sent %v, %v; want nothing sent and an error", got, err)
					}
				case err != nil:
					t.Fatalf("Get: %v; Chrome sent %v", err, want)
				default:
					if urlUpgraded[id] {
						if got.Scheme != "http" {
							t.Errorf("scheme %q, want http as asked", got.Scheme)
						}
						got.Scheme, got.SNI = want.Scheme, want.SNI
					}
					if got != want {
						t.Errorf("sent %v\nChrome %v", got, want)
					}
				}
			})
		}
	}
}

func TestCanonicalURL(t *testing.T) {
	// The WHATWG URL Standard's parser, as Chrome has it for http and https,
	// part by part; a refusal by what it says.
	for _, tc := range []struct{ in, want, refused string }{
		// The scheme.
		{in: "HTTP://example.com/", want: "http://example.com/"},
		{in: "hTtPs://example.com/", want: "https://example.com/"},
		{in: "https:example.com/a", want: "https://example.com/a"},
		{in: "https:/example.com/a", want: "https://example.com/a"},
		{in: `https:\\example.com\a`, want: "https://example.com/a"},
		{in: "https:////example.com/a", want: "https://example.com/a"},
		{in: "ftp://example.com/", refused: "is not an http or https URL"},
		{in: "wss://example.com/", refused: "is not an http or https URL"},
		{in: "http+x://example.com/", refused: "is not an http or https URL"},
		{in: "h2c://example.com/", refused: "is not an http or https URL"},
		{in: "://example.com/", refused: "names no scheme"},
		{in: "/a", refused: "names no scheme"},
		{in: "example.com", refused: "names no scheme"},
		{in: "1http://example.com/", refused: "names no scheme"},
		{in: "", refused: "names no scheme"},
		{in: " \t ", refused: "names no scheme"},
		// Spaces, controls and newlines.
		{in: " \x00\x1fhttps://example.com/a \x01", want: "https://example.com/a"},
		{in: "ht\ttp\ns://exa\rmple.com/a\tb", want: "https://example.com/ab"},
		{in: "https://example.com/a\x01b\x1f\x7fc", want: "https://example.com/a%01b%1F%7Fc"},
		// Credentials.
		{in: "https://u:p@example.com/", want: "https://u:p@example.com/"},
		{in: "https://u@example.com/", want: "https://u@example.com/"},
		{in: "https://:p@example.com/", want: "https://:p@example.com/"},
		{in: "https://u:@example.com/", want: "https://u@example.com/"},
		{in: "https://@example.com/", want: "https://example.com/"},
		{in: "https://a@b@example.com/", want: "https://a%40b@example.com/"},
		{in: "https://u:p:q@example.com/", want: "https://u:p%3Aq@example.com/"},
		{in: "https://u ser:p\"w@example.com/", want: "https://u%20ser:p%22w@example.com/"},
		{in: "https://u@/", refused: "names no host"},
		// The host.
		{in: "https://EXAMPLE.com/", want: "https://example.com/"},
		{in: "https://my_host.Example/", want: "https://my_host.example/"},
		{in: "https://пример.example.com/", want: "https://xn--e1afmkfd.example.com/"},
		{in: "https://XN--E1AFMKFD.example.com/", want: "https://xn--e1afmkfd.example.com/"},
		{in: "https://faß.example/", want: "https://xn--fa-hia.example/"},
		{in: "https://ｗｗｗ.example.com/", want: "https://www.example.com/"},
		{in: "https://www.ex%61mple.com/", want: "https://www.example.com/"},
		{in: "https://%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.com/", want: "https://xn--e1afmkfd.com/"},
		{in: "https://a..b/", want: "https://a..b/"},
		{in: "https://example.com./", want: "https://example.com./"},
		{in: "https://xn--a.example/", refused: "no name"},
		{in: "https://www.XN--A.example/", refused: "no name"},
		{in: "https://\u00ad/", refused: "no name"},
		{in: "https://a\u05d0.example/", refused: "no name"},
		{in: "https://ex%zzample.com/", refused: "a percent sign that escapes nothing"},
		{in: "https://www.exa mple.com/", refused: `holds " ", which no host may`},
		{in: "https://a<b.com/", refused: `holds "<"`},
		{in: "https://a%2Fb.com/", refused: `holds "/"`},
		{in: "https://ex／ample.com/", refused: `holds "/"`},
		{in: "https://a[b.com/", refused: `holds "["`},
		{in: "https://%3Ca.example/", refused: `holds "<"`},
		{in: "https://a%2525b.example/", refused: `holds "%"`},
		{in: "https:///", refused: "names no host"},
		{in: "https://", refused: "names no host"},
		{in: "https://:443/", refused: "names no host"},
		{in: "https:///page", want: "https://page/"},
		// IPv4 addresses.
		{in: "http://127.0.0.1/", want: "http://127.0.0.1/"},
		{in: "http://0x7f.0.0.1/", want: "http://127.0.0.1/"},
		{in: "http://0X7F.1/", want: "http://127.0.0.1/"},
		{in: "http://0177.0.0.1/", want: "http://127.0.0.1/"},
		{in: "http://127.1/", want: "http://127.0.0.1/"},
		{in: "http://2130706433/", want: "http://127.0.0.1/"},
		{in: "http://0x/", want: "http://0.0.0.0/"},
		{in: "http://00/", want: "http://0.0.0.0/"},
		{in: "http://127.0.0.1./", want: "http://127.0.0.1/"},
		{in: "http://1.2.3.4.5/", refused: "more than four parts"},
		{in: "http://256.1/", refused: `"256", past 255`},
		{in: "http://1.16777216/", refused: "past 255.255.255.255"},
		{in: "http://4294967296/", refused: "past 255.255.255.255"},
		{in: "http://99999999999999999999999999/", refused: "past 255.255.255.255"},
		{in: "http://0xffffffffffffffffffff/", refused: "past 255.255.255.255"},
		{in: "http://08/", refused: `with "08" in it`},
		{in: "http://1..2/", refused: `with "" in it`},
		{in: "http://a.0x1g/", want: "http://a.0x1g/"},
		{in: "http://1.2.example/", want: "http://1.2.example/"},
		// IPv6 addresses.
		{in: "http://[0:0:0:0:0:0:0:1]/", want: "http://[::1]/"},
		{in: "http://[::FFFF:127.0.0.1]/", want: "http://[::ffff:7f00:1]/"},
		{in: "http://[1:0:0:2:0:0:0:3]:8080/", want: "http://[1:0:0:2::3]:8080/"},
		{in: "http://[1:0:0:2:0:0:3:4]/", want: "http://[1::2:0:0:3:4]/"},
		{in: "http://[1:0:2:0:3:0:4:0]/", want: "http://[1:0:2:0:3:0:4:0]/"},
		{in: "http://[1::]/", want: "http://[1::]/"},
		{in: "http://[::]/", want: "http://[::]/"},
		{in: "http://[::1/", refused: "no closing bracket"},
		{in: "http://[::1]x/", refused: `"x" follows its IPv6 address`},
		{in: "http://[fe80::1%25eth0]/", refused: "is no IPv6 address"},
		{in: "http://[127.0.0.1]/", refused: "is no IPv6 address"},
		{in: "http://[::g]/", refused: "is no IPv6 address"},
		// The port.
		{in: "https://example.com:443/", want: "https://example.com/"},
		{in: "http://example.com:80/", want: "http://example.com/"},
		{in: "http://example.com:443/", want: "http://example.com:443/"},
		{in: "https://example.com:0000443/", want: "https://example.com/"},
		{in: "https://example.com:08443/", want: "https://example.com:8443/"},
		{in: "https://example.com:/", want: "https://example.com/"},
		{in: "https://example.com:65535/", want: "https://example.com:65535/"},
		{in: "https://example.com:0000000000065535/", want: "https://example.com:65535/"},
		{in: "https://example.com:65536/", refused: "its port 65536 is past 65535"},
		{in: "https://example.com:100000/", refused: "past 65535"},
		{in: "https://example.com:99999999999999999999/", refused: "past 65535"},
		{in: "https://example.com:8a/", refused: `its port "8a" is not a number`},
		{in: "https://example.com:-1/", refused: "is not a number"},
		{in: "https://example.com:1:2/", refused: "is not a number"},
		{in: "http://example.com:6000/", refused: "port 6000, which Chrome sends nothing to"},
		{in: "http://example.com:0/", refused: "port 0, which Chrome sends nothing to"},
		{in: "http://example.com:000/", refused: "port 0, which Chrome sends nothing to"},
		{in: "http://example.com:10080/", refused: "port 10080"},
		{in: "https://example.com:1/", refused: "port 1,"},
		{in: "http://example.com:8080/", want: "http://example.com:8080/"},
		{in: "http://example.com:6001/", want: "http://example.com:6001/"},
		{in: "http://example.com:4190/", want: "http://example.com:4190/"},
		{in: "http://example.com:6679/", want: "http://example.com:6679/"},
		// The path.
		{in: "https://example.com", want: "https://example.com/"},
		{in: "https://example.com/a/./b/../c", want: "https://example.com/a/c"},
		{in: "https://example.com/a/%2e/b/%2E%2e/c", want: "https://example.com/a/c"},
		{in: "https://example.com/a/%2E/b", want: "https://example.com/a/b"},
		{in: "https://example.com/a/.%2E/c/%2e./d", want: "https://example.com/d"},
		{in: "https://example.com/a/b/..", want: "https://example.com/a/"},
		{in: "https://example.com/a/b/.", want: "https://example.com/a/b/"},
		{in: "https://example.com/..", want: "https://example.com/"},
		{in: "https://example.com/../../a", want: "https://example.com/a"},
		{in: "https://example.com/.../a", want: "https://example.com/.../a"},
		{in: "https://example.com/.a/a./", want: "https://example.com/.a/a./"},
		{in: `https://example.com\a\b`, want: "https://example.com/a/b"},
		{in: "https://example.com//a//b/", want: "https://example.com//a//b/"},
		{in: "https://example.com/ !\"$&'()*+,-.:;<=>@[]^_`{|}~", want: "https://example.com/%20!%22$&'()*+,-.:;%3C=%3E@[]%5E_%60%7B%7C%7D~"},
		{in: "https://example.com/é ж 😀", want: "https://example.com/%C3%A9%20%D0%B6%20%F0%9F%98%80"},
		{in: "https://example.com/%41%7e%2F%2f", want: "https://example.com/%41%7e%2F%2f"},
		{in: "https://example.com/a%zz", refused: `has "%zz" in its path`},
		{in: "https://example.com/a%", refused: `has "%" in its path`},
		{in: "https://example.com/a%4", refused: `has "%4" in its path`},
		{in: "https://example.com/%41%4g", refused: `has "%4g" in its path`},
		// The query.
		{in: "https://example.com/? !\"$%&'()*+,-./:;<=>?@[\\]^_`{|}~", want: "https://example.com/?%20!%22$%&%27()*+,-./:;%3C=%3E?@[\\]^_`{|}~"},
		{in: "https://example.com/?q=é ж 😀", want: "https://example.com/?q=%C3%A9%20%D0%B6%20%F0%9F%98%80"},
		{in: "https://example.com/?a=%41%zz%", want: "https://example.com/?a=%41%zz%"},
		{in: "https://example.com?q", want: "https://example.com/?q"},
		{in: "https://example.com/a?", want: "https://example.com/a?"},
		{in: "https://example.com/a?#f", want: "https://example.com/a?"},
		{in: "https://example.com/a?b?c", want: "https://example.com/a?b?c"},
		// The fragment.
		{in: "https://example.com/a#f", want: "https://example.com/a"},
		{in: "https://example.com/a#f?q", want: "https://example.com/a"},
		{in: "https://example.com#f", want: "https://example.com/"},
		{in: "https://example.com/a?q#f#g", want: "https://example.com/a?q"},
	} {
		got, err := CanonicalURL(tc.in)
		switch {
		case tc.refused != "":
			if err == nil || !strings.Contains(err.Error(), tc.refused) {
				t.Errorf("CanonicalURL(%q) = %q, %v; want an error saying %q", tc.in, got, err, tc.refused)
			}
		case err != nil || got != tc.want:
			t.Errorf("CanonicalURL(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestACanonicalURLRefusalIsSaidOfTheURL(t *testing.T) {
	// The error names the URL as given, and unwraps to the reason alone, said
	// as of the URL, for whoever names it otherwise.
	_, err := CanonicalURL("ftp://example.com/")
	if err == nil || err.Error() != `tlsforge: "ftp://example.com/" is not an http or https URL` {
		t.Fatalf("err = %v", err)
	}
	if reason := errors.Unwrap(err); reason == nil || reason.Error() != "is not an http or https URL" {
		t.Errorf("unwraps to %v", reason)
	}
}

func TestALocationIsResolvedAgainstTheURLItCameFrom(t *testing.T) {
	// A relative Location takes what it does not say from the URL it came
	// from, as Chrome resolves one.
	base, err := requestURL("https://example.com:8443/a/b/c?q=1", nil)
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	for _, tc := range []struct{ location, want string }{
		{"d", "https://example.com:8443/a/b/d"},
		{"./d", "https://example.com:8443/a/b/d"},
		{"../d", "https://example.com:8443/a/d"},
		{"../../../../d", "https://example.com:8443/d"},
		{"..", "https://example.com:8443/a/"},
		{".", "https://example.com:8443/a/b/"},
		{"d?x#y", "https://example.com:8443/a/b/d?x"},
		{"/d", "https://example.com:8443/d"},
		{`\d`, "https://example.com:8443/d"},
		{"?x", "https://example.com:8443/a/b/c?x"},
		{"?", "https://example.com:8443/a/b/c?"},
		{"?x#f", "https://example.com:8443/a/b/c?x"},
		{"#f", "https://example.com:8443/a/b/c?q=1"},
		{"", "https://example.com:8443/a/b/c?q=1"},
		{"//other.example/d", "https://other.example/d"},
		{`\\other.example\d`, "https://other.example/d"},
		{`/\other.example/d`, "https://other.example/d"},
		{`\/other.example/d`, "https://other.example/d"},
		{"///other.example/d", "https://other.example/d"},
		{"https:d", "https://example.com:8443/a/b/d"},
		{"https:/d", "https://example.com:8443/d"},
		{"https://other.example/d", "https://other.example/d"},
		{"http:other.example/d", "http://other.example/d"},
		{"HTTP://OTHER.example:80/d", "http://other.example/d"},
		{"  /d  ", "https://example.com:8443/d"},
		{"d e", "https://example.com:8443/a/b/d%20e"},
		{"1a:b", "https://example.com:8443/a/b/1a:b"},
	} {
		got, err := requestURL(tc.location, base)
		if err != nil || got.String() != tc.want {
			t.Errorf("Location %q: %v, %v; want %q", tc.location, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ location, refused string }{
		{"mailto:x@example.com", "is not an http or https URL"},
		{"//other.example:6000/", "port 6000"},
		{"/a%zz", `has "%zz" in its path`},
		{"//", "names no host"},
	} {
		if got, err := requestURL(tc.location, base); err == nil || !strings.Contains(err.Error(), tc.refused) {
			t.Errorf("Location %q: %v, %v; want an error saying %q", tc.location, got, err, tc.refused)
		}
	}
}

func TestARedirectChromeWouldNotFollowEndsTheRequest(t *testing.T) {
	// A Location on a port Chrome sends nothing to, of another scheme or past
	// the ports there are fails the request where it is, nothing sent for it;
	// one url.Parse cannot read fails as the transport says.
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t)
	for _, tc := range []struct{ location, says string }{
		{"http://nothing.test:6000/x", `Get "http://nothing.test:6000/x": the Location is on port 6000, which Chrome sends nothing to (ERR_UNSAFE_PORT)`},
		{"ftp://nothing.test/x", "the Location is not an http or https URL"},
		{"http://nothing.test:65536/", "the Location is not a URL: its port 65536 is past 65535"},
		{"/a%zz", `failed to parse Location header "/a%zz"`},
	} {
		asked.Store(0)
		_, err := client.Get(server.URL + "/?to=" + url.QueryEscape(tc.location))
		if err == nil || !strings.HasPrefix(err.Error(), "tlsforge: ") || !strings.Contains(err.Error(), tc.says) || asked.Load() != 1 {
			t.Errorf("Location %q: %v, after %d requests; want an error saying %q", tc.location, err, asked.Load(), tc.says)
		}
	}
}

func TestALocationOfTheSameSchemeWithoutSlashesKeepsTheURLsCredentials(t *testing.T) {
	// http:/next after an http URL is relative to it, as Chrome reads one, so
	// the credentials of the URL it came from answer the 401 there.
	var said atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/start":
			w.Header().Set("Location", "http:/next")
			w.WriteHeader(http.StatusFound)
		case r.Header.Get("Authorization") == "":
			w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			said.Store(r.URL.Path + " " + r.Header.Get("Authorization"))
		}
	}))
	t.Cleanup(server.Close)
	res, err := newTestClient(t).Get(strings.Replace(server.URL, "http://", "http://u:p@", 1) + "/start")
	if err != nil || res.Status != http.StatusOK || said.Load() != "/next Basic dTpw" {
		t.Errorf("%v, %v: the server was told %v", res, err, said.Load())
	}
}

func TestALocationAfterAnAddressOrAPlainURLKeepsItsAuthority(t *testing.T) {
	// The URL a Location is relative to can be an IPv6 address on a port of
	// its own, or plain http on 80, which it names as the transport was told.
	for _, tc := range []struct{ base, location, want string }{
		{"http://[::1]:8080/a/b", "c", "http://[::1]:8080/a/c"},
		{"http://example.com:80/a", "b", "http://example.com/b"},
		{"https://example.com/a?", "#f", "https://example.com/a?"},
	} {
		base, err := url.Parse(tc.base)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", tc.base, err)
		}
		if got, err := requestURL(tc.location, base); err != nil || got.String() != tc.want {
			t.Errorf("%q after %q: %v, %v; want %q", tc.location, tc.base, got, err, tc.want)
		}
	}
}

func TestARequestURLIsSentAsItIsWritten(t *testing.T) {
	// The url.URL a request goes out for says the target as Chrome writes it,
	// in RequestURI and in String, and url.Parse reads it back the same; its
	// credentials are decoded, as a 401 is answered with them.
	for _, raw := range []string{
		"https://u%20x:p%3Aq@example.com:8443/a%2Fb/%41/é/!$&'()*+,;=:@[]~?q=%zz&r=\\^`{|}#f",
		"https://example.com/a?",
		"https://example.com//a",
		"http://[::1]:8080/",
		"https://example.com/plain",
	} {
		u, err := requestURL(raw, nil)
		if err != nil {
			t.Fatalf("requestURL(%q): %v", raw, err)
		}
		p, _ := parseURL(raw, nil)
		wantTarget := p.path
		if p.hasQuery {
			wantTarget += "?" + p.query
		}
		if got := u.RequestURI(); got != wantTarget {
			t.Errorf("%q: RequestURI() = %q, want %q", raw, got, wantTarget)
		}
		again, err := url.Parse(u.String())
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", u.String(), err)
		}
		if again.RequestURI() != wantTarget || again.Host != u.Host {
			t.Errorf("%q read back as %q on %q", u.String(), again.RequestURI(), again.Host)
		}
	}
	u, _ := requestURL("https://u%20x:p%3Aq@example.com/", nil)
	if password, _ := u.User.Password(); u.User.Username() != "u x" || password != "p:q" {
		t.Errorf("credentials %v", u.User)
	}
	if u, _ := requestURL("https://u@example.com/", nil); u.User.String() != "u" {
		t.Errorf("credentials without a password %v", u.User)
	}
	if u, _ := requestURL("https://:p@example.com/", nil); u.User.String() != ":p" {
		t.Errorf("a password without a name %v", u.User)
	}
	if u, _ := requestURL("https://example.com/plain", nil); u.RawPath != "" || u.User != nil {
		t.Errorf("a plain path keeps RawPath %q, credentials %v", u.RawPath, u.User)
	}
}

func TestAPercentSignIsLeftAsItIs(t *testing.T) {
	for _, tc := range []struct{ in, unescaped, stray string }{
		{"", "", ""},
		{"abc", "abc", ""},
		{"%41%62", "Ab", ""},
		{"%zz", "%zz", "%zz"},
		{"a%4", "a%4", "%4"},
		{"a%", "a%", "%"},
		{"%41%", "A%", "%"},
		{"%41%4g%42", "A%4gB", "%4g"},
		{"%%41", "%A", "%%4"},
		{"%e2%82%ac", "€", ""},
	} {
		if got := lenientUnescape(tc.in); got != tc.unescaped {
			t.Errorf("lenientUnescape(%q) = %q, want %q", tc.in, got, tc.unescaped)
		}
		if got := strayPercent(tc.in); got != tc.stray {
			t.Errorf("strayPercent(%q) = %q, want %q", tc.in, got, tc.stray)
		}
	}
}

func TestEveryBlockedPortIsInOrder(t *testing.T) {
	// The binary search needs them sorted, and each once: the 81 of
	// Chromium's kRestrictedPorts.
	if len(blockedPorts) != 81 {
		t.Errorf("%d blocked ports, want Chromium's 81", len(blockedPorts))
	}
	for i := 1; i < len(blockedPorts); i++ {
		if blockedPorts[i] <= blockedPorts[i-1] {
			t.Fatalf("blockedPorts[%d] = %d after %d", i, blockedPorts[i], blockedPorts[i-1])
		}
	}
	for _, port := range []string{"1", "6000", "10080"} {
		if _, err := CanonicalURL("http://example.com:" + port + "/"); err == nil {
			t.Errorf("port %s is not blocked", port)
		}
	}
}

func FuzzCanonicalURL(f *testing.F) {
	// Whatever a URL is, its canonical form is its own canonical form, which
	// url.Parse reads as the same request.
	for _, seed := range []string{
		"https://example.com/", "HTTP://EXAMPLE.COM:80/a/../b?c#d", "https://пример.example/é?ж", "http://0x7f.1/",
		"http://[::FFFF:127.0.0.1]:8080/", "https://u:p@example.com/%41", `https:\\example.com\a\.\b`,
		"https://example.com/ \"<>^`{|}?q= \"<>'", "http://example.com:6000/", "https://example.com/%zz",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		canonical, err := CanonicalURL(raw)
		if err != nil {
			return
		}
		again, err := CanonicalURL(canonical)
		if err != nil || again != canonical {
			t.Fatalf("CanonicalURL(%q) = %q, but CanonicalURL(%q) = %q, %v", raw, canonical, canonical, again, err)
		}
		u, _ := requestURL(raw, nil)
		read, err := url.Parse(canonical)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", canonical, err)
		}
		if read.RequestURI() != u.RequestURI() || read.Host != u.Host || read.Scheme != u.Scheme {
			t.Fatalf("%q reads as %s %s %s, sent as %s %s %s", canonical, read.Scheme, read.Host,
				read.RequestURI(), u.Scheme, u.Host, u.RequestURI())
		}
	})
}
