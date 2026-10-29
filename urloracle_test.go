package tlsforge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	tls_client "github.com/igor-lemon/tls-client"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

type urlOracleCase struct {
	Comparison        string `json:"comparison"`
	ProductionRefusal string `json:"production_refusal"`
	ID                string `json:"id"`
	Input             string `json:"input"`
	Base              string `json:"base"`
	Refusal           string `json:"refusal"`
	Expected          struct {
		Invalid       bool   `json:"invalid"`
		Canonical     string `json:"canonical"`
		Scheme        string `json:"scheme"`
		Authority     string `json:"authority"`
		Target        string `json:"target"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		UsernameBytes string `json:"username_bytes"`
		PasswordBytes string `json:"password_bytes"`
	} `json:"expected"`
}

func urlOracleCases(t *testing.T) []urlOracleCase {
	t.Helper()
	b, err := os.ReadFile("testdata/whatwg-url-components.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []urlOracleCase `json:"cases"`
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 44 {
		t.Fatalf("URL fixture has %d cases, want44", len(fixture.Cases))
	}
	return fixture.Cases
}

func oracleBase(t *testing.T, c urlOracleCase) *url.URL {
	t.Helper()
	if c.Base == "" {
		return nil
	}
	u, err := url.Parse(c.Base)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestWHATWGURLComponents(t *testing.T) {
	for _, c := range urlOracleCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			p, err := parseURL(c.Input, oracleBase(t, c))
			if c.Expected.Invalid {
				if err == nil {
					t.Fatal("WHATWG oracle rejects this URL")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			canonical, username, password := c.Expected.Canonical, c.Expected.Username, c.Expected.Password
			if c.Comparison == "base_credentials_tracked_by_chain" {
				// The WHATWG constructor keeps base userinfo. Redirect resolution
				// intentionally holds it in chain state, not in a request URL.
				canonical = c.Expected.Scheme + "://" + c.Expected.Authority + c.Expected.Target
				username, password = "", ""
			}
			if p.String() != canonical || p.username != username || p.password != password {
				t.Fatalf("components differ: %q username=%q password=%q", p.String(), p.username, p.password)
			}
			u, err := requestURL(c.Input, oracleBase(t, c))
			if c.Refusal != "" {
				if err == nil || !strings.Contains(err.Error(), c.Refusal) {
					t.Fatalf("want explicit refusal %q, got %v", c.Refusal, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if u.Scheme != c.Expected.Scheme || u.Host != c.Expected.Authority || u.RequestURI() != c.Expected.Target || u.Fragment != "" {
				t.Fatalf("request components differ: scheme=%q authority=%q target=%q fragment=%q", u.Scheme, u.Host, u.RequestURI(), u.Fragment)
			}
			user, pass := "", ""
			if u.User != nil {
				user = u.User.Username()
				pass, _ = u.User.Password()
			}
			userBytes, passBytes := c.Expected.UsernameBytes, c.Expected.PasswordBytes
			if c.Comparison == "base_credentials_tracked_by_chain" {
				userBytes, passBytes = "", ""
			}
			if base64.StdEncoding.EncodeToString([]byte(user)) != userBytes || base64.StdEncoding.EncodeToString([]byte(pass)) != passBytes {
				t.Fatalf("decoded credentials differ for %s", c.ID)
			}
		})
	}
}

func TestWHATWGRequestTargetsOnWire(t *testing.T) {
	for _, c := range urlOracleCases(t) {
		if c.Expected.Invalid || c.Refusal != "" || c.ProductionRefusal != "" {
			continue
		}
		for _, proto := range []string{"h1", "h2"} {
			if proto == "h2" && c.Expected.Scheme != "https" {
				continue
			}
			t.Run(proto+"/"+c.ID, func(t *testing.T) {
				mode := proto
				if c.Expected.Scheme == "http" {
					mode = "http"
				}
				server := newRecorder(t, mode, func(w http.ResponseWriter, r *http.Request) {
					if c.Base != "" && r.URL.RequestURI() == oracleBase(t, c).RequestURI() {
						w.Header().Set("Location", c.Input)
						w.WriteHeader(http.StatusFound)
						return
					}
					w.WriteHeader(http.StatusOK)
				})
				client := newTestClient(t, server.dialing())
				target := c.Input
				if c.Base != "" {
					target = c.Base
				}
				if _, err := client.Get(target); err != nil {
					t.Fatal(err)
				}
				requests := server.requests()
				want := 1
				if c.Base != "" {
					want = 2
				}
				if len(requests) != want {
					t.Fatalf("%d requests, want%d", len(requests), want)
				}
				got := requests[len(requests)-1]
				authority := ""
				for _, h := range got.headers {
					if strings.EqualFold(h[0], "host") || h[0] == ":authority" {
						authority = h[1]
					}
				}
				if authority != c.Expected.Authority || got.url != c.Expected.Scheme+"://"+withoutPort(c.Expected.Authority)+c.Expected.Target {
					t.Fatalf("wire URL %q, want %q", got.url, c.Expected.Canonical)
				}
				for _, auth := range authorizations(requests) {
					if auth != "" {
						t.Fatal("credentials sent without a challenge")
					}
				}
			})
		}
	}
}

func TestWHATWGCredentialsStayAtChallengingOrigin(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		for _, userinfo := range []string{"u%0X:p%zz", "u%40x:p%3Aa%2Fb", "%C3%A9:p", "u:"} {
			t.Run(proto+"/"+userinfo, func(t *testing.T) {
				expectedUser := map[string]string{"u%0X:p%zz": "u%0X:p%zz", "u%40x:p%3Aa%2Fb": "u@x:p:a/b", "%C3%A9:p": "é:p", "u:": "u:"}[userinfo]
				wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(expectedUser))
				server := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
					if r.Host == "other.test" || r.Header.Get("Authorization") == "" {
						w.Header().Set("WWW-Authenticate", `Basic realm="url-oracle", charset="UTF-8"`)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.Header().Set("Location", "//other.test/next?x=%40#omit")
					w.WriteHeader(http.StatusFound)
				})
				client := newTestClient(t, server.dialing())
				res, err := client.Get("https://" + userinfo + "@example.test/auth")
				if err != nil {
					t.Fatal(err)
				}
				got := server.requests()
				auth := authorizations(got)
				if res.Status != http.StatusUnauthorized || len(got) != 3 || strings.Join(auth, "|") != "|"+wantAuth+"|" {
					t.Fatalf("status=%d credentials sequence=%q, requests=%d", res.Status, auth, len(got))
				}
				if got[2].url != "https://other.test/next?x=%40" {
					t.Fatalf("redirect target %q", got[2].url)
				}
			})
		}
	}
}

// Known representation limits remain explicit. A successful WHATWG constructor
// does not imply that every current transport accepts the host or raw path.
func TestWHATWGUnsupportedURLRefusesBeforeDial(t *testing.T) {
	for _, c := range urlOracleCases(t) {
		if !c.Expected.Invalid && c.Refusal == "" && c.ProductionRefusal == "" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			var dials atomic.Int32
			client := newTestClient(t, WithTransportOption(tls_client.WithDialContext(func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected dial")
			})))
			_, err := client.Get(c.Input)
			if err == nil || dials.Load() != 0 {
				t.Fatalf("err=%v dials=%d", err, dials.Load())
			}
			if c.ProductionRefusal != "" && !strings.Contains(err.Error(), c.ProductionRefusal) {
				t.Fatalf("wrong refusal: %v", err)
			}
		})
	}
}

func TestInvalidUTF8RedirectRefusedBeforeNextDial(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "//%80.example/next")
				w.WriteHeader(http.StatusFound)
			})
			var dials atomic.Int32
			client := newTestClient(t, WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
				dials.Add(1)
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, server.addr)
			})))
			_, err := client.Get("https://example.test/start")
			if err == nil || dials.Load() != 1 || len(server.requests()) != 1 {
				t.Fatalf("err=%v dials=%d requests=%d", err, dials.Load(), len(server.requests()))
			}
		})
	}
}
