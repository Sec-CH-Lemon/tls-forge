package tlsforge

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	fhttp "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
)

func TestRedirectsDoNotRestoreCallerCredentials(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, mode := range []string{"as-given", "typed", "firefox"} {
			for _, target := range []string{"https://other.example", "https://sub.origin.example", "https://origin.example:8443"} {
				t.Run(protocol+"/"+mode+"/"+target, func(t *testing.T) {
					server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
						switch r.URL.Path {
						case "/start":
							http.Redirect(w, r, "/same", http.StatusFound)
						case "/same":
							http.Redirect(w, r, target+"/one", http.StatusFound)
						case "/one":
							http.Redirect(w, r, "/two", http.StatusFound)
						case "/two":
							http.Redirect(w, r, "https://origin.example/back", http.StatusFound)
						default:
							_, _ = w.Write([]byte("ok"))
						}
					})
					options := []Option{server.dialing()}
					switch mode {
					case "as-given":
						options = append(options, WithProfileValue(asGivenProfile(t, "chrome_155_macos")))
					case "typed":
						options = append(options, WithProfileValue(shippedProfile(t, "chrome_155_macos")))
					default:
						options = append(options, WithProfile("firefox_148"))
					}
					client := newTestClient(t, options...)
					to, _ := url.Parse(target)
					client.session.jar.SetCookies(to, []*fhttp.Cookie{{Name: "target-jar", Value: "kept", Path: "/"}})
					request := &Request{URL: "https://origin.example/start", Cookies: []Cookie{{Name: "initial-jar", Value: "kept", Path: "/"}},
						Header: NewHeader("Cookie", "caller-cookie=secret", "Authorization", "Bearer secret", "Proxy-Authorization", "Basic secret", "Proxy-Authenticate", "caller-secret", "X-Safe", "kept")}
					original := request.Header.Clone()
					if _, err := client.Do(request); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(request.Header, original) {
						t.Fatal("redirect changed the caller's headers")
					}
					requests := server.requests()
					if len(requests) != 5 {
						t.Fatalf("got %d requests, want 5", len(requests))
					}
					for i, got := range requests {
						var cookieFields []string
						for _, field := range got.headers {
							if strings.EqualFold(field[0], "cookie") {
								cookieFields = append(cookieFields, field[1])
							}
						}
						cookie := strings.Join(cookieFields, "; ")
						for _, name := range []string{"authorization", "proxy-authorization", "proxy-authenticate"} {
							value, _ := got.header(name)
							if i < 2 && value == "" || i >= 2 && value != "" {
								t.Errorf("hop %d: %s=%q", i, name, value)
							}
						}
						wantCallerCookie := i == 0 || i == 1 && mode != "typed"
						if strings.Contains(cookie, "caller-cookie=secret") != wantCallerCookie {
							t.Errorf("hop %d: caller Cookie %q", i, cookie)
						}
						// Jar cookies still follow host/path rules, including the
						// original host on the final return and same-host new ports.
						initialHost := i < 2 || i == 4 || to.Hostname() == "origin.example"
						targetHost := i == 2 || i == 3 || to.Hostname() == "origin.example"
						if strings.Contains(cookie, "initial-jar=kept") != initialHost || strings.Contains(cookie, "target-jar=kept") != targetHost {
							t.Errorf("hop %d: jar cookies %q", i, cookie)
						}
						if value, _ := got.header("x-safe"); value != "kept" {
							t.Errorf("hop %d lost the safe header", i)
						}
					}
				})
			}
		}
	}
}

// callersRedirectPolicy follows every redirect. Given as a transport option,
// it replaces tls-forge's own, and fhttp copies each hop's fields.
func callersRedirectPolicy() Option {
	return WithTransportOption(tls_client.WithCustomRedirectFunc(func(*fhttp.Request, []*fhttp.Request) error { return nil }))
}

// cookieSent is every Cookie field of a kept request, joined.
func cookieSent(got *keptRequest) string {
	var fields []string
	for _, field := range got.headers {
		if strings.EqualFold(field[0], "cookie") {
			fields = append(fields, field[1])
		}
	}
	return strings.Join(fields, "; ")
}

// A redirect policy of the caller's takes the hops out of tls-forge's hands,
// but not the caller's credentials past their origin: fhttp would copy them to
// a subdomain of its host, as net/http does, and no hop after it gets them
// back.
func TestACallersRedirectPolicyKeepsTheCallersCredentialsAtTheirOrigin(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, mode := range []string{"as-given", "typed", "firefox"} {
			for _, target := range []string{"https://sub.origin.example", "https://other.example", "https://origin.example:8443"} {
				t.Run(protocol+"/"+mode+"/"+target, func(t *testing.T) {
					server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
						switch r.URL.Path {
						case "/start":
							http.Redirect(w, r, "/same", http.StatusFound)
						case "/same":
							http.Redirect(w, r, target+"/one", http.StatusFound)
						case "/one":
							http.Redirect(w, r, "/two", http.StatusFound)
						case "/two":
							http.Redirect(w, r, "https://origin.example/back", http.StatusFound)
						default:
							_, _ = w.Write([]byte("ok"))
						}
					})
					options := []Option{server.dialing(), callersRedirectPolicy()}
					switch mode {
					case "as-given":
						options = append(options, WithProfileValue(asGivenProfile(t, "chrome_155_macos")))
					case "typed":
						options = append(options, WithProfileValue(shippedProfile(t, "chrome_155_macos")))
					default:
						options = append(options, WithProfile("firefox_148"))
					}
					client := newTestClient(t, options...)
					to, _ := url.Parse(target)
					client.session.jar.SetCookies(to, []*fhttp.Cookie{{Name: "target-jar", Value: "kept", Path: "/"}})
					request := &Request{URL: "https://origin.example/start", Cookies: []Cookie{{Name: "initial-jar", Value: "kept", Path: "/"}},
						Header: NewHeader("Cookie", "caller-cookie=secret", "Authorization", "Bearer secret", "Proxy-Authorization", "Basic secret",
							"Proxy-Authenticate", "caller-secret", "WWW-Authenticate", "caller-secret", "X-Safe", "kept")}
					if _, err := client.Do(request); err != nil {
						t.Fatal(err)
					}
					requests := server.requests()
					if len(requests) != 5 {
						t.Fatalf("got %d requests, want 5", len(requests))
					}
					for i, got := range requests {
						// The first two are at the origin the credentials
						// were given for.
						atOrigin := i < 2
						for _, name := range []string{"authorization", "proxy-authorization", "proxy-authenticate", "www-authenticate"} {
							if value, _ := got.header(name); (value != "") != atOrigin {
								t.Errorf("hop %d %s: %s=%q", i, got.url, name, value)
							}
						}
						cookie := cookieSent(got)
						if strings.Contains(cookie, "caller-cookie=secret") != atOrigin {
							t.Errorf("hop %d %s: caller Cookie %q", i, got.url, cookie)
						}
						initialHost := i < 2 || i == 4 || to.Hostname() == "origin.example"
						targetHost := i == 2 || i == 3 || to.Hostname() == "origin.example"
						if strings.Contains(cookie, "initial-jar=kept") != initialHost || strings.Contains(cookie, "target-jar=kept") != targetHost {
							t.Errorf("hop %d %s: jar cookies %q", i, got.url, cookie)
						}
						if value, _ := got.header("x-safe"); value != "kept" {
							t.Errorf("hop %d lost the safe header", i)
						}
					}
				})
			}
		}
	}
}

// A hop a redirect policy of the caller's followed is one tls-forge did not
// lay out. It is not sent again for a 421, or answered for a 401, with what
// tls-forge laid out for the first request: its fields, the credentials of
// its URL.
func TestAHopOfACallersRedirectPolicyIsNotSentAgainAsTheFirstRequest(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, status := range []int{http.StatusMisdirectedRequest, http.StatusUnauthorized} {
			t.Run(fmt.Sprint(protocol, "/", status), func(t *testing.T) {
				server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.URL.Path == "/start":
						http.Redirect(w, r, "https://other.example/hop", http.StatusFound)
					case status == http.StatusUnauthorized:
						w.Header().Set("WWW-Authenticate", `Basic realm="hop"`)
						fallthrough
					default:
						w.WriteHeader(status)
					}
				})
				client := newTestClient(t, server.dialing(), callersRedirectPolicy(), WithProfileValue(asGivenProfile(t, "chrome_155_macos")))
				header := NewHeader("Cookie", "caller-cookie=secret", "Proxy-Authorization", "Basic secret")
				if status == http.StatusMisdirectedRequest {
					// An Authorization of the caller's leaves a 401 unanswered.
					header.Add("Authorization", "Bearer secret")
				}
				res, err := client.Do(&Request{URL: "https://u:p@origin.example/start", Header: header})
				if err != nil {
					t.Fatal(err)
				}
				if res.Status != status {
					t.Errorf("answered %d", res.Status)
				}
				requests := server.requests()
				for _, got := range requests[1:] {
					for _, name := range []string{"authorization", "proxy-authorization"} {
						if value, _ := got.header(name); value != "" {
							t.Errorf("%s: %s=%q", got.url, name, value)
						}
					}
					if cookie := cookieSent(got); strings.Contains(cookie, "caller-cookie") {
						t.Errorf("%s: Cookie %q", got.url, cookie)
					}
				}
				if len(requests) != 2 {
					t.Errorf("sent %d requests, want the first and its hop", len(requests))
				}
			})
		}
	}
}

// The caller's Authorization stays at its origin, and so does the caller's say
// over authentication: a hop to another origin is answered with credentials of
// its own, its Location's or those the session keeps for its realm, as
// independently scoped HTTP authentication is. At the caller's origin a 401 is
// left to the caller, whatever else could answer it.
func TestAHopAwayFromTheCallersAuthorizationAuthenticatesOnItsOwn(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, how := range []string{"location", "realm", "same-origin"} {
			t.Run(protocol+"/"+how, func(t *testing.T) {
				server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/start" {
						to := map[string]string{"location": "https://u:p@other.example/auth/hop",
							"realm": "https://other.example/auth/hop", "same-origin": "https://u:p@origin.example/auth/hop"}[how]
						http.Redirect(w, r, to, http.StatusFound)
						return
					}
					if r.Header.Get("Authorization") != "Basic dTpw" {
						w.Header().Set("WWW-Authenticate", `Basic realm="hop"`)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					_, _ = w.Write([]byte("ok"))
				})
				client := newTestClient(t, server.dialing(), WithProfileValue(asGivenProfile(t, "chrome_155_macos")))
				if how == "realm" {
					// What the session keeps for the realm, from an answer before.
					if res, err := client.Do(&Request{URL: "https://u:p@other.example/auth/first"}); err != nil || res.Status != http.StatusOK {
						t.Fatalf("the realm's first answer: %v %v", res, err)
					}
				}
				res, err := client.Do(&Request{URL: "https://origin.example/start", Header: NewHeader("Authorization", "Bearer secret")})
				if err != nil {
					t.Fatal(err)
				}
				want := map[string][]string{"location": {"", "Basic dTpw"}, "realm": {"Basic dTpw"}, "same-origin": {"Bearer secret"}}[how]
				var sent []string
				for _, got := range server.requests() {
					if strings.HasSuffix(got.url, "/auth/hop") {
						value, _ := got.header("authorization")
						sent = append(sent, value)
					}
				}
				if !reflect.DeepEqual(sent, want) {
					t.Errorf("the hop was sent with %q, want %q", sent, want)
				}
				if status := map[bool]int{true: http.StatusUnauthorized, false: http.StatusOK}[how == "same-origin"]; res.Status != status {
					t.Errorf("answered %d, want %d", res.Status, status)
				}
			})
		}
	}
}
