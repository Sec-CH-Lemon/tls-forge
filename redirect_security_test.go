package tlsforge

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	fhttp "github.com/igor-lemon/fhttp"
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
