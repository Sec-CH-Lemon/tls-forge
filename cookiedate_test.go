package tlsforge

import (
	"net/http"
	"testing"
	"time"
)

func TestACookiesExpiresIsReadAsChromeReadsIt(t *testing.T) {
	when := func(y int, m time.Month, d, hh, mm, ss int) time.Time {
		return time.Date(y, m, d, hh, mm, ss, 0, time.UTC)
	}
	for _, tc := range []struct {
		value string
		want  time.Time
		ok    bool
	}{
		{"Wed, 21 Oct 2026 07:28:00 GMT", when(2026, 10, 21, 7, 28, 0), true},
		{"Thu, 01-Jan-70 00:00:01 GMT", when(1970, 1, 1, 0, 0, 1), true},
		{"Sat, 15-Apr-17 21:01:22 GMT", when(2017, 4, 15, 21, 1, 22), true},
		{"Thu, 19-Apr-2007 16:00:00 GMT", when(2007, 4, 19, 16, 0, 0), true},
		{`Thu, 19/Apr\2007 16:00:00 GMT`, when(2007, 4, 19, 16, 0, 0), true},
		{"Wednesday, 1-Jan-2003 00:00:00 GMT", when(2003, 1, 1, 0, 0, 0), true},
		{"1-Jan-2003 00:00:00 GMT", when(2003, 1, 1, 0, 0, 0), true},
		{"Wed,18-Apr-07 22:50:12 GMT", when(2007, 4, 18, 22, 50, 12), true},
		{"WillyWonka  , 18-apr-07 22:50:12", when(2007, 4, 18, 22, 50, 12), true},
		{"Mon, 18-Apr-1977 22:50:13 GMT", when(1977, 4, 18, 22, 50, 13), true},
		{"Mon, 18-Apr-77 22:50:13 GMT", when(1977, 4, 18, 22, 50, 13), true},
		{`"Sat, 15-Apr-17\"21:01:22\"GMT"`, when(2017, 4, 15, 21, 1, 22), true},
		{"Partyday, 18- April-07 22:50:12", when(2007, 4, 18, 22, 50, 12), true},
		{"Sat, 15-Apr-17 21:01:22 GMT-0400 (EDT)", when(2017, 4, 15, 21, 1, 22), true},
		{"Thu Apr 18 22:50:12 2007 GMT", when(2007, 4, 18, 22, 50, 12), true},
		{"22:50:12 Thu Apr 18 2007 GMT", when(2007, 4, 18, 22, 50, 12), true},
		{"2017 April 15 21:01:22", when(2017, 4, 15, 21, 1, 22), true},
		{"15 17 Apr 21:01:22", when(2017, 4, 15, 21, 1, 22), true},
		{"Sat, 15-Apr-17 ::00 21:01:22", when(2017, 4, 15, 21, 1, 22), true},
		{"Sat, 15-Apr-17 21:01:22 11:22:33", when(2017, 4, 15, 21, 1, 22), true},
		{"Sat, 15-Apr-17 boink:z 21:01:22", when(2017, 4, 15, 21, 1, 22), true},
		{"Sat, 15-Apr-69 21:01:22", when(2069, 4, 15, 21, 1, 22), true},
		{"Sat, 15-Apr-0 21:01:22", when(2000, 4, 15, 21, 1, 22), true},
		{"Sat, 15-Apr-12345 21:01:22", when(12345, 4, 15, 21, 1, 22), true},
		{"Sat, 123 15-Apr-17 21:01:22", when(123, 4, 15, 21, 1, 22), true}, // three digits are no day, but a year
		{"Sat, 1a 15-Apr-17 21:01:22", when(2017, 4, 15, 21, 1, 22), true}, // a day that is no number is passed over
		{"Sat, 15-Apr-17 91:22:33 21:01:22", time.Time{}, false},           // the first time, which is none
		{"Sat, 15-Apr-17 21:01", time.Time{}, false},
		{"Sat, 15-Apr-17 21:01:22:00", time.Time{}, false},
		{"Sat, 15-Apr-17 21:01:99999999999", time.Time{}, false},
		{"Sat, 15-Ap-17 21:01:22", time.Time{}, false},
		{"Sat, 31-Feb-17 21:01:22", time.Time{}, false},
		{"Sat, 15-Apr-17 21:01:60", time.Time{}, false},
		{"Sat, 15-Apr-123456 21:01:22", time.Time{}, false},
		{"Sat, 15-Apr 21:01:22", time.Time{}, false},
		{"Sat, Apr-17 21:01:22", time.Time{}, false},
		{"15-17 21:01:22", time.Time{}, false},
		{"ſep 15 2017 21:01:22", time.Time{}, false}, // no month but in ASCII
		{"", time.Time{}, false},
	} {
		if got, ok := cookieExpiry(tc.value); !got.Equal(tc.want) || ok != tc.ok {
			t.Errorf("cookieExpiry(%q) = %v %v, want %v %v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
	for _, tc := range []struct {
		attributes, want string
		found            bool
	}{
		{" Path=/; Expires=one; expires = two ;Secure", "two", true},
		{" Path=/", "", false},
		{"", "", false},
	} {
		if got, found := cookieExpires(tc.attributes); got != tc.want || found != tc.found {
			t.Errorf("cookieExpires(%q) = %q %v", tc.attributes, got, found)
		}
	}
}

// A cookie deleted by an Expires Go's parser does not read, a year of two
// digits, is deleted, as Chrome deletes it; one an Expires none can read
// says is a session's.
func TestACookieAnExpiresOfTwoDigitsDeletesIsDeleted(t *testing.T) {
	for _, proto := range []string{"h1", "h2"} {
		s := newRecorder(t, proto, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/set":
				w.Header().Add("Set-Cookie", "a=1; Path=/")
				w.Header().Add("Set-Cookie", "b=1; Path=/; Expires=nonsense")
			case "/delete":
				w.Header().Add("Set-Cookie", "a=gone; Path=/; Expires=Thu, 01-Jan-70 00:00:01 GMT")
			}
		})
		c := contextClient(t, s, WithProfile("chrome_156_macos"))
		for _, path := range []string{"/set", "/delete", "/after"} {
			if _, err := c.Do(&Request{URL: "https://www.example.com" + path}); err != nil {
				t.Fatalf("%s %s: %v", proto, path, err)
			}
		}
		got := s.requests()
		if cookie, _ := got[len(got)-1].header("cookie"); cookie != "b=1" {
			t.Errorf("%s: the request after said Cookie %q, want b=1", proto, cookie)
		}
	}
}
