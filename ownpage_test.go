package tlsforge

import (
	"reflect"
	"strings"
	"testing"
)

func TestTheOwnPageOfAURLIsTheRootOfItsOrigin(t *testing.T) {
	for _, tc := range []struct{ url, page string }{
		{"https://www.example.com/session?x=1#f", "https://www.example.com/"},
		{"https://www.example.com:8443/x", "https://www.example.com:8443/"},
		{"https://www.example.com:443/x", "https://www.example.com/"},
		{"http://www.example.com/x", "http://www.example.com/"},
		{"http://www.example.com:80/x", "http://www.example.com/"},
		{"https://u:p@www.example.com/x", "https://www.example.com/"},
		{"https://[::1]:8443/x", "https://[::1]:8443/"},
		{"https://WWW.Example.COM/x", "https://www.example.com/"},
		{"https://127.0.0.1/x", "https://127.0.0.1/"},
	} {
		if page, err := OwnPage(tc.url); err != nil || page != tc.page {
			t.Errorf("%s: %q, %v, want %q", tc.url, page, err, tc.page)
		}
	}
	if page, err := OwnPage("ftp://www.example.com/"); err == nil ||
		!strings.HasPrefix(err.Error(), `tlsforge: "ftp://www.example.com/" `) {
		t.Errorf("a URL that does not read: %q, %v", page, err)
	}
}

func TestARequestWithoutAContextGoesAsAnXHROfItsOwnPage(t *testing.T) {
	u := "https://www.example.com/session?x=1"
	xhr := &BrowserContext{Kind: KindXHR, Initiator: "https://www.example.com/"}
	given := &BrowserContext{Kind: KindForm, Initiator: "https://a.example/p"}
	for _, tc := range []struct {
		name string
		req  Request
		want *BrowserContext
	}{
		{"a GET goes as a navigation typed into the address bar", Request{URL: u}, nil},
		{"one named in lower case too", Request{Method: "get", URL: u}, nil},
		{"a GET with a body is nothing a page sends", Request{URL: u, Body: []byte("x")}, nil},
		{"a request in a context keeps it", Request{Method: "POST", URL: u, Browser: given}, given},
		{"a URL that does not read is left to Do", Request{Method: "POST", URL: "ftp://www.example.com/"}, nil},
		{"a POST", Request{Method: "POST", URL: u, Body: []byte("a=b")}, xhr},
		{"one named in lower case", Request{Method: "post", URL: u}, xhr},
		{"a POST of a form's fields", Request{Method: "POST", URL: u,
			Header: Header{{Name: "Content-Type", Value: formEncoded}}, Body: []byte("a=b")}, xhr},
		{"JSON with a field of its own", Request{Method: "POST", URL: u,
			Header: Header{{Name: "Content-Type", Value: "application/json"}, {Name: "X-Token", Value: "1"}}}, xhr},
		{"PUT", Request{Method: "PUT", URL: u, Body: []byte("a=b")}, xhr},
		{"PATCH", Request{Method: "PATCH", URL: u}, xhr},
		{"DELETE", Request{Method: "DELETE", URL: u}, xhr},
		{"HEAD", Request{Method: "HEAD", URL: u}, xhr},
		{"from the page of its own origin", Request{Method: "PUT", URL: "https://[::1]:8443/x"},
			&BrowserContext{Kind: KindXHR, Initiator: "https://[::1]:8443/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.req.Header.Clone()
			got := tc.req.FromItsOwnPage()
			if !reflect.DeepEqual(got.Browser, tc.want) {
				t.Errorf("sent as %+v, want %+v", got.Browser, tc.want)
			}
			rest := got
			rest.Browser = tc.req.Browser
			if !reflect.DeepEqual(rest, tc.req) {
				t.Errorf("the rest of the request became %+v", rest)
			}
			if !reflect.DeepEqual(tc.req.Header, before) {
				t.Errorf("its fields became %v", tc.req.Header)
			}
		})
	}
}
