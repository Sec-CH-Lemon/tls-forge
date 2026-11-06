package tlsforge

import (
	"net/http"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// An HTTP/1.1 answer whose chunked body ends its lines in LF alone is read as
// Chrome 156's HttpChunkedDecoder reads it where the profile says
// h1.chunked_bare_lf, as every Chrome profile does: a line ends at LF, a CR
// before it dropped; a size is cut at its extension, then of trailing spaces;
// a chunk's data ends in an empty line of LF or CRLF, and so do the trailer's
// lines. Without the key, RFC 9112's CRLF: the body does not read.
func TestAChunkedAnswerOfLFAloneIsReadAsChromeReadsIt(t *testing.T) {
	shipped, err := profile.Get("chrome_156_macos")
	if err != nil {
		t.Fatal(err)
	}
	if !shipped.Behavior.Flag("h1.chunked_bare_lf") {
		t.Fatal("the shipped profile reads no chunked body of LF alone")
	}
	without := shipped.Clone()
	delete(without.Behavior, "h1.chunked_bare_lf")
	for _, tc := range []struct{ name, body, want string }{
		{"LF alone", "5\nhello\n6\n world\n0\n\n", "hello world"},
		{"a size with an extension and spaces", "5;name=v \nhello\n6 \n world\n0\n\n", "hello world"},
		{"a trailer", "5\nhello\n0\nX-Trailer: 1\n\n", "hello"},
		{"CR here and there", "5\r\nhello\n6\n world\r\n0\n\r\n", "hello world"},
	} {
		site := tlsSite(t, false, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + tc.body)
			_ = rw.Flush()
		}))
		for _, p := range []*profile.Profile{shipped, without} {
			bareLF := p.Behavior.Flag("h1.chunked_bare_lf")
			client, err := New(WithProfileValue(p), WithInsecureSkipVerify())
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Do(&Request{URL: site.URL + "/"})
			_ = client.Close()
			var body string
			if err == nil {
				body = string(res.Body)
			}
			switch {
			case bareLF && (err != nil || body != tc.want):
				t.Errorf("%s: %v %q, want %q", tc.name, err, body, tc.want)
			case !bareLF && err == nil:
				t.Errorf("%s: a chunked body of LF alone read without h1.chunked_bare_lf: %q", tc.name, body)
			}
		}
	}
}
