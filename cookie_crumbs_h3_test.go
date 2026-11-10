package tlsforge

import (
	"io"
	"slices"
	"testing"
	"time"

	tc "github.com/igor-lemon/tls-client"
	"github.com/quic-go/qpack"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// A Cookie goes over HTTP/3 a field a crumb, as quiche's
// ValueSplittingHeaderList cuts it for Chrome's QPACK encoder
// (CookieCrumbling::kEnabled, quiche 0b2bc13f): at each ';', the one space
// after it dropped. HTTP/2 crumbles it already. Without
// h3.cookie_crumbs the value goes whole, in one field.
func TestACookieGoesOverHTTP3AFieldACrumbAsChromeWritesIt(t *testing.T) {
	shipped, err := profile.Get("chrome_156_macos")
	if err != nil {
		t.Fatal(err)
	}
	if !shipped.Behavior.Flag("h3.cookie_crumbs") {
		t.Fatal("the shipped profile writes a Cookie whole over HTTP/3")
	}
	without := shipped.Clone()
	delete(without.Behavior, "h3.cookie_crumbs")
	for _, p := range []*profile.Profile{shipped, without} {
		url, wire := qpackWirePeer(t)
		c := newTestClient(t, WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(4*time.Second),
			WithTransportOption(tc.WithProtocolRacing()))
		if _, err := c.Do(&Request{URL: url, Header: NewHeader("Cookie", "a=1; b=2;c=3;; d=4")}); err != nil {
			t.Fatal(err)
		}
		var block []byte
		select {
		case block = <-wire:
		case <-time.After(time.Second):
			t.Fatal("no request headers over QUIC")
		}
		decode := qpack.NewDecoder().Decode(block)
		var cookies []string
		for {
			f, err := decode()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.Name == "cookie" {
				cookies = append(cookies, f.Value)
			}
		}
		// tls-forge's own Cookie is the pairs given, joined by "; ", the empty
		// one dropped (ownCookie).
		want := []string{"a=1", "b=2", "c=3", "d=4"}
		if !p.Behavior.Flag("h3.cookie_crumbs") {
			want = []string{"a=1; b=2; c=3; d=4"}
		}
		if !slices.Equal(cookies, want) {
			t.Errorf("crumbs %v: the cookie fields %q, want %q", p.Behavior.Flag("h3.cookie_crumbs"), cookies, want)
		}
	}
}
