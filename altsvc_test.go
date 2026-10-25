package tlsforge

import (
	"net/url"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestARequestGoesOverHTTP3ToTheAlternativeItsOriginAdvertisedAsChrome(t *testing.T) {
	// Chrome 155 (bench/alt, a1-fetch and a2-learn): the request after an
	// answer that advertised h3 goes at once on the origin's HTTP/2
	// connection, QUIC to the alternative made apart, and the one after it
	// on that QUIC connection. No record names h3: the answer alone says.
	site := startH3Site(t, 0, 0)
	dns := echNames(t, nil, 0, 0)
	origin := "https://alt.h3.test:" + site.port
	advertised := origin + "/?alt=" + url.QueryEscape(`h3=":`+site.port+`"`)
	c := echClient(t, dns)
	if got := came(t, c, advertised); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if got := came(t, c, origin+"/b"); got != "HTTP/2.0" {
		t.Fatalf("the next came over %q, want the origin's HTTP/2 connection", got)
	}
	if !soon(2*time.Second, func() bool { return site.quicConns.Load() == 1 }) {
		t.Fatal("no QUIC connection made apart")
	}
	time.Sleep(300 * time.Millisecond)
	if got := came(t, c, origin+"/c"); got != "HTTP/3.0" {
		t.Errorf("the one after came over %q, want HTTP/3", got)
	}
	if site.quicConns.Load() != 1 || site.tcpConns.Load() != 1 {
		t.Errorf("QUIC connections %d, TCP %d", site.quicConns.Load(), site.tcpConns.Load())
	}
	// The JSON alone: a profile that follows no Alt-Svc never goes there.
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	off := p.Clone()
	off.Behavior["quic.alt_svc"] = []byte("false")
	for _, k := range []string{"quic.alt_svc_user_ports", "quic.alt_svc_remote_hosts", "quic.alt_svc_tcp_waits_with_h2"} {
		delete(off.Behavior, k)
	}
	c = echClient(t, dns, WithProfileValue(off))
	for _, u := range []string{advertised, origin + "/b", origin + "/c"} {
		if got := came(t, c, u); got != "HTTP/2.0" {
			t.Errorf("%s without quic.alt_svc came over %q", u, got)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if site.quicConns.Load() != 1 {
		t.Errorf("%d QUIC connections, want none more", site.quicConns.Load())
	}
}
