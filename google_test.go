package tlsforge

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// The hosts below are not a reading of Chromium's source. Each was resolved to
// a local server and asked for a page, and the answer is what the browser did.
func TestIsGoogleHost(t *testing.T) {
	for _, host := range []string{
		"google.com", "www.google.com", "images.google.com", "cloud.google.com",
		"accounts.google.com", "mail.google.com", "docs.google.com", "news.google.com",
		"google.de", "google.ru", "google.co.uk", "google.co.jp", "google.com.au",
		// Google's, and measured to receive it, despite not being country codes.
		"google.io", "google.org", "google.info", "google.net",
		"youtube.com", "www.youtube.com", "i.ytimg.com", "www.gstatic.com",
		"WWW.GOOGLE.COM", "www.google.com.",
	} {
		if !isGoogleHost(host) {
			t.Errorf("isGoogleHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{
		"example.com", "youtu.be", "blogger.com", "android.com", "google.dev",
		"googleusercontent.com", "notgoogle.com", "google", "", "co.uk",
		// Google's, and still sent nothing: owning the name is not the rule.
		"google.ai", "google.app", "google.page",
		// The one that matters: a host anybody can register must not be handed
		// headers meant for Google.
		"google.evil.com", "www.google.com.evil.com", "ytimg.com.evil.com",
	} {
		if isGoogleHost(host) {
			t.Errorf("isGoogleHost(%q) = true, want false", host)
		}
	}
}

// googleProfile is the shipped profile with a Google header list bolted on,
// spelled the way a capture produces it: the ordinary list with the block
// between `accept` and `sec-fetch-site`.
func googleProfile(t *testing.T) *profile.Profile {
	t.Helper()
	shipped, err := profile.Get(DefaultProfile)
	if err != nil {
		t.Fatalf("profile.Get: %v", err)
	}
	p := *shipped
	p.Headers = append([]profile.Field(nil), shipped.Headers...)

	block := []profile.Field{
		{Name: "x-browser-channel", Value: "stable"},
		{Name: "x-browser-year", Value: "2026"},
		{Name: validationHeader, Value: "iix1/iDR1W9e3SUCZHWKwrVpus8="},
		{Name: "x-browser-copyright", Value: "Copyright 2026 Google LLC. All Rights Reserved."},
		{Name: "x-client-data", Value: "CKuWywE="},
	}
	p.Google = &profile.Google{After: "accept", Headers: block}
	return &p
}

// loopbackProxy answers every CONNECT with a pipe to one address, which is how a
// test reaches a local server under a name it does not own. Without it, asking
// this client for https://www.google.com/ would ask the real one.
func loopbackProxy(t *testing.T, to string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			down, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = down.Close() }()
				buffered := bufio.NewReader(down)
				if _, err := fhttp.ReadRequest(buffered); err != nil {
					return
				}
				up, err := net.Dial("tcp", to)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				if _, err := io.WriteString(down, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				// From the buffered reader, not the connection: the client may
				// already have sent its first TLS bytes behind the CONNECT.
				go func() { _, _ = io.Copy(up, buffered) }()
				_, _ = io.Copy(down, up)
			}()
		}
	}()
	return "http://" + listener.Addr().String()
}

// TestGoogleHeadersReachTheWire is the whole feature, checked where it counts:
// on the bytes, in order, for a Google host and not for any other.
func TestGoogleHeadersReachTheWire(t *testing.T) {
	server := startEcho(t)
	client := newTestClient(t,
		WithProfileValue(googleProfile(t)),
		WithProxy(loopbackProxy(t, server.Addr())))

	sent := func(target string) []string {
		t.Helper()
		res, err := client.Get(target + "/api/all")
		if err != nil {
			t.Fatalf("Get %s: %v", target, err)
		}
		var got capture.Capture
		if err := json.Unmarshal(res.Body, &got); err != nil {
			t.Fatalf("reading the echo: %v", err)
		}
		if got.HTTP2 == nil {
			t.Fatal("no HTTP/2 data came back")
		}
		return got.HTTP2.HeaderOrder
	}

	order := strings.Join(sent("https://www.google.com"), ",")
	want := "accept,x-browser-channel,x-browser-year,x-browser-validation," +
		"x-browser-copyright,x-client-data,sec-fetch-site"
	if !strings.Contains(order, want) {
		t.Errorf("the block did not go out in the browser's order:\n got %s\nwant …%s…", order, want)
	}

	for _, name := range sent("https://example.com") {
		if strings.HasPrefix(name, "x-browser") || name == "x-client-data" {
			t.Errorf("%s was sent to a host that is not Google's", name)
		}
	}
}

func TestHeadersForPicksTheList(t *testing.T) {
	client := newTestClient(t, WithProfileValue(googleProfile(t)))
	google, _ := url.Parse("https://news.google.com/")
	if !client.headersFor(google).Has(validationHeader) {
		t.Error("a Google host did not get the Google list")
	}
	other, _ := url.Parse("https://example.com/")
	if client.headersFor(other).Has(validationHeader) {
		t.Error("a host that is not Google's got the Google list")
	}
	// A nil URL cannot arrive through Do, which parses before it asks. It is
	// still the one input for which "no host" and "Google's host" would be the
	// same answer, so the answer is pinned here rather than left to chance.
	if client.headersFor(nil).Has(validationHeader) {
		t.Error("a nil URL got the Google list")
	}

	// A profile with no Google list treats every host alike.
	plain := newTestClient(t)
	if plain.headersFor(google).Has(validationHeader) {
		t.Error("a profile without a Google list produced one")
	}
}

func TestClientHeadersOverrideTheGoogleList(t *testing.T) {
	client := newTestClient(t,
		WithProfileValue(googleProfile(t)),
		WithHeaders(NewHeader("accept-language", "de-DE,de;q=0.9")))
	google, _ := url.Parse("https://www.google.com/")
	if got := client.headersFor(google).Get("accept-language"); got != "de-DE,de;q=0.9" {
		t.Errorf("accept-language = %q; a caller's headers must reach Google too", got)
	}
}

func TestValidationIsDroppedWhenTheUserAgentIsNot(t *testing.T) {
	const ua = "Mozilla/5.0 Chrome/151.0.0.0"
	block := Header{
		{Name: "user-agent", Value: ua},
		{Name: validationHeader, Value: "iix1/iDR1W9e3SUCZHWKwrVpus8="},
	}

	if got := withoutStaleValidation(block, ua); !got.Has(validationHeader) {
		t.Error("the token was dropped from a request carrying the user-agent it was measured with")
	}
	got := withoutStaleValidation(block, "Mozilla/5.0 Chrome/152.0.0.0")
	if got.Has(validationHeader) {
		t.Error("the token survived a user-agent it was not measured with")
	}
	if !block.Has(validationHeader) {
		t.Error("the caller's own header list was modified")
	}
	// Nothing to drop is the common case, and it must not copy.
	plain := Header{{Name: "user-agent", Value: "anything"}}
	if len(withoutStaleValidation(plain, ua)) != len(plain) {
		t.Error("a list without the token came back changed")
	}
}

func TestProfileCarriesTheGoogleBlock(t *testing.T) {
	p := googleProfile(t)
	data, err := p.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !strings.Contains(string(data), `"google_headers"`) {
		t.Error("the Google block did not reach the JSON")
	}
	// The block carries only what is not in the ordinary list. A profile that
	// repeated the whole list would still work and would still be wrong.
	if strings.Count(string(data), `"sec-fetch-dest"`) != 1 {
		t.Error("the ordinary headers are in the file twice")
	}

	back, err := profile.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if back.Google == nil || len(back.Google.Headers) != len(p.Google.Headers) {
		t.Errorf("read back %+v, wrote %+v", back.Google, p.Google)
	}
	if back.Google.After != "accept" {
		t.Errorf("after = %q, want accept", back.Google.After)
	}
}
