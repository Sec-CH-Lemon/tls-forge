package tlsforge

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"
)

// tls-client files its connections, and the protocol each speaks, by the
// host and port of a request's URL, and reads a URL that names no port as one
// on 443 whatever its scheme. So http://example.com/ went out on whatever
// https://example.com/ had: after an HTTP/2 request a plain one failed
// ("http2: unsupported scheme"), and a plain request redirected to HTTPS on
// its own host failed there ("protocol negotiated"). A plain-http request is
// told the port its URL means, 80, and keeps the host it was asked for: Host
// says that one, and the request is shown by it.

// withPort gives a plain-http request whose URL names no port the one it
// means, and keeps the host as asked in req.Host.
func withPort(req *fhttp.Request) {
	if req.URL.Scheme != "http" || req.URL.Port() != "" {
		return
	}
	req.Host = req.URL.Host
	req.URL.Host = net.JoinHostPort(req.URL.Hostname(), "80")
}

// shownURL is the URL a request was asked for: its own, without the port
// withPort told the transport.
func shownURL(req *fhttp.Request) *url.URL {
	u := req.URL
	if u.Scheme != "http" || req.Host == "" || u.Host != net.JoinHostPort(strings.Trim(req.Host, "[]"), "80") {
		return u
	}
	shown := *u
	shown.Host = req.Host
	return &shown
}

// transportError is a failure of the transport, quoting the URL it failed on
// without the port 80 of plain HTTP: the port withPort told it, and the one a
// browser leaves out.
func transportError(err error) error {
	var quoted *url.Error
	if errors.As(err, &quoted) {
		quoted.URL = withoutDefaultPort(quoted.URL)
	}
	return fmt.Errorf("tlsforge: %w", err)
}

// withoutDefaultPort is a URL, as text, without the port 80 of plain HTTP.
// Text, not a url.URL, as the transport quotes a password as "***", which a
// URL would escape.
func withoutDefaultPort(raw string) string {
	rest, ok := strings.CutPrefix(raw, "http://")
	if !ok {
		return raw
	}
	end := len(rest)
	if at := strings.IndexAny(rest, "/?#"); at >= 0 {
		end = at
	}
	// The host ends the authority, after any credentials.
	if !strings.HasSuffix(rest[:end], ":80") {
		return raw
	}
	return "http://" + rest[:end-len(":80")] + rest[end:]
}
