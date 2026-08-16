package proxy

import (
	"crypto/tls"
	"net"
)

// tlsServer wraps an accepted connection in TLS using a per-host certificate.
//
// Split out so the handshake side is one line at the call site, and so the
// protocol list lives in one place: HTTP/1.1 only, on purpose. Answering "h2"
// here would oblige the proxy to speak HTTP/2 to its caller, which is a second
// protocol implementation for no gain — the connection to the destination is
// where the HTTP/2 fingerprint matters, and that one is the client's to make.
func tlsServer(conn net.Conn, cert *tls.Certificate) *tls.Conn {
	return tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
}
