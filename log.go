package tlsforge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttptrace "github.com/bogdanfinn/fhttp/httptrace"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
)

// Logging: what a client does to make a request, written down as it does it.
//
// A Trace hands a caller the moments of one request, and a response says how
// one ended. A log is for the request that went wrong and is looked into
// afterwards by somebody who was not watching. So each step is a record of its
// own, written when it happens, with what it found: what a name resolved to and
// which address answered, what a proxy said to CONNECT, what a handshake
// settled on, the ClientHello it was answered to and the certificates the
// server showed, which header fields went out in which order. A request that
// failed says which step it was in when it did. Every record that ends a step
// says how long the step took.
//
// Secrets stay out, as everywhere this project writes something down to be
// kept: a proxy's password, and the values of cookies and credentials.

// LevelTrace is the most a client says, below slog.LevelDebug: the ClientHello
// every connection sent, and every certificate a server showed.
const LevelTrace = slog.Level(-8)

// clientCount numbers the clients of the process, so that a log can tell their
// connections apart.
var clientCount atomic.Uint64

// logKey carries a request's log on its context: to the dialer that opens its
// connection, and to the policy that follows its redirects.
type logKey struct{}

// requestLogOf is the log a context carries, or nil.
func requestLogOf(ctx context.Context) *requestLog {
	r, _ := ctx.Value(logKey{}).(*requestLog)
	return r
}

// watchDial has a dial that no request is waiting on logged to the client's
// log. HTTP/2 dials every connection after a client's first that way, apart
// from the request that needs it. A dial a request waits on is logged with the
// request, whose hooks its context already carries.
func watchDial(ctx context.Context, log *slog.Logger, proxy string) context.Context {
	if log == nil || requestLogOf(ctx) != nil {
		return ctx
	}
	return newRequestLog(log.With("background", true), proxy, "connect").attachDial(ctx)
}

// requestLog writes one request down as it goes, or one dial, and keeps the
// step it is in, so that a request that fails can say where.
type requestLog struct {
	log *slog.Logger
	// proxy is the one the request goes through, which errors are cleaned of.
	proxy string
	began time.Time

	mu sync.Mutex
	// phase is the step in progress, since when; host is the name being looked
	// up, and dials when each address began to be dialled.
	phase string
	since time.Time
	host  string
	dials map[string]time.Time
}

func newRequestLog(log *slog.Logger, proxy, phase string) *requestLog {
	now := time.Now()
	return &requestLog{log: log, proxy: proxy, began: now, since: now, phase: phase,
		dials: map[string]time.Time{}}
}

// step begins a step, and is how long the one before it took.
func (r *requestLog) step(phase string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	took := now.Sub(r.since)
	r.phase, r.since = phase, now
	return took
}

// in is the step in progress.
func (r *requestLog) in() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.phase
}

// sinceStep is how long the step in progress has gone on.
func (r *requestLog) sinceStep() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Since(r.since)
}

// trace logs at LevelTrace, when anybody listens that low: what it says takes
// work to put together.
func (r *requestLog) trace(msg string, args ...any) {
	if r.log.Enabled(context.Background(), LevelTrace) {
		r.log.Log(context.Background(), LevelTrace, msg, args...)
	}
}

// errorText is an error as the log says it, without the proxy's password.
func (r *requestLog) errorText(err error) string {
	return redact.Error(err, r.proxy)
}

// attachDial hangs on a context what a dial is told: lookups and TCP dials,
// made by the standard library's dialer, which reads its hooks from the
// standard library's trace. Beside any a caller's Trace hung there: both are
// told.
func (r *requestLog) attachDial(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, logKey{}, r)
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart:     func(info httptrace.DNSStartInfo) { r.dnsStart(info.Host) },
		DNSDone:      r.dnsDone,
		ConnectStart: r.connectStart,
		ConnectDone:  r.connectDone,
	})
}

// attach hangs the whole request's hooks on its context: the dial's, and the
// transport's for the connection and what is written over it.
func (r *requestLog) attach(ctx context.Context) context.Context {
	ctx = r.attachDial(ctx)
	// The fields of one request, gathered as each is written, and started
	// afresh with every connection handed over, so that a hop of a redirect
	// says its own.
	var mu sync.Mutex
	var sent []string
	return fhttptrace.WithClientTrace(ctx, &fhttptrace.ClientTrace{
		GetConn: func(hostPort string) { r.trace("connection wanted", "to", hostPort) },
		GotConn: func(info fhttptrace.GotConnInfo) {
			mu.Lock()
			sent = nil
			mu.Unlock()
			r.gotConn(info)
		},
		PutIdleConn: r.putIdleConn,
		WroteHeaderField: func(name string, values []string) {
			mu.Lock()
			defer mu.Unlock()
			for _, value := range values {
				sent = append(sent, name+": "+redact.Value(name, value))
			}
		},
		WroteRequest: func(info fhttptrace.WroteRequestInfo) {
			mu.Lock()
			written := sent
			sent = nil
			mu.Unlock()
			r.wroteRequest(written, info.Err)
		},
		GotFirstResponseByte: r.firstByte,
	})
}

func (r *requestLog) dnsStart(host string) {
	r.step("dns")
	r.mu.Lock()
	r.host = host
	r.mu.Unlock()
	r.log.Debug("dns lookup", "host", host)
}

func (r *requestLog) dnsDone(info httptrace.DNSDoneInfo) {
	r.mu.Lock()
	host, took := r.host, time.Since(r.since)
	r.mu.Unlock()
	if info.Err != nil {
		r.log.Warn("dns failed", "host", host, "error", info.Err.Error(), "took", took)
		return
	}
	addrs := make([]string, 0, len(info.Addrs))
	for _, addr := range info.Addrs {
		addrs = append(addrs, addr.String())
	}
	r.log.Debug("dns answer", "host", host, "addrs", addrs, "took", took)
}

func (r *requestLog) connectStart(network, addr string) {
	r.mu.Lock()
	now := time.Now()
	r.dials[addr] = now
	if r.phase != "connect" {
		r.phase, r.since = "connect", now
	}
	r.mu.Unlock()
	r.log.Debug("dial", "network", network, "addr", addr)
}

func (r *requestLog) connectDone(network, addr string, err error) {
	r.mu.Lock()
	took := time.Since(r.dials[addr])
	delete(r.dials, addr)
	r.mu.Unlock()
	if err != nil {
		// Not the end of the request when the name has another address, which
		// a name with an IPv6 address no route leads to has every time: the
		// request's own failure, when it is one, says it.
		r.log.Debug("dial failed", "network", network, "addr", addr, "error", r.errorText(err), "took", took)
		return
	}
	next := "tls"
	if r.proxy != "" {
		next = "proxy"
	}
	r.step(next)
	r.log.Debug("dialed", "network", network, "addr", addr, "took", took)
}

func (r *requestLog) gotConn(info fhttptrace.GotConnInfo) {
	took := r.step("send")
	name := connName(info.Conn)
	if info.Reused {
		r.log.Debug("reused connection", "conn", name, "idle", info.IdleTime, "took", took)
		return
	}
	attrs := []any{"conn", name}
	if through := tunnelOf(info.Conn); through != nil {
		attrs = append(attrs, "tunnel", through.id)
	}
	secure, isSecure := info.Conn.(connectionStater)
	if !isSecure {
		r.log.Debug("connected", append(attrs, "took", took)...)
		return
	}
	state := secure.ConnectionState()
	attrs = append(attrs, "tls", utls.VersionName(state.Version), "cipher", utls.CipherSuiteName(state.CipherSuite),
		"alpn", state.NegotiatedProtocol, "resumed", state.DidResume, "server_name", state.ServerName)
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		attrs = append(attrs, "certificate", leaf.Subject.String(), "issuer", leaf.Issuer.String(),
			"expires", leaf.NotAfter)
	}
	r.log.Debug("connected", append(attrs, "took", took)...)
	if r.log.Enabled(context.Background(), LevelTrace) {
		r.handshake(name, info.Conn, state)
	}
}

// handshake is what a connection's handshake was, in full: the ClientHello it
// sent, and each certificate the server answered with. The length of the ECH
// payload is said because it is drawn afresh for each connection, as Chrome
// draws it, and is nowhere else to be seen.
func (r *requestLog) handshake(name string, conn net.Conn, state utls.ConnectionState) {
	if hello := sentHello(conn); hello != nil {
		sent := capture.FromClientHello(hello)
		args := []any{"conn", name, "ja4", sent.JA4, "ja4_r", sent.JA4Raw,
			"ja3", sent.JA3, "ja3_hash", sent.JA3Hash, "server_name", sent.ServerName, "alpn", sent.ALPN,
			"extensions", valueNames(sent.Extensions), "cipher_suites", valueNames(sent.CipherSuites),
			"versions", valueNames(sent.SupportedVersions), "groups", valueNames(sent.SupportedGroups),
			"key_shares", valueNames(sent.KeyShareGroups),
			"signature_algorithms", valueNames(sent.SignatureAlgorithms),
			"pre_shared_key", sent.Resumed, "bytes", len(hello.Raw)}
		if ech, ok := hello.EncryptedClientHello(); ok {
			args = append(args, "ech_payload_bytes", ech.PayloadLength)
		}
		r.trace("client hello", args...)
	}
	for depth, cert := range state.PeerCertificates {
		r.trace("certificate", certificateArgs(name, depth, cert)...)
	}
	r.trace("handshake extras", "conn", name, "ocsp_bytes", len(state.OCSPResponse),
		"scts", len(state.SignedCertificateTimestamps), "verified_chains", len(state.VerifiedChains))
}

func (r *requestLog) putIdleConn(err error) {
	if err != nil {
		r.log.Debug("connection not kept", "reason", err.Error())
		return
	}
	r.log.Debug("connection kept for the next request")
}

func (r *requestLog) wroteRequest(sent []string, err error) {
	took := r.step("wait")
	if err != nil {
		r.log.Warn("send failed", "error", r.errorText(err), "took", took)
		return
	}
	r.log.Debug("request sent", "headers", sent, "took", took)
}

func (r *requestLog) firstByte() {
	r.log.Debug("first byte", "took", r.step("receive"))
}

// redirect is a hop about to be followed, which starts the steps again: the
// answer that said so, and where it leads.
func (r *requestLog) redirect(hop, status int, location string, header map[string][]string) {
	took := r.step("redirect")
	r.log.Debug("redirect", "hop", hop, "status", status, "location", redact.URL(location),
		"headers", sortedHeaderLines(header), "took", took)
}

// stopped is a redirect that is not followed, the chain being as long as a
// request lets one be.
func (r *requestLog) stopped(hop, status int, location string) {
	took := r.step("redirect")
	r.log.Warn("redirect not followed", "hop", hop, "status", status, "location", redact.URL(location),
		"limit", maxRedirects, "took", took)
}

// preflight is the answer to a CORS preflight: allowed, or why not.
func (r *requestLog) preflight(target string, status int, refused error) {
	took := r.step("preflight")
	if refused != nil {
		r.log.Warn("preflight refused", "url", redact.URL(target), "status", status, "why", refused.Error(),
			"took", took)
		return
	}
	r.log.Info("preflight", "url", redact.URL(target), "status", status, "took", took)
}

// hintsAsked is what an origin asked for with Accept-CH: the client hints
// its navigations carry from then on, none for an empty one.
func (r *requestLog) hintsAsked(o origin, hints []string) {
	r.log.Debug("client hints asked", "origin", o.String(), "hints", strings.Join(hints, ","))
}

// restarted is a navigation started again for the client hints its answer
// from url said it needs.
func (r *requestLog) restarted(url string, hints []string) {
	r.log.Info("restarted for client hints", "url", redact.URL(url), "hints", strings.Join(hints, ","))
}

// start says what is asked for.
func (r *requestLog) start(method, rawURL string, body int) {
	attrs := []any{"method", method, "url", redact.URL(rawURL)}
	if r.proxy != "" {
		attrs = append(attrs, "proxy", redact.URL(r.proxy))
	}
	if body > 0 {
		attrs = append(attrs, "body_bytes", body)
	}
	r.log.Info("request", attrs...)
}

// answered is the answer's head, said before its body is read: a body that
// cannot be read still has a status and header fields to show.
func (r *requestLog) answered(res *fhttp.Response) {
	took := r.step("body")
	r.log.Debug("response headers", "status", res.StatusCode, "proto", res.Proto,
		"headers", sortedHeaderLines(res.Header), "took", took)
}

// ended says how the request ended: its answer, or why there is none and in
// which step it gave up.
func (r *requestLog) ended(res *Response, err error) {
	took := time.Since(r.began)
	if err != nil {
		r.log.Warn("request failed", "phase", r.in(), "error", r.errorText(err),
			"timeout", isTimeout(err), "took", took)
		return
	}
	attrs := []any{"status", res.Status, "bytes", len(res.Body), "url", redact.URL(res.URL)}
	if res.Encoding != "" {
		attrs = append(attrs, "decoded_from", res.Encoding)
	}
	r.log.Info("response", append(attrs, "took", took)...)
}

// What became of a tunnel, as connectDialer tells it.

// proxyTLS is the handshake with an HTTPS proxy, before it is asked for
// anything.
func (r *requestLog) proxyTLS(state tls.ConnectionState, err error) {
	took := r.step("proxy")
	if err != nil {
		r.log.Warn("proxy tls failed", "error", r.errorText(err), "took", took)
		return
	}
	attrs := []any{"tls", tls.VersionName(state.Version), "cipher", tls.CipherSuiteName(state.CipherSuite),
		"alpn", state.NegotiatedProtocol}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		attrs = append(attrs, "certificate", leaf.Subject.String(), "issuer", leaf.Issuer.String(),
			"expires", leaf.NotAfter)
	}
	r.log.Debug("proxy tls", append(attrs, "took", took)...)
}

// proxyAsk is the CONNECT, as it goes to the proxy.
func (r *requestLog) proxyAsk(target string, header fhttp.Header) {
	r.log.Debug("proxy connect", "proxy", redact.URL(r.proxy), "target", target,
		"headers", sortedHeaderLines(header))
}

// proxyAnswer is a tunnel the proxy opened, with what it said when it did.
func (r *requestLog) proxyAnswer(answer *fhttp.Response, tunnel uint64) {
	took := r.step("tls")
	r.log.Debug("proxy answer", "status", answer.Status, "tunnel", tunnel,
		"headers", sortedHeaderLines(answer.Header), "took", took)
}

// proxyRefused is a tunnel the proxy would not open, with why, as far as it
// said.
func (r *requestLog) proxyRefused(answer *fhttp.Response, said string) {
	r.log.Warn("proxy refused", "status", answer.Status, "headers", sortedHeaderLines(answer.Header),
		"body", said, "took", r.sinceStep())
}

// proxyFailed is a CONNECT that got no answer at all.
func (r *requestLog) proxyFailed(err error) {
	r.log.Warn("proxy connect failed", "error", r.errorText(err), "took", r.sinceStep())
}

// refusalBody is the start of what a proxy said when it would not open a
// tunnel, which is usually why: as much as it said it would send, up to 1 KiB.
// Nothing when it did not say how much, since that is read until the deadline.
func refusalBody(answer *fhttp.Response) string {
	if answer.ContentLength <= 0 {
		return ""
	}
	body := make([]byte, min(answer.ContentLength, 1024))
	n, _ := io.ReadFull(answer.Body, body)
	return string(body[:n])
}

// isTimeout says an error is a deadline running out rather than a refusal.
func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &timeout) && timeout.Timeout())
}

// connName names a connection by its two ends, which tells it from another in
// a log and is the same for every request it carries.
func connName(conn net.Conn) string {
	local, remote := "?", "?"
	if addr := conn.LocalAddr(); addr != nil {
		local = addr.String()
	}
	if addr := conn.RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	return local + "->" + remote
}

// sentHello is the ClientHello a connection's handshake began with, or nil.
// utls keeps the handshake message, and the parser reads records, so it is
// given one record holding it.
func sentHello(conn net.Conn) *fingerprint.ClientHello {
	uconn, ok := conn.(*utls.UConn)
	if !ok || uconn.HandshakeState.Hello == nil {
		return nil
	}
	message := uconn.HandshakeState.Hello.Raw
	record := append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...)
	hello, err := fingerprint.ParseClientHello(record)
	if err != nil {
		return nil
	}
	return hello
}

// certificateArgs are one certificate of a server's chain, as the log says it.
func certificateArgs(conn string, depth int, cert *x509.Certificate) []any {
	addresses := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		addresses = append(addresses, ip.String())
	}
	return []any{"conn", conn, "depth", depth, "subject", cert.Subject.String(), "issuer", cert.Issuer.String(),
		"serial", hex.EncodeToString(cert.SerialNumber.Bytes()), "not_before", cert.NotBefore,
		"not_after", cert.NotAfter, "dns_names", cert.DNSNames, "ip_addresses", addresses,
		"signature", cert.SignatureAlgorithm.String(), "key", cert.PublicKeyAlgorithm.String()}
}

// valueNames are wire codes by their names.
func valueNames(values []capture.Value) []string {
	names := make([]string, 0, len(values))
	for _, value := range values {
		names = append(names, value.Name)
	}
	return names
}

// sortedHeaderLines are header fields as "name: value" lines, sorted by name,
// which is the only order a map of them has, and without their secrets.
func sortedHeaderLines(header map[string][]string) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := []string{}
	for _, name := range names {
		for _, value := range header[name] {
			lines = append(lines, name+": "+redact.Value(name, value))
		}
	}
	return lines
}

// describe is what a client is, as its first records say: the profile and
// where it came from, and the handshake and the HTTP/2 preface it sends, as the
// transport was given them, which for a profile out of tls-client's catalogue
// is the only place they are.
func (c *Client) describe(cfg config, shuffles bool, sends profiles.ClientProfile) {
	p := c.profile
	order := "fixed"
	if shuffles {
		order = "shuffled for every connection"
	}
	attrs := []any{"profile", p.Name, "user_agent", p.UserAgent,
		"timeout", cfg.timeout, "follow_redirects", cfg.followRedirects,
		"session_resumption", !cfg.noResumption, "extension_order", order,
		"verify_certificates", !cfg.insecureSkipVerify, "cookie_jar", c.session.jar != nil,
		"warmed_cookies", len(cfg.cookies), "max_body", cfg.maxResponseBody}
	if cfg.proxy != "" {
		attrs = append(attrs, "proxy", redact.URL(cfg.proxy))
	}
	if p.Source() != "" {
		attrs = append(attrs, "file", p.Source())
	}
	c.log.Info("client", attrs...)

	if len(p.ClientHello) == 0 {
		c.log.Debug("profile handshake", "from", "tls-client's catalogue", "base", p.Base)
	} else if hello, err := fingerprint.ParseClientHello(p.ClientHello); err == nil {
		c.log.Debug("profile handshake", "from", "captured", "ja4", hello.JA4(), "alpn", hello.ALPN(),
			"extensions", len(hello.Extensions), "cipher_suites", len(hello.CipherSuites), "notes", p.Notes)
	}
	preface := &fingerprint.HTTP2{WindowUpdate: sends.GetConnectionFlow()}
	settings := []string{}
	for _, id := range sends.GetSettingsOrder() {
		value := sends.GetSettings()[id]
		preface.Settings = append(preface.Settings, fingerprint.Setting{ID: uint16(id), Value: value})
		settings = append(settings, fingerprint.SettingName(uint16(id))+"="+strconv.FormatUint(uint64(value), 10))
	}
	for _, priority := range sends.GetPriorities() {
		param := priority.PriorityParam
		preface.Priorities = append(preface.Priorities, fingerprint.Priority{StreamID: priority.StreamID,
			Exclusive: param.Exclusive, DependsOn: param.StreamDep, Weight: param.Weight})
	}
	for _, name := range sends.GetPseudoHeaderOrder() {
		preface.Headers = append(preface.Headers, fingerprint.HeaderField{Name: name})
	}
	c.log.Debug("profile http2", "akamai", preface.Akamai(), "settings", settings,
		"window_update", sends.GetConnectionFlow(), "pseudo_header_order", sends.GetPseudoHeaderOrder(),
		"priorities", len(preface.Priorities))
	names := []string{}
	for _, field := range c.headers {
		names = append(names, field.Name)
	}
	c.log.Debug("profile headers", "order", names)
}
