package tlsforge

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// The ECH a direct connection offers from its server's HTTPS records, held to
// Chrome 155's, measured: testdata/chrome155-ech-dns.json.

// echDNSFixture is the measurement: each scenario's runs, and the hellos
// whose inner hellos the server opened; and the fields of requests an HTTPS
// record sent to https, by protocol and case.
type echDNSFixture struct {
	Scenarios map[string]struct {
		Steps []string
		Runs  []echDNSRun
	}
	Hellos []struct {
		Scenario        string
		Cohort, Conn, N int
		Config          string
		ConfigHex       string `json:"config_hex"`
		Outer, Inner    string
		Encoded         string
	}
	Upgrade map[string]map[string][]string
}

// echDNSRun is one run of a scenario: what Chrome asked, its connections,
// its requests and their connections, its navigation's error.
type echDNSRun struct {
	DNS         []struct{ Type, Name string }
	Connections []echDNSConnection
	Requests    []struct {
		Conn      int
		Host, URI string
	}
	Error string
}

// echDNSConnection is what a connection's first hello offered: ECH with a
// config (and AEAD), GREASE ECH, or none; and what came of it.
type echDNSConnection struct {
	Conn        int
	Listener    string
	SNI         string
	Hello       string
	Config      string
	AEAD        int
	PSK         bool
	HRR         bool
	ECHAccepted bool `json:"ech_accepted"`
	Resumed     bool
}

// kind is the connection's as kindOf says one.
func (c echDNSConnection) kind() string {
	if c.Hello == "ech" {
		return "ech:" + c.Config
	}
	return c.Hello
}

func echDNSMeasured(t *testing.T) echDNSFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/chrome155-ech-dns.json")
	if err != nil {
		t.Fatal(err)
	}
	var f echDNSFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// helloOf reads a ClientHello handshake message: its random, session ID,
// cipher suites and extensions, in order.
type helloOf struct {
	random, session []byte
	suites          []uint16
	exts            []helloExt
}

type helloExt struct {
	id   uint16
	data []byte
}

func readHello(t *testing.T, raw []byte) helloOf {
	t.Helper()
	h := helloOfBytes(raw)
	if h.random == nil {
		t.Fatalf("hello %x does not read", raw[:min(len(raw), 16)])
	}
	return h
}

func (h helloOf) ext(id uint16) ([]byte, bool) {
	for _, e := range h.exts {
		if e.id == id {
			return e.data, true
		}
	}
	return nil, false
}

func greased(id uint16) bool { return id&0x0f0f == 0x0a0a && id>>8 == id&0xff }

// shape is a hello's extensions by type, GREASE named once, sorted.
func (h helloOf) shape() []uint16 {
	var out []uint16
	for _, e := range h.exts {
		id := e.id
		if greased(id) {
			id = 0x0a0a
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// chromeInnerRule says what of an outer and inner hello is not as the
// profile's layout makes the inner of the outer: own are the extensions it
// writes itself, omitted those it leaves out, the rest taken from the outer
// in its order, a session's PSK last; suites and versions of TLS 1.3 and
// GREASE; its own random and the outer's session; padded as RFC 9849 says;
// the outer with no PSK.
func chromeInnerRule(t *testing.T, outer, inner helloOf, encoded []byte, payload, maxName int, own, omitted []uint64) []string {
	t.Helper()
	var bad []string
	has := func(list []uint64, id uint16) bool { return slices.Contains(list, uint64(id)) }
	var want, got []uint16
	for _, e := range outer.exts {
		if has(own, e.id) {
			want = append(want, e.id)
		}
		if e.id == 41 {
			bad = append(bad, "outer pre_shared_key")
		}
	}
	for _, e := range outer.exts {
		if !has(own, e.id) && !has(omitted, e.id) && e.id != 41 && e.id != 21 {
			want = append(want, e.id)
		}
	}
	if _, ok := inner.ext(41); ok {
		want = append(want, 41)
	}
	for _, e := range inner.exts {
		got = append(got, e.id)
	}
	if !slices.Equal(got, want) {
		bad = append(bad, fmt.Sprintf("extensions %v, want %v", got, want))
	}
	for _, e := range inner.exts {
		if d, ok := outer.ext(e.id); ok && !has(own, e.id) && e.id != 41 && !bytes.Equal(d, e.data) {
			bad = append(bad, fmt.Sprintf("extension %d is not the outer's", e.id))
		}
	}
	var tls13 []uint16
	for _, s := range outer.suites {
		if greased(s) || s>>8 == 0x13 {
			tls13 = append(tls13, s)
		}
	}
	if !slices.Equal(inner.suites, tls13) {
		bad = append(bad, "suites")
	}
	if v, _ := inner.ext(43); len(v) != 5 || !greased(binary.BigEndian.Uint16(v[1:])) || binary.BigEndian.Uint16(v[3:]) != 0x0304 {
		bad = append(bad, fmt.Sprintf("versions %x", v))
	}
	if e, _ := inner.ext(0xfe0d); !bytes.Equal(e, []byte{1}) {
		bad = append(bad, "inner ECH")
	}
	if bytes.Equal(inner.random, outer.random) || !bytes.Equal(inner.session, outer.session) {
		bad = append(bad, "random or session")
	}
	sni, _ := inner.ext(0)
	unpadded := encodedLength(encoded)
	pad := max(0, maxName-(len(sni)-5))
	pad += 31 - (unpadded+pad-1)%32
	if unpadded < 0 || len(encoded) != unpadded+pad || bytes.ContainsFunc(encoded[unpadded:], func(r rune) bool { return r != 0 }) {
		bad = append(bad, fmt.Sprintf("padding: %d of %d", len(encoded)-unpadded, len(encoded)))
	}
	if payload != len(encoded)+16 {
		bad = append(bad, "payload")
	}
	return bad
}

// encodedLength is how much of an encoding its ClientHello takes, or -1.
func encodedLength(encoded []byte) int {
	s := cryptobyte.String(encoded)
	var session, suites, compression, exts cryptobyte.String
	if !s.Skip(34) || !s.ReadUint8LengthPrefixed(&session) || !s.ReadUint16LengthPrefixed(&suites) ||
		!s.ReadUint8LengthPrefixed(&compression) || !s.ReadUint16LengthPrefixed(&exts) {
		return -1
	}
	return len(encoded) - len(s)
}

// echLayout is the layout chrome_155_macos says of the inner hello.
func echLayout(t *testing.T) (own, omitted []uint64) {
	t.Helper()
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	b := p.RuntimeBehavior()
	return b.Numbers("tls.ech_inner_own"), b.Numbers("tls.ech_inner_omitted")
}

func TestTheProfilesInnerHelloLayoutIsChromesMeasured(t *testing.T) {
	// Every hello of Chrome's a server opened is made as the profile's
	// layout says: the JSON is held to the measurement.
	f := echDNSMeasured(t)
	own, omitted := echLayout(t)
	if len(f.Hellos) < 40 {
		t.Fatalf("%d hellos", len(f.Hellos))
	}
	for _, h := range f.Hellos {
		outer, inner := readHello(t, unhexed(t, h.Outer)), readHello(t, unhexed(t, h.Inner))
		config := unhexed(t, h.ConfigHex)
		maxName := int(config[len(config)-2-1-len("public.ech.test")-1])
		payload := 0
		if e, ok := outer.ext(0xfe0d); ok {
			s := cryptobyte.String(e[6:])
			var enc, p cryptobyte.String
			s.ReadUint16LengthPrefixed(&enc)
			s.ReadUint16LengthPrefixed(&p)
			payload = len(p)
		}
		if bad := chromeInnerRule(t, outer, inner, unhexed(t, h.Encoded), payload, maxName, own, omitted); bad != nil {
			t.Errorf("%s %d/%d/%d: %v", h.Scenario, h.Cohort, h.Conn, h.N, bad)
		}
	}
}

func unhexed(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// echKey is a config of a test site's and the key that opens what is sealed
// to it.
type echKey struct {
	id     uint8
	config []byte
	key    *ecdh.PrivateKey
}

func newECHKey(t *testing.T, id uint8, curve ecdh.Curve, kem uint16, suites [][2]uint16, maxName uint8) echKey {
	t.Helper()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(kem)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range suites {
				b.AddUint16(s[0])
				b.AddUint16(s[1])
			}
		})
		b.AddUint8(maxName)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.ech.test")) })
		b.AddUint16(0)
	})
	return echKey{id: id, config: b.BytesOrPanic(), key: key}
}

func echList(keys ...echKey) string {
	var body []byte
	for _, k := range keys {
		body = append(body, k.config...)
	}
	return string(append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...))
}

// echConnSeen is a connection an echSite took: its ClientHellos, and what
// was opened of each.
type echConnSeen struct {
	hellos  [][]byte
	opened  [][]byte // each hello's encoded inner, nil where none opened
	inner   [][]byte
	config  []uint8 // the config ID each hello sealed to, 0 for none
	payload []int
	enc     []int
	request string
}

// echSite is a site under ech.test of crypto/tls's server, which offers ECH
// with serve and keeps each connection's ClientHellos, opening them with every
// key of keys.
type echSite struct {
	server *httptest.Server
	port   string
	keys   []echKey
	mu     sync.Mutex
	conns  []*echConnSeen
}

type helloTap struct {
	net.Conn
	seen    *echConnSeen
	site    *echSite
	buf, hs []byte
	done    bool
	opener  *hpke.Recipient
}

func (h *helloTap) Read(p []byte) (int, error) {
	n, err := h.Conn.Read(p)
	h.site.mu.Lock()
	defer h.site.mu.Unlock()
	if h.done {
		return n, err
	}
	h.buf = append(h.buf, p[:n]...)
	for len(h.buf) >= 5 {
		l := int(h.buf[3])<<8 | int(h.buf[4])
		if len(h.buf) < 5+l {
			break
		}
		typ, frag := h.buf[0], h.buf[5:5+l]
		h.buf = h.buf[5+l:]
		switch typ {
		case 22:
			h.hs = append(h.hs, frag...)
			for len(h.hs) >= 4 {
				ml := int(h.hs[1])<<16 | int(h.hs[2])<<8 | int(h.hs[3])
				if len(h.hs) < 4+ml {
					break
				}
				if h.hs[0] == 1 {
					h.hello(slices.Clone(h.hs[:4+ml]))
				}
				h.hs = h.hs[4+ml:]
			}
		case 20:
		default:
			h.done = true
		}
	}
	return n, err
}

// hello keeps raw, and opens it when it is sealed to a key of the site's.
func (h *helloTap) hello(raw []byte) {
	s := h.seen
	s.hellos = append(s.hellos, raw)
	s.opened, s.inner = append(s.opened, nil), append(s.inner, nil)
	s.config, s.payload, s.enc = append(s.config, 0), append(s.payload, 0), append(s.enc, 0)
	i := len(s.hellos) - 1
	outer := new(helloOf)
	*outer = helloOfBytes(raw)
	e, ok := outer.ext(0xfe0d)
	if !ok || len(e) < 10 || e[0] != 0 {
		return
	}
	r := cryptobyte.String(e[1:])
	var kdf, aead uint16
	var id uint8
	var enc, payload cryptobyte.String
	r.ReadUint16(&kdf)
	r.ReadUint16(&aead)
	r.ReadUint8(&id)
	r.ReadUint16LengthPrefixed(&enc)
	r.ReadUint16LengthPrefixed(&payload)
	s.config[i], s.payload[i], s.enc[i] = id, len(payload), len(enc)
	if h.opener == nil {
		for _, k := range h.site.keys {
			if k.id != id {
				continue
			}
			priv, err1 := hpke.NewDHKEMPrivateKey(k.key)
			kd, err2 := hpke.NewKDF(kdf)
			ae, err3 := hpke.NewAEAD(aead)
			if errors.Join(err1, err2, err3) != nil {
				return
			}
			h.opener, _ = hpke.NewRecipient(enc, priv, kd, ae, append([]byte("tls ech\x00"), k.config...))
		}
	}
	if h.opener == nil {
		return
	}
	encoded, err := h.opener.Open(bytes.Replace(raw[4:], payload, make([]byte, len(payload)), 1), payload)
	if err != nil {
		return
	}
	s.opened[i], s.inner[i] = encoded, expandInner(*outer, encoded)
}

// helloOfBytes is readHello without a test to fail.
func helloOfBytes(raw []byte) helloOf {
	var h helloOf
	b := cryptobyte.String(raw[4:])
	var session, suites, compression, exts cryptobyte.String
	if !b.Skip(2) || !b.ReadBytes(&h.random, 32) || !b.ReadUint8LengthPrefixed(&session) ||
		!b.ReadUint16LengthPrefixed(&suites) || !b.ReadUint8LengthPrefixed(&compression) ||
		!b.ReadUint16LengthPrefixed(&exts) {
		return h
	}
	h.session = session
	for !suites.Empty() {
		var id uint16
		suites.ReadUint16(&id)
		h.suites = append(h.suites, id)
	}
	for !exts.Empty() {
		var e helloExt
		var data cryptobyte.String
		if !exts.ReadUint16(&e.id) || !exts.ReadUint16LengthPrefixed(&data) {
			break
		}
		e.data = data
		h.exts = append(h.exts, e)
	}
	return h
}

// expandInner is the inner hello an encoding says, the outer's extensions it
// names in their place, the outer's session ID its own.
func expandInner(outer helloOf, encoded []byte) []byte {
	s := cryptobyte.String(encoded)
	var vr, session, suites, compression []byte
	var exts cryptobyte.String
	if !s.ReadBytes(&vr, 34) || !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&session)) ||
		!s.ReadUint16LengthPrefixed((*cryptobyte.String)(&suites)) ||
		!s.ReadUint8LengthPrefixed((*cryptobyte.String)(&compression)) || !s.ReadUint16LengthPrefixed(&exts) {
		return nil
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(1)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(vr)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(outer.session) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(suites) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(compression) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for !exts.Empty() {
				var id uint16
				var data cryptobyte.String
				exts.ReadUint16(&id)
				exts.ReadUint16LengthPrefixed(&data)
				if id != 0xfd00 {
					b.AddUint16(id)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
					continue
				}
				var refs cryptobyte.String
				data.ReadUint8LengthPrefixed(&refs)
				for !refs.Empty() {
					var ref uint16
					refs.ReadUint16(&ref)
					d, _ := outer.ext(ref)
					b.AddUint16(ref)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(d) })
				}
			}
		})
	})
	return b.BytesOrPanic()
}

type helloListener struct {
	net.Listener
	site *echSite
}

func (l helloListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.site.mu.Lock()
	defer l.site.mu.Unlock()
	seen := &echConnSeen{}
	l.site.conns = append(l.site.conns, seen)
	return &helloTap{Conn: c, seen: seen, site: l.site}, nil
}

// echSiteCertificate is a certificate for every name under ech.test.
func echSiteCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ech.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"ech.test", "*.ech.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startECHSite serves names under ech.test, offering ECH with served (none:
// a server of no ECH), its key exchanges curves when given, and opening
// hellos with opens too.
func startECHSite(t *testing.T, served []tls.EncryptedClientHelloKey, opens []echKey, curves ...tls.CurveID) *echSite {
	t.Helper()
	site := &echSite{keys: opens}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/close" {
			w.Header().Set("Connection", "close")
		}
		_, _ = io.WriteString(w, "ok "+r.Host)
	}))
	// At [::1] too: TestNoHTTPSRecordIsAskedForWhereChromeAsksForNone asks
	// for it by localhost.
	atLocalhost(t, srv)
	srv.Listener = helloListener{srv.Listener, site}
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{echSiteCertificate(t)}, EncryptedClientHelloKeys: served,
		CurvePreferences: curves}
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			if tap, ok := tc.NetConn().(*helloTap); ok {
				return context.WithValue(ctx, echConnKey{}, tap.seen)
			}
		}
		return ctx
	}
	srv.Config.Handler = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if seen, ok := r.Context().Value(echConnKey{}).(*echConnSeen); ok {
				site.mu.Lock()
				seen.request = fmt.Sprintf("%s %s ech=%v", r.Host, r.URL.Path, r.TLS.ECHAccepted)
				site.mu.Unlock()
			}
			next.ServeHTTP(w, r)
		})
	}(srv.Config.Handler)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	site.server = srv
	_, site.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return site
}

type echConnKey struct{}

// seen is what the site took, connection by connection.
func (s *echSite) seen() []*echConnSeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.conns)
}

// echNames answers for names under ech.test: an address on the machine, and
// the HTTPS record records says of a name (asked about with its port), the
// HTTPS answer late by httpsLate and the address by aLate.
func echNames(t *testing.T, records map[string]*dnsmessage.SVCBResource, aLate, httpsLate time.Duration) *dnsFake {
	t.Helper()
	return startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		name := strings.TrimSuffix(q.Name.String(), ".")
		switch q.Type {
		case dnsmessage.TypeA:
			return []dnsRecord{{name: name, ttl: 60, a: netip.MustParseAddr("127.0.0.1")}}, aLate, 0
		case dnsmessage.TypeHTTPS:
			host := name
			if parts := strings.SplitN(name, ".", 3); len(parts) == 3 && parts[1] == "_https" {
				host = parts[2]
			}
			if r := records[host]; r != nil {
				return []dnsRecord{{name: name, ttl: 60, https: r}}, httpsLate, 0
			}
			return nil, httpsLate, 0
		}
		return nil, 0, 0
	})
}

// echClient is chrome_155_macos asking the names of dns.
func echClient(t *testing.T, dns *dnsFake, opts ...Option) *Client {
	t.Helper()
	c, err := New(append([]Option{WithProfile("chrome_155_macos"), WithDNSServer(dns.addr), WithInsecureSkipVerify(),
		WithTimeout(10 * time.Second)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// kindOf says what a connection's first hello offered, as the fixture says
// it: "ech:NAME" of the config it sealed to (names by ID), "grease", or
// "none"; refused when the server took no request on it.
func (s *echConnSeen) kindOf(names map[uint8]string) string {
	if len(s.hellos) == 0 {
		return "nothing"
	}
	kind := "none"
	if e, ok := helloOfBytes(s.hellos[0]).ext(0xfe0d); ok && len(e) > 0 {
		kind = "grease"
	}
	if s.opened[0] != nil {
		kind = "ech:" + names[s.config[0]]
	}
	return kind
}

func TestARequestOffersTheECHItsNamesHTTPSRecordGivesAsChromeDoes(t *testing.T) {
	good := newECHKey(t, 0x11, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
	site := startECHSite(t, []tls.EncryptedClientHelloKey{{Config: good.config, PrivateKey: good.key.Bytes(), SendAsRetry: true}},
		[]echKey{good})
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"ech.ech.test": service(1, "ech.ech.test", alpnParam("h2"),
		echParam(echList(good)))}, 0, 0)
	c := echClient(t, dns)
	res, err := c.Do(&Request{URL: "https://ech.ech.test:" + site.port + "/"})
	if err != nil || res.Status != 200 {
		t.Fatalf("%v %+v", err, res)
	}
	conns := site.seen()
	if len(conns) != 1 || conns[0].request != "ech.ech.test:"+site.port+" / ech=true" {
		t.Fatalf("the site saw %d connections, %q", len(conns), conns[0].request)
	}
	if q := dns.queries(); !slices.Contains(q, "HTTPS _"+site.port+"._https.ech.ech.test.") ||
		!slices.Contains(q, "A ech.ech.test.") {
		t.Errorf("asked %v", q)
	}
	// The hellos are Chrome's: made as the layout says, of the extensions
	// Chrome's are of, outer and inner.
	f := echDNSMeasured(t)
	own, omitted := echLayout(t)
	outer, inner := helloOfBytes(conns[0].hellos[0]), helloOfBytes(conns[0].inner[0])
	if bad := chromeInnerRule(t, outer, inner, conns[0].opened[0], conns[0].payload[0], 0, own, omitted); bad != nil ||
		conns[0].enc[0] != 32 {
		t.Errorf("not as Chrome makes them: %v, enc %d", bad, conns[0].enc[0])
	}
	sni, _ := outer.ext(0)
	if !bytes.HasSuffix(sni, []byte("public.ech.test")) {
		t.Errorf("the outer names %q", sni)
	}
	for _, h := range f.Hellos {
		if h.Scenario != "accept" || h.Cohort != 1 || h.Conn != 1 {
			continue
		}
		if c := readHello(t, unhexed(t, h.Outer)); !slices.Equal(c.shape(), outer.shape()) || len(c.exts) != len(outer.exts) {
			t.Errorf("outer %v, Chrome's %v", outer.shape(), c.shape())
		}
		if c := readHello(t, unhexed(t, h.Inner)); !slices.Equal(c.shape(), inner.shape()) {
			t.Errorf("inner %v, Chrome's %v", inner.shape(), c.shape())
		}
		if len(unhexed(t, h.Outer)) != len(conns[0].hellos[0]) || len(unhexed(t, h.Encoded)) != len(conns[0].opened[0]) {
			t.Errorf("lengths: outer %d, Chrome's %d", len(conns[0].hellos[0]), len(unhexed(t, h.Outer)))
		}
	}
}

func TestEveryECHScenarioGoesAsChromes(t *testing.T) {
	// Each scenario's connections, what their first hellos offered and which
	// carried the request, as Chrome's measured: the kinds of every
	// connection Chrome opened (it opens a duplicate at a navigation's start,
	// whose own retries are the same) and the request on the last of them.
	f := echDNSMeasured(t)
	good := newECHKey(t, 0x11, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
	pad := newECHKey(t, 0x22, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 64)
	chacha := newECHKey(t, 0x33, ecdh.X25519(), 0x20, [][2]uint16{{1, 3}, {1, 1}}, 0)
	p384 := newECHKey(t, 0x44, ecdh.P384(), 0x11, [][2]uint16{{1, 1}}, 0)
	p256 := newECHKey(t, 0x55, ecdh.P256(), 0x10, [][2]uint16{{1, 1}}, 0)
	stale := newECHKey(t, 0x66, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
	loop := newECHKey(t, 0x77, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
	names := map[uint8]string{0x11: "good", 0x22: "pad", 0x33: "chacha", 0x44: "p384", 0x55: "p256", 0x66: "stale", 0x77: "loop"}
	all := []echKey{good, pad, chacha, p384, p256, stale, loop}
	served := func(keys ...echKey) []tls.EncryptedClientHelloKey {
		var out []tls.EncryptedClientHelloKey
		for i, k := range keys {
			out = append(out, tls.EncryptedClientHelloKey{Config: k.config, PrivateKey: k.key.Bytes(), SendAsRetry: i == 0})
		}
		return out
	}
	looped := []tls.EncryptedClientHelloKey{{Config: loop.config, PrivateKey: stale.key.Bytes(), SendAsRetry: true}}
	record := func(name string, keys ...echKey) *dnsmessage.SVCBResource {
		if len(keys) == 0 {
			return service(1, name, alpnParam("h2"))
		}
		return service(1, name, alpnParam("h2"), echParam(echList(keys...)))
	}
	for _, tc := range []struct {
		scenario string
		served   []tls.EncryptedClientHelloKey
		name     string
		record   *dnsmessage.SVCBResource
		want     []string // the kinds of tls-forge's connections, in order
		err      bool
		aead     uint8
	}{
		{"accept", served(good), "ech", record("ech.ech.test", good), []string{"ech:good"}, false, 1},
		{"retry", served(good), "stale", record("stale.ech.test", stale), []string{"ech:stale", "ech:good"}, false, 1},
		{"disabled", nil, "ech", record("ech.ech.test", good), []string{"ech:good", "grease"}, false, 0},
		{"loop", looped, "stale", record("stale.ech.test", stale), []string{"ech:stale", "ech:loop"}, true, 0},
		{"noech", served(good), "noech", record("noech.ech.test"), []string{"grease"}, false, 0},
		{"norr", served(good), "norr", nil, []string{"grease"}, false, 0},
		{"dot", served(good), "dot", record(".", good), []string{"grease"}, false, 0},
		{"pad", served(pad), "pad", record("pad.ech.test", pad), []string{"ech:pad"}, false, 1},
		{"chacha", served(chacha), "chacha", record("chacha.ech.test", chacha), []string{"ech:chacha"}, false, 3},
		{"multi", served(good), "multi", record("multi.ech.test", p384, p256, good), []string{"ech:good"}, false, 1},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			// Chrome's connections are of these kinds, its request on the last.
			measured := f.Scenarios[tc.scenario]
			if len(measured.Runs) != 2 {
				t.Fatalf("%d runs measured", len(measured.Runs))
			}
			for i, run := range measured.Runs {
				for _, c := range run.Connections {
					if !slices.Contains(tc.want, c.kind()) {
						t.Errorf("Chrome's run %d: a connection of %q", i+1, c.kind())
					}
				}
				if tc.err != (run.Error != "") || !tc.err && len(run.Requests) == 0 {
					t.Errorf("Chrome's run %d: %q, %d requests", i+1, run.Error, len(run.Requests))
				}
				for _, r := range run.Requests {
					at := slices.IndexFunc(run.Connections, func(c echDNSConnection) bool { return c.Conn == r.Conn })
					if at < 0 || run.Connections[at].kind() != tc.want[len(tc.want)-1] {
						t.Errorf("Chrome's run %d: the request on connection %d", i+1, r.Conn)
					}
				}
			}
			site := startECHSite(t, tc.served, all)
			records := map[string]*dnsmessage.SVCBResource{}
			if tc.record != nil {
				records[tc.name+".ech.test"] = tc.record
			}
			c := echClient(t, echNames(t, records, 0, 0))
			res, err := c.Do(&Request{URL: "https://" + tc.name + ".ech.test:" + site.port + "/"})
			if (err != nil) != tc.err || err == nil && res.Status != 200 {
				t.Fatalf("%v", err)
			}
			conns := site.seen()
			var got []string
			for _, s := range conns {
				got = append(got, s.kindOf(names))
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("connections %v, want %v", got, tc.want)
			}
			last := conns[len(conns)-1]
			if !tc.err && last.request == "" || tc.err && last.request != "" {
				t.Errorf("the request: %q", last.request)
			}
			for i, s := range conns {
				if s.opened[0] == nil {
					continue
				}
				own, omitted := echLayout(t)
				maxName := 0
				if names[s.config[0]] == "pad" {
					maxName = 64
				}
				if bad := chromeInnerRule(t, helloOfBytes(s.hellos[0]), helloOfBytes(s.inner[0]), s.opened[0], s.payload[0],
					maxName, own, omitted); bad != nil {
					t.Errorf("connection %d: %v", i+1, bad)
				}
				aead := helloOfBytes(s.hellos[0])
				e, _ := aead.ext(0xfe0d)
				if tc.aead != 0 && e[4] != tc.aead {
					t.Errorf("connection %d: AEAD %d", i+1, e[4])
				}
			}
		})
	}
}

func TestASessionIsResumedInTheInnerHelloAloneAsChromeResumesIt(t *testing.T) {
	for _, hrr := range []bool{false, true} {
		good := newECHKey(t, 0x11, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
		var curves []tls.CurveID
		if hrr {
			curves = []tls.CurveID{tls.CurveP256}
		}
		site := startECHSite(t, []tls.EncryptedClientHelloKey{{Config: good.config, PrivateKey: good.key.Bytes(),
			SendAsRetry: true}}, []echKey{good}, curves...)
		dns := echNames(t, map[string]*dnsmessage.SVCBResource{"ech.ech.test": service(1, "ech.ech.test",
			echParam(echList(good)))}, 0, 0)
		c := echClient(t, dns)
		base := "https://ech.ech.test:" + site.port
		for _, path := range []string{"/close", "/"} {
			if res, err := c.Do(&Request{URL: base + path}); err != nil || res.Status != 200 {
				t.Fatalf("hrr %v, %s: %v", hrr, path, err)
			}
			c.CloseIdleConnections()
		}
		conns := site.seen()
		if len(conns) != 2 {
			t.Fatalf("hrr %v: %d connections", hrr, len(conns))
		}
		second := conns[1]
		want := 1
		if hrr {
			want = 2
		}
		if len(second.hellos) != want || !strings.HasSuffix(second.request, "ech=true") {
			t.Fatalf("hrr %v: %d hellos, %q", hrr, len(second.hellos), second.request)
		}
		own, omitted := echLayout(t)
		for i := range second.hellos {
			outer, inner := helloOfBytes(second.hellos[i]), helloOfBytes(second.inner[i])
			if _, ok := inner.ext(41); !ok {
				t.Errorf("hrr %v, hello %d: the inner resumes nothing", hrr, i+1)
			}
			if bad := chromeInnerRule(t, outer, inner, second.opened[i], second.payload[i], 0, own, omitted); bad != nil {
				t.Errorf("hrr %v, hello %d: %v", hrr, i+1, bad)
			}
		}
		if hrr {
			first, retried := helloOfBytes(second.hellos[0]), helloOfBytes(second.hellos[1])
			if !bytes.Equal(first.random, retried.random) || second.enc[1] != 0 ||
				!bytes.Equal(helloOfBytes(second.inner[0]).random, helloOfBytes(second.inner[1]).random) {
				t.Error("the second hellos are not the first's again")
			}
			if ks, _ := retried.ext(51); len(ks) != 2+4+65 || binary.BigEndian.Uint16(ks[2:]) != 0x17 {
				t.Errorf("the second key share %x", ks[:min(len(ks), 8)])
			}
		}
	}
}

func TestTheRecordsAreWaitedForNoLongerThanChromeWaits(t *testing.T) {
	// Late records give nothing; records in time, after late addresses, give
	// their ECH: the wait grows with the time the addresses took.
	good := newECHKey(t, 0x11, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
	for _, tc := range []struct {
		name            string
		aLate, httpLate time.Duration
		want            string
	}{
		{"in time", 0, 0, "ech:good"},
		{"late", 0, 300 * time.Millisecond, "grease"},
		{"late addresses, records in time", 300 * time.Millisecond, 310 * time.Millisecond, "ech:good"},
		{"late addresses, records later", 300 * time.Millisecond, 500 * time.Millisecond, "grease"},
	} {
		site := startECHSite(t, []tls.EncryptedClientHelloKey{{Config: good.config, PrivateKey: good.key.Bytes()}},
			[]echKey{good})
		dns := echNames(t, map[string]*dnsmessage.SVCBResource{"ech.ech.test": service(1, "ech.ech.test",
			echParam(echList(good)))}, tc.aLate, tc.httpLate)
		if _, err := echClient(t, dns).Do(&Request{URL: "https://ech.ech.test:" + site.port + "/"}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := site.seen()[0].kindOf(map[uint8]string{0x11: "good"}); got != tc.want {
			t.Errorf("%s: %s", tc.name, got)
		}
	}
}

func TestNoHTTPSRecordIsAskedForWhereChromeAsksForNone(t *testing.T) {
	// An address, a name the machine answers for, a profile that asks for
	// none, a proxy's connections: no HTTPS query.
	site := startECHSite(t, nil, nil)
	dns := echNames(t, nil, 0, 0)
	for _, tc := range []struct {
		name string
		url  string
		opts []Option
	}{
		{"an address", "https://127.0.0.1:" + site.port + "/", nil},
		{"localhost", "https://localhost:" + site.port + "/", nil},
		{"a profile that asks for none", "https://ech.ech.test:" + site.port + "/", []Option{WithProfile("firefox_148")}},
	} {
		before := len(dns.queries())
		c := echClient(t, dns, tc.opts...)
		if _, err := c.Do(&Request{URL: tc.url}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, q := range dns.queries()[before:] {
			if strings.HasPrefix(q, "HTTPS") {
				t.Errorf("%s: asked %s", tc.name, q)
			}
		}
	}
}

func TestAnHTTPSRecordSendsPlainHTTPToHTTPSAsChromeSendsIt(t *testing.T) {
	// The http:// request goes nowhere: a redirect's hop to https goes,
	// its fields where Chrome's were, measured.
	f := echDNSMeasured(t)
	for _, proto := range []string{"h2", "h1"} {
		for _, tc := range []struct{ name, url string }{
			{"http", "http://www.example.com:%s/p/up"},
			{"https", "https://www.example.com:%s/p/typed"},
		} {
			r := newRecorder(t, proto, nil)
			_, port, _ := net.SplitHostPort(r.addr)
			dns := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
				name := strings.TrimSuffix(q.Name.String(), ".")
				if q.Type == dnsmessage.TypeA {
					return []dnsRecord{{name: name, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
				}
				if q.Type == dnsmessage.TypeHTTPS && name == "_"+port+"._https.www.example.com" {
					return []dnsRecord{{name: name, https: service(1, "www.example.com", alpnParam("h2"))}}, 0, 0
				}
				return nil, 0, 0
			})
			c := echClient(t, dns)
			res, err := c.Do(&Request{URL: fmt.Sprintf(tc.url, port)})
			if err != nil || res.Status != 200 || !strings.HasPrefix(res.URL, "https://") {
				t.Fatalf("%s %s: %v %+v", proto, tc.name, err, res)
			}
			got := r.requests()
			if len(got) != 1 {
				t.Fatalf("%s %s: %d requests", proto, tc.name, len(got))
			}
			var names []string
			for _, h := range got[0].headers {
				names = append(names, h[0])
			}
			want := f.Upgrade[proto][tc.name]
			if len(want) == 0 || !slices.Equal(names, want) {
				t.Errorf("%s %s: %v\nChrome's %v", proto, tc.name, names, want)
			}
		}
	}
}

func TestADNSServerIsAskedForTheAddressesToo(t *testing.T) {
	// A name only the server knows is reached.
	site := startECHSite(t, nil, nil)
	dns := echNames(t, nil, 0, 0)
	c := echClient(t, dns)
	if res, err := c.Do(&Request{URL: "https://only.ech.test:" + site.port + "/"}); err != nil || res.Status != 200 {
		t.Fatalf("%v %+v", err, res)
	}
	if q := dns.queries(); !slices.Contains(q, "A only.ech.test.") {
		t.Errorf("asked %v", q)
	}
}

func TestAChromeProfileAsksTheMachinesServersItselfAsChromesBuiltInClientDoes(t *testing.T) {
	// No server named: the addresses and the records are asked of the
	// machine's servers by the client's own resolver, at the same time, so
	// a record the server answers with its addresses comes in time, where
	// the machine's resolver would answer from its cache before it.
	good := newECHKey(t, 0x11, ecdh.X25519(), 0x20, [][2]uint16{{1, 1}}, 0)
	site := startECHSite(t, []tls.EncryptedClientHelloKey{{Config: good.config, PrivateKey: good.key.Bytes(), SendAsRetry: true}},
		[]echKey{good})
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"ech.ech.test": service(1, "ech.ech.test", alpnParam("h2"),
		echParam(echList(good)))}, 0, 0)
	var mu sync.Mutex
	var dialed []string
	real := dialDNS
	t.Cleanup(func() { dialDNS = real })
	dialDNS = func(ctx context.Context, network, server string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network+" "+server)
		mu.Unlock()
		return real(ctx, network, dns.addr)
	}
	namingServers(t, "192.0.2.53:53")
	c, err := New(WithProfile("chrome_155_macos"), WithInsecureSkipVerify(), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	res, err := c.Do(&Request{URL: "https://ech.ech.test:" + site.port + "/"})
	if err != nil || res.Status != 200 {
		t.Fatalf("%v %+v", err, res)
	}
	if conns := site.seen(); len(conns) != 1 || conns[0].request != "ech.ech.test:"+site.port+" / ech=true" {
		t.Fatalf("the site saw %d connections", len(conns))
	}
	if q := dns.queries(); !slices.Contains(q, "A ech.ech.test.") || !slices.Contains(q, "HTTPS _"+site.port+"._https.ech.ech.test.") {
		t.Errorf("asked %v", q)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(dialed, "udp 192.0.2.53:53") {
		t.Errorf("dialed %v", dialed)
	}
}

func TestPlainHTTPGoesToHTTPSOnlyWhereTheProfileAndTheClientSay(t *testing.T) {
	// A plain server at a name with a record: a client through a proxy, one
	// whose profile does not send plain http to https, and a fresh client of
	// one that does, each as its own says.
	var asked []string
	var mu sync.Mutex
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.String()+" "+r.Host)
		mu.Unlock()
	}))
	defer plain.Close()
	_, port, _ := net.SplitHostPort(plain.Listener.Addr().String())
	dns := echNames(t, map[string]*dnsmessage.SVCBResource{"up.ech.test": service(1, "up.ech.test", alpnParam("h2"))}, 0, 0)
	url := "http://up.ech.test:" + port + "/x"
	// Through a proxy (the plain server, which answers whatever it is asked):
	// the proxy is asked for the http:// URL.
	if _, err := echClient(t, dns, WithProxy(plain.URL)).Do(&Request{URL: url}); err != nil {
		t.Fatal(err)
	}
	// A profile that does not upgrade asks the plain server itself.
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p = p.Clone()
	p.Behavior["dns.https_upgrade"] = json.RawMessage("false")
	if _, err := echClient(t, dns, WithProfileValue(p)).Do(&Request{URL: url}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := slices.Clone(asked)
	mu.Unlock()
	if len(got) != 2 || !strings.HasPrefix(got[0], "http://up.ech.test:"+port+"/x") || got[1] != "/x up.ech.test:"+port {
		t.Errorf("asked %q", got)
	}
	// A fresh client upgrades as the one it was made of: to https, which the
	// plain server does not speak.
	fresh, err := echClient(t, dns).Fresh()
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.Do(&Request{URL: url}); err == nil {
		t.Error("a fresh client sent plain http")
	}
	if mu.Lock(); len(asked) != 2 {
		t.Errorf("asked %q", asked)
	}
	mu.Unlock()
}

func TestAConnectionToPortEightyAsksForNoRecordOfItsPort(t *testing.T) {
	// Port 80's are plain http's: their records were asked for as 443's.
	dns := echNames(t, nil, 0, 0)
	_, _ = echClient(t, dns).Do(&Request{URL: "http://nothing.ech.test/"})
	for _, q := range dns.queries() {
		if strings.Contains(q, "_80._https") {
			t.Errorf("asked %s", q)
		}
	}
}
