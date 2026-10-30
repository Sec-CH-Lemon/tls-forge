package tlsforge

import (
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/dns/dnsmessage"
)

// alpsSite is an HTTP/3 site that gives in ALPS for h3 what alps makes of
// its origin, beside an HTTP/2 one on the same port; each answer says the
// protocol it came over and the Sec-CH-UA-Arch and Sec-CH-UA-Model it was
// sent. It keeps the extensions of each QUIC hello and how each QUIC
// connection ended.
type alpsSite struct {
	port        string
	mu          sync.Mutex
	hellos      [][]uint16
	closed      []error
	closedEvent chan struct{}
}

func startALPSSite(t *testing.T, alps func(origin string) []byte, control map[uint64]uint64) *alpsSite {
	t.Helper()
	s := &alpsSite{closedEvent: make(chan struct{}, 1)}
	udp, tcp := udpAndTCP(t)
	_, s.port, _ = net.SplitHostPort(tcp.Addr().String())
	said := func(proto string, h func(string) string) string {
		return proto + " arch=" + h("Sec-CH-UA-Arch") + " model=" + h("Sec-CH-UA-Model")
	}
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = io.WriteString(w, said(r.Proto, r.Header.Get))
	}))
	// TCP's first answer a round trip late, as on a network: QUIC is up first
	server.Listener = &slowFirstWord{Listener: tcp, lag: 100 * time.Millisecond}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.TLS.Certificates[0]
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos: []string{"h3"}}
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		s.hellos = append(s.hellos, hello.Extensions)
		s.mu.Unlock()
		return nil, nil
	}
	if alps != nil {
		cfg.ApplicationSettings = map[string][]byte{"h3": alps("https://h3.h3.test:" + s.port)}
	}
	h3 := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			// answered late: the client reads the server's settings first
			time.Sleep(300 * time.Millisecond)
		}
		_, _ = io.WriteString(w, said(r.Proto, r.Header.Get))
	}), TLSConfig: cfg, AdditionalSettings: control,
	}
	// Observe the QUIC context before HTTP/3 acceptance. An ALPS refusal can
	// close the connection during the handshake, before Server.ConnContext.
	transport := &quic.Transport{Conn: udp, ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
		go func() {
			<-ctx.Done()
			s.mu.Lock()
			s.closed = append(s.closed, context.Cause(ctx))
			s.mu.Unlock()
			select {
			case s.closedEvent <- struct{}{}:
			default:
			}
		}()
		return ctx, nil
	}}
	listener, err := transport.ListenEarly(http3.ConfigureTLSConfig(cfg), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h3.ServeListener(listener) }()
	t.Cleanup(func() { _ = h3.Close(); _ = listener.Close(); _ = transport.Close(); _ = udp.Close() })

	return s
}

func (s *alpsSite) seen() ([][]uint16, []error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.hellos), slices.Clone(s.closed)
}

func h3Frame(typ uint64, payload ...byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

func h3AcceptCH(origin, value string) []byte {
	p := quicvarint.Append(nil, uint64(len(origin)))
	p = append(p, origin...)
	p = quicvarint.Append(p, uint64(len(value)))
	p = append(p, value...)
	return h3Frame(0x89, p...)
}

func alpsNames(t *testing.T) *dnsFake {
	t.Helper()
	return echNames(t, map[string]*dnsmessage.SVCBResource{"h3.h3.test": service(1, "h3.h3.test", alpnParam("h3", "h2"))}, 0, 0)
}

func TestAQUICHelloOffersALPSForH3AsChromes(t *testing.T) {
	site := startALPSSite(t, nil, nil)
	c := echClient(t, alpsNames(t))
	if got := came(t, c, "https://h3.h3.test:"+site.port+"/"); !strings.HasPrefix(got, "HTTP/3.0") {
		t.Fatalf("came over %q", got)
	}
	hellos, _ := site.seen()
	// Chrome 155's QUIC hello, measured (bench/h3alps): its twelve
	// extensions, application_settings (17613) among them, in an order drawn
	got := slices.Clone(hellos[0])
	slices.Sort(got)
	want := []uint16{0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 51764, 65037}
	if !slices.Equal(got, want) {
		t.Errorf("the hello offered %v, want %v", got, want)
	}
}

func TestAPagesRequestOverHTTP3CarriesTheHintsALPSAsksFor(t *testing.T) {
	site := startALPSSite(t, func(origin string) []byte {
		// the first entry of the origin, as an Origin header writes it, is the one
		return slices.Concat(h3AcceptCH(origin, "Sec-CH-UA-Arch, Sec-CH-UA-Model"), h3AcceptCH(origin, "Sec-CH-UA-Bitness"),
			h3AcceptCH("https://other.test", "Sec-CH-UA-Full-Version-List"))
	}, nil)
	c := echClient(t, alpsNames(t))
	url := "https://h3.h3.test:" + site.port + "/"
	// as Chrome's two navigations on the connection: both carry them
	for _, u := range []string{url, url + "again"} {
		if got := came(t, c, u); got != `HTTP/3.0 arch="arm" model=""` {
			t.Errorf("%s: %q", u, got)
		}
	}
	// a script's request carries none (as over HTTP/2)
	res, err := c.Do(&Request{URL: url + "script", Browser: &BrowserContext{Kind: KindFetch, Initiator: url}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Text(); got != "HTTP/3.0 arch= model=" {
		t.Errorf("a fetch(): %q", got)
	}
}

func TestAServersALPSChromeRefusesSendsTheRequestOverTCPAsChromes(t *testing.T) {
	site := startALPSSite(t, func(string) []byte { return h3Frame(0x0) }, nil)
	c := echClient(t, alpsNames(t))
	if got := came(t, c, "https://h3.h3.test:"+site.port+"/"); got != "HTTP/2.0 arch= model=" {
		t.Errorf("came over %q, want HTTP/2", got)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var closed []error
	for {
		_, closed = site.seen()
		if len(closed) > 0 {
			break
		}
		select {
		case <-site.closedEvent:
		case <-timer.C:
			t.Fatal("the QUIC connection did not end")
		}
	}

	var te *quic.TransportError
	if !errors.As(closed[0], &te) || te.ErrorCode != 10 || te.FrameType != 6 ||
		te.ErrorMessage != "28:Error processing ALPS data: DATA frame forbidden" || !te.Remote {
		t.Errorf("the server's connection ended with %v", closed[0])
	}
}

func TestAControlStreamsSettingsAreHeldToWhatALPSGaveAsChromes(t *testing.T) {
	settings := func(pairs ...uint64) []byte {
		var p []byte
		for _, v := range pairs {
			p = quicvarint.Append(p, v)
		}
		return h3Frame(0x4, p...)
	}
	site := startALPSSite(t, func(string) []byte { return settings(1, 4096) }, map[uint64]uint64{1: 8192})
	c := echClient(t, alpsNames(t))
	url := "https://h3.h3.test:" + site.port + "/"
	// The request on the connection its client closes goes again over TCP,
	// as Chrome's did (HTTP_TRANSACTION_RESTART_AFTER_ERROR, -356).
	if got := came(t, c, url+"slow"); got != "HTTP/2.0 arch= model=" {
		t.Errorf("the request in flight came over %q, want TCP's", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, closed := site.seen()
		var ae *quic.ApplicationError
		if len(closed) > 0 && errors.As(closed[0], &ae) {
			if ae.ErrorCode != 0x109 || ae.ErrorMessage != "164:Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: 8192 while current value is: 4096" {
				t.Errorf("the server's connection ended with %v", closed[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the QUIC connection did not end as Chrome's: %v", closed)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// and the next request goes over TCP, QUIC broken for the site: no QUIC
	// connection made for it
	if got := came(t, c, url+"again"); got != "HTTP/2.0 arch= model=" {
		t.Errorf("the next came over %q", got)
	}
	time.Sleep(100 * time.Millisecond)
	if hellos, _ := site.seen(); len(hellos) != 1 {
		t.Errorf("%d QUIC hellos, want the one of the connection that failed", len(hellos))
	}
}

// h3Conn is an HTTP/3 connection's word of what its server's ALPS asks for.
type h3Conn struct {
	net.Conn
	asked map[string]string
}

func (c h3Conn) AcceptCH(origin string) (string, bool) {
	v, ok := c.asked[origin]
	return v, ok
}

func TestTheHintsALPSAsksForAreReadAsTheProtocolsFramesSayThem(t *testing.T) {
	o := originOf(mustURL(t, "https://a.test/"))
	// over HTTP/3, its transport read them: HTTP/2's frames are not looked for
	if v, ok := acceptCHAsked(h3Conn{asked: map[string]string{"https://a.test": "Sec-CH-UA-Arch"}}, o); !ok || v != "Sec-CH-UA-Arch" {
		t.Errorf("over HTTP/3: %q %v", v, ok)
	}
	if _, ok := acceptCHAsked(h3Conn{}, o); ok {
		t.Error("over HTTP/3 of nothing asked")
	}
	// over HTTP/2, its frames
	if _, ok := acceptCHAsked(&net.TCPConn{}, o); ok {
		t.Error("a connection that is not TLS")
	}
}
