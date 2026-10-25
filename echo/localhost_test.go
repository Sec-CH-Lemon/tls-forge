package echo

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

// heard is a listen that keeps what it was asked and every listener it gave,
// each of which keeps whether it was closed: told, when set, is the port the
// first one it gives says it is at, refuse says which addresses it refuses,
// as if nothing listened there, and instead which it listens at in place of
// another.
type heard struct {
	asked   []string
	given   []*heardListener
	told    int
	refuse  func(addr string) bool
	instead map[string]string
}

// heardListener is a listener a heard gave.
type heardListener struct {
	net.Listener
	port   int
	closed bool
}

func (l *heardListener) Addr() net.Addr {
	if l.port == 0 {
		return l.Listener.Addr()
	}
	return &net.TCPAddr{IP: l.Listener.Addr().(*net.TCPAddr).IP, Port: l.port}
}

func (l *heardListener) Close() error {
	l.closed = true
	return l.Listener.Close()
}

var errNothingThere = errors.New("nothing listens there")

func (h *heard) listen(network, addr string) (net.Listener, error) {
	h.asked = append(h.asked, addr)
	if h.refuse != nil && h.refuse(addr) {
		return nil, errNothingThere
	}
	if other, ok := h.instead[addr]; ok {
		addr = other
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	l := &heardListener{Listener: ln}
	if len(h.given) == 0 {
		l.port = h.told
	}
	h.given = append(h.given, l)
	return l, nil
}

// hearing has the server listen through h for the rest of the test.
func hearing(t *testing.T, h *heard) {
	t.Helper()
	original := listen
	t.Cleanup(func() { listen = original })
	listen = h.listen
}

// portOf is the port of a URL the server gives.
func portOf(t *testing.T, url string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(url, "https://"))
	if err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	return port
}

func TestTheServerAnswersAtBothAddressesLocalhostNames(t *testing.T) {
	// localhost names 127.0.0.1 and [::1], and a browser of it tries [::1]
	// first, as Chrome does: the main listener and the one that offers
	// HTTP/1.1 alone answer at both, each on its port.
	server := startServer(t)
	port, capturePort := portOf(t, server.URL()), portOf(t, server.CaptureURL())
	if server.Addr() != "127.0.0.1:"+port {
		t.Errorf("Addr = %s", server.Addr())
	}
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		if status, _ := get(t, http2Client(), "https://"+host+":"+port+"/api/all"); status != 200 {
			t.Errorf("%s:%s answered %d", host, port, status)
		}
		if status, _ := get(t, http1Client(), "https://"+host+":"+capturePort+"/api/all"); status != 200 {
			t.Errorf("%s:%s answered %d", host, capturePort, status)
		}
		// The HTTP/1.1 listener offers HTTP/1.1 alone at both.
		if res, err := http2Client().Get("https://" + host + ":" + capturePort + "/api/all"); err == nil {
			_ = res.Body.Close()
			t.Errorf("%s:%s answered HTTP/2", host, capturePort)
		}
	}
	var remotes []string
	for _, sess := range server.Sessions() {
		host, _, _ := net.SplitHostPort(sess.Remote())
		remotes = append(remotes, host)
	}
	if slices.Sort(remotes); !slices.Equal(remotes, []string{"127.0.0.1", "::1"}) {
		t.Errorf("connections from %v", remotes)
	}
}

func TestAPortAnotherProgramHoldsAtIPv6IsNotTheServers(t *testing.T) {
	// The port the system gives at 127.0.0.1 is one another program holds at
	// [::1], serving plain HTTP, as node's did: a client of localhost that
	// tried [::1] first reached that, and a capture waited out its timeout.
	// The server lets the port go and listens on one it holds at both.
	held, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = held.Close() }()
	reached := make(chan struct{}, 1)
	go func() {
		_ = http.Serve(held, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached <- struct{}{} }))
	}()
	h := &heard{told: held.Addr().(*net.TCPAddr).Port}
	hearing(t, h)
	server := startServer(t)
	port := portOf(t, server.URL())
	if port == strconv.Itoa(h.told) || !h.given[0].closed || h.asked[1] != "[::1]:"+strconv.Itoa(h.told) {
		t.Fatalf("listening on %s, the port held %d let go of: %v, asked %v", port, h.told, h.given[0].closed, h.asked)
	}
	for _, url := range []string{server.URL(), "https://[::1]:" + port} {
		status, body := get(t, http2Client(), url+"/api/all")
		var measured capture.Capture
		if err := json.Unmarshal(body, &measured); status != 200 || err != nil || measured.Negotiated != "h2" {
			t.Errorf("%s answered %d: %v, %.80s", url, status, err, body)
		}
	}
	select {
	case <-reached:
		t.Error("the other program was reached")
	default:
	}
}

func TestAnAddressGivenIsListenedAtAlone(t *testing.T) {
	// Where the server is told where to listen, it listens there: not at
	// [::1] as well, nor its HTTP/1.1 listener. (The port asked for is
	// listened at as the system's choice, so that no test takes a port to be
	// free.)
	h := &heard{instead: map[string]string{"127.0.0.1:8443": "127.0.0.1:0"}}
	hearing(t, h)
	server := startServer(t, WithAddr("127.0.0.1:8443"))
	if !slices.Equal(h.asked, []string{"127.0.0.1:8443", "127.0.0.1:0"}) || server.twin != nil || server.captureTwin != nil {
		t.Errorf("asked %v", h.asked)
	}
}

func TestWithoutAnIPv6LoopbackAddressTheServerListensAt127Alone(t *testing.T) {
	// A machine with no IPv6 loopback address, or none to be had: 127.0.0.1
	// alone, the HTTP/1.1 listener too, as before.
	h := &heard{refuse: func(addr string) bool { return strings.HasPrefix(addr, "[::1]:") }}
	hearing(t, h)
	server := startServer(t)
	if len(h.asked) != 5 || !slices.Equal(h.asked[2:], []string{"[::1]:0", "127.0.0.1:0", "127.0.0.1:0"}) ||
		!h.given[0].closed || server.twin != nil || server.captureTwin != nil {
		t.Errorf("asked %v", h.asked)
	}
	if status, _ := get(t, http2Client(), server.URL()+"/api/all"); status != 200 {
		t.Errorf("answered %d", status)
	}
	// None at 127.0.0.1 is no server, and not asked again.
	h = &heard{refuse: func(string) bool { return true }}
	hearing(t, h)
	if _, err := Start(); !errors.Is(err, errNothingThere) || !strings.HasPrefix(err.Error(), "echo: listen: ") ||
		len(h.asked) != 1 {
		t.Errorf("Start: %v, after asking %v", err, h.asked)
	}
}

func TestAServerThatCannotStartLetsGoOfEveryPort(t *testing.T) {
	// Its HTTP/1.1 listener not had, or its session ticket key not drawn:
	// every port it had is let go of, at [::1] too.
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T)
		opts   []Option
	}{
		{"no HTTP/1.1 listener", func(t *testing.T) {
			original := listenCapture
			t.Cleanup(func() { listenCapture = original })
			listenCapture = func(net.Listener, bool) (net.Listener, net.Listener, error) {
				return nil, nil, errNothingThere
			}
		}, nil},
		{"no session ticket key", func(t *testing.T) {
			original := readRandom
			t.Cleanup(func() { readRandom = original })
			readRandom = func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
		}, []Option{WithManual(true)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &heard{}
			hearing(t, h)
			tc.break_(t)
			if _, err := Start(tc.opts...); err == nil {
				t.Fatal("started")
			}
			if len(h.given) < 2 || slices.ContainsFunc(h.given, func(l *heardListener) bool { return !l.closed }) {
				t.Errorf("of %d listeners, not all let go of", len(h.given))
			}
		})
	}
}
