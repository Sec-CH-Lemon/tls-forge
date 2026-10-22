package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v3/internal/pcapng"
)

// What --pcap keeps of a request, read back from the file as Wireshark reads
// it: the section's comment, the secrets, and each connection put back
// together from its packets.

// capturedConn is a connection as a capture holds it.
type capturedConn struct {
	client, server uint16
	sent, received []byte
	// clientFIN is a FIN the client sent, last.
	clientFIN bool
}

type keptCapture struct {
	comment string
	secrets []string
	conns   []*capturedConn
}

// readCapture reads a pcapng file of raw IPv4 packets, as --pcap writes for
// connections over loopback.
func readCapture(t *testing.T, path string) keptCapture {
	t.Helper()
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the capture: %v", err)
	}
	var out keptCapture
	byPort := map[uint16]*capturedConn{}
	for len(file) > 0 {
		kind, length := binary.LittleEndian.Uint32(file), binary.LittleEndian.Uint32(file[4:])
		body := file[8 : length-4]
		file = file[length:]
		switch kind {
		case 0x0A0D0D0A:
			for options := body[16:]; len(options) >= 4; {
				code, size := binary.LittleEndian.Uint16(options), int(binary.LittleEndian.Uint16(options[2:]))
				if code == 1 {
					out.comment = string(options[4 : 4+size])
				}
				options = options[4+(size+3)&^3:]
			}
		case 0x0A:
			size := binary.LittleEndian.Uint32(body[4:])
			out.secrets = keyLines(string(body[8 : 8+size]))
		case 0x06:
			packet := body[20 : 20+binary.LittleEndian.Uint32(body[12:])]
			tcp := packet[20:]
			src, dst, flags := binary.BigEndian.Uint16(tcp), binary.BigEndian.Uint16(tcp[2:]), tcp[13]
			data := tcp[20:]
			if flags == 0x02 { // SYN: a connection begins
				c := &capturedConn{client: src, server: dst}
				byPort[src] = c
				out.conns = append(out.conns, c)
				continue
			}
			if c, ok := byPort[src]; ok {
				c.sent = append(c.sent, data...)
				c.clientFIN = flags&0x01 != 0
			} else {
				c := byPort[dst]
				c.received = append(c.received, data...)
			}
		}
	}
	return out
}

// randomOf is the client random of the ClientHello a connection began with,
// failing the test when it began with none.
func randomOf(t *testing.T, c *capturedConn) string {
	t.Helper()
	random, ok := pcapng.ClientRandom(c.sent)
	if !ok {
		t.Fatalf("the connection began with %q", c.sent[:min(len(c.sent), 40)])
	}
	return random
}

// linesOf are the lines of a key log that are of random.
func linesOf(lines []string, random string) []string {
	var out []string
	for _, line := range lines {
		if strings.Fields(line)[1] == random {
			out = append(out, line)
		}
	}
	return out
}

func TestFetchKeepsWhatEachRequestsConnectionsCarriedBesideItsOtherFiles(t *testing.T) {
	clock := fakeClock(t)
	var keys siteKeys
	server, _ := keyedSite(t, &keys)
	dir := filepath.Join(t.TempDir(), "out")
	report := filepath.Join(t.TempDir(), "run.json")
	code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--repeat", "2", "-o", dir, "--pcap",
		"--report="+report, "--report-format", "json", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	// Every file of a request under its name, the capture with them.
	name := "127.0.0.1-" + stamp(clock.now())
	want := []string{
		name + "-1-logs.log", name + "-1-response.txt", name + "-1-trace.json", name + "-1.pcapng",
		name + "-2-logs.log", name + "-2-response.txt", name + "-2-trace.json", name + "-2.pcapng",
		"run-" + stamp(clock.now()) + ".log",
	}
	if got := keptIn(t, dir); !slices.Equal(got, want) {
		t.Fatalf("the directory holds\n%v\nwant\n%v", got, want)
	}
	site := keys.lines()
	randoms := map[string]bool{}
	for run := 1; run <= 2; run++ {
		path := filepath.Join(dir, fmt.Sprintf("%s-%d.pcapng", name, run))
		capture := readCapture(t, path)
		// One connection, a try's own: its handshake, its secrets as the site
		// has them, what came back, and the FIN that let go of it before the
		// request was kept.
		if len(capture.conns) != 1 {
			t.Fatalf("run %d: %d connections", run, len(capture.conns))
		}
		conn := capture.conns[0]
		random := randomOf(t, conn)
		randoms[random] = true
		if mine := linesOf(site, random); len(mine) != 4 || !slices.Equal(capture.secrets, mine) {
			t.Errorf("run %d: the capture holds\n%s\nthe site's lines of its connection\n%s", run,
				strings.Join(capture.secrets, "\n"), strings.Join(mine, "\n"))
		}
		if len(conn.received) == 0 || !conn.clientFIN {
			t.Errorf("run %d: received %d bytes, the client's FIN %v", run, len(conn.received), conn.clientFIN)
		}
		if want := fmt.Sprintf("GET %s/, request %d of run %s:", server.URL, run, stamp(clock.now())); !strings.HasPrefix(capture.comment, want) ||
			!strings.Contains(capture.comment, "made up") || !strings.Contains(capture.comment, "whoever has it reads") {
			t.Errorf("run %d: the capture says %q", run, capture.comment)
		}
		if runtime.GOOS != "windows" {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("run %d: the capture is %v, %v", run, info.Mode(), err)
			}
		}
		// The request's log says where it is.
		log, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%s-%d-logs.log", name, run)))
		if !strings.Contains(string(log), "  capture  "+path+"\n") {
			t.Errorf("run %d: the log does not name its capture:\n%s", run, log)
		}
	}
	if len(randoms) != 2 {
		t.Errorf("two runs on %d connections", len(randoms))
	}
	// And so does the report.
	if doc := decoded(t, []byte(reportOf(t, report))); doc.Requests[0].Capture != filepath.Join(dir, name+"-1.pcapng") {
		t.Errorf("the report has the first capture at %q", doc.Requests[0].Capture)
	}
}

func TestFetchKeepsTheTunnelThroughAProxyInACapture(t *testing.T) {
	var keys siteKeys
	server, _ := keyedSite(t, &keys)
	proxy := startProxy(t)
	dir := filepath.Join(t.TempDir(), "out")
	code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--proxy", "http://alice:s3cr3t@"+proxy.addr,
		"-o", dir, "--pcap", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	captures, _ := filepath.Glob(filepath.Join(dir, "*.pcapng"))
	if len(captures) != 1 {
		t.Fatalf("kept %v", keptIn(t, dir))
	}
	// The connection to the proxy, which asked for the tunnel in the clear and
	// shook hands with the site through it.
	capture := readCapture(t, captures[0])
	if len(capture.conns) != 1 || !bytes.HasPrefix(capture.conns[0].sent,
		[]byte("CONNECT "+strings.TrimPrefix(server.URL, "https://")+" HTTP/1.1\r\n")) {
		t.Fatalf("%d connections, the first sent %q", len(capture.conns), capture.conns[0].sent[:40])
	}
	if port := fmt.Sprint(capture.conns[0].server); !strings.HasSuffix(proxy.addr, ":"+port) {
		t.Errorf("went to port %s, the proxy is at %s", port, proxy.addr)
	}
	if mine := linesOf(keys.lines(), randomOf(t, capture.conns[0])); len(mine) != 4 || !slices.Equal(capture.secrets, mine) {
		t.Errorf("the capture holds %d lines, the site %d of the connection", len(capture.secrets), len(mine))
	}
	// The credentials it gave the proxy are in it masked, past their scheme.
	basic := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	if file, _ := os.ReadFile(captures[0]); bytes.Contains(file, []byte(basic)) ||
		!bytes.Contains(capture.conns[0].sent, []byte("\r\nProxy-Authorization: Basic "+strings.Repeat("*", len(basic))+"\r\n")) {
		t.Errorf("the CONNECT went into the capture as\n%s", capture.conns[0].sent[:bytes.Index(capture.conns[0].sent, []byte("\r\n\r\n"))])
	}
}

// startSocksProxy is a SOCKS proxy on a loopback port, SOCKS5 (RFC 1928),
// SOCKS4 and SOCKS4a alike, which asks a SOCKS5 client for a user name and
// password (RFC 1929) when user is not empty, and joins each client to the
// address it asked for.
func startSocksProxy(t *testing.T, user, password string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				target, granted, ok := socksAsked(conn, user, password)
				if !ok {
					return
				}
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				if _, err := conn.Write(granted); err != nil {
					return
				}
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	return listener.Addr().String()
}

// socksAsked reads a SOCKS client's handshake up to the address it asks for,
// answering a SOCKS5 client as it goes, and is that address and the answer
// that opens the tunnel to it.
func socksAsked(conn net.Conn, user, password string) (string, []byte, bool) {
	failed := false
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			failed = true
		}
		return b
	}
	field := func() string { return string(read(int(read(1)[0]))) }
	upToNUL := func() string {
		var s []byte
		for one := read(1); !failed && one[0] != 0; one = read(1) {
			s = append(s, one[0])
		}
		return string(s)
	}
	port := func() string { return strconv.Itoa(int(binary.BigEndian.Uint16(read(2)))) }
	if read(1)[0] == 4 {
		command, at := read(1)[0], port()
		ip := read(4)
		_ = upToNUL()
		host := net.IP(ip).String()
		if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
			host = upToNUL()
		}
		return net.JoinHostPort(host, at), []byte{0, 0x5a, 0, 0, 0, 0, 0, 0}, !failed && command == 1
	}
	method := byte(0)
	if user != "" {
		method = 2
	}
	if offered := read(int(read(1)[0])); failed || !bytes.Contains(offered, []byte{method}) {
		return "", nil, false
	}
	_, _ = conn.Write([]byte{5, method})
	if user != "" {
		if read(1)[0] != 1 || field() != user || field() != password || failed {
			return "", nil, false
		}
		_, _ = conn.Write([]byte{1, 0})
	}
	request := read(4)
	var host string
	switch request[3] {
	case 1:
		host = net.IP(read(4)).String()
	case 3:
		host = field()
	}
	return net.JoinHostPort(host, port()), []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, !failed && request[1] == 1 && host != ""
}

func TestFetchKeepsTheHandshakeWithASOCKSProxyInACapture(t *testing.T) {
	// The connection to the proxy, which the transport dials: the handshake
	// with it in the clear, each way, then the site's TLS through it, its
	// secrets the site's own, and the FIN that let go of it.
	var keys siteKeys
	server, _ := keyedSite(t, &keys)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	number, _ := strconv.Atoi(port)
	at := binary.BigEndian.AppendUint16(nil, uint16(number))
	byName := "https://localhost:" + port + "/"
	plain, credentialed := startSocksProxy(t, "", ""), startSocksProxy(t, "alice", "s3cr3t")
	list := filepath.Join(t.TempDir(), "list.json")
	if err := os.WriteFile(list, []byte(`[{"url":"`+byName+`","proxy":"socks5h://`+plain+`"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	// What a SOCKS5 client asks for: the site's address, or its name.
	address := slices.Concat([]byte{5, 1, 0, 1, 127, 0, 0, 1}, at)
	name := slices.Concat([]byte{5, 1, 0, 3, byte(len("localhost"))}, []byte("localhost"), at)
	opened, granted := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, []byte{0, 0x5a, 0, 0, 0, 0, 0, 0}
	for _, tc := range []struct {
		name           string
		args           []string
		proxy          string
		sent, received []byte
	}{
		{"socks5", []string{"--proxy", "socks5://" + plain, server.URL}, plain,
			slices.Concat([]byte{5, 1, 0}, address), slices.Concat([]byte{5, 0}, opened)},
		{"socks5 with a password, which is masked", []string{"--proxy", "socks5://alice:s3cr3t@" + credentialed, server.URL},
			credentialed, slices.Concat([]byte{5, 2, 0, 2, 1, 5}, []byte("alice"), []byte{6}, []byte("******"), address),
			slices.Concat([]byte{5, 2, 1, 0}, opened)},
		{"socks5h", []string{"--proxy", "socks5h://" + plain, byName}, plain,
			slices.Concat([]byte{5, 1, 0}, name), slices.Concat([]byte{5, 0}, opened)},
		{"socks4", []string{"--proxy", "socks4://" + plain, server.URL}, plain,
			slices.Concat([]byte{4, 1}, at, []byte{127, 0, 0, 1}, []byte("nobody@0.0.0.0\x00")), granted},
		{"socks4a", []string{"--proxy", "socks4a://" + plain, byName}, plain,
			slices.Concat([]byte{4, 1}, at, []byte{0, 0, 0, 1}, []byte("nobody@0.0.0.0\x00localhost\x00")), granted},
		{"a list's entry through one", []string{"--input", list, "--format", "json"}, plain,
			slices.Concat([]byte{5, 1, 0}, name), slices.Concat([]byte{5, 0}, opened)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "out")
			code, _, stderr := exec(t, append([]string{"fetch", "--insecure", "--no-exit-lookup", "-o", dir, "--pcap"},
				tc.args...)...)
			if code != 0 {
				t.Fatalf("exit code = %d\n%s", code, stderr)
			}
			captures, _ := filepath.Glob(filepath.Join(dir, "*.pcapng"))
			if len(captures) != 1 {
				t.Fatalf("kept %v", keptIn(t, dir))
			}
			capture := readCapture(t, captures[0])
			if len(capture.conns) != 1 {
				t.Fatalf("%d connections", len(capture.conns))
			}
			if file, _ := os.ReadFile(captures[0]); bytes.Contains(file, []byte("s3cr3t")) {
				t.Error("the capture holds the proxy's password")
			}
			conn := capture.conns[0]
			if fmt.Sprint(conn.server) != strings.TrimPrefix(tc.proxy, "127.0.0.1:") {
				t.Errorf("went to port %d, the proxy is at %s", conn.server, tc.proxy)
			}
			// The handshake each way, and the TLS records after it.
			if !bytes.HasPrefix(conn.sent, tc.sent) || !bytes.HasPrefix(conn.received, tc.received) ||
				!bytes.HasPrefix(conn.received[len(tc.received):], []byte{22, 3}) || !conn.clientFIN {
				t.Errorf("sent %q…, received %q…, the client's FIN %v", conn.sent[:min(len(conn.sent), 60)],
					conn.received[:min(len(conn.received), 20)], conn.clientFIN)
			}
			if mine := linesOf(keys.lines(), randomOf(t, conn)); len(mine) != 4 ||
				!slices.Equal(capture.secrets, mine) {
				t.Errorf("the capture holds\n%s\nthe site's lines of its connection\n%s",
					strings.Join(capture.secrets, "\n"), strings.Join(mine, "\n"))
			}
		})
	}
}

func TestFetchKeepsTheConnectionAURLsRepeatsShareInEachCapture(t *testing.T) {
	var keys siteKeys
	server, _ := keyedSite(t, &keys)
	dir := filepath.Join(t.TempDir(), "out")
	code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--repeat", "2", "--reuse-connection",
		"-o", dir, "--pcap", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	captures, _ := filepath.Glob(filepath.Join(dir, "*.pcapng"))
	if len(captures) != 2 {
		t.Fatalf("kept %v", keptIn(t, dir))
	}
	first, second := readCapture(t, captures[0]), readCapture(t, captures[1])
	if len(first.conns) != 1 || len(second.conns) != 1 {
		t.Fatalf("%d and %d connections", len(first.conns), len(second.conns))
	}
	// One connection, which the second has from its start, the first's request
	// and answer in it, and which neither saw end: it is the URL's until its
	// last repeat is over.
	a, b := first.conns[0], second.conns[0]
	if a.client != b.client || !bytes.HasPrefix(b.sent, a.sent) || len(b.sent) <= len(a.sent) ||
		!bytes.HasPrefix(b.received, a.received) || a.clientFIN || b.clientFIN {
		t.Errorf("the first on port %d sent %d, the second on %d sent %d; FINs %v and %v",
			a.client, len(a.sent), b.client, len(b.sent), a.clientFIN, b.clientFIN)
	}
	if !slices.Equal(first.secrets, second.secrets) || len(first.secrets) != 4 {
		t.Errorf("the secrets of one connection, %d and %d lines", len(first.secrets), len(second.secrets))
	}
}

func TestFetchWritesTheSecretsToTheKeyLogAndTheCaptureAlike(t *testing.T) {
	// The address service is asked before the run, on a connection of its own
	// that no request went out on: its secrets go to the key log, and nowhere
	// into a capture.
	var keys siteKeys
	server, _ := keyedSite(t, &keys)
	service := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	var asked siteKeys
	service.TLS = &tls.Config{KeyLogWriter: &asked}
	service.StartTLS()
	t.Cleanup(service.Close)
	original := ipServices
	t.Cleanup(func() { ipServices = original })
	ipServices = []addressService{{URL: service.URL, read: readJSON}}

	dir := filepath.Join(t.TempDir(), "out")
	keylog := filepath.Join(t.TempDir(), "run.keys")
	code, _, stderr := exec(t, "fetch", "--insecure", "--keylog", keylog, "-o", dir, "--pcap", server.URL)
	if code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	written, _ := os.ReadFile(keylog)
	if got, want := keyLines(string(written)), keyLines(strings.Join(append(keys.lines(), asked.lines()...), "\n")); len(want) != 8 ||
		!slices.Equal(got, want) {
		t.Errorf("the key log holds %d lines, the site and the service %d", len(got), len(want))
	}
	captures, _ := filepath.Glob(filepath.Join(dir, "*.pcapng"))
	if len(captures) != 1 {
		t.Fatalf("kept %v", keptIn(t, dir))
	}
	if capture := readCapture(t, captures[0]); len(capture.conns) != 1 || !slices.Equal(capture.secrets, keys.lines()) {
		t.Errorf("the capture holds %d connections and\n%s", len(capture.conns), strings.Join(capture.secrets, "\n"))
	}
}

func TestFetchKeepsACaptureOfARequestThatWentNowhere(t *testing.T) {
	// No connection was made, and the capture says so: none in it.
	dir := filepath.Join(t.TempDir(), "out")
	code, _, stderr := exec(t, "fetch", "--no-exit-lookup", "-o", dir, "--pcap", "--timeout", "3s",
		"https://"+deadAddr(t)+"/")
	if code != 1 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	captures, _ := filepath.Glob(filepath.Join(dir, "*.pcapng"))
	if len(captures) != 1 {
		t.Fatalf("kept %v", keptIn(t, dir))
	}
	if capture := readCapture(t, captures[0]); len(capture.conns) != 0 || capture.secrets != nil || capture.comment == "" {
		t.Errorf("a request that went nowhere has %d connections and %d secrets", len(capture.conns), len(capture.secrets))
	}
}

func TestFetchRefusesACaptureWithoutADirectory(t *testing.T) {
	// Before anything is asked: exit code 2.
	server, asked := keyedSite(t, io.Discard)
	code, _, stderr := exec(t, "fetch", "--insecure", "--pcap", server.URL)
	if code != 2 || !strings.Contains(stderr,
		"--pcap keeps each request's connections beside its other files, and requires --output") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("a refused run asked %d times", got)
	}
}

func TestKeepRequestReportsACaptureItCannotWrite(t *testing.T) {
	r, j, about := keptRequest()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, requestName(r.URL, r.Started, j.id)+captureSuffix), 0o755); err != nil {
		t.Fatal(err)
	}
	var notAFile *os.PathError
	if err := keepRequest(dir, &r, nil, j, about, nil, newWire()); !errors.As(err, &notAFile) || r.Capture != "" {
		t.Errorf("with a directory in the way: %v, capture %q", err, r.Capture)
	}
}

// A wire, by itself.

// pipeConn is a connection whose ends are given.
type pipeConn struct {
	net.Conn
	local, remote net.Addr
}

func (p pipeConn) LocalAddr() net.Addr  { return p.local }
func (p pipeConn) RemoteAddr() net.Addr { return p.remote }

// stringAddr is an address that is only its string.
type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

// dialedPair is a connection dialed for request id through w, and the end the
// server has of it.
func dialedPair(t *testing.T, w *wire, id int, local, remote net.Addr) (net.Conn, net.Conn) {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { _ = near.Close(); _ = far.Close() })
	return w.tap(id).Dialed(pipeConn{Conn: near, local: local, remote: remote}, time.Now()), far
}

func helloOf(random byte) []byte {
	return append(append([]byte{22, 3, 1, 0, 200, 1, 0, 0, 196, 3, 3}, bytes.Repeat([]byte{random}, 32)...), 0)
}

func TestTheWireKeepsTheSecretsOfTheConnectionsItHas(t *testing.T) {
	w := newWire()
	conn, far := dialedPair(t, w, 1, stringAddr("127.0.0.1:5000"), stringAddr("127.0.0.1:443"))
	go func() { _, _ = io.Copy(io.Discard, far) }()
	if _, err := conn.Write(helloOf(0xab)); err != nil {
		t.Fatal(err)
	}
	mine := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	other := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
	// A line in two writes, a comment, a line of another connection, one the
	// random of which is written in capitals, and the end of none yet.
	for _, part := range []string{
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET " + mine, " 01\n# a comment\n",
		"SERVER_TRAFFIC_SECRET_0 " + other + " 02\n",
		"CLIENT_TRAFFIC_SECRET_0 " + strings.ToUpper(mine) + " 03\nCLIENT_RA",
	} {
		if n, err := w.Write([]byte(part)); n != len(part) || err != nil {
			t.Errorf("Write(%q) = %d, %v", part, n, err)
		}
	}
	streams, secrets := w.capture(1)
	want := "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + mine + " 01\nCLIENT_TRAFFIC_SECRET_0 " + strings.ToUpper(mine) + " 03\n"
	if len(streams) != 1 || string(secrets) != want {
		t.Errorf("%d streams, secrets\n%s", len(streams), secrets)
	}
	// Closed, and kept already: let go of, its secrets with it.
	_ = conn.Close()
	if len(w.conns) != 0 || len(w.secrets) != 0 {
		t.Errorf("%d connections and %d secrets left", len(w.conns), len(w.secrets))
	}
	if streams, secrets := w.capture(1); streams != nil || secrets != nil {
		t.Errorf("a request kept again has %v and %q", streams, secrets)
	}
}

func TestTheWireFindsTheClientHelloAConnectionBeganWith(t *testing.T) {
	hello := helloOf(0x11)
	random := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	for _, tc := range []struct {
		name   string
		writes [][]byte
		random string
		looked bool
	}{
		{"at once", [][]byte{hello}, random, true},
		{"in two writes", [][]byte{hello[:20], hello[20:]}, random, true},
		{"after a CONNECT in pieces", [][]byte{[]byte("CONN"), []byte("ECT a:443 HTTP/1.1\r\n"), []byte("\r\n"), hello}, random, true},
		{"not yet", [][]byte{hello[:20]}, "", false},
		{"plain HTTP", [][]byte{[]byte("GET / HTTP/1.1\r\n")}, "", true},
		{"after a CONNECT, plain HTTP", [][]byte{[]byte("CONNECT a:80 HTTP/1.1\r\n\r\nGET /")}, "", true},
		{"a CONNECT that never ends", [][]byte{[]byte("CONNECT a:443 HTTP/1.1\r\n"), bytes.Repeat([]byte("x"), maxHead)}, "", true},
		{"after a SOCKS5 handshake", [][]byte{{5, 2, 0, 2}, {1, 1, 'u', 1, 'p'}, {5, 1, 0, 1, 127, 0, 0, 1, 1, 187}, hello},
			random, true},
		{"after a SOCKS4 handshake", [][]byte{{4, 1, 1, 187, 127, 0, 0, 1, 'u', 0}, hello}, random, true},
		{"a SOCKS5 handshake not done", [][]byte{{5, 2, 0, 2}, {1, 1, 'u'}}, "", false},
		{"after a SOCKS5 handshake, plain HTTP", [][]byte{{5, 1, 0}, {5, 1, 0, 1, 127, 0, 0, 1, 0, 80},
			[]byte("GET / HTTP/1.1\r\n")}, "", true},
		{"a handshake record too long to wait for", [][]byte{{22, 3, 1}, make([]byte, maxHead)}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWire()
			conn, far := dialedPair(t, w, 1, stringAddr("127.0.0.1:5000"), stringAddr("127.0.0.1:443"))
			go func() { _, _ = io.Copy(io.Discard, far) }()
			for _, write := range tc.writes {
				if _, err := conn.Write(write); err != nil {
					t.Fatal(err)
				}
			}
			c := w.conns[0]
			_, wanted := w.secrets[tc.random]
			if c.random != tc.random || c.looked != tc.looked || (tc.random != "" && !wanted) ||
				(c.looked && c.head != nil) {
				t.Errorf("random %q, looked %v, head of %d, wanted %v", c.random, c.looked, len(c.head), wanted)
			}
		})
	}
}

func TestTheWireMasksWhatAProxyWasGivenInTheClear(t *testing.T) {
	// Write by write, as the client wrote them, cut where they may be: the
	// credentials masked in what the capture holds, and the ClientHello
	// found after them all the same.
	random := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	for _, tc := range []struct {
		name         string
		writes, want [][]byte
	}{
		{"a SOCKS5 password",
			[][]byte{{5, 2, 0, 2}, {1, 5, 'a', 'l', 'i', 'c', 'e', 6, 's', '3'}, []byte("cr3t"),
				{5, 1, 0, 1, 127, 0, 0, 1, 1, 187}, helloOf(0x11)},
			[][]byte{{5, 2, 0, 2}, {1, 5, 'a', 'l', 'i', 'c', 'e', 6, '*', '*'}, []byte("****"),
				{5, 1, 0, 1, 127, 0, 0, 1, 1, 187}, helloOf(0x11)}},
		{"a CONNECT's credentials",
			[][]byte{[]byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic YW"), []byte("xp\r\n\r\n"), helloOf(0x11)},
			[][]byte{[]byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic **"), []byte("**\r\n\r\n"), helloOf(0x11)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWire()
			conn, far := dialedPair(t, w, 1, stringAddr("127.0.0.1:5000"), stringAddr("127.0.0.1:1080"))
			go func() { _, _ = io.Copy(io.Discard, far) }()
			for _, write := range tc.writes {
				if _, err := conn.Write(write); err != nil {
					t.Fatal(err)
				}
			}
			// The client's own bytes as they were, and the capture's masked.
			if c := w.conns[0]; c.random != random || !c.looked {
				t.Errorf("random %q, looked %v", c.random, c.looked)
			}
			streams, _ := w.capture(1)
			for i, e := range streams[0].Events {
				if !bytes.Equal(e.Data, tc.want[i]) {
					t.Errorf("write %d: %q, want %q", i, e.Data, tc.want[i])
				}
			}
		})
	}
	// Once the ClientHello is found, what follows is as it was sent.
	w := newWire()
	conn, far := dialedPair(t, w, 1, stringAddr("127.0.0.1:5000"), stringAddr("127.0.0.1:1080"))
	go func() { _, _ = io.Copy(io.Discard, far) }()
	after := []byte("CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxp\r\n\r\n")
	for _, write := range [][]byte{helloOf(0x11), after} {
		if _, err := conn.Write(write); err != nil {
			t.Fatal(err)
		}
	}
	if streams, _ := w.capture(1); !bytes.Equal(streams[0].Events[1].Data, after) {
		t.Errorf("after the ClientHello: %q", streams[0].Events[1].Data)
	}
}

func TestTheWireSaysHowAConnectionEnded(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want []pcapng.Kind
	}{
		{"ended", io.EOF, []pcapng.Kind{pcapng.Received, pcapng.Ended}},
		{"reset", &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
			[]pcapng.Kind{pcapng.Received, pcapng.Reset}},
		{"out of time", os.ErrDeadlineExceeded, []pcapng.Kind{pcapng.Received}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWire()
			c := &wiredConn{w: w, users: map[int]bool{1: true}}
			w.received(c, []byte("x"), tc.err)
			w.received(c, nil, nil) // a read of nothing is nothing
			var got []pcapng.Kind
			for _, e := range c.events {
				got = append(got, e.What)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("%v, want %v", got, tc.want)
			}
		})
	}
	// Closed twice, closed once; and a write of nothing is nothing.
	w := newWire()
	c := &wiredConn{w: w, users: map[int]bool{1: true}}
	w.sent(c, nil)
	w.closing(c)
	w.closing(c)
	if len(c.events) != 1 || c.events[0].What != pcapng.Closed || len(w.conns) != 0 {
		t.Errorf("%v, %d connections", c.events, len(w.conns))
	}
}

func TestTheWireTellsAConnectionByItsEnds(t *testing.T) {
	w := newWire()
	near, far := stringAddr("127.0.0.1:5000"), stringAddr("127.0.0.1:443")
	conn, _ := dialedPair(t, w, 1, near, far)
	// Another request goes out on it: the one with the same two ends.
	other, _ := dialedPair(t, w, 1, stringAddr("127.0.0.1:5001"), far)
	w.tap(2).Used(pipeConn{local: near, remote: far})
	// None of the wire's: nothing.
	w.tap(3).Used(pipeConn{local: stringAddr("127.0.0.1:9"), remote: far})
	if streams, _ := w.capture(2); len(streams) != 1 || streams[0].Client != netip.MustParseAddrPort("127.0.0.1:5000") {
		t.Errorf("request 2 went out on %v", streams)
	}
	if streams, _ := w.capture(3); streams != nil {
		t.Errorf("request 3 went out on %v", streams)
	}
	// A closed one is gone out on by nobody, though its ends come again.
	_ = other.Close()
	_ = conn.Close()
	w.tap(4).Used(pipeConn{local: near, remote: far})
	if streams, _ := w.capture(4); streams != nil {
		t.Errorf("request 4 went out on %v", streams)
	}
	// Request 1 has both still, closed as they are.
	if streams, _ := w.capture(1); len(streams) != 2 || len(w.conns) != 0 {
		t.Errorf("request 1 went out on %d, %d left", len(streams), len(w.conns))
	}
}

func TestAddrPortOf(t *testing.T) {
	for _, tc := range []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, "192.0.2.1:443"},
		{stringAddr("[2001:db8::1]:8443"), "[2001:db8::1]:8443"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 80}, "[2001:db8::2]:80"},
		{stringAddr("[::ffff:192.0.2.1]:443"), "192.0.2.1:443"},
		{stringAddr("pipe"), "invalid AddrPort"},
	} {
		if got := addrPortOf(tc.addr).String(); got != tc.want {
			t.Errorf("addrPortOf(%v) = %s, want %s", tc.addr, got, tc.want)
		}
	}
}

func TestKeysGoToTheKeyLogAndTheWire(t *testing.T) {
	w := newWire()
	if keysTo(nil, w) != io.Writer(w) {
		t.Error("with no key log, the secrets go elsewhere than the wire")
	}
	var log bytes.Buffer
	if n, err := keysTo(&log, w).Write([]byte("line\n")); n != 5 || err != nil || log.String() != "line\n" {
		t.Errorf("%d, %v: the key log has %q", n, err, log.String())
	}
}
