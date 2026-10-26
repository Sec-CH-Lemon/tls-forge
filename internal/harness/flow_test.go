package harness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const flowFixture = "../../testdata/chrome155-flow.json"

// testShapes are answers a test can wait out.
var testShapes = map[string]FlowShape{
	"parts": {Note: "in parts", Window: 65535, Size: 40000, Part: 20000, Pause: 30, EndPause: 20},
	"whole": {Note: "whole", Window: 1 << 20, Size: 1000},
	"again": {Note: "with a second", Window: 65535, Size: 2000, EndPause: 10, Again: 3000, AgainAfter: 20},
	"long":  {Note: "a long pause", Window: 65535, Size: 2000, Part: 1000, Pause: 60000},
	"end":   {Note: "a long end", Window: 65535, Size: 1000, EndPause: 60000},
	"big":   {Note: "more than a small window", Window: 65535, Size: 100000},
	"short": {Note: "a short end", Window: 65535, Size: 1000, EndPause: 100},
}

// startedFlow is a FlowServer of shapes, closed with the test.
func startedFlow(t *testing.T, shapes map[string]FlowShape) *FlowServer {
	t.Helper()
	s, err := startFlowServer(shapes, 1)
	if err != nil {
		t.Fatalf("startFlowServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// flowClient is an HTTP/2 client over a framer of the test's, which tells the
// server of its windows only when the test does.
type flowClient struct {
	t     *testing.T
	conn  *tls.Conn
	fr    *http2.Framer
	enc   *hpack.Encoder
	block bytes.Buffer
	next  uint32
}

// dialFlow connects to s's port for window, its own window window, and says
// the connection's as Chrome does, which the server does not keep.
func dialFlow(t *testing.T, s *FlowServer, port int, window uint32) *flowClient {
	t.Helper()
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // the bench's own
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &flowClient{t: t, conn: conn, fr: http2.NewFramer(conn, conn), next: 1}
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.enc = hpack.NewEncoder(&c.block)
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("preface: %v", err)
	}
	if err := c.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window}); err != nil {
		t.Fatalf("SETTINGS: %v", err)
	}
	if err := c.fr.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatalf("WINDOW_UPDATE: %v", err)
	}
	return c
}

// get asks for path, and is its stream.
func (c *flowClient) get(path string) uint32 {
	c.t.Helper()
	c.block.Reset()
	for _, f := range [][2]string{{":method", "GET"}, {":authority", "www.example.com"}, {":scheme", "https"}, {":path", path}} {
		_ = c.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	sid := c.next
	c.next += 2
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: sid, BlockFragment: c.block.Bytes(), EndStream: true,
		EndHeaders: true}); err != nil {
		c.t.Fatalf("HEADERS: %v", err)
	}
	return sid
}

// answer is what came on sid: its status when n is 0, else its body until n
// bytes of it, or its end; and whether it ended.
func (c *flowClient) answer(sid uint32, n int) (status string, body int, ended bool) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for !ended && (body < n || n == 0 && status == "") {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.t.Fatalf("ReadFrame: %v", err)
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID == sid {
				status, ended = f.PseudoValue("status"), f.StreamEnded()
			}
		case *http2.DataFrame:
			if f.StreamID == sid {
				body += len(f.Data())
				ended = f.StreamEnded()
			}
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = c.fr.WriteSettingsAck()
			}
		}
	}
	return status, body, ended
}

// ping sends a PING and waits for its acknowledgement.
func (c *flowClient) ping() {
	c.t.Helper()
	if err := c.fr.WritePing(false, [8]byte{1}); err != nil {
		c.t.Fatalf("PING: %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.t.Fatalf("ReadFrame: %v", err)
		}
		if p, ok := f.(*http2.PingFrame); ok && p.IsAck() {
			return
		}
	}
}

// waitEnded waits for s to have sent every answer of id.
func waitEnded(t *testing.T, s *FlowServer, id string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !s.Ended(id); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not end", id)
		}
	}
}

func TestAFixtureOfWindowUpdatesIsWrittenAsItIsKept(t *testing.T) {
	f := &FlowFixture{Browser: "b", Measured: "2026-10-18", How: "<how>", Scenarios: map[string]FlowScenario{
		"s": {FlowShape: FlowShape{Note: "n", Window: 65535, Size: 3}, Updates: []FlowUpdate{{Window: windowFirst, Increment: 9, Part: 1}}},
	}}
	path := filepath.Join(t.TempDir(), "flow.json")
	if err := f.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, _ := os.ReadFile(path)
	want := "{\n \"browser\": \"b\",\n \"measured\": \"2026-10-18\",\n \"how\": \"<how>\",\n \"scenarios\": {\n  \"s\": {\n" +
		"   \"note\": \"n\",\n   \"window\": 65535,\n   \"size\": 3,\n   \"updates\": [\n    {\n     \"window\": \"first\",\n" +
		"     \"increment\": 9,\n     \"part\": 1\n    }\n   ]\n  }\n }\n}"
	if string(data) != want {
		t.Errorf("written\n%s\nwant\n%s", data, want)
	}
	read, err := LoadFlow(path)
	if err != nil || read.Scenarios["s"].Updates[0].Increment != 9 || read.Scenarios["s"].Window != 65535 {
		t.Errorf("LoadFlow: %+v, %v", read, err)
	}
	// The committed fixture is what the catalogue measures, as it would be
	// written.
	kept, err := LoadFlow(flowFixture)
	if err != nil {
		t.Fatalf("LoadFlow: %v", err)
	}
	if got, want := slices.Sorted(maps.Keys(kept.Scenarios)), slices.Sorted(maps.Keys(flowCatalogue)); !slices.Equal(got, want) {
		t.Fatalf("the fixture has %v, the catalogue %v", got, want)
	}
	for id, sc := range kept.Scenarios {
		if sc.FlowShape != flowCatalogue[id] {
			t.Errorf("%s: the fixture says %+v, the catalogue %+v", id, sc.FlowShape, flowCatalogue[id])
		}
	}
	again := filepath.Join(t.TempDir(), "again.json")
	if err := kept.Write(again); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if a, b := must(os.ReadFile(flowFixture)), must(os.ReadFile(again)); !bytes.Equal(a, b) {
		t.Error("the fixture is not as it would be written")
	}
}

// must is v, failing on nothing: a file a test has just read.
func must(v []byte, _ error) []byte { return v }

func TestAnAnswersBodyIsLinesOfXAfterItsHead(t *testing.T) {
	plain := flowBody(FlowShape{Size: 200}, "p", false)
	if len(plain) != 200 || !bytes.HasPrefix(plain, []byte("<!doctype html><title>flow</title><pre>\n")) ||
		plain[127] != '\n' || plain[128] != 'x' || plain[199] != 'x' {
		t.Errorf("plain: %q", plain)
	}
	first := flowBody(FlowShape{Size: 300, Again: 10, AgainAfter: 6000}, "a", false)
	if len(first) != 300 || !bytes.Contains(first, []byte("fetch('/flow/a/again').then(r=>r.arrayBuffer()),6000)")) {
		t.Errorf("first: %q", first)
	}
	second := flowBody(FlowShape{Size: 300, Again: 70}, "a", true)
	if len(second) != 70 || second[0] != 'x' || second[63] != '\n' {
		t.Errorf("second: %q", second)
	}
}

func TestWhatWindowUpdatesDifferInIsSaid(t *testing.T) {
	half, connHalf := uint32(3<<20), uint32(15<<19)
	up := func(window string, inc uint32, part int) FlowUpdate {
		return FlowUpdate{Window: window, Increment: inc, Part: part}
	}
	sc := func(updates ...FlowUpdate) FlowScenario { return FlowScenario{Updates: updates} }
	chrome := sc(up(windowFirst, half+9, 0), up(windowConnection, connHalf+8000, 0), up(windowFirst, 65545, 1))
	for _, c := range []struct {
		name string
		got  FlowScenario
		says string
	}{
		{"alike", sc(up(windowFirst, half+8192, 0), up(windowConnection, connHalf+1, 0), up(windowFirst, 73728, 1)), ""},
		{"fewer", sc(up(windowFirst, half+9, 0)), "1 window updates, want 3"},
		{"another window", sc(up(windowConnection, half+9, 0), up(windowConnection, connHalf+8000, 0), up(windowFirst, 65545, 1)),
			"update 1: of connection in part 0, want of first in part 0"},
		{"another part", sc(up(windowFirst, half+9, 1), up(windowConnection, connHalf+8000, 0), up(windowFirst, 65545, 1)),
			"update 1: of first in part 1, want of first in part 0"},
		{"not past half", sc(up(windowFirst, half, 0), up(windowConnection, connHalf+8000, 0), up(windowFirst, 65545, 1)),
			"update 1: 3145728, want 3145737: one past half of the window, one not"},
		{"the connection's not past half", sc(up(windowFirst, half+9, 0), up(windowConnection, connHalf, 0), up(windowFirst, 65545, 1)),
			"update 2: 7864320, want 7872320: one past half of the window, one not"},
		{"more than a read past half", sc(up(windowFirst, half+8193, 0), up(windowConnection, connHalf+8000, 0), up(windowFirst, 65545, 1)),
			"update 1: 3153921, more than a read past half of the window"},
		{"more than a read apart", sc(up(windowFirst, half+9, 0), up(windowConnection, connHalf+8000, 0), up(windowFirst, 65545+8193, 1)),
			"update 3: 73738, want 65545, more than a read apart"},
		{"more than a read less", sc(up(windowFirst, half+9, 0), up(windowConnection, connHalf+8000, 0), up(windowFirst, 65545-8193, 1)),
			"update 3: 57352, want 65545, more than a read apart"},
		// The stream's last, after another of it, from a reader slower than
		// the stream's end: no difference; the others held all the same.
		{"the stream's last missing", sc(up(windowFirst, half+9, 0), up(windowConnection, connHalf+8000, 0)), ""},
		{"the stream's last missing, another apart", sc(up(windowFirst, half, 0), up(windowConnection, connHalf+8000, 0)),
			"update 1: 3145728, want 3145737: one past half of the window, one not"},
	} {
		got := strings.Join(DiffFlow(chrome, c.got), "\n")
		if got != c.says && (c.says == "" || !strings.HasPrefix(got, c.says)) {
			t.Errorf("%s: %q, want %q", c.name, got, c.says)
		}
	}
	diff := CompareFlow(map[string]FlowScenario{"a": chrome, "b": chrome},
		map[string]FlowScenario{"a": sc(up(windowFirst, half+9, 0)), "c": chrome})
	if want := []string{"a: 1 window updates, want 3", "b was not measured",
		"c was measured, and the fixture has no such scenario"}; len(diff) != 3 || !strings.HasPrefix(diff[0], want[0]) ||
		diff[1] != want[1] || diff[2] != want[2] {
		t.Errorf("CompareFlow: %q", diff)
	}
	if diff := CompareFlow(map[string]FlowScenario{"a": chrome}, map[string]FlowScenario{"a": chrome}); diff != nil {
		t.Errorf("alike: %q", diff)
	}
	// The last missing is a difference when it is the connection's, or a
	// stream's only one.
	for name, want := range map[string]FlowScenario{
		"the connection's last": sc(up(windowConnection, connHalf+8000, 0), up(windowFirst, half+9, 0), up(windowConnection, connHalf+8000, 0)),
		"a stream's only one":   sc(up(windowConnection, connHalf+8000, 0), up(windowFirst, half+9, 0)),
		"the only one":          sc(up(windowFirst, half+9, 0)),
	} {
		lacking := FlowScenario{Updates: want.Updates[:len(want.Updates)-1]}
		if diff := DiffFlow(want, lacking); len(diff) != 1 || !strings.Contains(diff[0], "window updates, want") {
			t.Errorf("%s missing: %q", name, diff)
		}
	}
}

func TestTheFlowServerSendsAnAnswerInItsPartsAndKeepsWhatTheClientSaid(t *testing.T) {
	s := startedFlow(t, testShapes)
	if s.URL("parts") != fmt.Sprintf("https://www.example.com:%d/flow/parts", s.Ports[65535]) || len(s.Ports) != 2 {
		t.Errorf("URL %s, ports %v", s.URL("parts"), s.Ports)
	}
	// The client's own window, 30000 bytes: the server waits for it to grow
	// in the second part.
	c := dialFlow(t, s, s.Ports[65535], 30000)
	c.ping()
	sid := c.get("/flow/parts")
	if status, body, ended := c.answer(sid, 30000); status != "200" || body != 30000 || ended {
		t.Fatalf("first: %s, %d bytes, ended %v", status, body, ended)
	}
	// A PING answered, its answer passed over, and SETTINGS that move the
	// stream's window.
	if err := c.fr.WritePing(true, [8]byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := c.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 35000}); err != nil {
		t.Fatal(err)
	}
	if err := c.fr.WriteSettingsAck(); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := c.answer(sid, 5000); body != 5000 {
		t.Fatalf("after SETTINGS: %d bytes", body)
	}
	if err := c.fr.WriteWindowUpdate(sid, 6000); err != nil {
		t.Fatal(err)
	}
	if err := c.fr.WriteWindowUpdate(0, 7000); err != nil {
		t.Fatal(err)
	}
	if err := c.fr.WriteWindowUpdate(99, 1); err != nil {
		t.Fatal(err)
	}
	if _, body, ended := c.answer(sid, 1<<30); body != 5000 || !ended {
		t.Fatalf("the rest: %d bytes, ended %v", body, ended)
	}
	waitEnded(t, s, "parts")
	c.ping()
	got, err := s.Updates("parts")
	if want := []FlowUpdate{{windowFirst, 6000, 1}, {windowConnection, 7000, 1}, {windowOther, 1, 1}}; err != nil ||
		!slices.Equal(got, want) {
		t.Errorf("Updates: %v, %v, want %v", got, err, want)
	}
	// Anything else is not found.
	for _, path := range []string{"/favicon.ico", "/flow/none", "/flow/parts/again"} {
		if status, _, ended := c.answer(c.get(path), 0); status != "404" || !ended {
			t.Errorf("%s: %s, ended %v", path, status, ended)
		}
	}
	if _, err := s.Updates("whole"); err == nil {
		t.Error("an answer not asked for has updates")
	}
	// Reset forgets them, and the parts counted.
	s.Reset()
	if _, err := s.Updates("parts"); err == nil || s.Ended("parts") {
		t.Error("Reset forgot nothing")
	}
}

func TestAnAnswersSecondIsAskedForOnAnyConnection(t *testing.T) {
	s := startedFlow(t, testShapes)
	a := dialFlow(t, s, s.Ports[65535], 1<<20)
	if status, body, ended := a.answer(a.get("/flow/again"), 1<<30); status != "200" || body != 2000 || !ended {
		t.Fatalf("first: %s, %d, %v", status, body, ended)
	}
	if _, err := s.Updates("again"); err == nil || s.Ended("again") {
		t.Error("an answer whose second was not asked for has updates, or ended")
	}
	b := dialFlow(t, s, s.Ports[65535], 1<<20)
	sid := b.get("/flow/again/again")
	if status, body, ended := b.answer(sid, 1<<30); status != "200" || body != 3000 || !ended {
		t.Fatalf("second: %s, %d, %v", status, body, ended)
	}
	waitEnded(t, s, "again")
	if err := b.fr.WriteWindowUpdate(sid, 3000); err != nil {
		t.Fatal(err)
	}
	b.ping()
	// The first's part, its end, the second's, and its end: the update comes
	// in the fourth.
	if got, err := s.Updates("again"); err != nil || !slices.Equal(got, []FlowUpdate{{windowSecond, 3000, 3}}) {
		t.Errorf("Updates: %v, %v", got, err)
	}
}

func TestAnAnswerResetOrOnAConnectionGoneIsSentNoMore(t *testing.T) {
	s := startedFlow(t, testShapes)
	c := dialFlow(t, s, s.Ports[65535], 1000)
	sid := c.get("/flow/big")
	if _, body, _ := c.answer(sid, 1000); body != 1000 {
		t.Fatalf("%d bytes", body)
	}
	if err := c.fr.WriteRSTStream(sid, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	c.ping()
	if err := c.fr.WriteWindowUpdate(sid, 1000); err != nil {
		t.Fatal(err)
	}
	c.ping()
	time.Sleep(20 * time.Millisecond)
	if s.Ended("big") {
		t.Error("a reset answer ended")
	}
	// Reset before the frame that would end it.
	sid = c.get("/flow/short")
	if _, body, _ := c.answer(sid, 1000); body != 1000 {
		t.Fatalf("%d bytes", body)
	}
	if err := c.fr.WriteRSTStream(sid, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	c.ping()
	time.Sleep(200 * time.Millisecond)
	if s.Ended("short") {
		t.Error("an answer reset before its end ended")
	}
	// Waiting for a window on a connection the client then closes.
	d := dialFlow(t, s, s.Ports[65535], 1000)
	if _, body, _ := d.answer(d.get("/flow/big"), 1000); body != 1000 {
		t.Fatalf("%d bytes", body)
	}
	_ = d.conn.Close()
	time.Sleep(20 * time.Millisecond)
	if s.Ended("big") {
		t.Error("an answer on a closed connection ended")
	}
}

func TestClosingTheFlowServerEndsWhatIsGoing(t *testing.T) {
	// An answer in a pause, one before the frame that ends it, and a
	// connection open: Close ends them all, at once.
	s, err := startFlowServer(testShapes, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := dialFlow(t, s, s.Ports[65535], 1<<20)
	if _, body, _ := c.answer(c.get("/flow/long"), 1000); body != 1000 {
		t.Fatalf("%d bytes", body)
	}
	if _, body, _ := c.answer(c.get("/flow/end"), 1000); body != 1000 {
		t.Fatalf("%d bytes", body)
	}
	closed := make(chan struct{})
	go func() {
		_ = s.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for the pauses")
	}
	if s.Ended("long") || s.Ended("end") {
		t.Error("an answer cut short ended")
	}
	_ = s.Close()
}

func TestAConnectionThatIsNoHTTP2IsLetGo(t *testing.T) {
	s := startedFlow(t, testShapes)
	port := s.Ports[65535]
	for name, talk := range map[string]func() (net.Conn, error){
		"not TLS": func() (net.Conn, error) {
			conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err == nil {
				_, err = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			}
			return conn, err
		},
		"no ALPN": func() (net.Conn, error) {
			return tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the bench's own
		},
		"no preface": func() (net.Conn, error) {
			conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port),
				&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // the bench's own
			if err == nil {
				_, err = conn.Write([]byte(strings.Repeat("x", len(http2.ClientPreface))))
			}
			return conn, err
		},
	} {
		conn, err := talk()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(conn); err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "reset") &&
			!strings.Contains(err.Error(), "alert") {
			t.Errorf("%s: the connection was not let go: %v", name, err)
		}
		_ = conn.Close()
	}
}

func TestAConnectionThatArrivesAsTheFlowServerClosesIsClosedToo(t *testing.T) {
	s := startedFlow(t, testShapes)
	ours, theirs := net.Pipe()
	defer func() { _ = theirs.Close() }()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.done.Add(1)
	s.accept(&oneConnListener{conn: ours}, 65535)
	if _, err := ours.Write([]byte("x")); err == nil {
		t.Error("the connection was left open")
	}
	s.mu.Lock()
	s.closed = false
	s.mu.Unlock()
}

func TestAFlowServerThatCannotStartSaysWhy(t *testing.T) {
	failing := errors.New("no")
	oldKey, oldListen := newKey, listen
	t.Cleanup(func() { newKey, listen = oldKey, oldListen })
	newKey = func() (*ecdsa.PrivateKey, error) { return nil, failing }
	if _, err := startFlowServer(testShapes, 1); !errors.Is(err, failing) {
		t.Errorf("no key: %v", err)
	}
	newKey = oldKey
	calls := 0
	listen = func(network, addr string) (net.Listener, error) {
		if calls++; calls < 2 {
			return net.Listen(network, addr)
		}
		return nil, failing
	}
	if _, err := startFlowServer(testShapes, 1); !errors.Is(err, failing) {
		t.Errorf("no port: %v", err)
	}
	listen = oldListen
	s, err := StartFlowServer(0.5)
	if err != nil || s.Scale != 0.5 || len(s.Ports) != 3 {
		t.Fatalf("StartFlowServer: %v, %+v", err, s)
	}
	_ = s.Close()
}

// flowBrowser is a browser that reads the answer it opens to its end, and its
// second when the shape says, on a connection of its own.
type flowBrowser struct {
	shapes map[string]FlowShape
	fail   bool
	silent bool
}

func (b *flowBrowser) Open(_ context.Context, page, _ string) (func(), error) {
	if b.fail {
		return nil, errors.New("the fake would not open " + page)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if b.silent {
			return
		}
		read(page)
		id := page[strings.LastIndex(page, "/")+1:]
		if shape := b.shapes[id]; shape.Again > 0 {
			time.Sleep(time.Duration(shape.AgainAfter) * time.Millisecond)
			read(page + "/again")
		}
	}()
	return func() { <-done }, nil
}

func (b *flowBrowser) DumpDOM(context.Context, string) ([]byte, error) { return nil, nil }

// read asks for page over HTTP/2 and reads the answer to its end, on a
// connection of its own.
func read(page string) {
	res, err := client().Get(page)
	if err == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}
}

func TestWindowUpdatesAreMeasuredScenarioByScenario(t *testing.T) {
	shapes := map[string]FlowShape{"parts": testShapes["parts"], "again": testShapes["again"]}
	var progress bytes.Buffer
	got, err := measureFlow(context.Background(), &flowBrowser{shapes: shapes}, shapes, nil, quick, &progress)
	if err != nil {
		t.Fatalf("measureFlow: %v", err)
	}
	if len(got) != 2 || got["parts"].FlowShape != shapes["parts"] || got["again"].FlowShape != shapes["again"] ||
		!strings.Contains(progress.String(), "h2 again: ") || !strings.Contains(progress.String(), "h2 parts: ") {
		t.Errorf("measured %+v, said %q", got, progress.String())
	}
	if got, err := measureFlow(context.Background(), &flowBrowser{shapes: shapes}, shapes, []string{"parts"}, quick, nil); err != nil ||
		len(got) != 1 {
		t.Errorf("only parts: %v, %v", got, err)
	}
}

func TestAWindowUpdateMeasurementSaysWhyItIsNone(t *testing.T) {
	shapes := map[string]FlowShape{"parts": testShapes["parts"]}
	if _, err := MeasureFlow(context.Background(), &flowBrowser{}, []string{"none"}, nil); err == nil ||
		!strings.Contains(err.Error(), "there is no scenario none") {
		t.Errorf("an unknown scenario: %v", err)
	}
	if _, err := measureFlow(context.Background(), &flowBrowser{fail: true}, shapes, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "harness: parts: the fake would not open") {
		t.Errorf("a browser that does not open: %v", err)
	}
	if _, err := measureFlow(context.Background(), &flowBrowser{silent: true}, shapes, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), "had not gone within 2s") {
		t.Errorf("a browser that asks for nothing: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := measureFlow(ctx, &flowBrowser{silent: true}, shapes, nil, quick, nil); err == nil ||
		!strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Errorf("a measurement stopped: %v", err)
	}
	tempNowhere(t)
	if _, err := measureFlow(context.Background(), &flowBrowser{}, shapes, nil, quick, nil); err == nil {
		t.Error("measured with nowhere to keep a profile")
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := measureFlow(context.Background(), &flowBrowser{}, shapes, nil, quick, nil); !errors.Is(err, failing) {
		t.Errorf("measured with no server: %v", err)
	}
}
