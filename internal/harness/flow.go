package harness

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// FlowFixture is what testdata/chrome155-flow.json holds: the WINDOW_UPDATEs a
// browser sent while it read the answer of each scenario, as a server sent it.
type FlowFixture struct {
	// Browser says which browser was measured, how it was run and where.
	Browser string `json:"browser"`
	// Measured are the dates it was, and How says how.
	Measured  string                  `json:"measured"`
	How       string                  `json:"how"`
	Scenarios map[string]FlowScenario `json:"scenarios"`
}

// FlowShape is how the server sends a scenario's answer.
type FlowShape struct {
	Note string `json:"note"`
	// Window is the SETTINGS_INITIAL_WINDOW_SIZE the server advertises.
	Window uint32 `json:"window"`
	// Size is the body's, in bytes, sent in parts of Part bytes, the last
	// what is left, with a pause of Pause milliseconds after each but the
	// last: in one part when Part is 0. Each part goes as fast as the
	// client's windows let it.
	Size  int `json:"size"`
	Part  int `json:"part,omitempty"`
	Pause int `json:"pause,omitempty"`
	// EndPause is how long the server waits after the last part before it
	// ends the stream, in milliseconds, with a DATA frame of its own; 0 ends
	// it on the last part's last frame.
	EndPause int `json:"end_pause,omitempty"`
	// Again is the size of a second body, which the first, a page, asks for
	// with fetch() AgainAfter milliseconds after it has loaded: sent in one
	// part, its stream ended EndPause after it as the first's is. 0 for none.
	Again      int `json:"again,omitempty"`
	AgainAfter int `json:"again_after,omitempty"`
}

// FlowScenario is a scenario's answer and the WINDOW_UPDATEs the browser sent
// while it read it, in the order they came: those of every connection but each
// one's first, which said the connection's window as it began. Chrome may ask
// for flow-again's second answer on a connection of its own.
type FlowScenario struct {
	FlowShape
	Updates []FlowUpdate `json:"updates"`
}

// FlowUpdate is a WINDOW_UPDATE: of the connection's window or of the stream of
// the first answer or the second; its increment; and the part of the answers
// being sent when it came, counting each answer's parts in order and the frame
// that ends a stream on its own as one.
type FlowUpdate struct {
	Window    string `json:"window"`
	Increment uint32 `json:"increment"`
	Part      int    `json:"part"`
}

// The windows a FlowUpdate names.
const (
	windowConnection = "connection"
	windowFirst      = "first"
	windowSecond     = "second"
	windowOther      = "other"
)

// LoadFlow reads a fixture of WINDOW_UPDATEs.
func LoadFlow(path string) (*FlowFixture, error) { return load[FlowFixture](path) }

// Write writes the fixture to path as it is kept, as the fixture of requests
// is.
func (f *FlowFixture) Write(path string) error { return writeJSON(path, f) }

// flowCatalogue is every scenario the WINDOW_UPDATEs were measured in, by its
// name in the fixture: a navigation typed in, and, for the last, the fetch()
// its page makes. The streams end on a frame of their own after a pause, as
// does a part that crosses half of a window before the next comes: a reader
// tells a stream of its window only while the stream is open, and these let
// any reader catch up before it ends.
var flowCatalogue = map[string]FlowShape{
	"flow-small": {Note: "300 KiB in one part, the stream ended on its last frame", Window: 65535, Size: 300 << 10},
	"flow-half": {Note: "4 MiB, 3.5 MiB and a pause, then the rest", Window: 65535, Size: 4 << 20,
		Part: 3584 << 10, Pause: 500, EndPause: 500},
	"flow-half-16m": {Note: "flow-half from a server whose own window is 16 MiB", Window: 16 << 20, Size: 4 << 20,
		Part: 3584 << 10, Pause: 500, EndPause: 500},
	"flow-connection": {Note: "20 MiB, more than the connection's window, as fast as the windows let it",
		Window: 65535, Size: 20 << 20, EndPause: 2000},
	"flow-connection-1m": {Note: "flow-connection from a server whose own window is 1 MiB", Window: 1 << 20,
		Size: 20 << 20, EndPause: 2000},
	"flow-pause-6s": {Note: "three parts of 64 KiB, six seconds apart", Window: 65535, Size: 192 << 10,
		Part: 64 << 10, Pause: 6000, EndPause: 300},
	"flow-pause-4s": {Note: "three parts of 64 KiB, four seconds apart", Window: 65535, Size: 192 << 10,
		Part: 64 << 10, Pause: 4000, EndPause: 300},
	"flow-again": {Note: "a page of 2000 bytes, then a fetch() of 3000 its script makes six seconds later",
		Window: 65535, Size: 2000, EndPause: 300, Again: 3000, AgainAfter: 6000},
}

// FlowServer answers over HTTP/2 alone, from a port for each window the
// scenarios ask it to advertise, the answers of the flow catalogue at
// /flow/<name> (and the second of flow-again at /flow/<name>/again), and keeps
// the WINDOW_UPDATEs of every connection, and which part of the answers was
// going when each came, until it is reset: one scenario at a time. Its pauses
// are the catalogue's times Scale, which a test makes short.
type FlowServer struct {
	// Ports are its ports by the SETTINGS_INITIAL_WINDOW_SIZE each
	// advertises.
	Ports map[uint32]int
	Scale float64

	shapes    map[string]FlowShape
	tls       *tls.Config
	listeners []net.Listener
	done      sync.WaitGroup
	// stop ends the pauses of the answers going when the server closes.
	stop chan struct{}

	mu      sync.Mutex
	asked   map[string]bool
	ended   map[string]bool
	part    int
	updates []FlowUpdate
	closed  bool
	open    map[net.Conn]struct{}
}

// StartFlowServer starts a FlowServer for the flow catalogue, its pauses the
// catalogue's times scale.
func StartFlowServer(scale float64) (*FlowServer, error) {
	return startFlowServer(flowCatalogue, scale)
}

func startFlowServer(shapes map[string]FlowShape, scale float64) (*FlowServer, error) {
	cert, err := certificate()
	if err != nil {
		return nil, err
	}
	s := &FlowServer{Ports: map[uint32]int{}, Scale: scale, shapes: shapes, asked: map[string]bool{},
		ended: map[string]bool{}, open: map[net.Conn]struct{}{}, stop: make(chan struct{}),
		tls: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}}
	windows := map[uint32]bool{}
	for _, shape := range shapes {
		windows[shape.Window] = true
	}
	for _, window := range slices.Sorted(maps.Keys(windows)) {
		ln, err := listen("tcp", "127.0.0.1:0")
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("harness: %w", err)
		}
		s.listeners = append(s.listeners, ln)
		s.Ports[window] = ln.Addr().(*net.TCPAddr).Port
		s.done.Add(1)
		go s.accept(ln, window)
	}
	return s, nil
}

// URL is where the answer of the scenario id is asked for: from the port of
// the window it asks for, at www.example.com, which the browser takes to the
// loopback address.
func (s *FlowServer) URL(id string) string {
	return fmt.Sprintf("https://www.example.com:%d/flow/%s", s.Ports[s.shapes[id].Window], id)
}

func (s *FlowServer) accept(ln net.Listener, window uint32) {
	defer s.done.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = raw.Close()
			return
		}
		s.open[raw] = struct{}{}
		s.done.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.done.Done()
			defer s.forget(raw)
			s.serve(raw, window)
		}()
	}
}

func (s *FlowServer) forget(raw net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, raw)
	_ = raw.Close()
}

// flowConn is a connection's state: the windows the server may send in, the
// streams it answers, and what the client told it.
type flowConn struct {
	s       *FlowServer
	mu      sync.Mutex
	cond    *sync.Cond
	fr      *http2.Framer
	bw      *bufio.Writer
	enc     *hpack.Encoder
	block   strings.Builder
	connWin int64
	strWin  map[uint32]int64
	initial int64
	gone    bool
	// streams are what each stream answers: windowFirst or windowSecond.
	streams map[uint32]string
}

// serve speaks HTTP/2 on raw, advertising window as each stream's.
func (s *FlowServer) serve(raw net.Conn, window uint32) {
	conn := tls.Server(raw, s.tls)
	if err := conn.Handshake(); err != nil || conn.ConnectionState().NegotiatedProtocol != "h2" {
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	c := &flowConn{s: s, connWin: 65535, strWin: map[uint32]int64{}, initial: 65535, streams: map[uint32]string{}}
	c.cond = sync.NewCond(&c.mu)
	c.bw = bufio.NewWriter(conn)
	c.fr = http2.NewFramer(c.bw, conn)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	c.enc = hpack.NewEncoder(&c.block)
	c.mu.Lock()
	_ = c.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
	_ = c.bw.Flush()
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.gone = true
		c.cond.Broadcast()
		c.mu.Unlock()
	}()
	first := true
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return
		}
		c.mu.Lock()
		switch f := f.(type) {
		case *http2.SettingsFrame:
			c.settings(f)
		case *http2.WindowUpdateFrame:
			c.windowUpdate(f, first && f.StreamID == 0)
			first = first && f.StreamID != 0
		case *http2.MetaHeadersFrame:
			c.request(f)
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = c.fr.WritePing(true, f.Data)
				_ = c.bw.Flush()
			}
		case *http2.RSTStreamFrame:
			c.strWin[f.StreamID] = resetWindow
			c.cond.Broadcast()
		}
		c.mu.Unlock()
	}
}

// settings takes the client's SETTINGS, acknowledged.
func (c *flowConn) settings(f *http2.SettingsFrame) {
	if f.IsAck() {
		return
	}
	if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
		for id := range c.strWin {
			c.strWin[id] += int64(v) - c.initial
		}
		c.initial = int64(v)
		c.cond.Broadcast()
	}
	_ = c.fr.WriteSettingsAck()
	_ = c.bw.Flush()
}

// windowUpdate takes a WINDOW_UPDATE, and keeps it but the connection's first.
func (c *flowConn) windowUpdate(f *http2.WindowUpdateFrame, opening bool) {
	if f.StreamID == 0 {
		c.connWin += int64(f.Increment)
	} else {
		c.strWin[f.StreamID] += int64(f.Increment)
	}
	c.cond.Broadcast()
	if opening {
		return
	}
	window := windowConnection
	if f.StreamID != 0 {
		window = c.streams[f.StreamID]
		if window == "" {
			window = windowOther
		}
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.updates = append(c.s.updates, FlowUpdate{Window: window, Increment: f.Increment, Part: c.s.part})
}

// request answers a request: a scenario's answer, or 404.
func (c *flowConn) request(f *http2.MetaHeadersFrame) {
	path := f.PseudoValue("path")
	id, again := strings.CutSuffix(strings.TrimPrefix(path, "/flow/"), "/again")
	shape, ok := c.s.shapes[id]
	if !strings.HasPrefix(path, "/flow/") || !ok || again && shape.Again == 0 {
		c.headers(f.StreamID, "404", true)
		return
	}
	c.strWin[f.StreamID] = c.initial
	c.streams[f.StreamID] = windowFirst
	if again {
		c.streams[f.StreamID] = windowSecond
	}
	c.s.mu.Lock()
	c.s.asked[id+map[bool]string{true: "/again"}[again]] = true
	c.s.mu.Unlock()
	c.headers(f.StreamID, "200", false, "content-type", "text/html; charset=utf-8")
	c.s.done.Add(1)
	go func() {
		defer c.s.done.Done()
		c.answer(f.StreamID, id, shape, again)
	}()
}

// headers writes a HEADERS frame of the status and fields.
func (c *flowConn) headers(sid uint32, status string, end bool, fields ...string) {
	c.block.Reset()
	_ = c.enc.WriteField(hpack.HeaderField{Name: ":status", Value: status})
	for i := 0; i < len(fields); i += 2 {
		_ = c.enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	_ = c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: sid, BlockFragment: []byte(c.block.String()),
		EndHeaders: true, EndStream: end})
	_ = c.bw.Flush()
}

// answer sends the body of the scenario id, or its second, on sid as its shape
// says.
func (c *flowConn) answer(sid uint32, id string, shape FlowShape, again bool) {
	body := flowBody(shape, id, again)
	part, pause := shape.Part, shape.Pause
	if again || part == 0 {
		part, pause = len(body), 0
	}
	for at := 0; at < len(body); at += part {
		if at > 0 && !c.s.sleep(pause) {
			return
		}
		if at > 0 || again {
			c.s.nextPart()
		}
		last := at+part >= len(body)
		if !c.send(sid, body[at:min(at+part, len(body))], last && shape.EndPause == 0) {
			return
		}
	}
	if shape.EndPause > 0 {
		if !c.s.sleep(shape.EndPause) {
			return
		}
		c.s.nextPart()
		if !c.send(sid, nil, true) {
			return
		}
	}
	if again || shape.Again == 0 {
		c.s.mu.Lock()
		c.s.ended[id] = true
		c.s.mu.Unlock()
	}
}

// send writes data on sid in frames of at most 16 KiB as the windows let it,
// ending the stream on the last when end says so, and says whether it could:
// not on a stream reset, or a connection gone.
func (c *flowConn) send(sid uint32, data []byte, end bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		n := min(len(data), 16384)
		for n > 0 && (c.connWin <= 0 || c.strWin[sid] <= 0) && !c.gone && !c.reset(sid) {
			c.cond.Wait()
		}
		if c.gone || c.reset(sid) {
			return false
		}
		if n > 0 {
			n = int(min(int64(n), c.connWin, c.strWin[sid]))
		}
		c.connWin -= int64(n)
		c.strWin[sid] -= int64(n)
		done := n == len(data)
		_ = c.fr.WriteData(sid, end && done, data[:n])
		_ = c.bw.Flush()
		if data = data[n:]; done {
			return true
		}
	}
}

// nextPart says the next part of the answers is going.
func (s *FlowServer) nextPart() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.part++
}

// reset says whether the client reset sid.
func (c *flowConn) reset(sid uint32) bool { return c.strWin[sid] <= resetWindow/2 }

// resetWindow is the window of a stream the client reset: none, ever.
const resetWindow = -1 << 40

// sleep pauses for ms of the catalogue's milliseconds, times Scale, and says
// whether the server was left open meanwhile.
func (s *FlowServer) sleep(ms int) bool {
	timer := time.NewTimer(time.Duration(float64(ms) * s.Scale * float64(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.stop:
		return false
	}
}

// flowBody is the body of the scenario id, or of its second: lines of 63 x's,
// cheap to lay out however long the page, after a head; the first of a
// scenario with a second asks for it.
func flowBody(shape FlowShape, id string, again bool) []byte {
	size, head := shape.Size, "<!doctype html><title>flow</title><pre>\n"
	if again {
		size, head = shape.Again, ""
	} else if shape.Again > 0 {
		head = fmt.Sprintf("<!doctype html><title>flow</title><script>setTimeout(()=>fetch('/flow/%s/again')"+
			".then(r=>r.arrayBuffer()),%d)</script><pre>\n", id, shape.AgainAfter)
	}
	body := make([]byte, size)
	for i := range body {
		body[i] = 'x'
		if i%64 == 63 {
			body[i] = '\n'
		}
	}
	copy(body, head)
	return body
}

// Ended says whether every answer of the scenario id has gone, its streams
// ended.
func (s *FlowServer) Ended(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ended[id]
}

// Updates are the WINDOW_UPDATEs every connection sent since the server
// started or was reset, after each one's first, in the order they came: those
// of the scenario id, which is an error when its answers were not all asked
// for.
func (s *FlowServer) Updates(id string) ([]FlowUpdate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.asked[id] || s.shapes[id].Again > 0 && !s.asked[id+"/again"] {
		return nil, fmt.Errorf("harness: %s was not asked for", id)
	}
	return append([]FlowUpdate{}, s.updates...), nil
}

// Reset forgets every answer and WINDOW_UPDATE so far, and counts the parts
// of the answers afresh.
func (s *FlowServer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked, s.ended, s.part, s.updates = map[string]bool{}, map[string]bool{}, 0, nil
}

// Close stops the server and ends what it has open.
func (s *FlowServer) Close() error {
	s.mu.Lock()
	if !s.closed {
		close(s.stop)
	}
	s.closed = true
	for conn := range s.open {
		_ = conn.Close()
	}
	s.mu.Unlock()
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.done.Wait()
	return nil
}

// MeasureFlow is the WINDOW_UPDATEs b sends in each scenario of the flow
// catalogue named in only, or every one: what the fixture holds for them. It
// says each scenario it ran to progress, when there is one.
func MeasureFlow(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]FlowScenario, error) {
	return measureFlow(ctx, b, flowCatalogue, only, flowMeasured, progress)
}

// flowMeasured is the timing the fixture of WINDOW_UPDATEs was measured with:
// time enough for the slowest scenario, twelve seconds of pauses and more.
var flowMeasured = timing{poll: 200 * time.Millisecond, limit: 30 * time.Second, after: 700 * time.Millisecond}

func measureFlow(ctx context.Context, b Browser, shapes map[string]FlowShape, only []string, t timing,
	progress io.Writer) (map[string]FlowScenario, error) {
	for _, id := range only {
		if _, ok := shapes[id]; !ok {
			return nil, fmt.Errorf("harness: there is no scenario %s", id)
		}
	}
	ids := slices.Sorted(maps.Keys(shapes))
	if len(only) > 0 {
		ids = slices.Sorted(slices.Values(only))
	}
	s, err := startFlowServer(shapes, 1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if progress == nil {
		progress = io.Discard
	}
	out := map[string]FlowScenario{}
	for _, id := range ids {
		updates, err := s.runFlow(ctx, b, id, t)
		if err != nil {
			return nil, fmt.Errorf("harness: %s: %w", id, err)
		}
		out[id] = FlowScenario{FlowShape: shapes[id], Updates: updates}
		_, _ = fmt.Fprintf(progress, "h2 %s: %d window updates\n", id, len(updates))
	}
	return out, nil
}

// runFlow opens the scenario id in a fresh profile of b's until its answers
// have gone, and a little after, and is what its connection told the server.
func (s *FlowServer) runFlow(ctx context.Context, b Browser, id string, t timing) ([]FlowUpdate, error) {
	dir, err := os.MkdirTemp("", "tls-forge-harness-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	s.Reset()
	stop, err := b.Open(ctx, s.URL(id), dir)
	if err != nil {
		return nil, err
	}
	ended := false
	for deadline := time.Now().Add(t.limit); !ended && time.Now().Before(deadline); {
		if ended = s.Ended(id); !ended && !sleep(ctx, t.poll) {
			break
		}
	}
	if ended {
		ended = sleep(ctx, t.after)
	}
	stop()
	if !ended {
		return nil, fmt.Errorf("its answers had not gone within %s: %v", t.limit, ctx.Err())
	}
	return s.Updates(id)
}

// chromeReadSize is the most Chrome's network service was seen to take of a
// body at a time: what a WINDOW_UPDATE says past half of a window, or past
// what was untold when its time came, is at most this much more.
const chromeReadSize = 8 << 10

// DiffFlow is how the WINDOW_UPDATEs of got differ from want's, for answers of
// one shape: a line for each difference, none when they are alike. Alike is
// the same windows in the same order, each in the same part; one that says
// more than half of its window says at most a read more than half, as one
// whose time came says what was untold and at most a read more, so that two of
// those differ by a read at most. The connection's window is 15 MiB, a
// stream's 6 MiB, as Chrome advertises them.
func DiffFlow(want, got FlowScenario) []string {
	if len(got.Updates) != len(want.Updates) {
		return []string{fmt.Sprintf("%d window updates, want %d: %v, want %v", len(got.Updates), len(want.Updates),
			got.Updates, want.Updates)}
	}
	var out []string
	for i, w := range want.Updates {
		g := got.Updates[i]
		half := uint32(6<<20) / 2
		if w.Window == windowConnection {
			half = uint32(15<<20) / 2
		}
		switch {
		case g.Window != w.Window || g.Part != w.Part:
			out = append(out, fmt.Sprintf("update %d: of %s in part %d, want of %s in part %d", i+1, g.Window, g.Part,
				w.Window, w.Part))
		case (g.Increment > half) != (w.Increment > half):
			out = append(out, fmt.Sprintf("update %d: %d, want %d: one past half of the window, one not", i+1,
				g.Increment, w.Increment))
		case g.Increment > half && g.Increment > half+chromeReadSize:
			out = append(out, fmt.Sprintf("update %d: %d, more than a read past half of the window", i+1, g.Increment))
		case g.Increment <= half && max(g.Increment, w.Increment)-min(g.Increment, w.Increment) > chromeReadSize:
			out = append(out, fmt.Sprintf("update %d: %d, want %d, more than a read apart", i+1, g.Increment, w.Increment))
		}
	}
	return out
}

// CompareFlow is how the WINDOW_UPDATEs a browser sent, got, differ from what
// the fixture holds, want, as Compare says it for requests: a scenario not
// measured, one the fixture has not, and every difference DiffFlow finds in the
// others, after the scenario's name. Nothing when they are alike.
func CompareFlow(want, got map[string]FlowScenario) []string {
	var diff []string
	for _, id := range slices.Sorted(maps.Keys(want)) {
		measured, ok := got[id]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s was not measured", id))
			continue
		}
		for _, d := range DiffFlow(want[id], measured) {
			diff = append(diff, id+": "+d)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[id]; !ok {
			diff = append(diff, fmt.Sprintf("%s was measured, and the fixture has no such scenario", id))
		}
	}
	return diff
}
