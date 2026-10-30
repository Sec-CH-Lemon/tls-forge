//go:build ignore

// Command a10-h3-peer is a private loopback cache observation target.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	h3qlog "github.com/igor-lemon/quic-go-utls/http3/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	tls "github.com/igor-lemon/utls"
)

func main() {
	dir := flag.String("out", "", "private output directory")
	certPath := flag.String("cert", "", "certificate PEM")
	keyPath := flag.String("key", "", "private key PEM")
	scenarioPath := flag.String("scenarios", "scripts/a10-cache-scenarios.json", "stimuli")
	flag.Parse()
	must := func(e error) {
		if e != nil {
			panic(e)
		}
	}
	must(os.MkdirAll(*dir, 0700))
	raw, e := os.ReadFile(*scenarioPath)
	must(e)
	var cases []struct {
		ID                  string   `json:"id"`
		Control             []string `json:"cache_control"`
		Expires, Validators string
		Changed             bool
	}
	must(json.Unmarshal(raw, &cases))
	cert, e := tls.LoadX509KeyPair(*certPath, *keyPath)
	must(e)
	keys, e := os.OpenFile(filepath.Join(*dir, "tls.keys"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(e)
	defer keys.Close()
	requests, e := os.OpenFile(filepath.Join(*dir, "requests.ndjson"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(e)
	defer requests.Close()
	packets, e := os.OpenFile(filepath.Join(*dir, "packets.ndjson"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(e)
	defer packets.Close()
	headers, e := os.OpenFile(filepath.Join(*dir, "headers.ndjson"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(e)
	defer headers.Close()
	observer := &headerObserver{file: headers}
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	must(e)
	defer udp.Close()
	var mu sync.Mutex
	counts := map[string]int{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		counts[r.URL.Path]++
		n := counts[r.URL.Path]
		var found bool
		for _, s := range cases {
			if r.URL.Path != "/case/"+s.ID {
				continue
			}
			found = true
			now := time.Now().UTC()
			expiry := now.Add(-600 * time.Second)
			if s.Expires == "future" {
				expiry = now.Add(600 * time.Second)
			}
			for _, v := range s.Control {
				w.Header().Add("Cache-Control", v)
			}
			w.Header().Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
			w.Header().Set("Age", "120")
			w.Header().Set("Expires", expiry.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
			w.Header().Set("Content-Type", "text/plain")
			if s.Validators == "both" || s.Validators == "etag" {
				w.Header().Set("ETag", `"v1"`)
			}
			if s.Validators == "both" || s.Validators == "modified" {
				w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
			}
			status := 200
			if n > 1 && !s.Changed && (r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "") {
				status = 304
			}
			must(json.NewEncoder(requests).Encode(map[string]any{"url": r.URL.String(), "n": n, "protocol": r.Proto, "peer": r.RemoteAddr, "headers": r.Header, "response": map[string]any{"status": status, "headers": w.Header().Clone()}}))
			w.WriteHeader(status)
			if status != 304 {
				fmt.Fprintf(w, "body-%s-%d", s.ID, n)
			}
			break
		}
		if !found {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><link rel="icon" href="data:,"><body>cache witness</body>`)
		}
	})
	server := &http3.Server{QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return observer }}, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, KeyLogWriter: keys}, Handler: handler}
	go func() {
		if err := server.Serve(&packetRecorder{PacketConn: udp, file: packets}); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	address, _ := json.Marshal(map[string]string{"origin": "https://" + udp.LocalAddr().String()})
	must(os.WriteFile(filepath.Join(*dir, "address.json"), address, 0600))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	must(server.Close())
}

type packetRecorder struct {
	net.PacketConn
	file *os.File
	mu   sync.Mutex
}

func (p *packetRecorder) record(direction string, remote net.Addr, b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recordLocked(direction, remote, b)
}
func (p *packetRecorder) recordLocked(direction string, remote net.Addr, b []byte) error {
	return json.NewEncoder(p.file).Encode(struct {
		Time      int64  `json:"time_ns"`
		Direction string `json:"direction"`
		Local     string `json:"local"`
		Remote    string `json:"remote"`
		Data      []byte `json:"data"`
	}{time.Now().UnixNano(), direction, p.LocalAddr().String(), remote.String(), append([]byte(nil), b...)})
}
func (p *packetRecorder) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	if n > 0 {
		if recordErr := p.record("client", a, b[:n]); e == nil && recordErr != nil {
			e = recordErr
		}
	}
	return n, a, e
}
func (p *packetRecorder) WriteTo(b []byte, a net.Addr) (int, error) {
	// Keep the send and its successful record together: a loopback response
	// must not be recorded before the packet that introduced its server CID.
	p.mu.Lock()
	defer p.mu.Unlock()
	n, e := p.PacketConn.WriteTo(b, a)
	if n > 0 {
		if recordErr := p.recordLocked("server", a, b[:n]); e == nil && recordErr != nil {
			e = recordErr
		}
	}
	return n, e
}

type headerObserver struct {
	mu   sync.Mutex
	file *os.File
}

func (h *headerObserver) AddProducer() qlogwriter.Recorder { return h }
func (h *headerObserver) SupportsSchemas(string) bool      { return true }
func (h *headerObserver) Close() error                     { return nil }
func (h *headerObserver) RecordEvent(e qlogwriter.Event) {
	parsed, ok := e.(h3qlog.FrameParsed)
	if !ok {
		return
	}
	fields, ok := parsed.Frame.Frame.(h3qlog.HeadersFrame)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := json.NewEncoder(h.file).Encode(map[string]any{"stream_id": parsed.StreamID, "fields": fields.HeaderFields}); err != nil {
		panic(err)
	}
}
