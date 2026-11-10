//go:build ignore

// Command a8-h3-peer is an observation peer/client, built explicitly by the
// native A8 measurement workflow; it is not part of the shipped product.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	forge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tc "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
	"github.com/quic-go/qpack"
)

type scenario struct {
	InstanceScope  string `json:"browser_instance_scope"`
	BrowserMajor   int    `json:"browser_major"`
	Samples        int    `json:"connections_per_cohort"`
	RequestGap     int    `json:"request_gap_ms"`
	IdleTimeout    int    `json:"server_idle_timeout_ms"`
	ServerSettings []struct {
		ID    uint64 `json:"id"`
		Value uint64 `json:"value"`
	} `json:"server_settings"`
	Requests []struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	} `json:"requests"`
	Header struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"request_header"`
}

var experiment scenario

type connection struct {
	SettingsAfterRequests int              `json:"settings_after_requests"`
	SettingsAt            int64            `json:"settings_at_ns"`
	RequestTimes          map[int64]int64  `json:"request_times_ns"`
	TLSComplete           bool             `json:"tls_complete"`
	Resumed               bool             `json:"resumed"`
	ClosedReason          string           `json:"closed_reason"`
	ID                    int              `json:"id"`
	Closed                bool             `json:"closed"`
	Uni                   map[int64][]byte `json:"uni"`
	Requests              map[int64][]byte `json:"requests"`
	Errors                []string         `json:"errors"`
}
type observer struct {
	mu            sync.Mutex
	Connections   []*connection `json:"connections"`
	SettingsDelay int           `json:"settings_delay"`
	Live          []*quic.Conn  `json:"-"`
}

func (s *observer) save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func (s *observer) add() *connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &connection{ID: len(s.Connections) + 1, SettingsAfterRequests: s.SettingsDelay, RequestTimes: map[int64]int64{}, Uni: map[int64][]byte{}, Requests: map[int64][]byte{}}
	s.Connections = append(s.Connections, c)
	return c
}
func (s *observer) error(c *connection, e error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Errors = append(c.Errors, e.Error())
}
func (s *observer) uni(c *connection, id int64, b []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(c.Uni[id])+len(b) > 1<<20 {
		return false
	}
	c.Uni[id] = append(c.Uni[id], b...)
	return true
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

func certificate() (tls.Certificate, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return tls.Certificate{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		return tls.Certificate{}, e
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "A8 owned H3 peer"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, e
}
func response() []byte {
	var block bytes.Buffer
	encoder := qpack.NewEncoder(&block)
	_ = encoder.WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
	_ = encoder.WriteField(qpack.HeaderField{Name: "content-type", Value: "text/html"})
	frame := quicvarint.Append(nil, 1)
	frame = quicvarint.Append(frame, uint64(block.Len()))
	frame = append(frame, block.Bytes()...)
	body := []byte("<!doctype html><html><head><link rel=icon href=\"data:,\"></head><body>A8 H3 observed</body></html>")
	frame = quicvarint.Append(frame, 0)
	frame = quicvarint.Append(frame, uint64(len(body)))
	return append(frame, body...)
}
func serve(ctx context.Context, dir string, finish context.CancelFunc) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer udp.Close()
	packets, e := os.OpenFile(filepath.Join(dir, "packets.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	defer packets.Close()
	secrets, e := os.OpenFile(filepath.Join(dir, "keys.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	defer secrets.Close()
	cert, e := certificate()
	if e != nil {
		return e
	}
	listener, e := quic.ListenEarly(&packetRecorder{PacketConn: udp, file: packets}, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, KeyLogWriter: secrets, SessionTicketsDisabled: true}, &quic.Config{EnableDatagrams: true, MaxIncomingUniStreams: 16, MaxIdleTimeout: time.Duration(experiment.IdleTimeout) * time.Millisecond})
	if e != nil {
		return e
	}
	defer listener.Close()
	api, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer api.Close()
	state := &observer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	})
	mux.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		state.mu.Lock()
		live := append([]*quic.Conn(nil), state.Live...)
		state.mu.Unlock()
		for _, c := range live {
			_ = c.CloseWithError(0x100, "measurement connection boundary")
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("/settings-delay", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		var value struct {
			Requests int `json:"requests"`
		}
		if err := json.NewDecoder(r.Body).Decode(&value); err != nil || value.Requests < 0 || value.Requests > len(experiment.Requests) {
			http.Error(w, "invalid settings stimulus", 400)
			return
		}
		state.mu.Lock()
		state.SettingsDelay = value.Requests
		state.mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("/finish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		w.WriteHeader(204)
		_ = http.NewResponseController(w).Flush()
		finish()
	})
	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer httpServer.Close()
	go httpServer.Serve(api)
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	config := map[string]string{"spki": base64.StdEncoding.EncodeToString(sum[:]), "origin": "https://127.0.0.1:" + port, "api": "http://" + api.Addr().String(), "network": "owned IPv4 loopback; generic PacketConn record wrapper; explicit server keylog; no proxy"}
	b, _ := json.MarshalIndent(config, "", "  ")
	if e := os.WriteFile(filepath.Join(dir, "address.json"), b, 0600); e != nil {
		return e
	}
	var workers sync.WaitGroup
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, e := listener.Accept(ctx)
		if e != nil {
			break
		}
		c := state.add()
		settingsWritten := make(chan struct{})
		settingsAllowed := make(chan struct{})
		var allowSettings sync.Once
		if c.SettingsAfterRequests == 0 {
			allowSettings.Do(func() { close(settingsAllowed) })
		}
		state.mu.Lock()
		state.Live = append(state.Live, conn)
		state.mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-conn.Context().Done()
			state.mu.Lock()
			c.Closed = true
			c.ClosedReason = fmt.Sprint(context.Cause(conn.Context()))
			state.mu.Unlock()
		}()
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case <-conn.HandshakeComplete():
			case <-conn.Context().Done():
				return
			}
			defer close(settingsWritten)
			select {
			case <-settingsAllowed:
			case <-ctx.Done():
				return
			}
			state.mu.Lock()
			c.TLSComplete = true
			c.Resumed = conn.ConnectionState().TLS.DidResume
			state.mu.Unlock()
			control, e := conn.OpenUniStreamSync(ctx)
			if e != nil {
				state.error(c, e)
				return
			}
			var settings []byte
			for _, pair := range experiment.ServerSettings {
				settings = quicvarint.Append(settings, pair.ID)
				settings = quicvarint.Append(settings, pair.Value)
			}
			wire := quicvarint.Append(nil, 0)
			wire = quicvarint.Append(wire, 4)
			wire = quicvarint.Append(wire, uint64(len(settings)))
			_, e = control.Write(append(wire, settings...))
			state.mu.Lock()
			c.SettingsAt = time.Now().UnixNano()
			state.mu.Unlock()
			if e != nil {
				state.error(c, e)
			}
		}()
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				stream, e := conn.AcceptUniStream(ctx)
				if e != nil {
					return
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					buffer := make([]byte, 8192)
					for {
						n, e := stream.Read(buffer)
						if n > 0 && !state.uni(c, int64(stream.StreamID()), buffer[:n]) {
							state.error(c, fmt.Errorf("uni stream too large"))
							_ = conn.CloseWithError(0x102, "measurement bound")
							return
						}
						if e != nil {
							return
						}
					}
				}()
			}
		}()
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				stream, e := conn.AcceptStream(ctx)
				if e != nil {
					return
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
					raw, e := io.ReadAll(io.LimitReader(stream, 1<<20+1))
					if e != nil {
						state.error(c, e)
						return
					}
					if len(raw) > 1<<20 {
						state.error(c, fmt.Errorf("request stream too large"))
						return
					}
					state.mu.Lock()
					c.Requests[int64(stream.StreamID())] = raw
					c.RequestTimes[int64(stream.StreamID())] = time.Now().UnixNano()
					received := len(c.Requests)
					state.mu.Unlock()
					if received >= c.SettingsAfterRequests {
						allowSettings.Do(func() { close(settingsAllowed) })
					}
					if received >= c.SettingsAfterRequests {
						select {
						case <-settingsWritten:
						case <-ctx.Done():
							return
						}
					}
					if _, e = stream.Write(response()); e != nil {
						state.error(c, e)
					}
					_ = stream.Close()
				}()
			}
		}()
	}
	// Listener close terminates connection readers before immutable export.
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("peer workers did not stop")
	}
	return state.save(filepath.Join(dir, "observations.json"))
}
func client(ctx context.Context, dir, path string, samples int) error {
	raw, e := os.ReadFile(filepath.Join(dir, "address.json"))
	if e != nil {
		return e
	}
	var config map[string]string
	if e = json.Unmarshal(raw, &config); e != nil {
		return e
	}
	p, e := profile.Get(path)
	if e != nil {
		return e
	}
	p.Behavior["http.instance_scope"], _ = json.Marshal(experiment.InstanceScope)
	c, e := forge.New(forge.WithProfileValue(p), forge.WithInsecureSkipVerify(), forge.WithTimeout(10*time.Second), forge.WithTransportOption(tc.WithProtocolRacing()))
	if e != nil {
		return e
	}
	defer c.Close()
	for n := 0; n < samples; n++ {
		for step, stimulus := range experiment.Requests {
			request := &forge.Request{Context: ctx, URL: config["origin"] + stimulus.Path, Browser: &forge.BrowserContext{Kind: forge.KindNavigation}}
			if step > 0 {
				request.URL = config["origin"] + stimulus.Path
				request.Browser = &forge.BrowserContext{Kind: forge.KindFetch, Initiator: config["origin"] + "/"}
				request.Header = forge.NewHeader(experiment.Header.Name, experiment.Header.Value)
			}
			if step > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Duration(experiment.RequestGap) * time.Millisecond):
				}
			}
			r, e := c.Do(request)
			if e != nil {
				return e
			}
			if !bytes.Contains(r.Body, []byte("A8 H3 observed")) {
				return fmt.Errorf("unexpected response %q", r.Body)
			}
		}
		c.CloseIdleConnections()
	}
	return nil
}
func main() {
	mode := flag.String("mode", "server", "server, client or offline validate")
	dir := flag.String("out", "", "private output directory")
	path := flag.String("profile", "", "explicit candidate profile for client")
	samples := flag.Int("samples", 0, "connections in one cohort; zero reads the scenario")
	scenarioPath := flag.String("scenario", "scripts/a8-h3-scenario.json", "explicit experimental stimuli JSON")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	raw, err := os.ReadFile(*scenarioPath)
	if err == nil {
		err = json.Unmarshal(raw, &experiment)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *samples == 0 {
		*samples = experiment.Samples
	}
	if *samples < 1 || *samples > 4096 || experiment.RequestGap < 0 || experiment.IdleTimeout <= 0 || len(experiment.Requests) != 3 || len(experiment.ServerSettings) == 0 {
		fmt.Fprintln(os.Stderr, "invalid bounded scenario")
		os.Exit(1)
	}
	if *dir == "" && *mode != "validate" {
		err = fmt.Errorf("out required")
	} else if *mode == "server" {
		err = serve(ctx, *dir, stop)
	} else if *mode == "validate" {
		var p *profile.Profile
		p, err = profile.Get(*path)
		if err == nil && (p.Schema != profile.Schema || p.PerConnection == nil || p.BareBase()) {
			err = fmt.Errorf("full explicit candidate profile required")
		}
	} else if *mode == "client" {
		err = client(ctx, *dir, *path, *samples)
	} else {
		err = fmt.Errorf("invalid mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
