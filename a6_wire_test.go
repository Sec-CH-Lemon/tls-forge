package tlsforge

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

type a6Wire struct {
	settings       []profile.Setting
	settingsFrames int
	priorities     []profile.Priority
	flow, stream   uint32
	err            error
}

// This peer decodes original HTTP2 frames directly, without the candidate's
// framer or settings validator. It intentionally accepts any advertised value.
func a6RawPeer(t *testing.T, illegalData ...bool) (string, *atomic.Int32, <-chan a6Wire, func()) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	config := &tls.Config{Certificates: seed.TLS.Certificates, NextProtos: []string{"h2"}}
	seed.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	calls := new(atomic.Int32)
	done := make(chan a6Wire, 1)
	go func() {
		var got a6Wire
		defer func() { done <- got }()
		conn, err := listener.Accept()
		if err != nil {
			got.err = err
			return
		}
		calls.Add(1)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		preface := make([]byte, 24)
		if _, err = io.ReadFull(conn, preface); err != nil {
			got.err = err
			return
		}
		if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			got.err = fmt.Errorf("bad preface %x", preface)
			return
		}
		// Peer SETTINGS has no payload. HEADERS-only response works even when
		// the client's advertised receive window or header-list limit is zero.
		if _, err = conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
			got.err = err
			return
		}
		for {
			head := make([]byte, 9)
			if _, err = io.ReadFull(conn, head); err != nil {
				got.err = err
				return
			}
			n := int(head[0])<<16 | int(head[1])<<8 | int(head[2])
			data := make([]byte, n)
			if _, err = io.ReadFull(conn, data); err != nil {
				got.err = err
				return
			}
			t.Logf("RAW FRAME head=%x data=%x", head, data)
			switch head[3] {
			case 2:
				if n != 5 {
					got.err = fmt.Errorf("bad PRIORITY length %d", n)
					return
				}
				dependency := binary.BigEndian.Uint32(data)
				got.priorities = append(got.priorities, profile.Priority{StreamID: binary.BigEndian.Uint32(head[5:]), DependsOn: dependency & 0x7fffffff, Exclusive: dependency>>31 != 0, Weight: data[4]})
			case 4:
				if head[4]&1 == 0 {
					got.settingsFrames++
					if n%6 != 0 {
						got.err = fmt.Errorf("bad SETTINGS length %d", n)
						return
					}
					for i := 0; i < n; i += 6 {
						got.settings = append(got.settings, profile.Setting{ID: binary.BigEndian.Uint16(data[i:]), Value: binary.BigEndian.Uint32(data[i+2:])})
					}
					t.Logf("RAW SETTINGS %x", data)
				}
			case 8:
				if binary.BigEndian.Uint32(head[5:]) == 0 && n == 4 {
					got.flow = binary.BigEndian.Uint32(data)
				}
			case 1:
				got.stream = binary.BigEndian.Uint32(head[5:])
				response := []byte{0, 0, 1, 1, 5, 0, 0, 0, 0, 0x88}
				binary.BigEndian.PutUint32(response[5:9], got.stream)
				if len(illegalData) > 0 && illegalData[0] {
					response[4] = 4 // HEADERS without END_STREAM
					_, got.err = conn.Write(response)
					data := []byte{0, 0, 1, 0, 1, 0, 0, 0, 0, 'X'}
					binary.BigEndian.PutUint32(data[5:9], got.stream)
					if got.err == nil {
						_, got.err = conn.Write(data)
					}
				} else {
					_, got.err = conn.Write(response)
				}
				return
			}
		}
	}()
	return "https://" + listener.Addr().String() + "/", calls, done, func() { _ = listener.Close() }
}

func TestA6InvalidSettingsRejectedBeforeWire(t *testing.T) {
	for _, setting := range []profile.Setting{{ID: 5, Value: 1}, {ID: 4, Value: 1 << 31}, {ID: 1, Value: 1<<20 + 1}, {ID: 6, Value: 16<<20 + 1}} {
		t.Run(fmt.Sprintf("id=%d", setting.ID), func(t *testing.T) {
			address, calls, done, stop := a6RawPeer(t)
			p, err := profile.Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			p.HTTP2.Settings = []profile.Setting{setting}
			c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(time.Second))
			if err == nil {
				_, requestErr := c.Get(address)
				_ = c.Close()
				stop()
				got := <-done
				t.Fatalf("accepted invalid profile;TCP=%d SETTINGS=%v peer=%v request=%v", calls.Load(), got.settings, got.err, requestErr)
			}
			stop()
			<-done
			if calls.Load() != 0 || !strings.Contains(err.Error(), "http2.settings[0].value") {
				t.Fatal(calls.Load(), err)
			}
		})
	}
}

func TestA6ValidSettingsReachRawWire(t *testing.T) {
	for _, setting := range []profile.Setting{{ID: 4, Value: 0}, {ID: 4, Value: 1<<31 - 1}, {ID: 5, Value: 16384}, {ID: 5, Value: 1<<24 - 1}, {ID: 2, Value: 1}, {ID: 8, Value: 1}, {ID: 9, Value: 1}, {ID: 65535, Value: 1<<32 - 1}, {ID: 1, Value: 1 << 20}, {ID: 6, Value: 16 << 20}} {
		t.Run(fmt.Sprintf("%d=%d", setting.ID, setting.Value), func(t *testing.T) {
			address, calls, done, _ := a6RawPeer(t)
			p, err := profile.Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			p.Name = "neutral-wire"
			// The edge of a setting the base list holds replaces it there.
			p.HTTP2.Settings = []profile.Setting{{ID: 6, Value: 262144}, setting, {ID: 1, Value: 65536}}
			p.HTTP2.Settings = slices.DeleteFunc(p.HTTP2.Settings, func(s profile.Setting) bool { return s.ID == setting.ID && s != setting })
			p.HTTP2.ConnectionFlow = 2147418112
			p.HTTP2.StreamID = 2147483647
			p.HTTP2.HeaderPriority = nil
			raw, _ := json.Marshal(p)
			file := filepath.Join(t.TempDir(), "neutral-wire.json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c, err := New(WithProfile(file), WithInsecureSkipVerify(), WithTimeout(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Get(address); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if got.err != nil || !reflect.DeepEqual(got.settings, p.HTTP2.Settings) || got.flow != p.HTTP2.ConnectionFlow || got.stream != p.HTTP2.StreamID || calls.Load() != 1 {
				t.Fatalf("wire=%+v expected=%+v TCP=%d", got, p.HTTP2, calls.Load())
			}
		})
	}
}

func TestA6ZeroWindowRejectsPeerData(t *testing.T) {
	address, _, done, _ := a6RawPeer(t, true)
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.HTTP2.Settings = []profile.Setting{{ID: 4, Value: 0}}
	c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := c.Get(address)
	<-done
	if err == nil || !strings.Contains(err.Error(), "FLOW_CONTROL_ERROR") {
		t.Fatalf("advertised zero window accepted peer DATA: response=%v error=%v", res, err)
	}
	t.Log("RESULT: illegal DATA against advertised window0 rejected with FLOW_CONTROL_ERROR")
}

func TestA6ConnectionWindowIncrementReachesWire(t *testing.T) {
	for _, increment := range []uint32{0, 1, 2147418112} {
		t.Run(fmt.Sprint(increment), func(t *testing.T) {
			address, _, done, _ := a6RawPeer(t)
			p, err := profile.Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			p.HTTP2.ConnectionFlow = increment
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "explicit-connection-window.json")
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c, err := New(WithProfile(file), WithInsecureSkipVerify(), WithTimeout(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Get(address); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if got.err != nil || got.flow != increment {
				t.Fatalf("increment=%d wire=%+v", increment, got)
			}
		})
	}
}

// A body longer than the connection's first window is read whole whatever
// increment the profile gives that window, with the delay that tells the
// server of freed bytes or without it. Without the delay the client used to
// refill the connection to the increment itself, so 0 and 1, which the
// validator accepts, never told the server of anything and the request
// waited out its deadline after 65,535 bytes.
func TestA6SmallConnectionIncrementStillRefillsTheWindow(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 512<<10)
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			w.WriteHeader(http.StatusHTTPVersionNotSupported)
			return
		}
		_, _ = w.Write(body)
	}))
	site.EnableHTTP2 = true
	site.StartTLS()
	t.Cleanup(site.Close)
	for _, flow := range []uint32{0, 1, 1000, 65535, 15663105} {
		for _, delay := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/delay=%v", flow, delay), func(t *testing.T) {
				p, err := profile.Get("chrome_155_macos")
				if err != nil {
					t.Fatal(err)
				}
				p.HTTP2.ConnectionFlow = flow
				if !delay {
					delete(p.Behavior, "h2.window_update_delay_ms")
				} else if _, ok := p.Behavior["h2.window_update_delay_ms"]; !ok {
					t.Fatal("the shipped profile has no h2.window_update_delay_ms")
				}
				raw, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(t.TempDir(), "connection-window.json")
				if err = os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				c, err := New(WithProfile(file), WithInsecureSkipVerify(), WithTimeout(5*time.Second))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				res, err := c.Get(site.URL + "/long")
				if err != nil {
					t.Fatalf("a body of %d bytes: %v", len(body), err)
				}
				if res.Status != http.StatusOK || !bytes.Equal(res.Body, body) {
					t.Fatalf("status %d, %d bytes of %d", res.Status, len(res.Body), len(body))
				}
			})
		}
	}
}

func TestA6InitialSettingsPayloadBoundaries(t *testing.T) {
	for _, count := range []int{0, 2730} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			address, _, done, _ := a6RawPeer(t)
			p, err := profile.Get("chrome_155_macos")
			if err != nil {
				t.Fatal(err)
			}
			p.HTTP2.Settings = make([]profile.Setting, count)
			for i := range p.HTTP2.Settings {
				p.HTTP2.Settings[i] = profile.Setting{ID: uint16(100 + i), Value: uint32(i)}
			}
			p.HTTP2.ConnectionFlow = 0
			c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Get(address); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if got.err != nil || got.settingsFrames != 1 || len(got.settings) != count || got.flow != 0 {
				t.Fatalf("wire %+v", got)
			}
			for i := range p.HTTP2.Settings {
				if got.settings[i] != p.HTTP2.Settings[i] {
					t.Fatal("array order/value changed", i)
				}
			}
		})
	}
}

func TestA6PriorityFrameBoundaries(t *testing.T) {
	for _, stream := range []uint32{1, 2147483645} {
		for _, weight := range []uint8{0, 255} {
			t.Run(fmt.Sprintf("%d/%d", stream, weight), func(t *testing.T) {
				address, _, done, _ := a6RawPeer(t)
				p, err := profile.Get("chrome_155_macos")
				if err != nil {
					t.Fatal(err)
				}
				pr := profile.Priority{StreamID: stream, DependsOn: 2147483647, Exclusive: true, Weight: weight}
				p.HTTP2.Priorities = []profile.Priority{pr}
				p.HTTP2.HeaderPriority = nil
				c, err := New(WithProfileValue(p), WithInsecureSkipVerify(), WithTimeout(time.Second))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if _, err = c.Get(address); err != nil {
					t.Fatal(err)
				}
				got := <-done
				if got.err != nil || !reflect.DeepEqual(got.priorities, p.HTTP2.Priorities) || got.stream != stream+2 {
					t.Fatalf("priority wire=%+v", got)
				}
			})
		}
	}
}

func TestA6MalformedHelloRejectedBeforeConstruction(t *testing.T) {
	address, calls, done, stop := a6RawPeer(t)
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.ClientHello = []byte{1, 2, 3}
	c, err := New(WithProfileValue(p), WithInsecureSkipVerify())
	if c != nil {
		_ = c.Close()
	}
	stop()
	<-done
	if err == nil || calls.Load() != 0 {
		t.Fatal("malformed TLS identity reached network", address, err, calls.Load())
	}
}
