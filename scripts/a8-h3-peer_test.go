//go:build ignore

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type loopbackReply struct{ read, returned chan struct{} }

func (c *loopbackReply) ReadFrom(b []byte) (int, net.Addr, error) {
	<-c.read
	b[0] = 1
	close(c.returned)
	return 1, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}, nil
}
func (c *loopbackReply) WriteTo(b []byte, _ net.Addr) (int, error) {
	close(c.read)
	<-c.returned
	time.Sleep(10 * time.Millisecond)
	return len(b), nil
}
func (*loopbackReply) Close() error                     { return nil }
func (*loopbackReply) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (*loopbackReply) SetDeadline(time.Time) error      { return nil }
func (*loopbackReply) SetReadDeadline(time.Time) error  { return nil }
func (*loopbackReply) SetWriteDeadline(time.Time) error { return nil }

func TestSuccessfulSendIsRecordedBeforeImmediateReply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packets.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p := &packetRecorder{PacketConn: &loopbackReply{read: make(chan struct{}), returned: make(chan struct{})}, file: f}
	read := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 1)); read <- err }()
	if _, err := p.WriteTo([]byte{2}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(f)
	for _, expected := range []string{"server", "client"} {
		var record struct {
			Direction string `json:"direction"`
		}
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record.Direction != expected {
			t.Fatalf("recorded %s before %s", record.Direction, expected)
		}
	}
}
