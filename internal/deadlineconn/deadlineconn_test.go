package deadlineconn

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestWrapLeavesDisabledConnectionsAlone(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close() })
	t.Cleanup(func() { _ = right.Close() })
	if got := Wrap(left, 0); got != left {
		t.Error("a disabled timeout wrapped the connection")
	}
}

func TestReadTimesOutAndWriteRefreshesItsOwnDeadline(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close() })
	t.Cleanup(func() { _ = right.Close() })
	conn := Wrap(left, 20*time.Millisecond)

	started := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a silent peer did not time out")
	} else if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("read returned after %s", elapsed)
	}

	read := make(chan string, 1)
	go func() {
		body, _ := io.ReadAll(io.LimitReader(right, 2))
		read <- string(body)
	}()
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write after read timeout: %v", err)
	}
	if got := <-read; got != "ok" {
		t.Errorf("peer read %q", got)
	}
}

type deadlineFailure struct {
	net.Conn
	readErr  error
	writeErr error
}

func (c deadlineFailure) SetReadDeadline(time.Time) error  { return c.readErr }
func (c deadlineFailure) SetWriteDeadline(time.Time) error { return c.writeErr }

func TestDeadlineErrorsAreReturned(t *testing.T) {
	readErr := errors.New("read deadline failed")
	read := Wrap(deadlineFailure{readErr: readErr}, time.Second)
	if _, err := read.Read(nil); !errors.Is(err, readErr) {
		t.Errorf("Read error = %v", err)
	}

	writeErr := errors.New("write deadline failed")
	write := Wrap(deadlineFailure{writeErr: writeErr}, time.Second)
	if _, err := write.Write(nil); !errors.Is(err, writeErr) {
		t.Errorf("Write error = %v", err)
	}
}
