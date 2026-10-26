package deadlineconn

import (
	"bytes"
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

// timedOut says err is a deadline's.
func timedOut(err error) bool {
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}

// pipe is both ends of an in-memory connection, closed when the test ends.
func pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close() })
	t.Cleanup(func() { _ = right.Close() })
	return left, right
}

func TestADeadlineSetIsKeptUntilItIsTakenAway(t *testing.T) {
	// Not replaced by the idle timeout at the next read, as it was: a peer
	// that sent a byte at a time could stretch a step forever.
	left, right := pipe(t)
	conn := Wrap(left, time.Hour)
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for i := range 2 {
		started := time.Now()
		if _, err := conn.Read(make([]byte, 1)); !timedOut(err) {
			t.Fatalf("read %d: %v, want the deadline set", i, err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("read %d returned after %s", i, elapsed)
		}
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = right.Write([]byte("x"))
	}()
	if n, err := conn.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Errorf("a read with the deadline taken away = %d, %v", n, err)
	}
}

func TestTheIdleTimeoutStillBoundsAReadUnderALaterDeadline(t *testing.T) {
	left, _ := pipe(t)
	conn := Wrap(left, 20*time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	started := time.Now()
	if _, err := conn.Read(make([]byte, 1)); !timedOut(err) {
		t.Fatalf("read = %v, want the idle timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("read returned after %s", elapsed)
	}
}

func TestSetDeadlineBoundsReadsAndWrites(t *testing.T) {
	left, _ := pipe(t)
	conn := Wrap(left, time.Hour)
	if err := conn.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("nobody reads this")); !timedOut(err) {
		t.Errorf("write = %v, want the deadline set", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !timedOut(err) {
		t.Errorf("read = %v, want the deadline set", err)
	}
}

func TestADeadlineAlreadyPastEndsAReadUnderWay(t *testing.T) {
	// The usual way to stop a read from another goroutine.
	left, _ := pipe(t)
	conn := Wrap(left, time.Hour)
	ended := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		ended <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Unix(1, 0)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case err := <-ended:
		if !timedOut(err) {
			t.Errorf("read = %v, want the deadline set", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a deadline already past did not end the read")
	}
}

func TestTheEpochIsADeadlineLongPast(t *testing.T) {
	// Its Unix nanoseconds are zero, which is how no deadline is kept.
	left, _ := pipe(t)
	conn := Wrap(left, time.Hour)
	if err := conn.SetReadDeadline(time.Unix(0, 0)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !timedOut(err) {
		t.Errorf("read = %v, want the deadline set", err)
	}
}

func TestAWriteToAPeerThatKeepsReadingIsNotCutOff(t *testing.T) {
	// Four chunks to a peer that takes one every 40ms: longer than the idle
	// timeout in all, but never idle for as long.
	left, right := pipe(t)
	conn := Wrap(left, 100*time.Millisecond)
	sent := bytes.Repeat([]byte("0123456789abcdef"), 4*chunk/16)
	received := make(chan []byte, 1)
	go func() {
		var got []byte
		piece := make([]byte, chunk)
		for len(got) < len(sent) {
			time.Sleep(40 * time.Millisecond)
			n, err := io.ReadFull(right, piece)
			got = append(got, piece[:n]...)
			if err != nil {
				break
			}
		}
		received <- got
	}()
	started := time.Now()
	if n, err := conn.Write(sent); n != len(sent) || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Errorf("the write took %s, too little to tell a rolling deadline from one for the whole", elapsed)
	}
	if got := <-received; !bytes.Equal(got, sent) {
		t.Errorf("the peer read %d bytes, not what was written", len(got))
	}
}

func TestAWriteSaysHowMuchWentBeforeItFailed(t *testing.T) {
	left, right := pipe(t)
	conn := Wrap(left, time.Hour)
	go func() {
		_, _ = io.ReadFull(right, make([]byte, chunk))
		_ = right.Close()
	}()
	if n, err := conn.Write(make([]byte, 2*chunk)); n != chunk || err == nil {
		t.Errorf("write = %d, %v; want one chunk and the failure", n, err)
	}
}

func TestSetDeadlineReportsEachSidesFailure(t *testing.T) {
	readErr, writeErr := errors.New("read deadline failed"), errors.New("write deadline failed")
	if err := Wrap(deadlineFailure{readErr: readErr}, time.Second).SetDeadline(time.Now()); !errors.Is(err, readErr) {
		t.Errorf("SetDeadline = %v, want the read side's failure", err)
	}
	if err := Wrap(deadlineFailure{writeErr: writeErr}, time.Second).SetDeadline(time.Now()); !errors.Is(err, writeErr) {
		t.Errorf("SetDeadline = %v, want the write side's failure", err)
	}
}

func TestCloseWriteShutsTheWritingSideWhereItCan(t *testing.T) {
	// A TCP connection: its peer reads to the end of what it was sent, and
	// can still write back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	peer, ok := <-accepted
	if !ok {
		t.Fatal("nothing accepted")
	}
	t.Cleanup(func() { _ = peer.Close() })
	conn := Wrap(raw, time.Minute).(*Conn)
	if _, err := conn.Write([]byte("said")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(peer); err != nil || string(got) != "said" {
		t.Fatalf("the peer read %q, %v", got, err)
	}
	if _, err := peer.Write([]byte("back")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "back" {
		t.Errorf("read %q, %v", got, err)
	}
	// One that cannot shut a side alone says so.
	left, _ := pipe(t)
	if err := Wrap(left, time.Minute).(*Conn).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("a pipe's CloseWrite: %v", err)
	}
}
