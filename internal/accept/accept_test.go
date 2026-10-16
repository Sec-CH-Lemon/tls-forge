package accept

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestAFailureThatPassesIsWaitedOutLongerEachTime(t *testing.T) {
	var slept []time.Duration
	original := sleep
	t.Cleanup(func() { sleep = original })
	sleep = func(d time.Duration) { slept = append(slept, d) }

	// As Accept reports running out of descriptors.
	exhausted := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	var pause time.Duration
	for range 10 {
		if !Again(exhausted, &pause) {
			t.Fatal("running out of descriptors ended accepting")
		}
	}
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000}
	for i := range want {
		want[i] *= time.Millisecond
	}
	if len(slept) != len(want) {
		t.Fatalf("slept %v", slept)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Errorf("pause %d was %v, want %v", i, slept[i], want[i])
		}
	}
	if pause != time.Second {
		t.Errorf("pause = %v", pause)
	}
}

func TestAnyOtherFailureEndsAccepting(t *testing.T) {
	original := sleep
	t.Cleanup(func() { sleep = original })
	sleep = func(time.Duration) { t.Error("waited for a failure that does not pass") }
	for _, err := range []error{
		net.ErrClosed,
		&net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EINVAL)},
		errors.New("something else"),
	} {
		var pause time.Duration
		if Again(err, &pause) || pause != 0 {
			t.Errorf("Again(%v) went on, pause %v", err, pause)
		}
	}
}
