// Package accept says when a server tries accepting a connection again.
package accept

import (
	"errors"
	"syscall"
	"time"
)

const (
	first = 5 * time.Millisecond
	most  = time.Second
)

// sleep waits; a variable so a test need not.
var sleep = time.Sleep

// Again says whether to try accepting again after Accept failed with err, and
// waits before it does. A failure that passes, such as running out of file
// descriptors until some connection ends, is waited out: five milliseconds the
// first time, twice as long each time after, up to a second; pause keeps how
// long it was, and is set back to zero once a connection is accepted. Any other
// failure, the listener's closing among them, ends accepting.
func Again(err error, pause *time.Duration) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) || !errno.Temporary() {
		return false
	}
	*pause = min(max(2**pause, first), most)
	sleep(*pause)
	return true
}
