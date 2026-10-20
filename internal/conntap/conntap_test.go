package conntap

import (
	"context"
	"net"
	"testing"
	"time"
)

type tap struct{}

func (tap) Dialed(conn net.Conn, _ time.Time) net.Conn { return conn }
func (tap) Used(net.Conn)                              {}

func TestAContextCarriesTheTapItWasGiven(t *testing.T) {
	ctx := context.Background()
	if From(ctx) != nil {
		t.Error("a context carries a tap it was never given")
	}
	given := tap{}
	carried := With(ctx, given)
	if From(carried) != given {
		t.Errorf("the context carries %v", From(carried))
	}
	// And so does one made of it.
	derived, cancel := context.WithCancel(carried)
	defer cancel()
	if From(derived) != given {
		t.Errorf("a context made of it carries %v", From(derived))
	}
}
