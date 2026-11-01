//go:build !linux

package tlsforge

import (
	"net"
	"time"
)

// Chrome's current Darwin/Windows TCP observer has no TCP_INFO sample. No
// synthetic, initial or HTTP RTT is substituted for an unavailable kernel value.
func networkTCPRTT(net.Conn) (time.Duration, bool) { return 0, false }
