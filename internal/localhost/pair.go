package localhost

import "net"

// UDPAndTCP is a UDP socket and a TCP listener at 127.0.0.1 on one port the
// system picks, through listenPacket and listen ("udp4" and "tcp4"), as an
// HTTP/3 server's port is its TCP server's too.
//
// The system gives a protocol a port none of its own sockets holds, which
// the other protocol's may hold, or which the other protocol may not have:
// Windows keeps ranges of ports from programs, each protocol's own (netsh
// int ipv4 show excludedportrange), and gives UDP ports one after another,
// so that ten asked of UDP and then of TCP all fell in a range TCP may not
// have (2026-11-08, a runner: "listen tcp4 127.0.0.1:49844: bind: An attempt
// was made to access a socket in a way forbidden by its access permissions",
// and the next test's at 49854). So the first try asks UDP for a port and
// TCP for it, a port the other does not take is let go of, and the next try
// asks TCP first, Tries times at most.
func UDPAndTCP(listenPacket func(network, address string) (net.PacketConn, error),
	listen func(network, address string) (net.Listener, error)) (net.PacketConn, net.Listener, error) {
	var err error
	for try := range Tries {
		if try%2 == 0 {
			udp, e := listenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				return nil, nil, e
			}
			tcp, e := listen("tcp4", udp.LocalAddr().String())
			if e == nil {
				return udp, tcp, nil
			}
			_ = udp.Close()
			err = e
			continue
		}
		tcp, e := listen("tcp4", "127.0.0.1:0")
		if e != nil {
			return nil, nil, e
		}
		udp, e := listenPacket("udp4", tcp.Addr().String())
		if e == nil {
			return udp, tcp, nil
		}
		_ = tcp.Close()
		err = e
	}
	return nil, nil, err
}
