package tlsforge

import (
	"context"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	quic "github.com/igor-lemon/quic-go-utls"
	tc "github.com/igor-lemon/tls-client"
	"testing"
	"time"
)

func TestA13PeerClosesAcceptedQUICConnections(t *testing.T) {
	var server *quic.Conn
	if !t.Run("fixture", func(child *testing.T) {
		accepted := make(chan *quic.Conn, 1)
		target, _ := a13CatalogueH3PeerObserved(child, func(c *quic.Conn) { accepted <- c })
		p, err := profile.Get("okhttp4_android_10")
		if err != nil {
			child.Fatal(err)
		}
		// Hold client ownership in the parent: only the child fixture should close
		// its accepted server connection before the child returns.
		client := newTestClient(t, WithProfileValue(p), WithTimeout(6*time.Second), WithTransportOption(tc.WithProtocolRacing()))
		response, err := client.Get(target)
		if err != nil || string(response.Body) != "ok" {
			child.Fatalf("response %+v %v", response, err)
		}
		select {
		case server = <-accepted:
		case <-time.After(time.Second):
			child.Fatal("missing accepted connection")
		}
	}) {
		t.Fatal("fixture request failed")
	}
	if server == nil {
		t.Fatal("no connection")
	}
	select {
	case <-server.Context().Done():
	default:
		t.Fatal("fixture left accepted QUIC connection running")
	}
	if context.Cause(server.Context()) == nil {
		t.Fatal("missing close cause")
	}
}
