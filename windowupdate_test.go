package tlsforge

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v4/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/v4/profile"
	tls_client "github.com/igor-lemon/tls-client"
)

// timedScale is how much quicker than Chrome's five seconds a replay runs the
// scenarios whose pauses its rule for a little of a window is about: the
// server's pauses and the client's wait alike.
const timedScale = 0.3

func TestWindowUpdatesGoAsChromeSentThem(t *testing.T) {
	// Each scenario of the flow fixture sent to tls-forge as it was to Chrome
	// 155, from the same server, whose answers come in the same parts: the
	// WINDOW_UPDATEs, of which window, in which part, and how much each says,
	// are Chrome's, past half of a window by a read of Chrome's at most, or
	// what was untold when the time came, whatever window the server said.
	fixture, err := harness.LoadFlow("testdata/chrome155-flow.json")
	if err != nil {
		t.Fatalf("LoadFlow: %v", err)
	}
	onEveryPlatform(t, func(t *testing.T, chrome *profile.Profile) { flowsAsChromes(t, chrome, fixture) })
}

// flowsAsChromes sends every scenario of the flow fixture wearing chrome, the
// scenarios side by side, and holds the WINDOW_UPDATEs to Chrome's.
func flowsAsChromes(t *testing.T, chrome *profile.Profile, fixture *harness.FlowFixture) {
	for id, want := range fixture.Scenarios {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			scale := 1.0
			if want.Pause >= 4000 || want.AgainAfter > 0 {
				scale = timedScale
			}
			server, err := harness.StartFlowServer(scale)
			if err != nil {
				t.Fatalf("StartFlowServer: %v", err)
			}
			t.Cleanup(func() { _ = server.Close() })
			built, err := chrome.ClientProfile()
			if err != nil {
				t.Fatalf("ClientProfile: %v", err)
			}
			delay := time.Duration(scale * float64(built.GetWindowUpdateDelay()))
			p := chrome.Clone()
			p.Behavior["h2.window_update_delay_ms"] = json.RawMessage(strconv.FormatInt(delay.Milliseconds(), 10))
			client := newTestClient(t, WithProfileValue(p),
				WithTransportOption(tls_client.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
					_, port, _ := net.SplitHostPort(addr)
					var d net.Dialer
					return d.DialContext(ctx, network, "127.0.0.1:"+port)
				})))
			if _, err := client.Get(server.URL(id)); err != nil {
				t.Fatalf("Get: %v", err)
			}
			if want.Again > 0 {
				time.Sleep(time.Duration(scale * float64(want.AgainAfter) * float64(time.Millisecond)))
				if _, err := client.Get(server.URL(id) + "/again"); err != nil {
					t.Fatalf("Get again: %v", err)
				}
			}
			for deadline := time.Now().Add(10 * time.Second); !server.Ended(id) && time.Now().Before(deadline); {
				time.Sleep(10 * time.Millisecond)
			}
			// What a last read freed comes a moment after its answer.
			time.Sleep(200 * time.Millisecond)
			got, err := server.Updates(id)
			if err != nil {
				t.Fatalf("Updates: %v", err)
			}
			if diff := harness.DiffFlow(want, harness.FlowScenario{FlowShape: want.FlowShape, Updates: got}); diff != nil {
				t.Errorf("sent %v\nChrome %v\n%s", got, want.Updates, strings.Join(diff, "\n"))
			}
		})
	}
}
