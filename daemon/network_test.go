package daemon

import (
	"context"
	"strings"
	"testing"
)

func TestNetworkContextParserPropagatesMalformedInput(t *testing.T) {
	for _, raw := range []string{"", `{"network":`, `{"unused":null,broken}`} {
		if _, e := requestNetworkContext([]byte(raw)); e == nil {
			t.Fatal("malformed parser input accepted", raw)
		}
	}
}

func TestNetworkContextRejectsBeforeClientSideEffects(t *testing.T) {
	for _, field := range []string{
		`"network":{}`, `"network":{"type":"wifi","id":"","generation":0,"signal":5}`,
		`"network":{"type":"wifi","id":"","generation":9007199254740992,"signal":null}`,
		`"network":{"type":"wifi","id":"","generation":0,"signal":null,"rtt":100}`,
		`"network":{"Type":"wifi","id":"","generation":0,"signal":null}`,
		`"network":{"type":"wifi","id":"","generation":0,"signal":null,"signal":0}`,
		`"Network":null`, `"network":null,"network":null`,
	} {
		c := &fakeClient{}
		r := handle(context.Background(), `{"id":14,"engine_major":1,"url":"https://must-not-resolve.invalid/","setCookie":["x=y"],`+field+`}`, c)
		if r.ID != 14 || r.Error == "" || c.got != nil {
			t.Fatal(field, r, c.got)
		}
	}
	for _, signal := range []string{"null", "0", "4"} {
		c := &fakeClient{}
		r := handle(context.Background(), `{"id":15,"engine_major":1,"url":"https://must-not-resolve.invalid/","network":{"type":"wifi","id":"observed-network","generation":5,"signal":`+signal+`}}`, c)
		if r.Error != "" || c.got == nil || c.got.Network == nil {
			t.Fatal(r, c.got)
		}
		n := c.got.Network
		if n.Type != "wifi" || n.ID != "observed-network" || n.Generation != 5 {
			t.Fatal(n)
		}
		if (n.Signal == nil) != (signal == "null") {
			t.Fatal("missing/zero signal collapsed", n)
		}
	}
	c := &fakeClient{}
	r := handle(context.Background(), `{"id":16,"control":"hello"}`, c)
	for _, capability := range []string{"catalogue_json_v1", "network_hints_estimator_v1", "network_context_v1"} {
		if !strings.Contains(strings.Join(r.Capabilities, ","), capability) {
			t.Fatal("capability missing", r)
		}
	}
	if c.got != nil {
		t.Fatal("hello caused request")
	}
}
