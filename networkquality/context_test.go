package networkquality

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTypedNetworkContextStrictlyPreservesUnavailableAndZero(t *testing.T) {
	var missing, zero Context
	if e := json.Unmarshal([]byte(`{"type":"wifi","id":"network-a","generation":1,"signal":null}`), &missing); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal([]byte(`{"type":"wifi","id":"network-a","generation":1,"signal":0}`), &zero); e != nil {
		t.Fatal(e)
	}
	if missing.signal() != -1 || zero.signal() != 0 {
		t.Fatal("unknown and known zero conflated")
	}
	clone := zero.Clone()
	*clone.Signal = 4
	if zero.signal() != 0 {
		t.Fatal("input clone aliases caller")
	}
	if e := (Context{Type: "wifi", ID: strings.Repeat("x", 4097)}).Validate(); e == nil {
		t.Fatal("unbounded identity accepted")
	}
	if e := (Context{Type: "wifi", ID: string([]byte{0xff})}).Validate(); e == nil {
		t.Fatal("non-UTF8 identity accepted")
	}
}
func TestTypedNetworkContextRejectsPartialOrAmbiguousTransitions(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{"type":"wifi"}`, `{"type":"wifi","id":"a","generation":1,"signal":null,"rtt":100}`,
		`{"Type":"wifi","id":"a","generation":1,"signal":null}`, `{"type":"wifi","type":"wifi","id":"a","generation":1,"signal":null}`,
		`{"type":"made-up","id":"a","generation":1,"signal":null}`, `{"type":"wifi","id":"a","generation":9007199254740992,"signal":null}`,
		`{"type":"wifi","id":"a","generation":1,"signal":-1}`, `{"type":"wifi","id":"a","generation":1,"signal":5}`, `{"type":"wifi","id":"a","generation":1.5,"signal":null}`,
		`{"type":"wifi","id":42,"generation":1,"signal":null}`, `{"type":"wifi","id":"a","generation":1,"signal":"0"}`, `{`, string([]byte{0xff}), strings.Repeat(" ", 32769),
	} {
		var c Context
		if e := json.Unmarshal([]byte(raw), &c); e == nil {
			t.Fatalf("ambiguous context accepted: %s", raw)
		}
	}
}

func TestNetworkIdentityDoesNotLoseUnicodeOrNullFields(t *testing.T) {
	for _, raw := range []string{
		`{"type":"wifi","id":"\ud800","generation":1,"signal":null}`,
		`{"type":"wifi","id":"\udc00","generation":1,"signal":null}`,
		`{"type":"wifi","id":"\ud800\u0061","generation":1,"signal":null}`,
		`{"type":"wifi","id":null,"generation":1,"signal":null}`,
		`{"type":"wifi","id":"a","generation":null,"signal":null}`,
		`{"type":`, `{"type":"wifi",`, `{"type":"wifi","id":"a","generation":1,"signal":null`,
		`{"type":"wifi","id":"a","generation":1,"signal":null} {}`,
	} {
		var c Context
		if e := json.Unmarshal([]byte(raw), &c); e == nil {
			t.Fatal("lossy or malformed context accepted", raw)
		}
	}
	for _, raw := range []string{
		`{"type":"wifi","id":"\ud83d\ude00","generation":1,"signal":null}`,
		`{"type":"wifi","id":"\ufffd","generation":1,"signal":null}`,
		`{"type":"wifi","id":"slash\/and\\unicode","generation":0,"signal":4}`,
	} {
		var c Context
		if e := json.Unmarshal([]byte(raw), &c); e != nil {
			t.Fatal("valid identity rejected", raw, e)
		}
	}
}
