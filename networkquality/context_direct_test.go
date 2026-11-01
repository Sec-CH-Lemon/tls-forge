package networkquality

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDirectNetworkDecoderRejectsMalformedInputAtomically(t *testing.T) {
	for _, raw := range []string{string([]byte{255}), "", `{`, `{"type":`, `{"type":"wifi" "id":"a"}`, `{"type":"wifi","id":"a","generation":1,"signal":null`, `{"type":"wifi","id":"a","generation":1,"signal":null} {}`} {
		c := Context{Type: "wifi", ID: "unchanged", Generation: 3}
		before := c.Clone()
		if err := c.UnmarshalJSON([]byte(raw)); err == nil {
			t.Fatalf("malformed input accepted: %q", raw)
		}
		if !reflect.DeepEqual(c, before) {
			t.Fatal("failed input mutated context")
		}
	}
}
func FuzzNetworkContextDecoder(f *testing.F) {
	for _, raw := range []string{`{"type":"wifi","id":"a","generation":1,"signal":null}`, `{"type":"wifi","id":"\ud83d\ude00","generation":1,"signal":0}`, `{"type":`, `{`, `null`} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		var c Context
		if c.UnmarshalJSON([]byte(raw)) != nil {
			return
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var round Context
		if err := round.UnmarshalJSON(b); err != nil || !reflect.DeepEqual(c, round) {
			t.Fatal("non-roundtrippable context", c, string(b), round, err)
		}
	})
}
