package tlsforge

import (
	"encoding/json"
	"github.com/Sec-CH-Lemon/tls-forge/v4/profile"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestScriptInputsCombineValuesWithoutChangingTheCaller(t *testing.T) {
	original := NewHeader("X-Probe", " first ", "content-type", "application/octet-stream", "x-probe", "\tsecond\t", "X-Probe", "")
	before := append(Header(nil), original...)
	for _, kind := range []RequestKind{KindFetch, KindXHR} {
		b := BrowserContext{Kind: kind, Initiator: "https://example.com/page"}
		r, err := b.resolve("POST", mustURL(t, "https://example.com/echo"), original, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if got := r.script.Values("x-probe"); !reflect.DeepEqual(got, []string{"first, second, "}) {
			t.Errorf("%s: %q", kind, got)
		}
	}
	if !reflect.DeepEqual(original, before) {
		t.Fatal("caller headers changed")
	}
}

// The fixture is a fresh real Chrome oracle,including names not used to discover
// the original defect. Recorders inspect actual H2/H1 bytes,not Header maps.
func TestScriptHeaderMapMatchesFreshChrome(t *testing.T) {
	data, err := os.ReadFile("testdata/chrome155-script-headers.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID     string      `json:"id"`
			Input  [][2]string `json:"input_headers"`
			Order  []string    `json:"renderer_order"`
			Wire   [][2]string `json:"wire_headers"`
			WireH1 [][2]string `json:"wire_h1"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, proto := range []string{"h2", "h1"} {
		for _, tc := range fixture.Cases {
			t.Run(proto+"/"+tc.ID, func(t *testing.T) {
				server := newRecorder(t, proto, nil)
				client := contextClient(t, server)
				var headers Header
				for _, h := range tc.Input {
					headers = append(headers, profile.Field{Name: h[0], Value: h[1]})
				}
				b := &BrowserContext{Kind: KindFetch, Initiator: "https://localhost:18444/page"}
				body := make([]byte, 1028)
				for i := range body {
					body[i] = byte(i)
				}
				_, err := client.Do(&Request{Method: "POST", URL: "https://localhost:18444/fingerprint", Browser: b, Header: headers, Body: body})
				if err != nil {
					t.Fatal(err)
				}
				got := server.requests()
				if len(got) != 1 {
					t.Fatalf("%d requests", len(got))
				}
				names := map[string]bool{"user-agent": true, "sec-ch-ua": true, "sec-ch-ua-mobile": true, "sec-ch-ua-platform": true}
				for _, h := range tc.Input {
					names[strings.ToLower(h[0])] = true
				}
				var order []string
				var values [][2]string
				for _, h := range got[0].headers {
					n := strings.ToLower(h[0])
					if names[n] {
						order = append(order, n)
						values = append(values, [2]string{h[0], h[1]})
					}
				}
				if !slices.Equal(order, tc.Order) {
					t.Errorf("order %q,want Chrome %q", order, tc.Order)
				}
				var expected [][2]string
				wire := tc.Wire
				if proto == "h1" {
					wire = tc.WireH1
				}
				for _, h := range wire {
					n := strings.ToLower(h[0])
					if names[n] {
						expected = append(expected, [2]string{h[0], h[1]})
					}
				}
				if !reflect.DeepEqual(values, expected) {
					t.Errorf("headers %v,want Chrome %v", values, expected)
				}
				if got[0].body != string(body) {
					t.Error("binary body changed")
				}
			})
		}
	}
}

func TestRawRequestsKeepRepeatedFields(t *testing.T) {
	for _, proto := range []string{"h2", "h1"} {
		s := newRecorder(t, proto, nil)
		c := contextClient(t, s)
		h := NewHeader("x-probe", "first", "x-probe", "second")
		if _, err := c.Do(&Request{URL: "https://example.com/raw", Header: h}); err != nil {
			t.Fatal(err)
		}
		var values []string
		for _, f := range s.requests()[0].headers {
			if strings.EqualFold(f[0], "x-probe") {
				values = append(values, f[1])
			}
		}
		if !slices.Equal(values, []string{"first", "second"}) {
			t.Errorf("%s:raw headers changed:%q", proto, values)
		}
	}
}

func TestOriginAskingForDefaultHintsDoesNotDuplicateThem(t *testing.T) {
	h := hop{to: originOf(mustURL(t, "https://example.com/")), hints: NewHeader("sec-ch-ua", "brand", "sec-ch-ua-mobile", "?0")}
	order := scriptHeaderOrder(h)
	for _, name := range []string{"sec-ch-ua", "sec-ch-ua-mobile"} {
		n := 0
		for _, s := range order {
			if s == name {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%s appears %d times", name, n)
		}
	}
}
