package daemon

import (
	"context"
	"strings"
	"testing"
)

func TestEngineGateBeforeDaemonClientAndProxyInit(t *testing.T) {
	for _, metadata := range []string{"", `"engine_major":null,`, `"engine_major":0,`, `"engine_major":1,`, `"engine_major":2,`, `"engine_major":3,`, `"engine_major":5,`, `"engine_major":-1,`, `"engine_major":4.5,`, `"engine_major":"1",`, `"engine_major":true,`, `"engine_major":4,"engine_major":4,`, `"engine_major":0,"Engine_Major":1,`} {
		client := &fakeClient{}
		line := `{` + metadata + `"id":41,"url":"https://must-not-resolve.invalid/","setCookie":["x=y"]}`
		got := handle(context.Background(), line, client)
		if got.Error == "" || client.got != nil {
			t.Fatal(metadata, got, client.got)
		}
		init := `{` + metadata + `"id":42,"control":"init","proxy":"http://must-not-resolve.invalid:80"}`
		if _, _, err := ReadInit(strings.NewReader(init)); err == nil {
			t.Fatal("init bypass", metadata)
		}
	}
	client := &fakeClient{}
	got := handle(context.Background(), `{"id":5,"control":"hello"}`, client)
	if got.EngineMajor == nil || *got.EngineMajor != 4 || got.Version != "4.0.0" || got.Protocol != 3 || client.got != nil {
		t.Fatal(got)
	}
	if got := handle(context.Background(), `{"id":6,"engine_major":4,"url":"https://example.invalid/"}`, client); got.Error != "" || client.got == nil {
		t.Fatal(got)
	}
}
