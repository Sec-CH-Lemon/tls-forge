package daemon

import (
	"context"
	"strings"
	"testing"
)

func TestEngineGateBeforeDaemonClientAndProxyInit(t *testing.T) {
	for _, metadata := range []string{"", `"engine_major":null,`, `"engine_major":0,`, `"engine_major":7,`, `"engine_major":2,`, `"engine_major":3,`, `"engine_major":4,`, `"engine_major":5,`, `"engine_major":6,`, `"engine_major":8,`, `"engine_major":-1,`, `"engine_major":1.5,`, `"engine_major":"1",`, `"engine_major":true,`, `"engine_major":1,"engine_major":1,`, `"engine_major":0,"Engine_Major":1,`} {
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
	if got.EngineMajor == nil || *got.EngineMajor != 1 || got.Version != "1.0.0" || got.Protocol != 3 || client.got != nil {
		t.Fatal(got)
	}
	if got := handle(context.Background(), `{"id":6,"engine_major":1,"url":"https://example.invalid/"}`, client); got.Error != "" || client.got == nil {
		t.Fatal(got)
	}
}

func TestRequestBodyPresenceSurvivesJSON(t *testing.T) {
	for _, tt := range []struct {
		field    string
		provided bool
		want     string
	}{
		{"", false, ""}, {`,"body":null`, false, ""}, {`,"body":""`, true, ""}, {`,"body":"","bodyEncoding":"base64"`, true, ""}, {`,"body":"eA==","bodyEncoding":"base64"`, true, "x"},
	} {
		c := &fakeClient{}
		r := handle(context.Background(), `{"id":1,"engine_major":1,"url":"https://example.invalid/"`+tt.field+`}`, c)
		if r.Error != "" || c.got == nil {
			t.Fatal(tt, r)
		}
		if (c.got.Body != nil) != tt.provided || string(c.got.Body) != tt.want {
			t.Fatal("request body presence/bytes lost", tt, c.got.Body)
		}
	}
}

func TestAControlButHelloIsHeldToTheEngineMajorToo(t *testing.T) {
	// hello alone is offline discovery: any other control line says the major
	// it was written for, and one of another engine is refused before it is
	// read for what it asks.
	for line, want := range map[string]string{
		`{"id":7,"control":"init","proxy":"http://p.test:80"}`:                  "engine_major is required",
		`{"id":7,"engine_major":2,"control":"init","proxy":"http://p.test:80"}`: "engine_major 2 is incompatible",
		`{"id":7,"engine_major":1,"control":"init","proxy":"http://p.test:80"}`: "init is the first line",
		`{"id":7,"engine_major":1,"control":"nothing"}`:                         `unknown control "nothing"`,
		`{"id":7,"engine_major":1,"Engine_Major":1,"control":"nothing"}`:        "invalid engine_major spelling",
	} {
		client := &fakeClient{}
		got := handle(context.Background(), line, client)
		if !strings.Contains(got.Error, want) || got.ID != 7 || client.got != nil {
			t.Errorf("%s: %+v, want %q", line, got, want)
		}
	}
}
