package profile

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

func TestA12CloseNotifyVariantsChangeOnlyTheirDeclaredChoice(t *testing.T) {
	for _, platform := range []string{"linux", "macos", "windows"} {
		file := "../example/profiles/chrome_156_" + platform + "_close_notify.json"
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		source, err := Get("chrome_156_" + platform)
		if err != nil {
			t.Fatal(err)
		}
		if !variant.Behavior.Flag("tls.close_notify") || source.Behavior.Flag("tls.close_notify") || variant.Name != "chrome_156_"+platform+"_close_notify" {
			t.Fatal("variant/default identity or choice changed")
		}
		saved, err := variant.Save()
		if err != nil || !bytes.Equal(saved, raw) {
			t.Fatal("variant is not canonical executable JSON", err)
		}
		if _, err := variant.ClientProfile(); err != nil {
			t.Fatal(err)
		}
		copy := variant.Clone()
		copy.Name, copy.Notes = source.Name, source.Notes
		copy.Behavior["tls.close_notify"] = []byte("false")
		if !reflect.DeepEqual(copy, source) {
			t.Fatal("variant changed another browser field")
		}
		for _, other := range []int{0, 2} {
			copy := variant.Clone()
			copy.EngineMajor = Major(other)
			if err := copy.Validate(); err == nil {
				t.Fatalf("variant silently accepted engine major%d", other)
			}
		}
	}
}
