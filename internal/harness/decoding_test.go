package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/unicode"
)

func ptr(s string) *string { return &s }

func TestAFixtureOfDecodingsIsWrittenAsItIsKept(t *testing.T) {
	committed, err := os.ReadFile(decodingFixture)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fixture, err := LoadDecoding(decodingFixture)
	if err != nil {
		t.Fatalf("LoadDecoding: %v", err)
	}
	out := filepath.Join(t.TempDir(), "decoding.json")
	if err := fixture.Write(out); err != nil {
		t.Fatalf("Write: %v", err)
	}
	written, _ := os.ReadFile(out)
	if !bytes.Equal(written, committed) {
		t.Error("the fixture read and written again is not the fixture")
	}
	if _, err := LoadDecoding(filepath.Join(t.TempDir(), "none.json")); !os.IsNotExist(err) {
		t.Errorf("LoadDecoding of nothing: %v", err)
	}
	broken := filepath.Join(t.TempDir(), "broken.json")
	_ = os.WriteFile(broken, []byte(`{"cases":[{"name":1}]}`), 0o644)
	if _, err := LoadDecoding(broken); err == nil || !strings.Contains(err.Error(), "broken.json") {
		t.Errorf("LoadDecoding of a broken file: %v", err)
	}
}

func TestACaseSaysWhatTheBrowserShowedAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		c    DecodingCase
		want string
	}{
		{DecodingCase{Name: "a", Note: "<&>", Body: []byte{0xff}, Word: []byte("w"), Encoding: "utf-8", Text: ptr("x<y")},
			`{"name":"a","note":"<&>","content_type":null,"body":"/w==","word":"dw==","chrome_encoding":"utf-8","chrome_text":"x<y"}`},
		{DecodingCase{Name: "b", ContentType: ptr("text/plain")},
			`{"name":"b","note":"","content_type":"text/plain","body":null,"word":null,"chrome_text":null}`},
		{DecodingCase{Name: "c", Shows: "nothing: no document", Text: ptr("dropped")},
			`{"name":"c","note":"","content_type":null,"body":null,"word":null,"chrome_shows":"nothing: no document"}`},
	} {
		// As the fixture is written: json.Marshal would escape what it
		// does not.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		err := enc.Encode(tc.c)
		got := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		if err != nil || string(got) != tc.want {
			t.Errorf("Marshal: %s, %v\nwant %s", got, err, tc.want)
		}
		var back DecodingCase
		if err := json.Unmarshal(got, &back); err != nil || back.Name != tc.c.Name || back.Shows != tc.c.Shows ||
			(back.Text == nil) != (tc.c.Text == nil || tc.c.Shows != "") {
			t.Errorf("Unmarshal: %+v, %v", back, err)
		}
	}
	var c DecodingCase
	if err := json.Unmarshal([]byte(`{"body":"not base64"}`), &c); err == nil {
		t.Error("read a body that is no base64")
	}
	if _, err := json.Marshal(DecodingCase{Text: ptr("\xff")}); err != nil {
		t.Errorf("Marshal of a text that is no UTF-8: %v", err)
	}
}

// dumped is what a fake browser dumps of each page: what dom makes of what it
// was served.
func dumped(dom func(name string, res *http.Response, body []byte) string) *fake {
	return &fake{dump: func(page string, res *http.Response, body []byte) []byte {
		return []byte(dom(page[strings.LastIndex(page, "/")+1:], res, body))
	}}
}

func TestEachPageIsServedAsItWasAndReadAsTheBrowserShowsIt(t *testing.T) {
	cases := []DecodingCase{
		{Name: "typed", ContentType: ptr("text/html; charset=windows-1251"), Body: []byte("<p>a</p>"), Word: []byte("w")},
		{Name: "untyped", Body: []byte("plain"), Word: []byte("plain")},
		{Name: "empty", ContentType: ptr("text/plain"), Body: []byte("x"), Word: []byte("x")},
	}
	served := map[string][]string{}
	b := dumped(func(name string, res *http.Response, body []byte) string {
		served[name] = append(res.Header.Values("Content-Type"), res.Header.Get("Cache-Control"), string(body))
		switch name {
		case "typed":
			return "<html><head><title>windows-1251|%D0%9F%D1%80</title></head></html>"
		case "untyped":
			return "<html><body><pre>plain</pre></body></html>"
		}
		return "  \n"
	})
	var progress bytes.Buffer
	got, err := MeasureDecoding(context.Background(), b, cases, &progress)
	if err != nil {
		t.Fatalf("MeasureDecoding: %v", err)
	}
	if strings.Join(served["typed"], "|") != "text/html; charset=windows-1251|no-store|<p>a</p>" ||
		strings.Join(served["untyped"], "|") != "no-store|plain" {
		t.Errorf("served %q", served)
	}
	if got[0].Encoding != "windows-1251" || *got[0].Text != "Пр" || got[0].Shows != "" ||
		got[1].Encoding != "" || *got[1].Text != "plain" || got[2].Text != nil || got[2].Shows != "nothing: no document" {
		t.Errorf("measured %+v", got)
	}
	// The case is otherwise as it was given.
	if got[0].Name != "typed" || string(got[0].Body) != "<p>a</p>" || *got[0].ContentType != "text/html; charset=windows-1251" {
		t.Errorf("measured %+v", got[0])
	}
	if progress.String() != "decoding typed\ndecoding untyped\ndecoding empty\n" {
		t.Errorf("progress %q", progress.String())
	}
	// A page that is not one of the cases is not found.
	elsewhere := &missing{}
	got, err = MeasureDecoding(context.Background(), elsewhere, []DecodingCase{{Name: "a", Word: []byte("zzz")}}, nil)
	if err != nil || elsewhere.status != http.StatusNotFound || got[0].Text != nil || got[0].Shows != "" {
		t.Errorf("measured %+v, %v, status %d", got, err, elsewhere.status)
	}
}

func TestAPageThatCannotBeDumpedIsNoMeasurement(t *testing.T) {
	cases := []DecodingCase{{Name: "a"}}
	refusing := &fake{dump: func(string, *http.Response, []byte) []byte { return nil }}
	refusing.fail = "x"
	b := &broken{}
	if _, err := MeasureDecoding(context.Background(), b, cases, nil); err == nil || err.Error() != "harness: a: no dump" {
		t.Errorf("MeasureDecoding: %v", err)
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := MeasureDecoding(context.Background(), refusing, cases, nil); !errors.Is(err, failing) {
		t.Errorf("MeasureDecoding with no server: %v", err)
	}
}

// missing is a browser that asks for a page beside the one it is sent to.
type missing struct {
	fake
	status int
}

func (m *missing) DumpDOM(_ context.Context, page string) ([]byte, error) {
	res, err := client().Get(page + "-beside")
	if err != nil {
		return nil, err
	}
	_ = res.Body.Close()
	m.status = res.StatusCode
	return []byte(res.Status), nil
}

// broken is a browser that dumps nothing.
type broken struct{ fake }

func (*broken) DumpDOM(context.Context, string) ([]byte, error) { return nil, errors.New("no dump") }

func TestWhatTheBrowserMadeOfAPageIsReadOutOfItsDump(t *testing.T) {
	word := []byte("Привет мир")
	w1251, _ := charmap.Windows1251.NewEncoder().Bytes(word)
	for _, tc := range []struct {
		name, dump string
		word       []byte
		encoding   string
		text       *string
		shows      string
	}{
		{"a probe", "<title>UTF-8|%D0%9F%20%zz%</title>", word, "UTF-8", ptr("П %zz%"), ""},
		{"a probe of bytes that are no UTF-8", "<title>windows-1252|%FF</title>", word, "windows-1252", ptr("�"), ""},
		{"a title that is no probe", "<title>a b|c</title><pre>Привет мир</pre>", word, "", ptr("Привет мир"), ""},
		{"the word escaped", "<pre>&#1055;ривет&nbsp;мир Привет мир</pre>", word, "", ptr("Привет мир"), ""},
		{"the encoding it was read in", "<pre>Привет мир</pre>", w1251, "", ptr("Привет мир"), ""},
		{"the longest of what is found", "<p>Ã© é</p>", []byte("é"), "", ptr("Ã©"), ""},
		{"the first of the longest", "<p>Пр оП</p>", []byte{0xcf, 0xf0}, "", ptr("Пр"), ""},
		{"nothing of it", "<p>other</p>", word, "", nil, ""},
		{"replaced", "<p>��</p>", word, "", ptr("�"), ""},
		{"replaced, but the word is there in another form", "<p>� Привет</p>", word, "", nil, ""},
		{"no document", " \n\t", word, "", nil, "nothing: no document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoding, text, shows := extract([]byte(tc.dump), tc.word)
			if encoding != tc.encoding || shows != tc.shows || (text == nil) != (tc.text == nil) || text != nil && *text != *tc.text {
				t.Errorf("extract: %q, %v, %q", encoding, text, shows)
			}
		})
	}
}

func TestEveryEncodingAWordIsLookedForInDecodesIt(t *testing.T) {
	sjis, _ := japanese.ShiftJIS.NewEncoder().Bytes([]byte("日本"))
	utf16le, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().Bytes([]byte("Пр"))
	want := map[string]struct {
		bytes []byte
		text  string
	}{
		"utf-8":          {[]byte("a\xe2\x82b"), "a�b"},
		"windows-1251":   {[]byte{0xcf, 0xf0}, "Пр"},
		"windows-1252":   {[]byte{0x80, 0x81, 0x9f, 'a', 0xe9}, "€\u0081Ÿaé"},
		"koi8-r":         {[]byte{0xf0, 0xd2}, "Пр"},
		"koi8-u":         {[]byte{0xa4}, "є"},
		"utf-16le":       {utf16le, "Пр"},
		"utf-16be":       {[]byte{0x04, 0x1f}, "П"},
		"x-user-defined": {[]byte{'a', 0x80, 0xff}, "a"},
		"gbk":            {[]byte{0xc4, 0xe3}, "你"},
		"big5":           {[]byte{0xa4, 0x40}, "一"},
		"shift_jis":      {sjis, "日本"},
		"euc-jp":         {[]byte{0xc6, 0xfc}, "日"},
		"euc-kr":         {[]byte{0xb0, 0xa1}, "가"},
		"iso-8859-5":     {[]byte{0xbf}, "П"},
		"windows-1250":   {[]byte{0x8a}, "Š"},
		"ibm866":         {[]byte{0x8f}, "П"},
		"x-mac-cyrillic": {[]byte{0x8f}, "П"},
	}
	if len(decoders) != len(want) {
		t.Fatalf("%d decoders, %d tested", len(decoders), len(want))
	}
	for _, d := range decoders {
		if got := d.decode(want[d.name].bytes); got != want[d.name].text {
			t.Errorf("%s: %q, want %q", d.name, got, want[d.name].text)
		}
	}
}

func TestWhatDiffersOfADecodingIsSaid(t *testing.T) {
	want := []DecodingCase{
		{Name: "a", Encoding: "utf-8", Text: ptr("x")},
		{Name: "b", Text: nil},
		{Name: "c", Shows: "nothing: no document"},
		{Name: "d", Text: ptr("y")},
	}
	if diff := CompareDecoding(want, want); diff != nil {
		t.Errorf("CompareDecoding: %v", diff)
	}
	got := []DecodingCase{
		{Name: "a", Encoding: "windows-1252", Text: ptr("x")},
		{Name: "b", Text: ptr("z")},
		{Name: "c"},
	}
	diff := CompareDecoding(want, got)
	if len(diff) != 4 ||
		diff[0] != `a: the browser read "x" as "windows-1252" and showed "", the fixture "x" as "utf-8" and ""` ||
		diff[1] != `b: the browser read "z" as "" and showed "", the fixture nothing as "" and ""` ||
		!strings.HasPrefix(diff[2], `c: the browser read nothing as "" and showed "", the fixture nothing as "" and "nothing: no document"`) ||
		diff[3] != "d was not measured" {
		t.Errorf("CompareDecoding: %q", diff)
	}
	// The same text read differently is a difference too.
	if diff := CompareDecoding([]DecodingCase{{Name: "e", Text: ptr("1")}}, []DecodingCase{{Name: "e", Text: ptr("2")}}); len(diff) != 1 {
		t.Errorf("CompareDecoding: %q", diff)
	}
}

func TestUnquote(t *testing.T) {
	for in, want := range map[string]string{
		"":           "",
		"a%20b":      "a b",
		"%D0%9F":     "П",
		"%zz":        "%zz",
		"%":          "%",
		"%4":         "%4",
		"%4g":        "%4g",
		"%ff%fe":     "��",
		"100%25":     "100%",
		"%41%61%2Fx": "Aa/x",
	} {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}
