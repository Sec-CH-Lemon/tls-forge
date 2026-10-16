package fingerprint

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestAPreambleIsReadToTheEndOfTheFirstHeaderBlock(t *testing.T) {
	h := chromeHTTP2Fields()
	raw := preambleOf(h, wire{ackFirst: true})
	// What follows the block is not the preamble's.
	after := append(append([]byte(nil), raw...), 0, 0, 0, 4, 1, 0, 0, 0, 0)
	preamble, err := ParsePreamble(after)
	if err != nil {
		t.Fatalf("ParsePreamble: %v", err)
	}
	if !bytes.Equal(preamble.Raw, raw) {
		t.Errorf("Raw kept %d bytes, want %d", len(preamble.Raw), len(raw))
	}
	var said []string
	for _, frame := range preamble.Frames {
		said = append(said, frame.String())
	}
	want := []string{"SETTINGS on 0", "WINDOW_UPDATE on 0", "SETTINGS on 0, ACK",
		"HEADERS on 1, END_STREAM|END_HEADERS|PRIORITY"}
	if !reflect.DeepEqual(said, want) {
		t.Errorf("frames %q, want %q", said, want)
	}
	if !preamble.Frames[2].Ack() || preamble.Frames[0].Ack() || preamble.Frames[3].Ack() {
		t.Error("an acknowledgement was not told apart")
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(preamble.Block)
	if err != nil || len(fields) != len(h.Headers) || fields[0].Name != ":method" {
		t.Errorf("the block decodes to %v, %v", fields, err)
	}

	// Split into a CONTINUATION, the block is the same.
	split, err := ParsePreamble(preambleOf(h, wire{split: true}))
	if err != nil || !bytes.Equal(split.Block, preamble.Block) || len(split.Frames) != 4 ||
		split.Frames[3].String() != "CONTINUATION on 1, END_HEADERS" {
		t.Errorf("split: %+v, %v", split, err)
	}
}

func TestAPaddedHeadersFrameGivesItsBlockWithoutPadding(t *testing.T) {
	var out bytes.Buffer
	framer := http2.NewFramer(&out, nil)
	block := []byte{0x82, 0x87}
	_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block, EndHeaders: true,
		PadLength: 3, Priority: http2.PriorityParam{StreamDep: 0, Weight: 15}})
	preamble, err := ParsePreamble(out.Bytes())
	if err != nil || !bytes.Equal(preamble.Block, block) ||
		preamble.Frames[0].String() != "HEADERS on 1, END_HEADERS|PADDED|PRIORITY" {
		t.Errorf("%+v, %v", preamble, err)
	}
	// Without priority too.
	out.Reset()
	_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block, EndHeaders: true, PadLength: 2})
	if preamble, err := ParsePreamble(out.Bytes()); err != nil || !bytes.Equal(preamble.Block, block) {
		t.Errorf("%+v, %v", preamble, err)
	}
}

// frame is the bytes of one frame.
func frame(typ, flags uint8, stream uint32, payload ...byte) []byte {
	out := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(out, payload...)
}

func TestFramesThatAreNotAPreamble(t *testing.T) {
	settings := frame(4, 0, 0)
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"nothing", nil, "end before"},
		{"no request", settings, "end before"},
		{"a header cut short", append(settings, 0, 0), "frame header cut short at byte 9"},
		{"a payload cut short", frame(8, 0, 0, 0, 0, 1)[:11], "WINDOW_UPDATE on 0 cut short at byte 0"},
		{"a block left open", frame(1, 0x1, 1, 0x82), "end before"},
		{"another frame inside a block", append(frame(1, 0, 1, 0x82), settings...), "SETTINGS on 0 inside the header block of stream 1"},
		{"a CONTINUATION of another stream", append(frame(1, 0, 1, 0x82), frame(9, 4, 3, 0x87)...), "CONTINUATION on 3, END_HEADERS inside"},
		{"a CONTINUATION of nothing", frame(9, 4, 1, 0x82), "with no header block open"},
		{"padding without its length", frame(1, 0x8|0x4, 1), "without its pad length"},
		{"priority without its fields", frame(1, 0x20|0x4, 1, 0, 0, 0), "without its priority"},
		{"padding past the end", frame(1, 0x8|0x4, 1, 5, 0x82), "padded past its end"},
	} {
		_, err := ParsePreamble(tc.raw)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.want == "end before" && !errors.Is(err, ErrNoRequest) {
			t.Errorf("%s: %v is not ErrNoRequest", tc.name, err)
		}
	}
}

func TestFramesAreSaidByName(t *testing.T) {
	for _, tc := range []struct {
		frame Frame
		want  string
	}{
		{Frame{Type: 4}, "SETTINGS on 0"},
		{Frame{Type: 6, Flags: 1}, "PING on 0, ACK"},
		{Frame{Type: 16, Stream: 0}, "PRIORITY_UPDATE on 0"},
		{Frame{Type: 0x0b, Flags: 0x41, Stream: 7}, "0x0b on 7, 0x41"},
		{Frame{Type: 1, Flags: 0x25 | 0x40, Stream: 1}, "HEADERS on 1, END_STREAM|END_HEADERS|PRIORITY|0x40"},
	} {
		if got := tc.frame.String(); got != tc.want {
			t.Errorf("%+v is %q, want %q", tc.frame, got, tc.want)
		}
	}
	if (Frame{Type: 1, Flags: 1}).Ack() || !(Frame{Type: 6, Flags: 1}).Ack() {
		t.Error("only SETTINGS and PING acknowledge")
	}
}

func TestEachFieldIsSaidAsItWasWritten(t *testing.T) {
	// One of each representation. The bytes of the first three are RFC 7541's
	// own (appendix C.4.1); the never-indexed field is the encoder's.
	var never bytes.Buffer
	_ = hpack.NewEncoder(&never).WriteField(hpack.HeaderField{Name: "cookie-crumb-x", Value: "1", Sensitive: true})
	block := []byte{
		0x3f, 0xe1, 0x1f, //                        a size update to 4096
		0x82,                                     // :method: GET, from the static table
		0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, // :authority: www.example.com, with indexing,
		0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff, // the name from the table, the value Huffman
		0x00, 0x03, 'a', 'b', 'c', 0x01, 'x', //    abc: x, without indexing, the name written
	}
	block = append(block, never.Bytes()...)
	block = append(block, 0xbd) // the static table's last entry, www-authenticate
	block = append(block, 0xbe) // the dynamic table's first entry: :authority again

	got, err := Representations(block, 4096)
	if err != nil {
		t.Fatalf("Representations: %v", err)
	}
	var said []string
	for _, r := range got {
		said = append(said, r.Field+" | "+r.String())
	}
	want := []string{
		" | size update 4096",
		":method | indexed static 2",
		":authority | with indexing, name static 1, value huffman",
		"abc | without indexing, new name, value plain",
		"cookie-crumb-x | never indexed, new name huffman, value plain",
		"www-authenticate | indexed static 61",
		":authority | indexed dynamic 62",
	}
	if !reflect.DeepEqual(said, want) {
		t.Errorf("got\n%q\nwant\n%q", said, want)
	}
	if got := got[2].describe(false); got != "with indexing, name static 1" {
		t.Errorf("without the value: %q", got)
	}
}

func TestHeaderBlocksThatDoNotRead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block []byte
		want  string
	}{
		{"an integer cut short", []byte{0xff}, "integer cut short"},
		{"a literal's index cut short", []byte{0x7f}, "integer cut short"},
		{"an integer past 63 bits", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, "integer cut short"},
		{"an index with no string after", []byte{0x41}, "string cut short"},
		{"a name with no string after", []byte{0x40}, "string cut short"},
		{"a string past the end", []byte{0x41, 0x05, 'a'}, "string cut short"},
		{"a string length cut short", []byte{0x41, 0xff}, "string cut short"},
		{"an index no table has", []byte{0xc0}, "header block"},
		{"Huffman that is not", []byte{0x41, 0x81, 0xff}, "header block"},
	} {
		if _, err := Representations(tc.block, 4096); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A size update grows nothing past the table it is written for.
	if _, err := Representations([]byte{0x3f, 0xe2, 0x1f}, 4096); err == nil {
		t.Error("a size update past the table was read")
	}
	if got, err := Representations(nil, 4096); err != nil || got != nil {
		t.Errorf("an empty block: %v, %v", got, err)
	}
}
