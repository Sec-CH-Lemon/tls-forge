package fingerprint

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// The HTTP/2 a client sends before its first request is whole, read from the
// bytes as they went: which frames, in what order, with which flags, and how
// each field of the request's header block was written (RFC 7541, section 6).
// Neither survives a decoder: a server that hands on SETTINGS and decoded
// fields has already lost both, and both are the client's own.

// Frame is one HTTP/2 frame as it went: its type, flags, stream and length.
type Frame struct {
	Type   uint8
	Flags  uint8
	Stream uint32
	Length int
}

var frameNames = map[uint8]string{
	0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE",
	6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION", 10: "ALTSVC", 12: "ORIGIN",
	16: "PRIORITY_UPDATE",
}

// frameFlags are the flags each type defines, in the order they are said.
var frameFlags = map[uint8][]struct {
	bit  uint8
	name string
}{
	0: {{0x1, "END_STREAM"}, {0x8, "PADDED"}},
	1: {{0x1, "END_STREAM"}, {0x4, "END_HEADERS"}, {0x8, "PADDED"}, {0x20, "PRIORITY"}},
	4: {{0x1, "ACK"}},
	5: {{0x4, "END_HEADERS"}, {0x8, "PADDED"}},
	6: {{0x1, "ACK"}},
	9: {{0x4, "END_HEADERS"}},
}

const (
	frameHeaders      = 1
	frameSettings     = 4
	framePing         = 6
	frameContinuation = 9

	flagAck        = 0x1
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
)

// String is a frame as a person reads it: its type, its stream, and its
// flags by name, any the type does not define in hex.
func (f Frame) String() string {
	name, ok := frameNames[f.Type]
	if !ok {
		name = fmt.Sprintf("0x%02x", f.Type)
	}
	var flags []string
	rest := f.Flags
	for _, flag := range frameFlags[f.Type] {
		if rest&flag.bit != 0 {
			flags = append(flags, flag.name)
			rest &^= flag.bit
		}
	}
	if rest != 0 {
		flags = append(flags, fmt.Sprintf("0x%02x", rest))
	}
	out := fmt.Sprintf("%s on %d", name, f.Stream)
	if len(flags) > 0 {
		out += ", " + strings.Join(flags, "|")
	}
	return out
}

// Ack reports a SETTINGS or PING frame that acknowledges the server's: when it
// goes depends on when the server's arrived, not on the client.
func (f Frame) Ack() bool {
	return (f.Type == frameSettings || f.Type == framePing) && f.Flags&flagAck != 0
}

// Preamble is what a client sent from the end of its preface to the end of
// the header block of its first request.
type Preamble struct {
	// Raw is the bytes it was read from, without whatever followed.
	Raw    []byte
	Frames []Frame
	// Block is the first request's header block, its fragments joined, without
	// padding or priority.
	Block []byte
}

// ErrNoRequest reports frames that end before a request's header block does.
var ErrNoRequest = errors.New("fingerprint: the frames end before a request's header block does")

// ParsePreamble reads frames up to the end of the first header block. Bytes
// past it are not read, and are not in Raw.
func ParsePreamble(raw []byte) (*Preamble, error) {
	out := &Preamble{}
	var open uint32 // the stream whose header block is being read
	for at := 0; at < len(raw); {
		if len(raw)-at < 9 {
			return nil, fmt.Errorf("fingerprint: a frame header cut short at byte %d", at)
		}
		head := raw[at : at+9]
		frame := Frame{
			Length: int(head[0])<<16 | int(head[1])<<8 | int(head[2]),
			Type:   head[3],
			Flags:  head[4],
			Stream: binary.BigEndian.Uint32(head[5:9]) & 0x7fffffff,
		}
		payload := raw[at+9:]
		if len(payload) < frame.Length {
			return nil, fmt.Errorf("fingerprint: %s cut short at byte %d", frame, at)
		}
		payload = payload[:frame.Length]
		at += 9 + frame.Length
		out.Frames = append(out.Frames, frame)

		switch {
		case open != 0 && (frame.Type != frameContinuation || frame.Stream != open):
			return nil, fmt.Errorf("fingerprint: %s inside the header block of stream %d", frame, open)
		case open == 0 && frame.Type == frameContinuation:
			return nil, fmt.Errorf("fingerprint: %s with no header block open", frame)
		case frame.Type == frameHeaders:
			fragment, err := headerFragment(frame, payload)
			if err != nil {
				return nil, err
			}
			out.Block = append(out.Block, fragment...)
		case frame.Type == frameContinuation:
			out.Block = append(out.Block, payload...)
		default:
			continue
		}
		if frame.Flags&flagEndHeaders != 0 {
			out.Raw = raw[:at]
			return out, nil
		}
		open = frame.Stream
	}
	return nil, ErrNoRequest
}

// headerFragment is the header block fragment of a HEADERS frame: its payload
// without the padding and the priority it may carry.
func headerFragment(frame Frame, payload []byte) ([]byte, error) {
	padding := 0
	if frame.Flags&flagPadded != 0 {
		if len(payload) == 0 {
			return nil, fmt.Errorf("fingerprint: %s without its pad length", frame)
		}
		padding = int(payload[0])
		payload = payload[1:]
	}
	if frame.Flags&flagPriority != 0 {
		if len(payload) < 5 {
			return nil, fmt.Errorf("fingerprint: %s without its priority", frame)
		}
		payload = payload[5:]
	}
	if padding > len(payload) {
		return nil, fmt.Errorf("fingerprint: %s padded past its end", frame)
	}
	return payload[:len(payload)-padding], nil
}

// Representation is how one field of a header block was written: whole, from
// a table, or as a literal with or without indexing or never to be indexed,
// its name from a table or written out; each string written out Huffman-coded
// or not. A table size update is one too, of no field.
type Representation struct {
	// Field is the field's name, decoded; empty for a size update.
	Field string
	// Kind is "indexed", "with indexing", "without indexing", "never indexed"
	// or "size update".
	Kind string
	// Index is the table index of the field, or of its name, 0 for a name
	// written out, or the size a size update sets.
	Index uint64
	// NameHuffman and ValueHuffman say which strings were Huffman-coded.
	NameHuffman, ValueHuffman bool
}

// staticEntries is how many fields the static table holds (RFC 7541, appendix
// A): an index past it is the dynamic table's.
const staticEntries = 61

// String is a representation as a person reads it, without its field's name.
func (r Representation) String() string {
	return r.describe(true)
}

func (r Representation) describe(withValue bool) string {
	switch r.Kind {
	case "size update":
		return fmt.Sprintf("size update %d", r.Index)
	case "indexed":
		return "indexed " + tableIndex(r.Index)
	}
	name := "new name"
	if r.Index != 0 {
		name = "name " + tableIndex(r.Index)
	} else if r.NameHuffman {
		name += " huffman"
	}
	out := r.Kind + ", " + name
	if withValue {
		out += ", value " + map[bool]string{true: "huffman", false: "plain"}[r.ValueHuffman]
	}
	return out
}

func tableIndex(i uint64) string {
	if i <= staticEntries {
		return fmt.Sprintf("static %d", i)
	}
	return fmt.Sprintf("dynamic %d", i)
}

// Representations reads a header block, written for a table of tableSize
// bytes, field by field: first how each was written, then, decoding the
// block, which field each is.
func Representations(block []byte, tableSize uint32) ([]Representation, error) {
	var out []Representation
	for p := block; len(p) > 0; {
		var r Representation
		var err error
		switch b := p[0]; {
		case b&0x80 != 0:
			r.Kind = "indexed"
			r.Index, p, err = varint(7, p)
		case b&0xc0 == 0x40:
			r.Kind = "with indexing"
			p, err = r.literal(6, p)
		case b&0xe0 == 0x20:
			r.Kind = "size update"
			r.Index, p, err = varint(5, p)
		case b&0xf0 == 0x10:
			r.Kind = "never indexed"
			p, err = r.literal(4, p)
		default:
			r.Kind = "without indexing"
			p, err = r.literal(4, p)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	// The decoder finds what the walk above cannot: a string that is not
	// Huffman code, an index no table has. It reads the representations the
	// walk did, by the same bits, and gives a field for each but a size
	// update.
	fields, err := hpack.NewDecoder(tableSize, nil).DecodeFull(block)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: header block: %w", err)
	}
	next := 0
	for i := range out {
		if out[i].Kind != "size update" && next < len(fields) {
			out[i].Field = fields[next].Name
			next++
		}
	}
	return out, nil
}

// literal reads a literal representation whose index has an n-bit prefix:
// the name's index, or the name written out, then the value.
func (r *Representation) literal(n byte, p []byte) ([]byte, error) {
	var err error
	if r.Index, p, err = varint(n, p); err != nil {
		return nil, err
	}
	if r.Index == 0 {
		if r.NameHuffman, p, err = hpackString(p); err != nil {
			return nil, err
		}
	}
	r.ValueHuffman, p, err = hpackString(p)
	return p, err
}

// varint reads an integer with an n-bit prefix (RFC 7541, section 5.1).
func varint(n byte, p []byte) (uint64, []byte, error) {
	limit := uint64(1)<<n - 1
	i := uint64(p[0]) & limit
	p = p[1:]
	if i < limit {
		return i, p, nil
	}
	for shift := uint(0); len(p) > 0 && shift < 63; shift += 7 {
		b := p[0]
		p = p[1:]
		i += uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return i, p, nil
		}
	}
	return 0, nil, errors.New("fingerprint: an HPACK integer cut short")
}

// hpackString reads a string: whether it is Huffman-coded, and past it.
func hpackString(p []byte) (bool, []byte, error) {
	if len(p) == 0 {
		return false, nil, errors.New("fingerprint: an HPACK string cut short")
	}
	huffman := p[0]&0x80 != 0
	length, p, err := varint(7, p)
	if err != nil || uint64(len(p)) < length {
		return false, nil, errors.New("fingerprint: an HPACK string cut short")
	}
	return huffman, p[length:], nil
}
