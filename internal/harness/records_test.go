package harness

import (
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// record is a TLS record of type typ whose plaintext is n bytes, as TLS 1.3
// writes one: a tag and the content type after it.
func record(typ byte, n int) []byte {
	length := n
	if typ == 23 {
		length += tls13Overhead
	}
	return append([]byte{typ, 3, 3, byte(length >> 8), byte(length)}, make([]byte, length)...)
}

func TestTheRecordsOfAConnectionAreKeptByWhatTheyCarried(t *testing.T) {
	r := &clientRecords{}
	// A ClientHello, a ChangeCipherSpec and the client's Finished carry
	// nothing it writes; then records of 30, 9 and 100 bytes, read in pieces.
	var raw []byte
	for _, rec := range [][]byte{record(22, 500), record(20, 1), record(23, 36), record(23, 30), record(23, 9), record(23, 100)} {
		raw = append(raw, rec...)
	}
	for i := 0; i < len(raw); i += 7 {
		r.read(raw[i:min(i+7, len(raw))])
	}
	if !slices.Equal(r.ends, []int{30, 39, 139}) {
		t.Fatalf("ends %v", r.ends)
	}
	for _, tc := range []struct {
		name  string
		spans []frameSpan
		want  []string
	}{
		{"a frame a record", []frameSpan{{'H', 21, 0, 30}, {'D', 91, 39, 139}}, []string{"H", "D91"}},
		{"two in one", []frameSpan{{'H', 10, 0, 19}, {'D', 2, 19, 30}}, []string{"H+D2"}},
		{"one across two", []frameSpan{{'H', 30, 0, 39}}, []string{"h", "h"}},
		{"a CONTINUATION after", []frameSpan{{'H', 21, 0, 30}, {'C', 0, 30, 39}}, []string{"H", "C"}},
		{"others' frames between", []frameSpan{{'D', 91, 39, 139}}, []string{"D91"}},
		{"none", nil, nil},
	} {
		if got := r.layout(tc.spans); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// A record cut short is kept once it is whole.
	r.read(record(23, 5)[:6])
	if len(r.ends) != 3 {
		t.Errorf("a part of a record kept: %v", r.ends)
	}
}

func TestARecordingConnectionKeepsWhatItReads(t *testing.T) {
	ours, theirs := net.Pipe()
	t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	r := &clientRecords{}
	c := &recordingConn{Conn: ours, records: r}
	go func() { _, _ = theirs.Write(append(record(23, 36), record(23, 4)...)) }()
	buf := make([]byte, 100)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	read := 0
	for read < len(record(23, 36))+len(record(23, 4)) {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		read += n
	}
	if !slices.Equal(r.ends, []int{4}) {
		t.Errorf("ends %v", r.ends)
	}
}

func TestARequestsFramesAreKeptWithTheRecordsThatCarriedThem(t *testing.T) {
	s := started(t, catalogue)
	p := parser(s)
	p.records = &clientRecords{}
	head := block(":method", "POST", ":scheme", "https", ":authority", "www.example.com", ":path", "/p/x")
	headers := frame(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 1, head)
	data := frame(http2.FrameData, http2.FlagDataEndStream, 1, []byte("abc"))
	stream := append([]byte(http2.ClientPreface), headers...)
	stream = append(stream, data...)
	// The preface and the HEADERS frame in a record, the DATA in another.
	p.records.read(record(23, 36))
	p.records.read(record(23, len(http2.ClientPreface)+len(headers)))
	p.records.read(record(23, len(data)))
	p.write(stream)
	entries := requests(t, s)
	if len(entries) != 1 || !slices.Equal(entries[0].Data, []int{3}) || !slices.Equal(entries[0].Records, []string{"H", "D3"}) {
		t.Fatalf("kept %+v", entries)
	}
	// Written says them in a scenario of records, and not otherwise.
	written, err := s.Written(entries, 0, true)
	if err != nil || !slices.Equal(written[0][0].Data, []int{3}) || !slices.Equal(written[0][0].Records, []string{"H", "D3"}) {
		t.Errorf("written %+v, %v", written, err)
	}
	if written, err := s.Written(entries, 0, false); err != nil || written[0][0].Data != nil || written[0][0].Records != nil {
		t.Errorf("written without records %+v, %v", written, err)
	}
	// A connection without records says none.
	s.Reset()
	q := parser(s)
	q.write(stream)
	if entries := requests(t, s); len(entries) != 1 || entries[0].Records != nil || !slices.Equal(entries[0].Data, []int{3}) {
		t.Errorf("kept %+v", entries)
	}
}
