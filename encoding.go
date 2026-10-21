package tlsforge

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/klauspost/compress/zstd"
)

// Content codings: a body as it came over the wire, and as it is read.
//
// The transport would decode a body itself, and did it in ways no browser
// does. A deflate body that was what RFC 9110 says deflate is, zlib, was
// copied into memory by the goroutine that reads the connection before the
// response was handed over, while that same goroutine was the one that had to
// deliver the bytes: the request hung until its deadline. A raw deflate body
// lost its first two bytes. And over HTTP/2 a body was decoded with its
// Content-Encoding and Content-Length left on, so a response said gzip of a
// body that was not, and a proxy that passed both on broke the page for
// whoever was behind it.
//
// So the transport is told to leave bodies alone, which also keeps it from
// adding an Accept-Encoding of its own, and a body is decoded here, as Chrome
// decodes it: from every coding Chrome accepts, in the reverse of the order
// they were applied, or not at all when one of them is a coding Chrome does
// not know either. What is kept is counted on what comes out, so a small body
// that decodes to an enormous one stops at the limit.

// decoders are the codings Chrome accepts, each a reader of the decoded bytes
// over the encoded ones.
var decoders = map[string]func(io.Reader) (io.ReadCloser, error){
	"gzip":    gzipDecoder,
	"x-gzip":  gzipDecoder,
	"deflate": deflateDecoder,
	"br":      brotliDecoder,
	"zstd":    zstdDecoder,
}

// maxZstdWindow is the largest window a zstd body may ask for, as Chrome has
// it and as RFC 9659 lets a decoder of HTTP content refuse beyond: a body that
// wants more memory than that to decode is refused rather than given it.
const maxZstdWindow = 8 << 20

// transportCodings are the codings the transport decodes when a caller's own
// transport options let it, spelled as it matches them: one Content-Encoding
// value, exactly.
var transportCodings = map[string]bool{"gzip": true, "br": true, "deflate": true, "zstd": true}

func gzipDecoder(r io.Reader) (io.ReadCloser, error) {
	g := &chromeGzip{source: bufio.NewReader(r)}
	if err := g.next(); err != nil {
		return nil, err
	}
	return g, nil
}

// Chrome's HTTP gzip decoder checks the compressed stream but does not require
// or validate its CRC/ISIZE trailer. A truncated DEFLATE stream still fails.
// Keep an actual DEFLATE end-of-stream boundary, so an unexpected EOF in the
// payload cannot be mistaken for a missing trailer.
type chromeGzip struct {
	source *bufio.Reader
	member io.ReadCloser
	done   bool
}

func (g *chromeGzip) next() error {
	// gzip.NewReader validates the complete optional header without reading
	// DEFLATE data when its input already implements io.ByteReader.
	header, err := gzip.NewReader(g.source)
	if err != nil {
		return err
	}
	_ = header.Close()
	g.member = flate.NewReader(g.source)
	return nil
}

func (g *chromeGzip) Read(p []byte) (int, error) {
	for !g.done {
		n, err := g.member.Read(p)
		if err != io.EOF {
			return n, err
		}
		_ = g.member.Close()
		var trailer [8]byte
		_, err = io.ReadFull(g.source, trailer[:])
		if err != nil {
			g.done = true
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return n, io.EOF
			}
			return n, err
		}
		magic, err := g.source.Peek(2)
		if len(magic) < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
			g.done = true
			if err != nil && !errors.Is(err, io.EOF) {
				return n, err
			}
			return n, io.EOF
		}
		if err := g.next(); err != nil {
			return n, err
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, io.EOF
}

func (g *chromeGzip) Close() error { return g.member.Close() }

func brotliDecoder(r io.Reader) (io.ReadCloser, error) {
	return io.NopCloser(brotli.NewReader(r)), nil
}

// zstdOptions are how a zstd body is decoded: on the goroutine that reads it,
// and refused when it asks for a window larger than maxZstdWindow. A variable
// so that a test can hand the decoder an option it refuses.
var zstdOptions = []zstd.DOption{zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(maxZstdWindow)}

func zstdDecoder(r io.Reader) (io.ReadCloser, error) {
	decoder, err := zstd.NewReader(r, zstdOptions...)
	if err != nil {
		return nil, err
	}
	return decoder.IOReadCloser(), nil
}

// deflateDecoder reads deflate as Chrome does: zlib, which is what the name
// means, when the body begins with a zlib header, and the raw deflate many
// servers send under the same name when it does not.
func deflateDecoder(r io.Reader) (io.ReadCloser, error) {
	buffered := bufio.NewReader(r)
	if head, _ := buffered.Peek(2); len(head) == 2 && zlibHeader(head[0], head[1]) {
		return zlib.NewReader(buffered)
	}
	return flate.NewReader(buffered), nil
}

// zlibHeader says two bytes are a zlib header (RFC 1950): deflate as the
// method, a window of at most 32 KiB, and a check that makes the pair a
// multiple of 31. Raw deflate begins with a block header instead, which passes
// all three by chance once in a few hundred bodies at most.
func zlibHeader(cmf, flg byte) bool {
	return cmf&0x0f == 8 && cmf>>4 <= 7 && (uint16(cmf)<<8|uint16(flg))%31 == 0
}

// codingsOf is the content codings a body was encoded with, in the order they
// were applied: every Content-Encoding field, split at its commas, in lower
// case, without identity, which encodes nothing.
func codingsOf(header fhttp.Header) []string {
	var out []string
	for _, field := range fieldValues(header, "content-encoding") {
		for _, coding := range strings.Split(field, ",") {
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding != "" && coding != "identity" {
				out = append(out, coding)
			}
		}
	}
	return out
}

// fieldValues is every value of a header field, whatever the case its name
// came in: the transport keeps HTTP/1.1 names canonical and HTTP/2 names as
// they arrived.
func fieldValues(header fhttp.Header, lower string) []string {
	var out []string
	for name, values := range header {
		if strings.EqualFold(name, lower) {
			out = append(out, values...)
		}
	}
	return out
}

// hasBody says a response to a request can carry a body at all. One that
// cannot keeps its Content-Encoding as a description of the representation it
// names, which is what HTTP says such a field is.
func hasBody(method string, status int) bool {
	return method != fhttp.MethodHead && status != fhttp.StatusNoContent && status != fhttp.StatusNotModified
}

// readBody is a response's body as the caller gets it, with the codings it was
// decoded from, joined as a header joins them, or none when it is the bytes as
// they came.
//
// It comes as it came, its Content-Encoding still true of it, when it has no
// coding, when it is one of a 206's ranges (a piece of an encoded body does not
// decode on its own), when it is empty, and when any of its codings is one
// Chrome does not know either: Chrome passes such a body through undecoded
// rather than decode part of it.
func readBody(res *fhttp.Response, method string, limit int64) ([]byte, string, error) {
	body := bufio.NewReaderSize(chromeReads{res.Body}, chromeReadSize)
	codings := codingsOf(res.Header)
	if _, err := body.Peek(1); len(codings) == 0 || !hasBody(method, res.StatusCode) ||
		res.StatusCode == fhttp.StatusPartialContent || err != nil || !knownCodings(codings) {
		read, err := readAtMost(body, limit)
		if err != nil {
			return nil, "", readingError(err)
		}
		return read, "", nil
	}
	if res.Uncompressed && len(codings) == 1 && transportCodings[fieldValues(res.Header, "content-encoding")[0]] {
		// A caller's own transport options let the transport decode it, which it
		// does for one coding exactly as spelled; it says so by Uncompressed and
		// leaves the field on.
		read, err := readAtMost(body, limit)
		if err != nil {
			return nil, "", readingError(err)
		}
		return read, codings[0], nil
	}

	var reader io.Reader = body
	for i := len(codings) - 1; i >= 0; i-- {
		decoder, err := decoders[codings[i]](reader)
		if err != nil {
			return nil, "", decodingError(codings, err)
		}
		defer func() { _ = decoder.Close() }()
		reader = decoder
	}
	read, err := readAtMost(reader, limit)
	switch {
	case errors.Is(err, ErrResponseTooLarge):
		return nil, "", err
	case err != nil:
		return nil, "", decodingError(codings, err)
	}
	return read, strings.Join(codings, ", "), nil
}

// knownCodings says every coding is one Chrome accepts.
func knownCodings(codings []string) bool {
	for _, coding := range codings {
		if decoders[coding] == nil {
			return false
		}
	}
	return true
}

// readAtMost reads a body whole, unless it is longer than limit, which it says
// with ErrResponseTooLarge once limit and one more byte have come.
// chromeReadSize is the most a read takes of a body at a time, as Chrome's
// network service takes a response's body from its HTTP/2 stream in pieces of
// at most 8 KiB: what is freed of a window past half of it, which the
// transport tells the server of as Chrome does, is at most that much more, as
// Chrome's WINDOW_UPDATEs were measured (testdata/chrome155-flow.json).
const chromeReadSize = 8 << 10

// chromeReads is a body read chromeReadSize at a time at most.
type chromeReads struct{ io.Reader }

func (r chromeReads) Read(p []byte) (int, error) {
	if len(p) > chromeReadSize {
		p = p[:chromeReadSize]
	}
	return r.Reader.Read(p)
}

func readAtMost(r io.Reader, limit int64) ([]byte, error) {
	read, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(read)) > limit {
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, limit)
	}
	return read, nil
}

// readingError is a body that could not be read as it came.
func readingError(err error) error {
	if errors.Is(err, ErrResponseTooLarge) {
		return err
	}
	return fmt.Errorf("tlsforge: reading body: %w", err)
}

// decodingError is a body that could not be decoded: corrupt, cut short, or
// wanting more of a decoder than it is given.
func decodingError(codings []string, err error) error {
	return fmt.Errorf("tlsforge: decoding a %s body: %w", strings.Join(codings, ", "), err)
}
