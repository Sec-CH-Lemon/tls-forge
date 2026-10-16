package atomicfile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// keepSeams puts every stand-in back as it was when the test ends.
func keepSeams(t *testing.T) {
	t.Helper()
	stat, open, create, chmod := statFile, openFile, createTemp, chmodFile
	write, sync, closing, rename, remove := writeFile, syncFile, closeFile, renameFile, removeFile
	t.Cleanup(func() {
		statFile, openFile, createTemp, chmodFile = stat, open, create, chmod
		writeFile, syncFile, closeFile, renameFile, removeFile = write, sync, closing, rename, remove
	})
}

// oldFile is a file holding "old", in a directory of its own.
func oldFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// leftAsItWas fails the test unless path still holds "old" and is alone in its
// directory: nothing written beside it was left behind.
func leftAsItWas(t *testing.T, path string) {
	t.Helper()
	if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
		t.Errorf("the file holds %q (%v), want what it held", data, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("left beside the file: %v", names)
	}
}

func TestWriteReplacesFileAndPermissions(t *testing.T) {
	path := oldFile(t)
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("contents = %q, want new", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if runtime.GOOS == "windows" {
		// Windows has no Unix permission bits. Go's Chmod implementation uses
		// only 0200 to clear or set the Windows read-only attribute; Stat then
		// commonly reports a writable regular file as 0666.
		if mode&0o200 == 0 {
			t.Fatalf("mode = %o, want a writable file", mode)
		}
	} else if mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
	}
}

func TestWriteErrors(t *testing.T) {
	keepSeams(t)
	originalClose := closeFile
	small, large := []byte("data"), bytes.Repeat([]byte("x"), 3*bufferSize)

	for _, test := range []struct {
		name string
		data []byte
		fail func()
		says string
	}{
		{"create", small, func() {
			createTemp = func(string, string) (*os.File, error) { return nil, errors.New("no room") }
		}, "create temporary file for"},
		{"chmod", small, func() {
			chmodFile = func(*os.File, os.FileMode) error { return errors.New("not allowed") }
		}, "set permissions on temporary file for"},
		// Gathered first and written when the buffer is flushed.
		{"write", small, func() {
			writeFile = func(*os.File, []byte) (int, error) { return 0, errors.New("disk full") }
		}, "write temporary file for"},
		// Too much to gather, and written at once.
		{"write of more than the buffer", large, func() {
			writeFile = func(*os.File, []byte) (int, error) { return 0, errors.New("disk full") }
		}, "write temporary file for"},
		// Less written and nothing said, which the buffer would otherwise ask
		// again for, forever.
		{"short write", small, func() {
			writeFile = func(*os.File, []byte) (int, error) { return 0, nil }
		}, io.ErrShortWrite.Error()},
		{"short write of more than the buffer", large, func() {
			writeFile = func(_ *os.File, p []byte) (int, error) { return len(p) / 2, nil }
		}, io.ErrShortWrite.Error()},
		{"sync", small, func() {
			syncFile = func(*os.File) error { return errors.New("io error") }
		}, "sync temporary file for"},
		{"close", small, func() {
			closeFile = func(file *os.File) error {
				_ = originalClose(file)
				return errors.New("io error")
			}
		}, "close temporary file for"},
		{"rename", small, func() {
			renameFile = func(string, string) error { return errors.New("cross-device link") }
		}, "replace "},
	} {
		t.Run(test.name, func(t *testing.T) {
			keepSeams(t)
			test.fail()
			path := oldFile(t)
			err := Write(path, test.data, 0o600)
			if err == nil || !strings.Contains(err.Error(), test.says) || !strings.Contains(err.Error(), path) {
				t.Fatalf("Write() error = %v, want one that says %q of %s", err, test.says, path)
			}
			leftAsItWas(t, path)
		})
	}
}

func TestStreamKeepsTheFileWhenWritingFails(t *testing.T) {
	// A report that fails half way through leaves the last one as it was, and
	// its own error says what failed: nothing is put in front of it.
	path := oldFile(t)
	failed := errors.New("fetch: writing the report: template broke")
	err := Stream(path, 0o600, func(w io.Writer) error {
		_, _ = io.WriteString(w, "half a report")
		return failed
	})
	if err != failed {
		t.Fatalf("Stream() error = %v, want the writer's own", err)
	}
	leftAsItWas(t, path)
}

func TestStreamWritesThroughABuffer(t *testing.T) {
	// Thousands of small writes, as a report is rendered, reach the file as a
	// few large ones.
	keepSeams(t)
	writes := 0
	original := writeFile
	writeFile = func(file *os.File, p []byte) (int, error) {
		writes++
		return original(file, p)
	}
	path := filepath.Join(t.TempDir(), "report.html")
	var want strings.Builder
	err := Stream(path, 0o600, func(w io.Writer) error {
		for i := range 20_000 {
			piece := strings.Repeat("<td>", 1+i%7)
			want.WriteString(piece)
			if _, err := io.WriteString(w, piece); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != want.String() {
		t.Errorf("the file holds %d bytes, want the %d written", len(data), want.Len())
	}
	if most := want.Len()/bufferSize + 1; writes > most {
		t.Errorf("%d writes reached the file, want at most %d", writes, most)
	}
}

func TestStreamReplacesALinkRatherThanWhatItPointsTo(t *testing.T) {
	// Following it would write wherever somebody had pointed it, in a
	// directory anybody can write to.
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	if err := Write(link, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if info, err := os.Lstat(link); err != nil || !info.Mode().IsRegular() {
		t.Errorf("the link was not replaced by a file: %v, %v", info, err)
	}
	if data, _ := os.ReadFile(link); string(data) != "new" {
		t.Errorf("the replacement holds %q", data)
	}
	if data, _ := os.ReadFile(target); string(data) != "old" {
		t.Errorf("what the link pointed to holds %q", data)
	}
}

func TestStreamWritesIntoADeviceAsItIs(t *testing.T) {
	// Replaced, the null device would be a file of cookies for every program
	// on the machine, which a run as root can do.
	if err := Write(os.DevNull, []byte("a session"), 0o600); err != nil {
		t.Fatalf("Write(%s): %v", os.DevNull, err)
	}
	info, err := os.Stat(os.DevNull)
	if err != nil || info.Mode().IsRegular() {
		t.Errorf("%s is not a device any more: %v, %v", os.DevNull, info, err)
	}
}

func TestStreamIsNoWayToReplaceADirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, []byte("a report"), 0o600); err == nil {
		t.Fatal("Write() over a directory = nil")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("the directory is %v (%v)", info, err)
	}
}

func TestWriteOfNothingAtAllEnds(t *testing.T) {
	// More than the buffer, and nothing of it written with nothing said: the
	// buffer asks again for as long as it is answered so, which without the
	// check would be forever.
	keepSeams(t)
	writeFile = func(*os.File, []byte) (int, error) { return 0, nil }
	path := oldFile(t)
	done := make(chan error, 1)
	go func() { done <- Write(path, bytes.Repeat([]byte("x"), 3*bufferSize), 0o600) }()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("Write() = %v, want a short write", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Write() never returned")
	}
	leftAsItWas(t, path)
}

func TestStreamIntoADeviceErrors(t *testing.T) {
	keepSeams(t)
	originalClose := closeFile
	closed := 0
	refused := errors.New("refused")
	for _, test := range []struct {
		name  string
		fail  func()
		write func(io.Writer) error
		says  string
	}{
		{"open", func() {
			openFile = func(string, int, os.FileMode) (*os.File, error) { return nil, refused }
		}, nil, "refused"},
		{"the writer", func() {}, func(io.Writer) error { return refused }, "refused"},
		{"write", func() {
			writeFile = func(*os.File, []byte) (int, error) { return 0, errors.New("broken pipe") }
		}, nil, "write " + os.DevNull + ": broken pipe"},
		{"close", func() {
			closeFile = func(file *os.File) error {
				_ = originalClose(file)
				return errors.New("io error")
			}
		}, nil, "close " + os.DevNull + ": io error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			keepSeams(t)
			test.fail()
			counted := closeFile
			closeFile = func(file *os.File) error {
				closed++
				return counted(file)
			}
			write := test.write
			if write == nil {
				write = func(w io.Writer) error {
					_, err := io.WriteString(w, "a report")
					return err
				}
			}
			before := closed
			err := Stream(os.DevNull, 0o600, write)
			if err == nil || !strings.Contains(err.Error(), test.says) {
				t.Fatalf("Stream() error = %v, want one that says %q", err, test.says)
			}
			// Whatever failed once it was open, it was closed.
			if test.name != "open" && closed != before+1 {
				t.Errorf("the device was closed %d times, want once", closed-before)
			}
		})
	}
}
