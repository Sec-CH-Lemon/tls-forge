// Package atomicfile replaces files without exposing partially written data.
package atomicfile

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	statFile   = os.Stat
	openFile   = os.OpenFile
	createTemp = os.CreateTemp
	chmodFile  = (*os.File).Chmod
	writeFile  = (*os.File).Write
	syncFile   = (*os.File).Sync
	closeFile  = (*os.File).Close
	renameFile = os.Rename
	removeFile = os.Remove
)

// bufferSize is how much is gathered before it is written. A report is
// rendered in thousands of small pieces, and a write each is a system call
// each.
const bufferSize = 64 << 10

// Write atomically replaces path with data and applies mode to the replacement.
func Write(path string, data []byte, mode os.FileMode) error {
	return Stream(path, mode, func(w io.Writer) error {
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("write temporary file for %s: %w", path, err)
		}
		return nil
	})
}

// Stream atomically replaces path with what write writes, and applies mode to
// the replacement.
//
// It is written to a file beside path and moved over it only once write has
// returned and the file is synced and closed: until then, and whenever any of
// it fails, path holds what it held, and the file beside it is removed. What
// write returns is returned as it is; anything else is said with the step that
// failed. A symbolic link at path is replaced by the file, and what it pointed
// to is left as it was.
//
// What is at path and is not a file, a device or a pipe such as /dev/null,
// is opened and written to as it is instead. There is no file there to
// replace, and replacing it would take it away from everything else that
// uses it. A directory cannot be opened to write to, and says so.
func Stream(path string, mode os.FileMode, write func(io.Writer) error) error {
	if info, err := statFile(path); err == nil && !info.Mode().IsRegular() {
		return into(path, write)
	}

	tmp, err := createTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = removeFile(tmpName) }()

	if err := chmodFile(tmp, mode); err != nil {
		_ = closeFile(tmp)
		return fmt.Errorf("set permissions on temporary file for %s: %w", path, err)
	}
	buffered := bufio.NewWriterSize(fileWriter{tmp}, bufferSize)
	if err := write(buffered); err != nil {
		_ = closeFile(tmp)
		return err
	}
	if err := buffered.Flush(); err != nil {
		_ = closeFile(tmp)
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := syncFile(tmp); err != nil {
		_ = closeFile(tmp)
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := closeFile(tmp); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	if err := renameFile(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// into writes to what is at path as it is, through the same buffer.
func into(path string, write func(io.Writer) error) error {
	file, err := openFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	buffered := bufio.NewWriterSize(fileWriter{file}, bufferSize)
	if err := write(buffered); err != nil {
		_ = closeFile(file)
		return err
	}
	if err := buffered.Flush(); err != nil {
		_ = closeFile(file)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := closeFile(file); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// fileWriter writes to a file through writeFile, which a test can make fail.
//
// Less written than given is an error even when nothing says so. The buffer in
// front of it would otherwise ask again for as long as it was answered that
// way, which is forever.
type fileWriter struct{ file *os.File }

func (w fileWriter) Write(p []byte) (int, error) {
	n, err := writeFile(w.file, p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
