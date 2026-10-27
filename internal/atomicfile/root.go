package atomicfile

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
)

// WriteRoot atomically replaces a regular file inside root. Root operations
// reject escaping links, including a concurrently replaced parent directory.
// Unlike Stream, a device or pipe is never an explicit destination here.
func WriteRoot(root *os.Root, path string, data []byte, mode os.FileMode) error {
	temp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"-"+rand.Text())
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temp) }()
	n, err := writeFile(file, data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = syncFile(file)
	}
	closed := closeFile(file)
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return root.Rename(temp, path)
}
