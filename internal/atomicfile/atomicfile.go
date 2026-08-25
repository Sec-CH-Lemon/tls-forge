// Package atomicfile replaces files without exposing partially written data.
package atomicfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	createTemp = os.CreateTemp
	chmodFile  = (*os.File).Chmod
	writeFile  = (*os.File).Write
	syncFile   = (*os.File).Sync
	closeFile  = (*os.File).Close
	renameFile = os.Rename
	removeFile = os.Remove
)

// Write atomically replaces path with data and applies mode to the replacement.
func Write(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}

	tmpName := tmp.Name()
	defer func() { _ = removeFile(tmpName) }()

	if err := chmodFile(tmp, mode); err != nil {
		_ = closeFile(tmp)
		return fmt.Errorf("set permissions on temporary file for %s: %w", path, err)
	}
	if n, err := writeFile(tmp, data); err != nil {
		_ = closeFile(tmp)
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	} else if n != len(data) {
		_ = closeFile(tmp)
		return fmt.Errorf("write temporary file for %s: %w", path, io.ErrShortWrite)
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
