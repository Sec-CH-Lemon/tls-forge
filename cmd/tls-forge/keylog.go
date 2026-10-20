package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// keyLogFile is where a run writes the TLS secrets of every connection it
// makes, the file --keylog names, in the NSS key log format: added to, as the
// browsers add to the file SSLKEYLOGFILE names, so that one file holds the
// secrets of every run a capture saw. What cannot be written is said once
// the run is over, as for the log: a run whose secrets were not kept is no
// run whose requests failed.
type keyLogFile struct {
	path string
	file io.WriteCloser
	out  *logWriter
}

// openKeyLogFile opens the file the secrets go to, added to, and 0600 when it
// makes it: anybody who has it reads a capture of the run. A variable so that
// a test can hand back a file that will not be written.
var openKeyLogFile = func(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

// openKeyLog opens the key log at path, its directory made, or none for no
// path.
func openKeyLog(path string) (*keyLogFile, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	file, err := openKeyLogFile(path)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	return &keyLogFile{path: path, file: file, out: &logWriter{w: file}}, nil
}

// writer is what the run's clients write their secrets to, or nil.
func (k *keyLogFile) writer() io.Writer {
	if k == nil {
		return nil
	}
	return k.out
}

// said is what the run says of its key log, or nothing.
func (k *keyLogFile) said() string {
	if k == nil {
		return ""
	}
	return k.path + " · the TLS secrets of every connection: anybody with it reads a capture of the run"
}

// close closes the key log, and says what kept the secrets from being
// written, if anything did.
func (k *keyLogFile) close() error {
	if k == nil {
		return nil
	}
	if err := errors.Join(k.out.failed(), k.file.Close()); err != nil {
		return fmt.Errorf("fetch: writing the key log %s: %w", k.path, err)
	}
	return nil
}
