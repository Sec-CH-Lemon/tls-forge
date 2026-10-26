package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// What --clear-output-dir does before a run writes into the directory --output
// names: it empties it, of everything in it, hidden files and directories
// included, and leaves the directory itself, with its permissions, where it
// was.
//
// It deletes, so before anything is deleted it makes sure the directory is one
// whose emptying is a clean slate rather than a disaster: not the root of the
// file system, not the home directory or one that holds it, not the directory
// the command runs in or one that holds that — `-o .` is one keystroke from
// `-o out` — and not one holding a git repository, a file the run is about to
// read, or the file its output is being redirected to. Each is refused with
// the reason, and nothing is removed. A directory is known by what it is, not
// by how it is named: through a link, in other capitals where names ignore
// case (`-o /Users/ME` is /Users/me on a Mac), or by another name the system
// gives it (macOS's /System/Volumes/Data/Users/me).

// workingDir and homeDir are os.Getwd and os.UserHomeDir, named so a test can
// stand in for either.
var (
	workingDir = os.Getwd
	homeDir    = os.UserHomeDir
)

// clearOutput empties dir, and says how many entries it took out of it. A
// directory that is not there yet has nothing in it. reads are the files the
// run reads, by the flag that names them, and streams the files its standard
// output and error are written to, of those that are files.
func clearOutput(dir string, reads map[string]string, streams []fs.FileInfo) (int, error) {
	cwd, err := workingDir()
	if err != nil {
		return 0, fmt.Errorf("fetch: --clear-output-dir: %w", err)
	}
	real, err := filepath.EvalSymlinks(absolute(dir, cwd))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	var info fs.FileInfo
	if err == nil {
		info, err = os.Stat(real)
	}
	if err != nil {
		return 0, fmt.Errorf("fetch: --clear-output-dir: %w", err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("fetch: --clear-output-dir: %s is not a directory", dir)
	}
	if why := refusal(real, resolve(cwd), home(), reads); why != "" {
		return 0, fmt.Errorf("%w: --clear-output-dir: %s %s; nothing was removed", errUsage, dir, why)
	}
	if why := heldBack(real, streams); why != "" {
		return 0, fmt.Errorf("%w: --clear-output-dir: %s %s; nothing was removed", errUsage, dir, why)
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		return 0, fmt.Errorf("fetch: --clear-output-dir: %w", err)
	}
	cleared := 0
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(real, entry.Name())); err != nil {
			return cleared, fmt.Errorf("fetch: --clear-output-dir: %w", err)
		}
		cleared++
	}
	return cleared, nil
}

// refusal is why a directory, every path resolved, is not to be emptied by
// where it is, or nothing when it may be. A file the run reads is named by a
// path that may be relative to cwd.
func refusal(dir, cwd, home string, reads map[string]string) string {
	switch {
	case filepath.Dir(dir) == dir:
		return "is the root of the file system"
	case home != "" && within(home, dir):
		return "is the home directory, or holds it"
	case within(cwd, dir):
		return "is the directory the command runs in, or holds it"
	}
	for _, flag := range slices.Sorted(maps.Keys(reads)) {
		if path := reads[flag]; path != "" && within(resolve(absolute(path, cwd)), dir) {
			return fmt.Sprintf("holds %s %s, which the run reads", flag, path)
		}
	}
	return ""
}

// heldBack is why what is in a directory keeps it from being emptied: a git
// repository, or the file the run's output is being written to, which would
// go on being written to with nobody able to read it. Nothing when nothing
// does. What cannot be read is passed over: removing it will say so.
func heldBack(dir string, streams []fs.FileInfo) string {
	why := ""
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return nil
		}
		if entry.Name() == ".git" {
			why = "holds a git repository, " + path
			return filepath.SkipAll
		}
		if info, err := entry.Info(); err == nil && entry.Type().IsRegular() {
			for _, stream := range streams {
				if os.SameFile(info, stream) {
					why = "holds " + path + ", which the run's output is written to"
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	return why
}

// streamFiles are the files writers write to, of those that are files: the
// run's standard output and error, when either is redirected to one.
func streamFiles(writers ...io.Writer) []fs.FileInfo {
	var files []fs.FileInfo
	for _, writer := range writers {
		file, ok := writer.(*os.File)
		if !ok {
			continue
		}
		if info, err := file.Stat(); err == nil && info.Mode().IsRegular() {
			files = append(files, info)
		}
	}
	return files
}

// absolute is path, made absolute against dir when it is not.
func absolute(path, dir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// resolve is path with every symbolic link in it followed, or path as it is
// when that cannot be done: one that is not there leads nowhere else.
func resolve(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return path
}

// home is the home directory, resolved, or nothing when there is none.
func home() string {
	dir, err := homeDir()
	if err != nil {
		return ""
	}
	return resolve(dir)
}

// within says path is dir, or something in it: by what is there when dir
// is, one of the directories path is in, up to the root, being dir, whatever
// names they go by; by their names alone when dir is not there.
func within(path, dir string) bool {
	info, err := os.Stat(dir)
	if err != nil {
		return namedWithin(path, dir)
	}
	for at := path; ; at = filepath.Dir(at) {
		if there, err := os.Stat(at); err == nil && os.SameFile(there, info) {
			return true
		}
		if filepath.Dir(at) == at {
			return false
		}
	}
}

// namedWithin says path is dir, or something in it, by their names, which
// differ only in case where names ignore it (foldsCase), and nowhere else:
// not by filepath.Rel, which on Windows ignores case whatever foldsCase says.
// Both are absolute.
func namedWithin(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	if foldsCase {
		path, dir = strings.ToLower(path), strings.ToLower(dir)
	}
	if !strings.HasSuffix(dir, string(filepath.Separator)) {
		dir += string(filepath.Separator)
	}
	return path+string(filepath.Separator) == dir || strings.HasPrefix(path, dir)
}
