package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// A run's files, settled before it touches any of them.
//
// fetch reads as many as four files and writes as many as five, and any two
// of its flags can name one file: a trace over the list it was given, a report
// over the session it started from, the log over the trace. Each was a file
// lost, found out only once the run had read the one and opened the other. So
// every file a run reads or writes is put in one plan first, which is checked
// before the list is read, a directory emptied or a file opened, and refuses,
// as a usage error and with nothing touched:
//
//   - two flags naming one file when the run writes it for either: by one
//     name, through a symbolic link, by a hard link, or by a name that differs
//     only in case where names ignore it. Two that only read it may, and so may
//     --cookies and --save-cookies, which start a session from a file and save
//     it back there;
//   - a file the run writes that its standard output or error is redirected to;
//   - a file that is the --output directory, or that the directory or another
//     file would have to be made in;
//   - a file the run writes that is a directory, or is named as one, or whose
//     directory cannot be made because a file is where it would go.
//
// A file in the directory --clear-output-dir is about to empty is taken as not
// there, since it will not be. Whether a file the run reads may be in it at
// all is for the clearing to say.

// The flags of the two files that may be one: a session started from a file
// and saved back to it.
const (
	flagCookies     = "--cookies"
	flagSaveCookies = "--save-cookies"
)

// fileUse is what a run does with a file.
type fileUse int

const (
	// readsFile leaves it as it was.
	readsFile fileUse = iota
	// writesFile replaces it, or adds to it: a file of sessions is read
	// first, and written again with what it held.
	writesFile
)

// plannedFile is one file of a run's.
type plannedFile struct {
	// flag is what names it: the flag given its path, or for a stream, the
	// stream.
	flag string
	// path is as it was given. A stream has none.
	path string
	use  fileUse
	// stream says it is known by being where standard output or error goes,
	// rather than by a name.
	stream bool
	// at is the path made absolute, with every link in it followed as far as
	// it is there, and info what is there, when anything is.
	at   string
	info fs.FileInfo
}

// named is a file as a message refers to it, by what names it.
func (f plannedFile) named() string {
	if f.stream {
		return "the file " + f.flag + " is written to"
	}
	return "the file " + f.flag + " names"
}

// filePlan is every file a run reads or writes, and the directory it keeps its
// requests in.
type filePlan struct {
	cwd   string
	files []plannedFile
	// output is the --output directory as it was given and as it is located,
	// and cleared says --clear-output-dir empties it before anything is
	// written.
	output, outputAt string
	cleared          bool
}

// newFilePlan is a plan of no files, keeping requests nowhere. Without a
// working directory, a relative path is told from another as it is spelt.
func newFilePlan() *filePlan {
	cwd, _ := workingDir()
	return &filePlan{cwd: cwd}
}

// keepIn names the directory the run's requests are kept in, and says whether
// it is emptied first.
func (p *filePlan) keepIn(dir string, cleared bool) {
	if dir != "" {
		p.output, p.outputAt, p.cleared = dir, located(dir, p.cwd), cleared
	}
}

// add puts the file a flag names in the plan. A flag given nothing names none.
func (p *filePlan) add(flag, path string, use fileUse) {
	if path == "" {
		return
	}
	f := plannedFile{flag: flag, path: path, use: use, at: located(path, p.cwd)}
	if info, err := os.Stat(f.at); err == nil {
		f.info = info
	}
	p.files = append(p.files, f)
}

// stream puts the file a stream is redirected to in the plan, when it is one.
func (p *filePlan) stream(name string, w io.Writer) {
	for _, info := range streamFiles(w) {
		p.files = append(p.files, plannedFile{flag: name, use: writesFile, stream: true, info: info})
	}
}

// check is why the run cannot go ahead with its files, or nil when it can.
// Streams are put in the plan last, so that a message about one names it
// after the flag it is about.
func (p *filePlan) check() error {
	if err := p.checkOutput(); err != nil {
		return err
	}
	for i, b := range p.files {
		for _, a := range p.files[:i] {
			if err := p.clash(a, b); err != nil {
				return err
			}
		}
		if err := p.checkPlace(b); err != nil {
			return err
		}
	}
	return nil
}

// checkOutput is why the --output directory cannot be one, or nil.
func (p *filePlan) checkOutput() error {
	if p.output == "" {
		return nil
	}
	if info, err := os.Stat(p.outputAt); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%w: --output %s is not a directory", errUsage, p.output)
		}
		return nil
	}
	if blocker := p.blocked(p.outputAt); blocker != "" {
		return fmt.Errorf("%w: --output %s cannot be made: %s is not a directory",
			errUsage, p.output, spelt(blocker, p.outputAt, p.output))
	}
	return nil
}

// clash is why two files of a run cannot both be what they are, or nil.
func (p *filePlan) clash(a, b plannedFile) error {
	switch {
	case a.use == readsFile && b.use == readsFile:
		// Read twice is read.
		return nil
	case a.stream && b.stream:
		// Both to one file is the shell's doing, and the run shares it.
		return nil
	case (a.stream && b.use == readsFile) || (b.stream && a.use == readsFile):
		// The run has read the file before it writes a line, and the shell
		// had already opened it.
		return nil
	case resumes(a, b) || resumes(b, a):
		// A session started from a file and saved back to it.
		return nil
	}
	if p.same(a, b) {
		subject, object := b, a
		if b.stream {
			subject, object = a, b
		}
		return fmt.Errorf("%w: %s %s is %s", errUsage, subject.flag, subject.path, object.named())
	}
	if a.stream || b.stream {
		return nil
	}
	// One the run makes as a file, and the other would have it be a directory.
	for _, pair := range [2][2]plannedFile{{a, b}, {b, a}} {
		outer, inner := pair[0], pair[1]
		if outer.use != readsFile && strictlyWithin(inner.at, outer.at) {
			return fmt.Errorf("%w: %s %s would be in %s, %s", errUsage, inner.flag, inner.path, outer.path, outer.named())
		}
	}
	return nil
}

// resumes says from is the session a run starts from and to the one it saves.
func resumes(from, to plannedFile) bool {
	return from.flag == flagCookies && to.flag == flagSaveCookies
}

// checkPlace is why a file the run writes cannot be written where it is, or
// nil when it can.
func (p *filePlan) checkPlace(f plannedFile) error {
	if f.stream || f.use == readsFile {
		return nil
	}
	if p.output != "" {
		if samePath(f.at, p.outputAt) {
			return fmt.Errorf("%w: %s %s is the --output directory", errUsage, f.flag, f.path)
		}
		if strictlyWithin(p.outputAt, f.at) {
			return fmt.Errorf("%w: --output %s would be in %s, %s", errUsage, p.output, f.path, f.named())
		}
	}
	if strings.HasSuffix(f.path, "/") || strings.HasSuffix(f.path, string(os.PathSeparator)) {
		return fmt.Errorf("%w: %s %s names a directory, and is written as a file", errUsage, f.flag, f.path)
	}
	if info := p.there(f); info != nil && info.IsDir() {
		return fmt.Errorf("%w: %s %s is a directory", errUsage, f.flag, f.path)
	}
	if blocker := p.blocked(f.at); blocker != "" {
		return fmt.Errorf("%w: %s %s cannot be written: %s is not a directory",
			errUsage, f.flag, f.path, spelt(blocker, f.at, f.path))
	}
	return nil
}

// same says two files are one: by what is there when both are, and by where
// they are when either is not.
func (p *filePlan) same(a, b plannedFile) bool {
	if ai, bi := p.there(a), p.there(b); ai != nil && bi != nil {
		return os.SameFile(ai, bi)
	}
	return !a.stream && !b.stream && samePath(a.at, b.at)
}

// there is what is at a file's path, or nil when nothing is or nothing will
// be: a file in the directory about to be emptied.
func (p *filePlan) there(f plannedFile) fs.FileInfo {
	if !f.stream && p.emptied(f.at) {
		return nil
	}
	return f.info
}

// emptied says path is in the directory --clear-output-dir empties.
func (p *filePlan) emptied(path string) bool {
	return p.cleared && strictlyWithin(path, p.outputAt)
}

// blocked is the file in the way of the directory path goes in, or nothing
// when there is none: the nearest of its directories that is there is one. In
// the directory being emptied, only that directory counts.
func (p *filePlan) blocked(path string) string {
	for dir := filepath.Dir(path); filepath.Dir(dir) != dir; dir = filepath.Dir(dir) {
		if info, err := os.Stat(dir); err == nil && !p.emptied(dir) {
			if !info.IsDir() {
				return dir
			}
			return ""
		}
	}
	return ""
}

// spelt is dir, a directory of the located path at, as the path was given:
// what a person typed reads better than where the links in it led. What is
// below dir is not there yet, so it is spelt alike in both and comes off the
// path as given; dir as it is located when it does not.
func spelt(dir, at, given string) string {
	rel, err := filepath.Rel(dir, at)
	tail := string(filepath.Separator) + rel
	if shown := filepath.Clean(given); err == nil && strings.HasSuffix(shown, tail) && shown != tail {
		return strings.TrimSuffix(shown, tail)
	}
	return dir
}

// located is path made absolute against cwd, with every symbolic link in it
// followed as far as it is there: a file not made yet is where the links to
// its directory lead.
func located(path, cwd string) string {
	dir, rest := absolute(path, cwd), ""
	for filepath.Dir(dir) != dir {
		if _, err := os.Lstat(dir); err == nil {
			break
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = filepath.Dir(dir)
	}
	return filepath.Join(resolve(dir), rest)
}

// foldsCase says this system's file names are told apart without regard to
// case, as they are by default on macOS and Windows. A variable, so that a
// test can try both.
var foldsCase = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// samePath says two located paths name one file.
func samePath(a, b string) bool {
	return a == b || (foldsCase && strings.EqualFold(a, b))
}

// strictlyWithin says path is in dir, and is not dir itself, by any name.
func strictlyWithin(path, dir string) bool {
	return !samePath(path, dir) && !sameThere(path, dir) && within(path, dir)
}

// sameThere says two paths lead to one file that is there.
func sameThere(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}
