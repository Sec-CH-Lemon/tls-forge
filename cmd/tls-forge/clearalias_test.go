package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// caseFolds says names in dir are found without regard to their case, as on
// macOS and Windows by default: a file made there is found by its name in
// capitals.
func caseFolds(t *testing.T, dir string) bool {
	t.Helper()
	tree(t, dir, "case-probe")
	_, err := os.Stat(filepath.Join(dir, "CASE-PROBE"))
	if err := os.Remove(filepath.Join(dir, "case-probe")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	return err == nil
}

// otherName is dir by another name the system gives it, which no link in it
// leads to: macOS's /System/Volumes/Data, where the directories a person
// keeps are; nothing where there is none.
func otherName(dir string) string {
	alias := filepath.Join("/System/Volumes/Data", dir)
	a, err := os.Stat(alias)
	if err != nil {
		return ""
	}
	if d, err := os.Stat(dir); err != nil || !os.SameFile(a, d) {
		return ""
	}
	return alias
}

func TestClearOutputDirKnowsADirectoryByAnyName(t *testing.T) {
	// A directory whose emptying is a disaster is refused whatever it is
	// called: in other capitals where names ignore case, through a link to
	// what holds it, by another name the system gives it. Where names keep
	// case, the name in capitals is another directory, not there yet, which
	// the run makes; either way the one kept from harm is as it was, byte for
	// byte, and nothing was asked of the network or logged when it is refused.
	for _, tc := range []struct {
		name string
		// set lays the case out under tmp, and is the arguments to fetch, the
		// directory kept from harm, and whether the directory -o names is that
		// one or holds it, whatever the file system.
		set  func(t *testing.T, tmp, url string) (args []string, kept string, always bool)
		want string
	}{
		{"the home directory, in capitals", func(t *testing.T, tmp, url string) ([]string, string, bool) {
			homeAt(t, filepath.Join(tmp, "Home"))
			return []string{"-o", filepath.Join(tmp, "HOME"), url}, filepath.Join(tmp, "Home"), false
		}, "is the home directory, or holds it"},
		{"one that holds it, in capitals", func(t *testing.T, tmp, url string) ([]string, string, bool) {
			homeAt(t, filepath.Join(tmp, "a", "Home"))
			return []string{"-o", filepath.Join(tmp, "A"), url}, filepath.Join(tmp, "a"), false
		}, "is the home directory, or holds it"},
		{"the directory the command runs in, in capitals", func(t *testing.T, tmp, url string) ([]string, string, bool) {
			t.Chdir(filepath.Join(tmp, "Work"))
			return []string{"-o", filepath.Join(tmp, "WORK"), url}, filepath.Join(tmp, "Work"), false
		}, "is the directory the command runs in, or holds it"},
		{"a file the run reads, its directory in capitals", func(t *testing.T, tmp, url string) ([]string, string, bool) {
			list := filepath.Join(tmp, "Out", "urls.txt")
			if err := os.WriteFile(list, []byte(url+"\n"), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			return []string{"-o", filepath.Join(tmp, "OUT"), "--input", list}, filepath.Join(tmp, "Out"), false
		}, "holds --input "},
		{"the home directory, through a link to what holds it", func(t *testing.T, tmp, url string) ([]string, string, bool) {
			homeAt(t, filepath.Join(tmp, "real", "home"))
			if err := os.Symlink(filepath.Join(tmp, "real"), filepath.Join(tmp, "link")); err != nil {
				t.Skipf("Symlink: %v", err)
			}
			return []string{"-o", filepath.Join(tmp, "link", "home"), url}, filepath.Join(tmp, "real"), true
		}, "is the home directory, or holds it"},
		{"the home directory, by another name the system gives it", func(t *testing.T, tmp, url string) ([]string, string, bool) {
			homeAt(t, filepath.Join(tmp, "home"))
			alias := otherName(filepath.Join(tmp, "home"))
			if alias == "" {
				t.Skip("no other name for a directory here")
			}
			return []string{"-o", alias, url}, filepath.Join(tmp, "home"), true
		}, "is the home directory, or holds it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, asked := replying(t, 200)
			tmp := resolve(t.TempDir())
			tree(t, tmp, "Home/notes.txt", "a/Home/notes.txt", "Work/notes.txt", "Out/notes.txt",
				"real/home/notes.txt", "home/notes.txt")
			args, kept, always := tc.set(t, tmp, server.URL)
			before := contentsOf(t, kept)
			log := filepath.Join(t.TempDir(), "run.log")
			code, _, stderr := exec(t, append([]string{"fetch", "--clear-output-dir", "--log", log}, args...)...)
			sameContents(t, kept, before)
			if !always && !caseFolds(t, tmp) {
				// Another directory, which the run made and wrote in.
				if code == 2 || strings.Contains(stderr, tc.want) {
					t.Errorf("exit code = %d where names keep case\n%s", code, stderr)
				}
				return
			}
			if code != 2 || !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "nothing was removed") {
				t.Errorf("exit code = %d, want 2 and %q\n%s", code, tc.want, stderr)
			}
			if n := asked.Load(); n != 0 {
				t.Errorf("the server was asked %d times", n)
			}
			if _, err := os.Stat(log); err == nil {
				t.Error("a log was opened")
			}
		})
	}
}

func TestWithinKnowsADirectoryByWhatItIs(t *testing.T) {
	tmp := resolve(t.TempDir())
	tree(t, tmp, "out/a/file.txt", "other/file.txt")
	out := filepath.Join(tmp, "out")
	cases := []struct {
		name, path, dir string
		want, strictly  bool
	}{
		{"itself", out, out, true, false},
		{"a file in it", filepath.Join(out, "a", "file.txt"), out, true, true},
		{"one not made yet in it", filepath.Join(out, "a", "new", "x.txt"), out, true, true},
		{"one beside it", filepath.Join(tmp, "other", "file.txt"), out, false, false},
		{"what holds it", tmp, out, false, false},
		{"anything, in the root", out, "/", true, true},
	}
	if alias := otherName(out); alias != "" {
		cases = append(cases,
			struct {
				name, path, dir string
				want, strictly  bool
			}{"itself by another name", alias, out, true, false},
			struct {
				name, path, dir string
				want, strictly  bool
			}{"a file in it by another name", filepath.Join(alias, "a", "file.txt"), out, true, true})
	}
	if caseFolds(t, tmp) {
		cases = append(cases,
			struct {
				name, path, dir string
				want, strictly  bool
			}{"itself in capitals", filepath.Join(tmp, "OUT"), out, true, false},
			struct {
				name, path, dir string
				want, strictly  bool
			}{"one not made yet, in capitals", filepath.Join(tmp, "OUT", "new.txt"), out, true, true})
	}
	for _, tc := range cases {
		if got := within(tc.path, tc.dir); got != tc.want {
			t.Errorf("%s: within = %v, want %v", tc.name, got, tc.want)
		}
		if got := strictlyWithin(tc.path, tc.dir); got != tc.strictly {
			t.Errorf("%s: strictlyWithin = %v, want %v", tc.name, got, tc.strictly)
		}
	}
}

func TestWithinByNamesWhereTheDirectoryIsNotThere(t *testing.T) {
	for _, folds := range []bool{true, false} {
		foldingCase(t, folds)
		for _, tc := range []struct {
			path, dir string
			want      bool
		}{
			{"/x/out/a.txt", "/x/out", true},
			{"/x/outer/a.txt", "/x/out", false},
			{"/x", "/x/out", false},
			// In other capitals, where names ignore case.
			{"/X/OUT/a.txt", "/x/out", folds},
			{"/x/out", "/X/Out", folds},
		} {
			if got := within(tc.path, tc.dir); got != tc.want {
				t.Errorf("folds %v: within(%q, %q) = %v, want %v", folds, tc.path, tc.dir, got, tc.want)
			}
		}
	}
}

func TestSameThere(t *testing.T) {
	tmp := resolve(t.TempDir())
	tree(t, tmp, "a.txt", "b.txt")
	a, b := filepath.Join(tmp, "a.txt"), filepath.Join(tmp, "b.txt")
	for _, tc := range []struct {
		name string
		x, y string
		want bool
	}{
		{"one file", a, a, true},
		{"two", a, b, false},
		{"the first not there", filepath.Join(tmp, "c.txt"), a, false},
		{"the second not there", a, filepath.Join(tmp, "c.txt"), false},
	} {
		if got := sameThere(tc.x, tc.y); got != tc.want {
			t.Errorf("%s: sameThere = %v", tc.name, got)
		}
	}
}
