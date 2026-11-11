"""fork_sync lays a fork's patches over another release of bogdanfinn's.

The pure parts (renames, imports, go.mod merges, conflict choices) are held
to tables; the commands run against small repositories made here: a release
v1 and v2 of bogdanfinn's, a fork whose branch is v1, its anchor, patches
and a merge on top.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

import fork_sync

SCRIPT = os.path.abspath(fork_sync.__file__)
PIN = "v1.0.1-0.20261101000000-abcdefabcdef"
ANCHOR = "Rename the module to github.com/igor-lemon/fhttp"
_saved = {}


def setUpModule():
    home = tempfile.mkdtemp(prefix="fork-sync-home-")
    config = os.path.join(home, "gitconfig")
    open(config, "w").close()
    env = {"GIT_CONFIG_GLOBAL": config, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
           "GIT_TERMINAL_PROMPT": "0"}
    for k, v in env.items():
        _saved[k] = os.environ.get(k)
        os.environ[k] = v
    _saved["home"] = home


def tearDownModule():
    shutil.rmtree(_saved.pop("home"), ignore_errors=True)
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if r.returncode:
        raise AssertionError(f"git {' '.join(args)}: {r.stderr}")
    return r.stdout.strip()


def write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(text)


def read(root, path):
    with open(os.path.join(root, path), encoding="utf-8") as f:
        return f.read()


def commit(repo, message, files=(), remove=()):
    for path, text in dict(files).items():
        write(repo, path, text)
    for path in remove:
        os.remove(os.path.join(repo, path))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def show(repo, rev, path):
    return git(repo, "show", f"{rev}:{path}") + "\n"


def run(*argv):
    """fork_sync's main with argv: (exit code, stdout, stderr)."""
    out, err, code = io.StringIO(), io.StringIO(), 0
    with mock.patch.object(sys, "argv", ["fork_sync.py", *argv]), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            fork_sync.main()
        except SystemExit as e:
            if isinstance(e.code, str):
                err.write(e.code)
                code = 1
            else:
                code = e.code or 0
    return code, out.getvalue(), err.getvalue()


def a_go(import_path, a="fmt.Sprint(tls.X)", b="1"):
    return textwrap.dedent(f"""\
        package fhttp

        import (
        \t"fmt"

        \ttls "{import_path}"
        )

        func A() string {{ return {a} }}

        // spacer one
        // spacer two
        // spacer three

        func B() int {{ return {b} }}
        """)


def go_mod(module, go, *requires):
    return (f"module {module}\n\ngo {go}\n\nrequire (\n" +
            "".join(f"\t{r}\n" for r in requires) + ")\n")


C_GO = textwrap.dedent("""\
    package fhttp

    import (
    \t"github.com/bogdanfinn/utls"
    \t"github.com/hashicorp/x"
    )

    var C = utls.Name + x.Name
    """)


class Fixture:
    """bogdanfinn's fhttp released as v1 and v2, and a fork of it whose
    branch tls-forge is v1, the anchor, patches, and a merge on top."""

    def __init__(self, root, *, conflict=False, old_file=False,
                 anchor_license=False, keeps_utls=False, v2_tidy=None, moved=False):
        self.root = root
        self.upstream = os.path.join(root, "upstream")
        self.fork = os.path.join(root, "fhttp")
        self.work = os.path.join(root, "work")
        up = self.upstream
        os.makedirs(up)
        git(up, "init", "-q", "-b", "main")
        v1 = {"go.mod": go_mod("github.com/bogdanfinn/fhttp", "1.20",
                               "github.com/bogdanfinn/utls v1.0.0",
                               "golang.org/x/text v0.1.0"),
              "a.go": a_go("github.com/bogdanfinn/utls"),
              "sub/go.mod": "module example.com/sub\n\ngo 1.20\n\n"
                            "require github.com/bogdanfinn/fhttp v1.0.0\n",
              "LICENSE": "license\n",
              ".github/ci.yml": "on: push\n",
              ".github/old.yml": "on: pull_request\n"}
        if moved:
            v1["x.txt"] = "one\ntwo\nthree\nfour\nfive\n"
        if old_file:
            v1["old.go"] = "package fhttp\n\nvar Old = 1\n"
        commit(up, "v1", v1)
        git(up, "tag", "v1")
        v2 = {"go.mod": go_mod("github.com/bogdanfinn/fhttp", "1.21",
                               "github.com/bogdanfinn/utls v1.1.0",
                               "golang.org/x/text v0.1.0",
                               "golang.org/x/net v0.2.0"),
              "a.go": a_go("github.com/bogdanfinn/utls", b="2"),
              "b.go": "package fhttp\n\nimport \"github.com/bogdanfinn/utls\"\n\n"
                      "var _ = utls.X\n",
              "sub/go.mod": "module example.com/sub\n\ngo 1.20\n\n"
                            "require github.com/bogdanfinn/fhttp v2.0.0\n"}
        if anchor_license:
            v2["LICENSE"] = "license, 2026\n"
        if v2_tidy is not None:
            v2["d.txt"] = v2_tidy
        if moved:
            git(up, "mv", "x.txt", "y.txt")
        commit(up, "v2", v2, remove=[".github/old.yml"] + (["old.go"] if old_file else []))
        git(up, "tag", "v2")

        git(root, "clone", "-q", up, self.fork)
        fk = self.fork
        git(fk, "remote", "rename", "origin", "upstream")
        git(fk, "checkout", "-q", "-b", "tls-forge", "v1")
        utls = "github.com/bogdanfinn/utls" if keeps_utls else "github.com/igor-lemon/utls"
        anchor = {"go.mod": go_mod("github.com/igor-lemon/fhttp", "1.20",
                                   f"github.com/igor-lemon/utls {PIN}",
                                   "golang.org/x/text v0.1.0"),
                  "a.go": a_go(utls),
                  "sub/go.mod": "module example.com/sub\n\ngo 1.20\n\n"
                                "require github.com/igor-lemon/fhttp v1.0.0\n",
                  "LEMON.md": "# The fork\n",
                  ".lemon/notes.txt": "notes\n",
                  "lemon/lemon.go": "package lemon\n"}
        if anchor_license:
            anchor["LICENSE"] = "license, the fork's\n"
        commit(fk, ANCHOR, anchor, remove=[".github/ci.yml", ".github/old.yml"])
        self.patches = []
        if keeps_utls:
            # the fork took utls from its fork after the anchor: the line the
            # new anchor renames, changed with the one after it
            self.patch("Take utls from its fork", {"a.go": a_go(
                "github.com/igor-lemon/utls").replace(
                "\ttls \"github.com/igor-lemon/utls\"\n",
                "\ttls \"github.com/igor-lemon/utls\"\n"
                "\t_ \"github.com/igor-lemon/utls/dicttls\"\n")})
        mod = read(fk, "go.mod").replace("go 1.20", "go 1.22").replace(
            "\tgolang.org/x/text v0.1.0\n",
            "\tgolang.org/x/text v0.1.0\n\tgolang.org/x/sys v0.3.0\n")
        self.patch("Add C", {"c.go": C_GO, "go.mod": mod, "nonl.txt": "a\nb"})
        a = read(fk, "a.go").replace("fmt.Sprint(tls.X)", 'fmt.Sprint(tls.X, "!")')
        if conflict:
            a = a.replace("return 1 }", "return 10 }")
        self.patch("Change A", {"a.go": a})
        self.patch("Tidy", {"d.txt": "one\n"})
        self.patch("Tidy", {"d.txt": "one\ntwo\n"})
        if old_file:
            self.patch("Touch old", {"old.go": "package fhttp\n\nvar Old = 2\n"})
        if moved:
            git(fk, "mv", "x.txt", "z.txt")
            self.patch("Move x", {"moved.txt": "moved\n"})
        git(fk, "checkout", "-q", "-b", "side", "v1")
        commit(fk, "side", {"side.txt": "side\n"})
        git(fk, "checkout", "-q", "tls-forge")
        git(fk, "merge", "-q", "-s", "ours", "--no-ff", "-m", "Merge side", "side")
        self.head = git(fk, "rev-parse", "HEAD")

    def patch(self, subject, files):
        self.patches.append(commit(self.fork, subject, files))

    def on_branch(self, name, files, remove=(), base="v2"):
        """A commit of the fork's on a branch of its own: an oracle."""
        git(self.fork, "checkout", "-q", "-b", name, base)
        sha = commit(self.fork, name, files, remove)
        git(self.fork, "checkout", "-q", "tls-forge")
        return sha

    def start(self, *extra, ref="v2"):
        return run("start", self.fork, ref, "--work", self.work, *extra)

    def subjects(self):
        anchor = fork_sync.state(self.work, "anchor")
        return [git(self.work, "log", "-1", "--format=%s", anchor)] + \
            git(self.work, "log", "--reverse", "--format=%s",
                f"{anchor}..HEAD").splitlines()

    def at(self, subject):
        anchor = fork_sync.state(self.work, "anchor")
        for line in git(self.work, "log", "--format=%H %s",
                        f"{anchor}..HEAD").splitlines():
            sha, s = line.split(" ", 1)
            if s == subject:
                return sha
        raise AssertionError(f"no patch {subject}")


class Repos(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fork-sync-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def fixture(self, **kw):
        return Fixture(self.root, **kw)


class RenameTests(unittest.TestCase):
    def test_every_fork_is_renamed_and_nothing_else(self):
        cases = {
            "github.com/bogdanfinn/utls": "github.com/igor-lemon/utls",
            "github.com/bogdanfinn/utls/dicttls": "github.com/igor-lemon/utls/dicttls",
            '"github.com/bogdanfinn/tls-client"': '"github.com/igor-lemon/tls-client"',
            "github.com/bogdanfinn/quic-go-utls/http3": "github.com/igor-lemon/quic-go-utls/http3",
            "github.com/bogdanfinn/websocket v1": "github.com/igor-lemon/websocket v1",
            "github.com/bogdanfinn/fhttp@v0.7.3": "github.com/igor-lemon/fhttp@v0.7.3",
            # not forks, or a longer name that begins as one
            "github.com/bogdanfinn/tls-client-ext": "github.com/bogdanfinn/tls-client-ext",
            "github.com/bogdanfinn/fhttp2": "github.com/bogdanfinn/fhttp2",
            "github.com/bogdanfinn/utlsx": "github.com/bogdanfinn/utlsx",
            "github.com/bogdanfinn/other": "github.com/bogdanfinn/other",
            "github.com/igor-lemon/utls": "github.com/igor-lemon/utls",
            "": "",
        }
        for given, want in cases.items():
            with self.subTest(given=given):
                self.assertEqual(fork_sync.rename_text(given), want)

    def test_a_tree_is_renamed_in_go_files_and_go_mods_alone(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "go.mod", "module github.com/bogdanfinn/fhttp\n\ngo 1.20\n\n"
                  "require github.com/bogdanfinn/utls v1.0.0\n"
                  "// replace github.com/bogdanfinn/utls => ../utls\n")
            write(d, "x/a.go", 'package x\n\nimport (\n\t"github.com/bogdanfinn/utls"\n'
                  '\t"github.com/hashicorp/y"\n)\n')
            write(d, "x/same.go", 'package x\n\nimport (\n\t"z"\n\t"a"\n)\n')
            write(d, "README.md", "github.com/bogdanfinn/utls\n")
            write(d, ".git/config.go", "github.com/bogdanfinn/utls\n")
            fork_sync.rename(d, {"github.com/igor-lemon/utls": PIN})
            self.assertEqual(read(d, "go.mod"),
                             "module github.com/igor-lemon/fhttp\n\ngo 1.20\n\n"
                             f"require github.com/igor-lemon/utls {PIN}\n"
                             "// replace github.com/bogdanfinn/utls => ../utls\n")
            self.assertEqual(read(d, "x/a.go"), 'package x\n\nimport (\n'
                             '\t"github.com/hashicorp/y"\n\t"github.com/igor-lemon/utls"\n)\n')
            # a file the rename did not change keeps its imports' order
            self.assertEqual(read(d, "x/same.go"), 'package x\n\nimport (\n\t"z"\n\t"a"\n)\n')
            self.assertEqual(read(d, "README.md"), "github.com/bogdanfinn/utls\n")
            self.assertEqual(read(d, ".git/config.go"), "github.com/bogdanfinn/utls\n")


class ImportTests(unittest.TestCase):
    def test_each_group_of_a_block_is_sorted_by_path(self):
        given = ('package x\n\nimport "single"\n\nimport (\n\t"zz"\n\talias "bb"\n'
                 '\t. "aa" // a comment\n\n\t"yy"\n\t"xx"\n\t// a comment line\n\t"ww"\n'
                 '\t"vv"\n)\n\nfunc main() {}\n')
        want = ('package x\n\nimport "single"\n\nimport (\n\t. "aa" // a comment\n'
                '\talias "bb"\n\t"zz"\n\n\t"xx"\n\t"yy"\n\t// a comment line\n\t"vv"\n'
                '\t"ww"\n)\n\nfunc main() {}\n')
        self.assertEqual(fork_sync.sort_imports(given), want)

    def test_an_import_a_rename_made_twice_is_kept_once(self):
        given = 'import (\n\t"github.com/igor-lemon/utls"\n\t"github.com/igor-lemon/utls"\n)'
        self.assertEqual(fork_sync.sort_imports(given),
                         'import (\n\t"github.com/igor-lemon/utls"\n)')

    def test_a_file_without_a_block_and_a_block_left_open_are_kept(self):
        for text in ("", "package x\n", 'package x\n\nimport (\n\t"b"\n\t"a"'):
            with self.subTest(text=text):
                self.assertEqual(fork_sync.sort_imports(text),
                                 text.replace('"b"\n\t"a"', '"a"\n\t"b"'))


class GoModTests(unittest.TestCase):
    MOD = ("module m\n\ngo 1.21\n\nrequire single.example/x v1.0.0 // indirect\n\n"
           "require (\n\ta.example/a v1.2.3\n\tb.example/b v0.0.0-2020-abc // indirect\n)\n\n"
           "replace (\n\ta.example/a v1.2.3 => ../a\n)\n\n// require gone.example/g v9.9.9\n")

    def test_requirements_read_single_lines_and_blocks_only(self):
        self.assertEqual(fork_sync.requirements(self.MOD),
                         {"single.example/x": "v1.0.0", "a.example/a": "v1.2.3",
                          "b.example/b": "v0.0.0-2020-abc"})
        self.assertEqual(fork_sync.requirements(""), {})

    def test_repin_changes_the_versions_pinned_and_keeps_the_rest(self):
        got = fork_sync.repin(self.MOD, {"a.example/a": "v2.0.0",
                                         "single.example/x": "v1.1.0",
                                         "absent.example/z": "v1.0.0"})
        self.assertEqual(got, self.MOD.replace("\ta.example/a v1.2.3\n", "\ta.example/a v2.0.0\n")
                         .replace("x v1.0.0 // indirect", "x v1.1.0 // indirect"))
        self.assertEqual(fork_sync.repin("require a.example/a v1.0.0",
                                         {"a.example/a": "v1.1.0"}),
                         "require a.example/a v1.1.0")

    def test_versions_are_ordered_as_semver_orders_them(self):
        order = ["notaversion", "v0.0.0-2020-abc", "v1.2.3-alpha", "v1.2.3-alpha.1",
                 "v1.2.3-alpha.beta", "v1.2.3-beta.2", "v1.2.3-beta.11", "v1.2.3",
                 "v1.2.10", "v1.10.0", "v2.0.0+incompatible"]
        for lower, upper in zip(order, order[1:]):
            with self.subTest(lower=lower, upper=upper):
                self.assertLess(fork_sync.semver_key(lower), fork_sync.semver_key(upper))
                self.assertEqual(fork_sync.higher(lower, upper), upper)
                self.assertEqual(fork_sync.higher(upper, lower), upper)
        self.assertEqual(fork_sync.higher("v1.0.0", "v1.0.0"), "v1.0.0")

    def test_a_merge_takes_theirs_changes_module_by_module(self):
        base = go_mod("m", "1.20", "a.example/a v1.0.0", "b.example/b v1.0.0",
                      "c.example/c v1.0.0", "d.example/d v1.0.0", "e.example/e v1.0.0")
        ours = go_mod("m", "1.21", "a.example/a v1.0.0", "b.example/b v1.5.0",
                      "c.example/c v1.0.0", "d.example/d v1.2.0", "e.example/e v1.0.0",
                      "o.example/o v1.0.0") + "\nreplace (\n\tc.example/c v1.0.0 => ../c\n)\n"
        theirs = go_mod("m", "1.22.1", "a.example/a v1.1.0", "b.example/b v1.3.0",
                        "e.example/e v1.0.0", "t.example/t v0.1.0")
        got = fork_sync.merge_gomod(base, ours, theirs)
        self.assertEqual(fork_sync.requirements(got), {
            "a.example/a": "v1.1.0",   # theirs alone moved it
            "b.example/b": "v1.5.0",   # both did: the higher
            "d.example/d": "v1.2.0",   # theirs dropped it, ours moved it: kept
            "e.example/e": "v1.0.0",
            "o.example/o": "v1.0.0",   # ours alone added it
            "t.example/t": "v0.1.0",   # theirs alone added it
        })                             # c: theirs dropped it, ours kept it as it was
        self.assertIn("\ngo 1.22.1\n", got)
        # the replace of the module dropped is not a requirement: kept
        self.assertIn("replace (\n\tc.example/c v1.0.0 => ../c\n)\n", got)

    def test_a_module_theirs_adds_goes_into_the_block_of_its_kind(self):
        ours = ("module m\n\ngo 1.21\n\nrequire (\n\ta.example/a v1.0.0\n\tz.example/z v1.0.0\n)\n\n"
                "require (\n\tc.example/c v1.0.0 // indirect\n\tg.example/g v1.0.0 // indirect\n)\n\n"
                "// replace a.example/a => ../a\n")
        base = ours.replace("\tg.example/g v1.0.0 // indirect\n", "")
        theirs = base.replace("\ta.example/a v1.0.0\n",
                              "\ta.example/a v1.0.0\n\tm.example/m v0.1.0\n").replace(
            "\tc.example/c v1.0.0 // indirect\n",
            "\tb.example/b v0.2.0 // indirect\n\tb.example/b2 v0.2.0 // indirect\n"
            "\tc.example/c v1.0.0 // indirect\n\tq.example/q v0.3.0 // indirect\n")
        got = fork_sync.merge_gomod(base, ours, theirs)
        self.assertEqual(got, ours.replace(
            "\ta.example/a v1.0.0\n", "\ta.example/a v1.0.0\n\tm.example/m v0.1.0\n").replace(
            "\tc.example/c v1.0.0 // indirect\n\tg.example/g v1.0.0 // indirect\n",
            "\tb.example/b v0.2.0 // indirect\n\tb.example/b2 v0.2.0 // indirect\n"
            "\tc.example/c v1.0.0 // indirect\n\tg.example/g v1.0.0 // indirect\n"
            "\tq.example/q v0.3.0 // indirect\n"))

    def test_a_module_with_no_block_of_its_kind_goes_into_the_first(self):
        # the single line before the block, a block of mixed kinds
        ours = ("module m\n\nrequire s.example/s v1.0.0\n\nrequire (\n\ta.example/a v1.0.0\n"
                "\tb.example/b v1.0.0 // indirect\n)\n")
        theirs = ours.replace("\tb.example/b v1.0.0 // indirect\n",
                              "\tb.example/b v1.0.0 // indirect\n\tc.example/c v1.0.0 // indirect\n")
        self.assertEqual(fork_sync.merge_gomod(ours, ours, theirs), theirs)
        # a block of mixed kinds is of neither: a direct one goes to the direct block
        ours += "\nrequire (\n\tz.example/z v1.0.0\n)\n"
        theirs = ours.replace("\tz.example/z v1.0.0\n", "\tm.example/m v1.0.0\n\tz.example/z v1.0.0\n")
        self.assertEqual(fork_sync.merge_gomod(ours, ours, theirs), theirs)

    def test_a_module_with_no_block_at_all_goes_into_a_block_of_its_own(self):
        ours = "module m\n\ngo 1.21\n\nrequire a.example/a v1.0.0\n"
        theirs = ours + "\nrequire (\n\tb.example/b v1.0.0 // indirect\n)\n"
        self.assertEqual(fork_sync.merge_gomod(ours, ours, theirs), theirs)

    def test_a_block_left_with_nothing_goes(self):
        base = go_mod("m", "1.21", "a.example/a v1.0.0") + \
            "\nrequire (\n\tb.example/b v1.0.0 // indirect\n)\n\n// end\n"
        theirs = go_mod("m", "1.21", "a.example/a v1.0.0") + "\n// end\n"
        self.assertEqual(fork_sync.merge_gomod(base, base, theirs), theirs)
        # one taken away where another comes: the one that comes stays
        swap = base.replace("b.example/b v1.0.0", "c.example/c v1.0.0")
        self.assertEqual(fork_sync.merge_gomod(base, base, swap), swap)

    def test_go_is_the_higher_as_go_orders_its_versions(self):
        mod = "module m\n\ngo {}\n\nrequire a.example/a v1.0.0\n".format
        # a language version comes before its prereleases and releases
        order = ["nonsense", "1", "1.21", "1.21alpha1", "1.21beta2", "1.21rc1", "1.21rc2",
                 "1.21.0", "1.21.1", "1.22", "1.22rc1", "1.22.0", "1.22.10", "2.0"]
        for lower, upper in zip(order, order[1:]):
            with self.subTest(lower=lower, upper=upper):
                for ours, theirs in ((lower, upper), (upper, lower)):
                    self.assertIn(f"\ngo {upper}\n",
                                  fork_sync.merge_gomod(mod("1.20"), mod(ours), mod(theirs)))
        # a side without a go line leaves ours as it is
        none = "module m\n\nrequire a.example/a v1.0.0\n"
        self.assertNotIn("\ngo ", fork_sync.merge_gomod(none, none, mod("1.22")))
        self.assertIn("\ngo 1.21\n", fork_sync.merge_gomod(none, mod("1.21"), none))

    def test_the_merge_driver_writes_what_it_merged_over_ours(self):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            ours = go_mod("m", "1.20", "a.example/a v1.0.0") + "\n// ours alone\n"
            for name, text in (("o", go_mod("m", "1.20", "a.example/a v1.0.0")),
                               ("a", ours),
                               ("b", go_mod("m", "1.22", "a.example/a v1.1.0"))):
                write(d, name, text)
                paths.append(os.path.join(d, name))
            self.assertEqual(run("gomod", *paths), (0, "", ""))
            # ours, as it is laid out, with theirs's changes
            self.assertEqual(read(d, "a"), go_mod("m", "1.22", "a.example/a v1.1.0")
                             + "\n// ours alone\n")
            self.assertEqual(read(d, "o"), go_mod("m", "1.20", "a.example/a v1.0.0"))


class StateTests(unittest.TestCase):
    def test_a_work_with_nothing_dropped_has_nothing_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git"))
            self.assertEqual(fork_sync.dropped(d), set())
            fork_sync.drop(d, "a" * 40)
            fork_sync.drop(d, "b" * 40)
            self.assertEqual(fork_sync.dropped(d), {"a" * 40, "b" * 40})

    def test_an_operation_is_under_way_as_git_says_it_is(self):
        with tempfile.TemporaryDirectory() as d:
            git(d, "init", "-q")
            self.assertIsNone(fork_sync.in_progress(d))
            # a REBASE_HEAD a finished rebase left behind is none
            commit(d, "one", {"a.txt": "a\n"})
            git(d, "update-ref", "REBASE_HEAD", "HEAD")
            self.assertIsNone(fork_sync.in_progress(d))
            git(d, "update-ref", "CHERRY_PICK_HEAD", "HEAD")
            self.assertEqual(fork_sync.in_progress(d), ["cherry-pick", "--continue"])
            for name in ("rebase-merge", "rebase-apply"):
                os.makedirs(os.path.join(d, ".git", name))
                # the rebase's, though a pick it stopped at left CHERRY_PICK_HEAD
                self.assertEqual(fork_sync.in_progress(d), ["rebase", "--continue"])
                os.rmdir(os.path.join(d, ".git", name))

    def test_a_git_that_fails_says_its_command(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, err = run("series", d)
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("git rev-list --first-parent tls-forge: "), err)


class ConflictTests(unittest.TestCase):
    def test_changes_apart_are_merged_word_by_word(self):
        self.assertEqual(fork_sync.token_merge("a b c d", "A b c d", "a b c D"), "A b c D")
        self.assertEqual(fork_sync.token_merge("a b", "a b", "a b"), "a b")
        self.assertEqual(fork_sync.token_merge("a b", "a X b", "a X b"), "a X b")
        # a string literal is one word, quotes and escapes included
        self.assertIsNone(fork_sync.token_merge('f("a b")', 'f("a c")', 'f("x b")'))
        self.assertEqual(fork_sync.token_merge('f("a", 1)', 'f("b", 1)', 'f("a", 2)'),
                         'f("b", 2)')

    def test_changes_to_one_word_clash(self):
        self.assertIsNone(fork_sync.token_merge("a b c", "a X c", "a Y c"))
        self.assertIsNone(fork_sync.token_merge("a b c", "a X Y", "a b Z"))

    def test_insertions_at_one_place_clash_unless_both_are_kept(self):
        self.assertIsNone(fork_sync.token_merge("a b", "a X b", "a Y b"))
        self.assertEqual(fork_sync.token_merge("a b", "a X b", "a Y b", "union"), "a X Y b")

    def test_a_conflict_is_read_into_its_three_sides(self):
        text = ("keep\n<<<<<<< ours\no1\n||||||| base\nb1\n=======\nt1\nt2\n"
                ">>>>>>> theirs\nmid\n<<<<<<< ours\n=======\nt3\n>>>>>>> theirs\nend\n")
        lines, hs = fork_sync.hunks_of(text)
        self.assertEqual(len(lines), 15)
        self.assertEqual([(s, e) for s, e, _ in hs], [(1, 8), (10, 13)])
        self.assertEqual(hs[0][2], {"o": ["o1\n"], "b": ["b1\n"], "t": ["t1\n", "t2\n"]})
        self.assertEqual(hs[1][2], {"o": [], "b": [], "t": ["t3\n"]})

    def test_the_candidates_of_a_hunk_are_each_once(self):
        names = [n for n, _ in fork_sync.candidates({"o": ["a 1\n"], "b": ["a 0\n"],
                                                       "t": ["a 2\n"]})]
        self.assertEqual(names, ["ours", "theirs", "both", "theirs+ours", "base"])
        # one insertion both sides made: ours, both, and the base it was not in
        self.assertEqual(fork_sync.candidates({"o": ["x\n"], "b": [], "t": ["x\n"]}),
                         [("ours", "x\n"), ("both", "x\nx\n"), ("base", "")])

    def test_distance_counts_lines_then_how_unlike_they_are(self):
        self.assertEqual(fork_sync.distance("a\n", "a\n"), (0, 0))
        near, far = fork_sync.distance("abcd\n", "abce\n"), fork_sync.distance("abcd\n", "wxyz\n")
        self.assertEqual(near[0], far[0])
        self.assertLess(near, far)
        self.assertEqual(fork_sync.distance("a\nb\n", "a\n"), (1, 1))

    def test_each_hunk_is_resolved_toward_the_oracle(self):
        base, ours, theirs = "x\none\ny\n", "x\nours\ny\n", "x\ntheirs\ny\n"
        _, merged = fork_sync.merge_file(base, ours, theirs)
        self.assertIn("<<<<<<< ours", merged)
        for oracle, pick in (("x\nours\ny\n", "ours"), ("x\ntheirs\ny\n", "theirs"),
                             ("x\nours\ntheirs\ny\n", "both"), ("x\none\ny\n", "base")):
            with self.subTest(oracle=oracle):
                text, log = fork_sync.resolve_toward(merged, oracle)
                self.assertEqual(text, oracle)
                self.assertTrue(log[0].startswith(f"hunk 1: {pick} ((0, 0)"), log)
        _, clean = fork_sync.merge_file(base, base, theirs)
        self.assertEqual(fork_sync.resolve_toward(clean, "anything"), (theirs, []))


class SettleTests(unittest.TestCase):
    def go_on(self, moved):
        """settle over a conflict resolved, whose first continue git
        refuses; moved: whether that refusal moved the operation on (to the
        next conflict of a rebase), after which the next continue goes."""
        refused = subprocess.CompletedProcess([], 1, "", "refused")
        went = subprocess.CompletedProcess([], 0, "", "")
        asked = []

        def where(work):
            asked.append(work)
            return ("h2", "c2", "") if moved and len(asked) > 1 else ("h", "c1", "")

        states = iter([["cherry-pick", "--continue"]] * 3 + [None])
        log = io.StringIO()
        with mock.patch.object(fork_sync, "in_progress", lambda w: next(states)), \
                mock.patch.object(fork_sync, "autoresolve", return_value=[]), \
                mock.patch.object(fork_sync, "staged_nothing", return_value=False), \
                mock.patch.object(fork_sync, "where", where), \
                mock.patch.object(fork_sync.subprocess, "run",
                                  side_effect=[refused, went]) as ran, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                fork_sync.settle("/nowhere", "oracle", log, "a patch")
                code = 0
            except SystemExit as e:
                code = e.code
        return code, ran.call_count, out.getvalue()

    def test_a_continue_that_moves_nothing_stops_rather_than_going_round(self):
        code, calls, out = self.go_on(moved=False)
        self.assertEqual((code, calls), (1, 1))
        self.assertIn("refused", out)

    def test_a_continue_that_moved_on_is_settled_again(self):
        self.assertEqual(self.go_on(moved=True)[:2], (0, 2))


class StartTests(Repos):
    def test_the_patches_are_laid_over_the_release_renamed(self):
        f = self.fixture()
        code, out, err = f.start()
        self.assertEqual(code, 0, out + err)
        self.assertEqual(err, "")
        self.assertIn("fhttp: 4 patches over v2", out)
        self.assertIn("4 patches over the anchor", out)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])
        anchor = fork_sync.state(f.work, "anchor")
        self.assertEqual(git(f.work, "rev-parse", anchor + "^"), git(f.work, "rev-parse", "v2"))
        self.assertEqual(fork_sync.state(f.work, "head"), f.head)
        self.assertEqual(fork_sync.state(f.work, "onto"), git(f.work, "rev-parse", "v2"))
        # the anchor: the release renamed, its nested go.mod too, and the
        # anchor's own files; a file the anchor took away is away again
        self.assertEqual(show(f.work, anchor, "sub/go.mod"),
                         "module example.com/sub\n\ngo 1.20\n\n"
                         "require github.com/igor-lemon/fhttp v2.0.0\n")
        self.assertEqual(show(f.work, anchor, "go.mod"),
                         go_mod("github.com/igor-lemon/fhttp", "1.21",
                                f"github.com/igor-lemon/utls {PIN}",
                                "golang.org/x/text v0.1.0", "golang.org/x/net v0.2.0"))
        self.assertEqual(show(f.work, anchor, "b.go"),
                         'package fhttp\n\nimport "github.com/igor-lemon/utls"\n\nvar _ = utls.X\n')
        self.assertEqual(show(f.work, anchor, "LEMON.md"), "# The fork\n")
        self.assertEqual(show(f.work, anchor, ".lemon/notes.txt"), "notes\n")
        # a Go file of the anchor's own, which the old base lacked, is kept
        self.assertEqual(show(f.work, anchor, "lemon/lemon.go"), "package lemon\n")
        self.assertEqual(show(f.work, anchor, "LICENSE"), "license\n")
        files = git(f.work, "ls-tree", "-r", "--name-only", anchor).splitlines()
        # taken away by the anchor, the release keeping it or not
        self.assertNotIn(".github/ci.yml", files)
        self.assertNotIn(".github/old.yml", files)
        self.assertFalse(os.path.exists(os.path.join(f.work, ".github/ci.yml")))
        self.assertEqual(git(f.work, "log", "-1", "--format=%an <%ae>", anchor),
                         "Test <test@example.com>")
        # a patch that named bogdanfinn's path is renamed, its imports sorted
        self.assertEqual(show(f.work, f.at("Add C"), "c.go"),
                         C_GO.replace('\t"github.com/bogdanfinn/utls"\n\t"github.com/hashicorp/x"\n',
                                      '\t"github.com/hashicorp/x"\n\t"github.com/igor-lemon/utls"\n'))
        # go.mod merged module by module by the merge driver
        self.assertEqual(fork_sync.requirements(show(f.work, "HEAD", "go.mod")),
                         {"github.com/igor-lemon/utls": PIN, "golang.org/x/text": "v0.1.0",
                          "golang.org/x/net": "v0.2.0", "golang.org/x/sys": "v0.3.0"})
        self.assertIn("\ngo 1.22\n", show(f.work, "HEAD", "go.mod"))
        self.assertEqual(show(f.work, "HEAD", "a.go"),
                         a_go("github.com/igor-lemon/utls", a='fmt.Sprint(tls.X, "!")', b="2"))
        # two patches of one subject are both laid
        self.assertEqual(show(f.work, "HEAD", "d.txt"), "one\ntwo\n")
        self.assertNotIn("side.txt", git(f.work, "ls-tree", "-r", "--name-only", "HEAD"))
        # the fork's checkout is left as it was
        self.assertEqual(git(f.fork, "rev-parse", "HEAD"), f.head)
        self.assertEqual(git(f.fork, "status", "--porcelain"), "")

    def test_a_file_of_the_anchor_the_release_changed_is_said(self):
        f = self.fixture(anchor_license=True)
        code, out, err = f.start("--anchor-only")
        self.assertEqual(code, 0, out + err)
        self.assertIn("warning: LICENSE: the release changed it", err)
        self.assertEqual(show(f.work, "HEAD", "LICENSE"), "license, the fork's\n")
        self.assertEqual(f.subjects(), [ANCHOR])
        code, out, err = run("continue", "--work", f.work)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])

    def test_a_conflict_stops_until_it_is_resolved(self):
        f = self.fixture(conflict=True)
        code, out, err = f.start()
        self.assertEqual(code, 1, out + err)
        self.assertIn("Change A:", out)
        self.assertIn("UU a.go", out)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C"])
        code, out, err = run("continue", "--work", f.work)
        self.assertEqual(code, 1)
        self.assertRegex((out + err).lower(), "unmerged|unresolved conflict")
        write(f.work, "a.go", a_go("github.com/igor-lemon/utls", a='fmt.Sprint(tls.X, "!")',
                                   b="10"))
        git(f.work, "add", "a.go")
        code, out, err = run("continue", "--work", f.work)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])
        self.assertIn("return 10 }", show(f.work, "HEAD", "a.go"))

    def test_a_patch_resolved_to_nothing_is_dropped_for_good(self):
        f = self.fixture(conflict=True)
        self.assertEqual(f.start()[0], 1)
        git(f.work, "checkout", "--ours", "a.go")
        git(f.work, "add", "a.go")
        code, out, err = run("continue", "--work", f.work)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Tidy", "Tidy"])
        self.assertEqual(fork_sync.dropped(f.work), {f.patches[1]})
        # laid over again: the patch is not picked, so nothing stops
        code, out, err = run("continue", "--work", f.work)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Tidy", "Tidy"])

    def test_what_is_asked_after_a_patch_left_empty_waits_for_the_next(self):
        # the release has the first Tidy's file as it wrote it: nothing is
        # left of that patch, and its command must not change Change A
        f = self.fixture(v2_tidy="one\n")
        code, out, err = f.start("--run", "Tidy=echo ran > ran.txt")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy"])
        self.assertEqual(fork_sync.dropped(f.work), {f.patches[2]})
        names = lambda s: git(f.work, "diff-tree", "--no-commit-id", "--name-only", "-r",
                              f.at(s)).splitlines()
        self.assertNotIn("ran.txt", names("Change A"))
        self.assertIn("ran.txt", names("Tidy"))
        self.assertEqual(show(f.work, "HEAD", "d.txt"), "one\ntwo\n")
        self.assertIn("nothing is left of it over the release: dropped",
                      read(f.work, ".git/fork-sync-log"))

    def test_a_stop_between_two_patches_of_one_subject_lays_the_second(self):
        f = self.fixture(v2_tidy="zero\n")
        code, out, err = f.start()
        self.assertEqual(code, 1, out + err)
        self.assertIn("AA d.txt", out)
        write(f.work, "d.txt", "one\n")
        git(f.work, "add", "d.txt")
        code, out, err = run("continue", "--work", f.work)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])
        self.assertEqual(show(f.work, "HEAD", "d.txt"), "one\ntwo\n")

    def test_conflicts_of_the_rename_alone_take_the_patchs_side(self):
        f = self.fixture(keeps_utls=True)
        code, out, err = f.start()
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects()[:2], [ANCHOR, "Take utls from its fork"])
        self.assertIn('\t_ "github.com/igor-lemon/utls/dicttls"\n',
                      show(f.work, "HEAD", "a.go"))
        self.assertIn("conflicts of the rename alone",
                      read(f.work, ".git/fork-sync-log"))

    def test_an_oracle_resolves_every_conflict(self):
        f = self.fixture(conflict=True, old_file=True)
        final = a_go("github.com/igor-lemon/utls", a='fmt.Sprint(tls.X, "!")', b="10")
        oracle = f.on_branch("oracle", {"a.go": final,
                                        "old.go": "package fhttp\n\nvar Old = 2\n"})
        code, out, err = f.start("--oracle", oracle)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects()[-1], "Touch old")
        self.assertEqual(show(f.work, "HEAD", "a.go"), final)
        self.assertEqual(show(f.work, "HEAD", "old.go"), "package fhttp\n\nvar Old = 2\n")
        log = read(f.work, ".git/fork-sync-log")
        self.assertIn("a.go: hunk 1: theirs", log)
        self.assertIn("old.go: DU, kept (the oracle has it)", log)

    def test_an_oracle_without_a_file_takes_it_away(self):
        f = self.fixture(conflict=True, old_file=True)
        final = a_go("github.com/igor-lemon/utls", a='fmt.Sprint(tls.X, "!")', b="10")
        oracle = f.on_branch("oracle", {"a.go": final})
        code, out, err = f.start("--oracle", oracle)
        self.assertEqual(code, 0, out + err)
        # nothing is left of the patch that changed it: it goes
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])
        self.assertNotIn("old.go", git(f.work, "ls-tree", "-r", "--name-only", "HEAD"))
        self.assertFalse(os.path.exists(os.path.join(f.work, "old.go")))
        log = read(f.work, ".git/fork-sync-log")
        self.assertIn("old.go: DU, removed (the oracle has not)", log)
        self.assertIn("nothing is left of it: skipped", log)

    def test_a_conflict_the_oracle_cannot_resolve_is_left_by_hand(self):
        f = self.fixture(conflict=True)
        oracle = f.on_branch("oracle", {}, remove=["a.go"])
        code, out, err = f.start("--oracle", oracle)
        self.assertEqual(code, 1)
        self.assertIn("left to resolve by hand", out)
        self.assertIn("a.go  (not in the oracle)", out)

    def test_a_file_both_sides_moved_is_left_by_hand(self):
        f = self.fixture(moved=True)
        oracle = f.on_branch("oracle", {"moved.txt": "moved\n"})
        code, out, err = f.start("--oracle", oracle)
        self.assertEqual(code, 1, out + err)
        self.assertIn("left to resolve by hand", out)
        for line in ("DD x.txt", "AU y.txt", "UA z.txt"):
            self.assertIn(line, out)
        self.assertNotIn("moved.txt", out)

    def test_start_again_in_the_same_work_starts_afresh(self):
        f = self.fixture()
        self.assertEqual(f.start()[0], 0)
        first = fork_sync.state(f.work, "anchor")
        # An anchor made again differs from the first by its committer's date
        # alone, which git keeps in whole seconds: two starts within one
        # second made the same commit, and this test failed (one run in ten
        # here, and release.yml's dry run 43038559597). The second start is
        # dated another day.
        with mock.patch.dict(os.environ,
                             {"GIT_COMMITTER_DATE": "2001-02-03T04:05:06Z"}):
            code, out, err = f.start()
        self.assertEqual(code, 0, out + err)
        self.assertNotEqual(fork_sync.state(f.work, "anchor"), first)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])

    def test_a_command_runs_and_a_file_is_laid_in_after_a_patch(self):
        f = self.fixture()
        extra = f.on_branch("extra", {"extra.txt": "extra\n"})
        code, out, err = f.start("--run", "Add C=echo ran > ran.txt",
                                 "--inject", f"Change A=extra.txt@{extra}")
        self.assertEqual(code, 0, out + err)
        names = lambda s: git(f.work, "diff-tree", "--no-commit-id", "--name-only", "-r",
                              f.at(s)).splitlines()
        self.assertIn("ran.txt", names("Add C"))
        self.assertIn("extra.txt", names("Change A"))
        log = read(f.work, ".git/fork-sync-log")
        self.assertIn("ran: echo ran > ran.txt", log)
        self.assertIn("extra.txt: laid in from", log)

    def test_a_command_for_a_patch_there_is_not_is_refused(self):
        f = self.fixture()
        code, out, err = f.start("--run", "Nope=true")
        self.assertEqual(code, 1)
        self.assertIn("no patch is called: Nope", err)

    def test_a_branch_without_an_anchor_is_refused(self):
        f = self.fixture()
        with self.assertRaises(SystemExit) as e:
            fork_sync.series(f.fork, "v2")
        self.assertIn("no commit «Rename the module", str(e.exception.code))

    def test_series_lists_the_anchor_and_the_patches(self):
        f = self.fixture()
        code, out, err = run("series", f.fork)
        self.assertEqual(code, 0, err)
        self.assertEqual([line.split(" ", 1)[1] for line in out.splitlines()],
                         [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])


class AfterStartTests(Repos):
    def started(self, **kw):
        f = self.fixture(**kw)
        code, out, err = f.start()
        self.assertEqual(code, 0, out + err)
        return f

    def test_finish_merges_the_old_head_and_says_how_the_patches_changed(self):
        f = self.started()
        tip = git(f.work, "rev-parse", "HEAD")
        code, out, err = run("finish", "--work", f.work, "-m", "Patches laid over v2")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(git(f.work, "rev-parse", "HEAD^1"), tip)
        self.assertEqual(git(f.work, "rev-parse", "HEAD^2"), f.head)
        self.assertEqual(git(f.work, "rev-parse", "HEAD^{tree}"),
                         git(f.work, "rev-parse", tip + "^{tree}"))
        self.assertEqual(git(f.work, "log", "-1", "--format=%s"), "Patches laid over v2")
        counts = dict(re.findall(r"(were|changed|gone|new) (\d+)", out))
        # Add C changed more than range-diff pairs: gone and new, or changed
        self.assertEqual(counts["were"], "3", out)
        self.assertIn((counts["changed"], counts["gone"], counts["new"]),
                      {("1", "0", "0"), ("0", "1", "1")}, out)
        self.assertIn("the tree is not the old head's", out)
        self.assertIn(f"new head {git(f.work, 'rev-parse', 'HEAD')}", out)
        self.assertIn("Add C", read(f.work, ".git/fork-sync-range-diff"))
        # the new branch is laid out as the old: its series is the new one,
        # and the old head merged in is none of the patches checked
        self.assertEqual(fork_sync.series(f.work, "HEAD")[0], fork_sync.state(f.work, "anchor"))
        code, out, err = run("check", "--work", f.work, "--build", "true")
        self.assertEqual(code, 0, out + err)
        self.assertIn("5 of 5 build", out)

    def test_a_patch_after_an_earlier_finish_keeps_the_old_history_out(self):
        f = self.started()
        self.assertEqual(run("finish", "--work", f.work, "-m", "Patches laid over v2")[0], 0)
        git(f.fork, "fetch", "-q", f.work, "HEAD")
        git(f.fork, "merge", "-q", "--ff-only", "FETCH_HEAD")
        commit(f.fork, "After", {"after.txt": "after\n"})
        again = os.path.join(self.root, "again")
        code, out, err = run("start", f.fork, "v2", "--work", again)
        self.assertEqual(code, 0, out + err)
        code, out, err = run("finish", "--work", again, "-m", "Patches laid over v2 again")
        self.assertEqual(code, 0, out + err)
        # the patches as they were, none of the branch's earlier history gone
        counts = dict(re.findall(r"(were|changed|gone|new) (\d+)", out))
        self.assertEqual((counts["were"], counts["changed"], counts["gone"], counts["new"]),
                         ("5", "0", "0", "0"), out)
        self.assertIn("the tree is the old head's", out)
        self.assertEqual(git(again, "replace", "-l"), "")

    def test_a_patch_range_diff_pairs_as_changed_is_counted_so(self):
        f = self.fixture(conflict=True)
        self.assertEqual(f.start()[0], 1)
        write(f.work, "a.go", a_go("github.com/igor-lemon/utls", a='fmt.Sprint(tls.X, "!")',
                                   b="10"))
        git(f.work, "add", "a.go")
        self.assertEqual(run("continue", "--work", f.work)[0], 0)
        code, out, err = run("finish", "--work", f.work, "-m", "Patches laid over v2")
        self.assertEqual(code, 0, out + err)
        counts = dict(re.findall(r"(were|changed|gone|new) (\d+)", out))
        self.assertGreaterEqual(int(counts["changed"]), 1, out)

    def test_absorb_and_fix_refuse_a_finished_series(self):
        f = self.started()
        self.assertEqual(run("finish", "--work", f.work, "-m", "done")[0], 0)
        write(f.work, "c.go", "x\n")
        for argv in (("absorb", "--work", f.work),
                     ("fix", "--work", f.work, "--at", "Add C", "--cmd", "true")):
            with self.subTest(argv=argv[0]):
                code, out, err = run(*argv)
                self.assertEqual(code, 1)
                self.assertIn("the series is finished", err)
        self.assertEqual(read(f.work, "c.go"), "x\n")

    def test_nothing_finishes_or_absorbs_while_a_conflict_is_open(self):
        f = self.fixture(conflict=True)
        self.assertEqual(f.start()[0], 1)
        for argv in (("finish", "--work", f.work, "-m", "x"), ("absorb", "--work", f.work)):
            with self.subTest(argv=argv[0]):
                code, out, err = run(*argv)
                self.assertEqual(code, 1)
                self.assertIn("an operation is under way", err)

    def test_what_is_uncommitted_goes_into_the_patch_that_wrote_its_lines(self):
        f = self.started()
        write(f.work, "c.go", show(f.work, "HEAD", "c.go").replace("x.Name", "x.Other"))
        write(f.work, "d.txt", "one\nTWO\n")
        code, out, err = run("absorb", "--work", f.work)
        self.assertEqual(code, 0, out + err)
        self.assertIn("squashed in; tree is the oracle's", out)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])
        self.assertIn("x.Other", show(f.work, f.at("Add C"), "c.go"))
        # into the second of two patches of one subject, which wrote the line
        tidies = git(f.work, "log", "--reverse", "--format=%H", "--grep=^Tidy$",
                     fork_sync.state(f.work, "anchor") + "..HEAD").split()
        self.assertEqual(show(f.work, tidies[0], "d.txt"), "one\n")
        self.assertEqual(show(f.work, tidies[1], "d.txt"), "one\nTWO\n")
        self.assertEqual(git(f.work, "status", "--porcelain"), "")

    def test_an_oracle_given_is_absorbed_and_the_tree_left_alone(self):
        f = self.started()
        anchor = fork_sync.state(f.work, "anchor")
        write(f.work, "c.go", show(f.work, "HEAD", "c.go").replace("x.Name", "x.Other"))
        git(f.work, "add", "c.go")
        oracle = git(f.work, "commit-tree", git(f.work, "write-tree"), "-p", "HEAD", "-m", "o")
        git(f.work, "reset", "-q", "--hard", "HEAD")
        code, out, err = run("absorb", "--work", f.work, "--oracle", oracle)
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("absorbing", out)
        self.assertEqual(git(f.work, "rev-parse", "HEAD^{tree}"),
                         git(f.work, "rev-parse", oracle + "^{tree}"))
        self.assertEqual(fork_sync.state(f.work, "anchor"), anchor)

    def test_a_line_without_its_newline_is_absorbed_as_it_is(self):
        f = self.started()
        for text in ("a\nB", "a\nB\nc", "a\nB\nc\n"):
            with self.subTest(text=text):
                write(f.work, "nonl.txt", text)
                code, out, err = run("absorb", "--work", f.work)
                self.assertEqual(code, 0, out + err)
                self.assertEqual(git(f.work, "cat-file", "blob",
                                     f.at("Add C") + ":nonl.txt") + ("\n" if text.endswith("\n") else ""),
                                 text)

    def test_a_hunk_beside_a_later_patchs_line_goes_into_that_patch(self):
        # the first Tidy wrote "one", the second the line after it: moved to
        # the first, the hunk would not go past the second
        f = self.started()
        write(f.work, "d.txt", "ONE\ntwo\n")
        code, out, err = run("absorb", "--work", f.work)
        self.assertEqual(code, 0, out + err)
        self.assertIn("squashed in; tree is the oracle's", out)
        tidies = git(f.work, "log", "--reverse", "--format=%H", "--grep=^Tidy$",
                     fork_sync.state(f.work, "anchor") + "..HEAD").split()
        self.assertEqual(show(f.work, tidies[0], "d.txt"), "one\n")
        self.assertEqual(show(f.work, tidies[1], "d.txt"), "ONE\ntwo\n")

    def test_a_rule_that_puts_a_hunk_where_it_cannot_go_is_settled_toward_the_tree(self):
        f = self.started()
        write(f.work, "d.txt", "ONE\ntwo\n")
        code, out, err = run("absorb", "--work", f.work, "--to", "Add C=d.txt")
        self.assertEqual(code, 0, out + err)
        self.assertIn("squashed in; tree is the oracle's", out)
        self.assertIn("absorb\n", read(f.work, ".git/fork-sync-log"))

    def test_fixups_that_miss_the_tree_go_no_further(self):
        f = self.started()
        head = git(f.work, "rev-parse", "HEAD")
        write(f.work, "c.go", show(f.work, "HEAD", "c.go").replace("x.Name", "x.Other"))
        real = fork_sync.hunks_between

        def amiss(*args):
            return [[s, n, lines + ["amiss\n"]] for s, n, lines in real(*args)]

        with mock.patch.object(fork_sync, "hunks_between", amiss):
            code, out, err = run("absorb", "--work", f.work)
        self.assertEqual(code, 1)
        self.assertIn("the fixups do not make the oracle's tree", err)
        self.assertNotEqual(git(f.work, "rev-parse", "HEAD"), head)  # left to look at

    def test_a_dry_run_says_where_and_leaves_the_tree_as_it_was(self):
        f = self.started()
        head = git(f.work, "rev-parse", "HEAD")
        changed = show(f.work, "HEAD", "c.go").replace("x.Name", "x.Other")
        write(f.work, "c.go", changed)
        code, out, err = run("absorb", "--work", f.work, "--dry-run")
        self.assertEqual(code, 0, out + err)
        self.assertIn("Add C: c.go#1", out)
        self.assertEqual(git(f.work, "rev-parse", "HEAD"), head)
        self.assertEqual(read(f.work, "c.go"), changed)

    def test_a_hunk_no_patch_wrote_is_refused_and_left_as_it_was(self):
        f = self.started()
        head = git(f.work, "rev-parse", "HEAD")
        write(f.work, "b.go", show(f.work, "HEAD", "b.go") + "// more\n")
        write(f.work, "new.txt", "new\n")
        code, out, err = run("absorb", "--work", f.work)
        self.assertEqual(code, 1)
        self.assertIn("b.go#1 (lines 5,0)", out)
        self.assertIn("new.txt (whole file)", out)
        self.assertEqual(git(f.work, "rev-parse", "HEAD"), head)
        self.assertTrue(read(f.work, "b.go").endswith("// more\n"))
        self.assertEqual(read(f.work, "new.txt"), "new\n")

    def test_rules_and_nearness_place_what_no_patch_wrote(self):
        f = self.started()
        write(f.work, "b.go", show(f.work, "HEAD", "b.go") + "// more\n")
        write(f.work, "new.txt", "new\n")
        write(f.work, "a.go", show(f.work, "HEAD", "a.go").replace("spacer one", "spacer 1"))
        os.remove(os.path.join(f.work, "c.go"))
        code, out, err = run("absorb", "--work", f.work, "--near", "2",
                             "--to", "Add C=b.go#1", "--to", "Change A=new.txt")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])
        add_c = git(f.work, "diff-tree", "--no-commit-id", "--name-status", "-r", f.at("Add C"))
        self.assertIn("b.go", add_c)
        self.assertNotIn("c.go", add_c)
        self.assertIn("spacer 1", show(f.work, f.at("Change A"), "a.go"))
        self.assertEqual(show(f.work, f.at("Change A"), "new.txt"), "new\n")

    def test_a_rule_for_a_patch_there_is_not_is_refused(self):
        f = self.started()
        write(f.work, "b.go", "x\n")
        code, out, err = run("absorb", "--work", f.work, "--to", "Nope=b.go")
        self.assertEqual(code, 1)
        self.assertIn("no patch is called: Nope", err)
        self.assertEqual(read(f.work, "b.go"), "x\n")

    def test_fix_changes_a_patch_and_lays_the_rest_over_again(self):
        f = self.started()
        # a large repository's names are longer than seven digits in a todo
        git(f.work, "config", "core.abbrev", "12")
        code, out, err = run("fix", "--work", f.work, "--at", "Add C",
                             "--cmd", "printf 'var D = 1\\n' >> c.go")
        self.assertEqual(code, 0, out + err)
        self.assertIn("fixed", out)
        self.assertEqual(f.subjects(), [ANCHOR, "Add C", "Change A", "Tidy", "Tidy"])
        self.assertTrue(show(f.work, f.at("Add C"), "c.go").endswith("var D = 1\n"))
        code, out, err = run("fix", "--work", f.work, "--at", "Tidy", "--cmd", "true")
        self.assertEqual(code, 1)
        self.assertIn("2 patches are called: Tidy", err)

    def test_fix_stops_at_a_later_patch_it_clashes_with(self):
        f = self.started()
        code, out, err = run("fix", "--work", f.work, "--at", "Add C",
                             "--cmd", "printf 'package fhttp\\n' > a.go")
        self.assertEqual(code, 1, out + err)
        self.assertIn("stopped:", out)
        self.assertIn("a.go", out)
        self.assertIn("rebase --continue", out)

    def test_fix_says_whether_the_tree_is_the_oracles(self):
        f = self.fixture()
        self.assertEqual(f.start("--oracle", "v2")[0], 0)
        code, out, err = run("fix", "--work", f.work, "--at", "Add C",
                             "--cmd", "true")
        self.assertEqual(code, 0, out + err)
        self.assertIn("fixed; tree is NOT the oracle's", out)

    def test_fix_says_when_the_rebase_did_not_stop_at_the_patch(self):
        f = self.started()
        real = subprocess.run

        def rebase_through(args, *a, **kw):
            if "rebase" in args:
                return subprocess.CompletedProcess(args, 0, "", "went through")
            return real(args, *a, **kw)

        with mock.patch.object(fork_sync.subprocess, "run", rebase_through):
            code, out, err = run("fix", "--work", f.work, "--at", "Add C", "--cmd", "true")
        self.assertEqual(code, 1)
        self.assertIn("the rebase did not stop at the patch: went through", err)

    def test_check_says_a_commit_it_could_not_export(self):
        f = self.started()
        real = subprocess.Popen

        def popen(args, **kw):
            if "archive" in args:
                args = ["git", "-C", f.work, "archive", "nowhere"]
            return real(args, **kw)

        with mock.patch.object(fork_sync.subprocess, "Popen", popen):
            code, out, err = run("check", "--work", f.work, "--build", "true")
        self.assertEqual(code, 1)
        self.assertIn("could not be exported", err)

    def test_check_builds_every_commit_in_an_export_of_its_own(self):
        f = self.started()
        bin_ = os.path.join(self.root, "bin")
        log = os.path.join(self.root, "go.log")
        write(bin_, "go", '#!/bin/sh\necho "go $* in $(basename "$PWD")" >> "$FAKE_GO_LOG"\n'
              'test -f LEMON.md || exit 3\nexit "${FAKE_GO_EXIT:-0}"\n')
        os.chmod(os.path.join(bin_, "go"), stat.S_IRWXU)
        other = os.path.join(self.root, "other")
        env = {"PATH": bin_ + os.pathsep + os.environ["PATH"], "FAKE_GO_LOG": log}
        with mock.patch.dict(os.environ, env):
            code, out, err = run("check", "--work", f.work, "--with", other,
                                 "--build", "go build ./...", "--test", "./... -run X")
            self.assertEqual(code, 0, out + err)
            self.assertIn("5 of 5 build", out)
            calls = read(self.root, "go.log").splitlines()
            self.assertEqual(len(calls), 11)
            self.assertEqual(calls[0], f"go work init . {other} in "
                             + fork_sync.state(f.work, "anchor")[:12])
            self.assertEqual(calls[-1].split(" in ")[0], "go test -count=1 ./... -run X")
            with mock.patch.dict(os.environ, {"FAKE_GO_EXIT": "1"}):
                code, out, err = run("check", "--work", f.work, "--build", "go vet",
                                     "--test", "./...", "--last-only")
            self.assertEqual(code, 1)
            self.assertIn("FAILS", out)
            self.assertIn("0 of 1 build; tests fail", out)
        made, real = [], tempfile.mkdtemp

        def mkdtemp(**kw):
            made.append(real(**kw))
            return made[-1]

        with mock.patch.object(fork_sync.tempfile, "mkdtemp", mkdtemp):
            self.assertEqual(run("check", "--work", f.work, "--build", "true")[0], 0)
        self.assertEqual(len(made), 1)
        self.assertFalse(os.path.exists(made[0]))


class ReviewTests(Repos):
    """review against a release of two the author made in four commits, and a
    branch laid over the second whose patches rewrite, write beside, bring
    back and take away what the author did."""

    A = textwrap.dedent("""\
        package x

        import "github.com/bogdanfinn/utls"

        func A() int { return 1 }
        func B() int { return 1 }
        func C() int { return 1 }
        // said twice
        // said twice
        // removed by the author
        // removed by the author, again in the fork
        """)

    def make(self):
        up = os.path.join(self.root, "up")
        os.makedirs(up)
        git(up, "init", "-q", "-b", "main")
        commit(up, "v1", {"a.go": self.A, "gone.go": "package x\n\nvar Gone = 1\n",
                          "go.sum": "a h1:x\n", "with space.txt": "first\n",
                          "q.sql": "-- comment one\nselect 1;\n",
                          "old space.txt": "gone with its spaces\n"})
        git(up, "tag", "v1")
        # one of two lines alike goes; U and V name a fork the anchor renames
        a = self.A.replace("A() int { return 1 }", "A() int { return 2 }").replace(
            "// said twice\n// said twice\n", "// said twice\n").replace(
            "// removed by the author\n// removed by the author, again in the fork\n",
            'var U = "github.com/bogdanfinn/utls/u"\n'
            'var V = "github.com/bogdanfinn/utls/v"\n'
            "func D() int { return 4 }\n)});\n")
        self.u1 = commit(up, "Change A, add D", {
            "a.go": a, "go.sum": "a h1:y\n", "with space.txt": "first\nsecond line here\n",
            "naïve.txt": "a name past ASCII\n"})
        self.u2 = commit(up, "Later", {"later.go": "package x\n\nvar Later = 1\n",
                                       "a.go": a + "func E() int { return 5 }\n"},
                         remove=["gone.go", "old space.txt"])
        self.u3 = commit(up, "SQL", {"a.go": a, "q.sql": "++ plus line\nselect 1;\n"})
        self.u4 = commit(up, "Sums alone", {"go.sum": "a h1:z\n", "b.txt": "{  }\n"})
        git(up, "tag", "v2")
        git(up, "checkout", "-q", "-b", "tls-forge")
        commit(up, ANCHOR + " github.com/igor-lemon/x",
               {"a.go": fork_sync.rename_text(read(up, "a.go"))})
        self.p1 = commit(up, "Keep A", {"a.go": read(up, "a.go").replace(
            "A() int { return 2 }", "A() int { return 1 }").replace(
            "utls/u\"", "utls/ours\"")})
        self.p2 = commit(up, "Beside D", {"a.go": read(up, "a.go").replace(
            "func D() int { return 4 }\n", "func D() int { return 4 }\n// ours\n")})
        self.p3 = commit(up, "Bring a comment back", {
            "a.go": read(up, "a.go") + "// removed by the author, again in the fork\n"})
        self.p4 = commit(up, "No later", {"own.go": "package x\n"}, remove=["later.go"])
        self.p5 = commit(up, "Change B", {"a.go": read(up, "a.go").replace(
            "B() int { return 1 }", "B() int { return 22 }")})
        git(up, "checkout", "-q", "-b", "side", "v2")
        commit(up, "side", {"side.txt": "side\n"})
        git(up, "checkout", "-q", "tls-forge")
        git(up, "merge", "-q", "-s", "ours", "--no-ff", "-m", "Merge side", "side")
        return up

    def test_review_says_where_the_patches_meet_the_authors_changes(self):
        up = self.make()
        code, out, err = run("review", up, "--since", "v1")
        self.assertEqual(code, 0, err)
        r = json.loads(out)
        short = lambda c: c[:9]
        self.assertEqual(r["since"], short(git(up, "rev-parse", "v1")))
        self.assertEqual(r["onto"], short(git(up, "rev-parse", "v2")))
        patches = {p["subject"]: p["upstream"] for p in r["patches"]}
        # Change B rewrites a line of v1's: none of the author's fresh ones
        self.assertEqual(sorted(patches), ["Beside D", "Bring a comment back",
                                           "Keep A", "No later"])
        # U's line, though the anchor renamed it last, is the author's
        self.assertEqual(patches["Keep A"], {short(self.u1): {
            "subject": "Change A, add D", "files": {"a.go": {"rewritten": 2, "beside": 0}}}})
        beside = patches["Beside D"][short(self.u1)]["files"]["a.go"]
        self.assertEqual(beside, {"rewritten": 0, "beside": 2})
        # an insertion at the end has only the line before it
        self.assertEqual(patches["Bring a comment back"][short(self.u1)]["files"],
                         {"a.go": {"rewritten": 0, "beside": 1}})
        self.assertEqual(patches["No later"], {short(self.u2): {
            "subject": "Later", "files": {"later.go": {"rewritten": 3, "beside": 0}}}})
        upstream = {u["subject"]: u for u in r["upstream"]}
        # Sums alone: go.sum and a slight line, nothing to say
        self.assertEqual(sorted(upstream), ["Change A, add D", "Later", "SQL"])
        u1 = upstream["Change A, add D"]["files"]
        self.assertEqual(u1["a.go"]["lost"], ["func A() int { return 2 }",
                                             'var U = "github.com/igor-lemon/utls/u"'])
        # Keep A brought v1's line back, and a patch one of the comments
        self.assertEqual(u1["a.go"]["returned"],
                         ["func A() int { return 1 }",
                          "// removed by the author, again in the fork"])
        # V kept, renamed on both sides; a line said twice still said once
        self.assertEqual((u1["a.go"]["added"], u1["a.go"]["kept"],
                          u1["a.go"]["removed"], u1["a.go"]["back"]), (4, 2, 3, 2))
        self.assertNotIn("go.sum", u1)
        self.assertEqual(u1["with space.txt"]["kept"], 1)
        self.assertEqual(u1["naïve.txt"], {"added": 1, "kept": 1, "removed": 0, "back": 0,
                                          "lost": [], "returned": []})
        u2 = upstream["Later"]["files"]
        # what Later added and SQL took away again is none of the head's business
        self.assertNotIn("a.go", u2)
        self.assertEqual(u2["later.go"]["lost"], ["package x", "var Later = 1"])
        self.assertEqual(u2["gone.go"]["removed"], 2)
        self.assertEqual(u2["old space.txt"]["removed"], 1)
        u3 = upstream["SQL"]["files"]["q.sql"]
        self.assertEqual((u3["added"], u3["kept"], u3["removed"], u3["back"]), (1, 1, 1, 0))
        self.assertEqual(upstream["SQL"]["added"], 1)

    def test_review_of_a_branch_without_an_anchor_is_refused(self):
        up = self.make()
        code, _, err = run("review", up, "--since", "v1", "--head", "v2")
        self.assertEqual(code, 1)
        self.assertIn("no commit «Rename the module…»", err)

    def test_slight_lines_are_told_apart(self):
        for line, slight in (("}", True), ("{  }", True), (")});", True), ("//", True),
                             ("/*", True), ("x++", True), ("x++;", False),
                             ("x := 1", False), ("return x", False)):
            self.assertEqual(fork_sync.trivial(line), slight, line)


class SpacesTests(Repos):
    def test_every_command_works_where_a_path_has_a_space(self):
        spaced = os.path.join(self.root, "a dir")
        os.makedirs(spaced)
        script = os.path.join(spaced, "fork sync.py")
        shutil.copy(SCRIPT, script)
        f = Fixture(spaced)

        def cli(*argv):
            return subprocess.run([sys.executable, script, *argv], capture_output=True,
                                  text=True)

        r = cli("start", f.fork, "v2", "--work", f.work)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("golang.org/x/sys v0.3.0", show(f.work, "HEAD", "go.mod"))
        r = cli("check", "--work", f.work, "--build", "test -f LEMON.md", "--last-only")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = cli("fix", "--work", f.work, "--at", "Add C", "--cmd", "echo more >> c.go")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(show(f.work, f.at("Add C"), "c.go").endswith("more\n"))


if __name__ == "__main__":
    unittest.main()
