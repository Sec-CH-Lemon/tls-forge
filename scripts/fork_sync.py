#!/usr/bin/env python3
"""Lay tls-forge's patches of a fork over a release of bogdanfinn's.

A fork's branch `tls-forge` is, along its first parents: a release of
bogdanfinn's; the commit that renames the modules (the anchor, its subject
"Rename the module ..."); this fork's patches, one commit a change; and on
top, merges `-s ours` of the branch's earlier heads, so that the branch only
moves forward and every commit a published pin names stays in it. This
script lays the patches over another release, in a clone (WORK) of the
fork's checkout, which it never changes:

  start FORK REF  the anchor made again over bogdanfinn's REF (the modules of
                  the five forks renamed in every Go file and go.mod, imports
                  sorted, the anchor's own files such as LEMON.md taken), then
                  the patches cherry-picked one at a time, each renamed the
                  same way (an old patch may name bogdanfinn's path). git
                  rerere remembers a resolution; go.mod is merged module by
                  module (the higher version), go.sum by union. A conflict
                  stops it: resolve, `git add`, then
  continue        the patch committed and the rest laid over.
  absorb          what is uncommitted in WORK (or --oracle's tree), laid into
                  the patches: each hunk into the newest patch that wrote its
                  lines or the line on either side (--near N: or the N lines
                  around them), unless
                  --to "SUBJECT=PATH[#N,...]" says which; then squashed in.
  fix             --at SUBJECT changed by --cmd, the patches after it laid
                  over again.
  check           go build and go vet (--build CMD) at every commit of the new
                  series, each in an export of its own; --with DIR adds a
                  module to a go.work there (a fork's other forks).
  finish          the new series merged with the fork's head `-s ours`; prints
                  `git range-diff` of the old series and the new, and the
                  command that moves the fork's branch.
  series FORK     the anchor and the patches of the fork's branch.
  review FORK     --since OLD: where the patches meet what the author changed
                  since the release they were over (JSON): the author's fresh
                  lines each patch rewrites or writes beside, and, for each of
                  the author's commits, the lines it added the head lacks
                  (`lost`) and the lines it removed the head has again
                  (`returned`), the modules renamed. Whatever is lost or
                  returned is a patch's to answer for: the same fix the author
                  made goes, the fork's own reason stays, said in LEMON.md.

With --oracle REV (a tree the series must end at: converting a branch that
merged a release), start resolves every conflict toward REV's files itself,
--inject "SUBJECT=PATH@REV" lays a file in after a patch and --run
"SUBJECT=CMD" runs a command after it.
"""
import argparse
import collections
import contextlib
import difflib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

FORKS = ["utls", "fhttp", "websocket", "quic-go-utls", "tls-client"]
NEW = "github.com/igor-lemon/"
ANCHOR = "Rename the module"
STATE = "fork-sync"  # under WORK/.git


def git(cwd, *args, check=True, capture=True):
    r = subprocess.run(["git", "-C", cwd, *args], text=True,
                       capture_output=capture)
    if check and r.returncode != 0:
        sys.exit(f"git {' '.join(args)}: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout.strip() if capture else ""


def first_parents(repo, head):
    return git(repo, "rev-list", "--first-parent", head).split()


def series(repo, head):
    """The anchor and the patches after it, oldest first, of head's first
    parents: merges are passed over (they are earlier heads, or an upstream
    release merged before this script)."""
    patches = []
    for c in first_parents(repo, head):
        subject = git(repo, "log", "-1", "--format=%s", c)
        if subject.startswith(ANCHOR):
            return c, list(reversed(patches))
        if len(git(repo, "rev-list", "--parents", "-n1", c).split()) == 2:
            patches.append(c)
    sys.exit(f"{head}: no commit «{ANCHOR}…» along its first parents")


MODULE = re.compile(r"github\.com/bogdanfinn/(" +
                    "|".join(re.escape(f) for f in FORKS) + r")(?![A-Za-z0-9-])")


def rename_text(text):
    return MODULE.sub(lambda m: NEW + m.group(1), text)


def rename(work, pins):
    """bogdanfinn's modules that have forks renamed in every Go file and in
    go.mod; a forked module go.mod requires takes the version pins gives."""
    changed = []
    for root, dirs, files in os.walk(work):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            if not (name.endswith(".go") or name == "go.mod"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if name == "go.mod":
                # a commented line (an old replace) is left as it was
                new = repin("".join(l if l.lstrip().startswith("//") else
                                    rename_text(l)
                                    for l in text.splitlines(keepends=True)),
                            pins)
            else:
                new = rename_text(text)
            if new != text:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new)
                if name.endswith(".go"):
                    changed.append(path)
    for path in changed:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        new = sort_imports(text)
        if new != text:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)


SPEC = re.compile(r'^\t(?:[\w.]+ )?"([^"]+)"(?:\s*//.*)?$')


def sort_imports(text):
    """Each run of import specs of a parenthesized import block sorted by
    path, as gofmt sorts them; nothing else of the file is touched (gofmt
    would also lay out doc comments as its Go version does)."""
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        out.append(lines[i])
        if lines[i] == "import (":
            i += 1
            run = []
            while i < len(lines) and lines[i] != ")":
                m = SPEC.match(lines[i])
                if m and any(l == lines[i] for _, l in run):
                    pass  # the same import twice: a rename made it so
                elif m:
                    run.append((m.group(1), lines[i]))
                else:
                    out += [l for _, l in sorted(run, key=lambda x: x[0])]
                    run = []
                    out.append(lines[i])
                i += 1
            out += [l for _, l in sorted(run, key=lambda x: x[0])]
            continue
        i += 1
    return "\n".join(out)


REQ = re.compile(r"^(\s*(?:require\s+)?)(\S+)(\s+)(v\S+)(.*)$")


def require_lines(text):
    """Each line of a go.mod's text, and REQ's match of it where it is a
    requirement: a require line, or a line of a require block (a replace or
    exclude block's lines are none)."""
    block = False
    for line in text.splitlines(keepends=True):
        s, m = line.strip(), None
        if s.startswith("require ("):
            block = True
        elif block and s == ")":
            block = False
        elif block or s.startswith("require "):
            m = REQ.match(line.rstrip("\n"))
        yield line, m


def requirements(text):
    """module -> version of every require of a go.mod's text."""
    return {m.group(2): m.group(4) for _, m in require_lines(text) if m}


def repin(text, pins):
    lines = []
    for line, m in require_lines(text):
        if m and m.group(2) in pins:
            line = (m.group(1) + m.group(2) + m.group(3) + pins[m.group(2)]
                    + m.group(5) + ("\n" if line.endswith("\n") else ""))
        lines.append(line)
    return "".join(lines)


GOVERSION = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+)|(alpha|beta|rc)(\d+))?$")


def go_version_key(v):
    """As go/version orders Go versions: 1.21 < 1.21rc1 < 1.21.0 < 1.21.1;
    a version it does not read is below every other."""
    m = GOVERSION.match(v)
    if not m:
        return (-1,)
    major, minor = int(m.group(1)), int(m.group(2) or 0)
    if m.group(3) is not None:
        return (major, minor, 4, int(m.group(3)))
    if m.group(4):
        return (major, minor, ("alpha", "beta", "rc").index(m.group(4)) + 1,
                int(m.group(5)))
    return (major, minor, 0, 0)


def semver_key(v):
    m = re.match(r"^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$", v)
    if not m:
        return ((0, 0, 0), 0, ())
    pre = m.group(4)
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p)
                for p in pre.split(".")) if pre else ()
    # a release sorts after every prerelease of its version
    return (tuple(int(x) for x in m.group(1, 2, 3)), 0 if pre else 1, ids)


def higher(a, b):
    return a if semver_key(a) >= semver_key(b) else b


def place(text, removed, new):
    """text without the requirements of removed, and each line of new
    (module -> its require line) in a require block of its kind, `//
    indirect` or not, where its module sorts: the first block of that kind,
    else the first block, else a block of its own at the end. A block left
    with nothing in it goes (2026-11-11: a module a patch added in a block of
    its own, and a later patch took away, left `require (\\n)`)."""
    lines = list(require_lines(text))
    blocks, start = [], None
    for i, (line, _) in enumerate(lines):
        if line.strip().startswith("require ("):
            start = i
        elif start is not None and line.strip() == ")":
            reqs = [m for _, m in lines[start + 1:i] if m]
            kinds = {"// indirect" in m.group(5) for m in reqs}
            blocks.append((start, i, kinds.pop() if len(kinds) == 1 else None))
            start = None
    before, alone = collections.defaultdict(list), []
    for mod, line in sorted(new.items()):
        fits = [b for b in blocks if b[2] == ("// indirect" in line)] or blocks
        if not fits:
            alone.append(line)
            continue
        start, end, _ = fits[0]
        at = next((j for j in range(start + 1, end)
                   if lines[j][1] and lines[j][1].group(2) > mod), end)
        before[at].append(line)
    text = "".join("".join(before[i]) + ("" if m and m.group(2) in removed else line)
                   for i, (line, m) in enumerate(lines))
    if alone:
        text = text.rstrip("\n") + "\n\nrequire (\n" + "".join(alone) + ")\n"
    return re.sub(r"\n?^require \(\n\)\n", "", text, flags=re.M)


def merge_gomod(base, ours, theirs):
    """ours with theirs's changes since base laid over it, module by module:
    a version both changed is the higher; go is the higher too."""
    b, o, t = requirements(base), requirements(ours), requirements(theirs)
    pins = {}
    for mod, v in t.items():
        if b.get(mod) == v:
            continue
        pins[mod] = higher(o[mod], v) if mod in o else v
    text = repin(ours, {m: v for m, v in pins.items() if m in o})
    comments = {m.group(2): m.group(5) for _, m in require_lines(theirs) if m}
    text = place(text, {m for m in b if m not in t and o.get(m) == b[m]},
                 {m: f"\t{m} {pins[m]}{comments[m]}\n" for m in pins if m not in o})
    gos = [re.search(r"^go (\S+)$", x, re.M) for x in (ours, theirs)]
    if all(gos):
        go = max((g.group(1) for g in gos), key=go_version_key)
        text = re.sub(r"^go \S+$", "go " + go, text, count=1, flags=re.M)
    return text


def gomod_driver(args):
    texts = []
    for path in args:
        with open(path, encoding="utf-8") as f:
            texts.append(f.read())
    base, ours, theirs = texts
    with open(args[1], "w", encoding="utf-8") as f:
        f.write(merge_gomod(base, ours, theirs))


def state(work, key, value=None):
    path = os.path.join(work, ".git", STATE + "-" + key)
    if value is None:
        with open(path) as f:
            return f.read().strip()
    with open(path, "w") as f:
        f.write(value + "\n")


def subject_of(work, c):
    return git(work, "log", "-1", "--format=%s", c)


def dropped(work):
    """The old patches nothing is left of over the release: not picked
    again."""
    path = os.path.join(work, ".git", STATE + "-dropped")
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return set(f.read().split())


def drop(work, c):
    with open(os.path.join(work, ".git", STATE + "-dropped"), "a") as f:
        f.write(c + "\n")


def blob(work, rev, path):
    """path's bytes at rev, or None where rev has no such file."""
    r = subprocess.run(["git", "-C", work, "show", f"{rev}:{path}"],
                       capture_output=True)
    return r.stdout if r.returncode == 0 else None


def staged_nothing(work):
    return subprocess.run(["git", "-C", work, "diff", "--cached", "--quiet",
                           "HEAD"]).returncode == 0


def where(work):
    """HEAD and the commit an operation is picking: what moves as it goes."""
    return tuple(git(work, "rev-parse", "-q", "--verify", ref, check=False)
                 for ref in ("HEAD", "CHERRY_PICK_HEAD", "REBASE_HEAD"))


def in_progress(work):
    """The command that goes on with the operation WORK is in, or None. A
    rebase is known by its directory, as git knows it: a rebase --skip that
    ends one leaves REBASE_HEAD behind; and a pick it stopped at has a
    CHERRY_PICK_HEAD that is the rebase's to go on with."""
    if any(os.path.isdir(os.path.join(work, ".git", d))
           for d in ("rebase-merge", "rebase-apply")):
        return ["rebase", "--continue"]
    if git(work, "rev-parse", "-q", "--verify", "CHERRY_PICK_HEAD", check=False):
        return ["cherry-pick", "--continue"]
    return None


def new_series(work):
    """The patches laid over the anchor, oldest first: along first parents,
    so that once finished, the old head merged in is none of them."""
    anchor = state(work, "anchor")
    return git(work, "rev-list", "--reverse", "--first-parent", "--no-merges",
               f"{anchor}..HEAD").split()


def unfinished(work):
    """Refuses a series finish merged the old head into: a rebase of it
    would lay the old series out again."""
    if git(work, "rev-list", "--merges", f"{state(work, 'anchor')}..HEAD"):
        sys.exit("the series is finished: absorb and fix go before finish")


def rename_patch(work, logf):
    """The rename made of what the last commit brought (an old patch may
    name a module by bogdanfinn's path, as the fork did before it took the
    module from its own fork); amended when it changes anything."""
    changed = []
    for path in git(work, "diff-tree", "--no-commit-id", "--name-only", "-r",
                    "--diff-filter=AM", "HEAD").splitlines():
        if not path.endswith(".go"):
            continue
        full = os.path.join(work, path)
        with open(full, encoding="utf-8") as f:
            text = f.read()
        new = sort_imports(rename_text(text))
        if new != text:
            with open(full, "w", encoding="utf-8") as f:
                f.write(new)
            changed.append(path)
    if changed:
        git(work, "add", *changed)
        git(work, "commit", "-q", "--amend", "--no-edit")
        logf.write(f"  renamed in: {', '.join(changed)}\n")


TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*"|`[^`]*`|\w+|[^\S\n]+|\n|[^\w\s]')


def merge_file(base, ours, theirs, style="zdiff3"):
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for n, t in (("o", ours), ("b", base), ("t", theirs)):
            p = os.path.join(d, n)
            with open(p, "w", encoding="utf-8") as f:
                f.write(t)
            paths.append(p)
        r = subprocess.run(["git", "merge-file", "-p", "--" + style,
                            "-L", "ours", "-L", "base", "-L", "theirs", *paths],
                           capture_output=True, text=True)
        return r.returncode, r.stdout


def token_merge(base, ours, theirs, style="diff3"):
    """base, ours and theirs merged a word at a time (a string literal is a
    word): None where they clash. With style "union" an insertion both made
    at one place is kept twice, ours first."""
    b, o, t = (TOKEN.findall(x) for x in (base, ours, theirs))

    def changes(side):
        return [(i1, i2, side[j1:j2]) for op, i1, i2, j1, j2 in
                difflib.SequenceMatcher(None, b, side, autojunk=False)
                .get_opcodes() if op != "equal"]

    co, ct = changes(o), changes(t)
    out, pos, io, it = [], 0, 0, 0
    while io < len(co) or it < len(ct):
        x = co[io] if io < len(co) else None
        y = ct[it] if it < len(ct) else None
        if x and y and (x[0] < y[1] or (x[0] == y[0])) and \
                (y[0] < x[1] or (x[0] == y[0])):
            # the two touch the same tokens, or insert at one place
            if x == y:
                pick = [x]
            elif style == "union" and x[0] == x[1] == y[0] == y[1]:
                pick = [x, (y[0], y[1], y[2])]
            else:
                return None
            io += 1
            it += 1
        elif y is None or (x and x[0] <= y[0]):
            pick = [x]
            io += 1
        else:
            pick = [y]
            it += 1
        # a pick never begins before pos: changes of one side are apart, and
        # one of each side that touch are a clash or the same insertion
        for i1, i2, rep in pick:
            out += b[pos:i1]
            out += rep
            pos = max(pos, i2)
    out += b[pos:]
    return "".join(out)


def hunks_of(text):
    lines = text.splitlines(keepends=True)
    out, i = [], 0
    while i < len(lines):
        if lines[i].startswith("<<<<<<< "):
            s, part, h = i, "o", {"o": [], "b": [], "t": []}
            i += 1
            while not lines[i].startswith(">>>>>>> "):
                if lines[i].startswith("||||||| "):
                    part = "b"
                elif lines[i].rstrip("\n") == "=======":
                    part = "t"
                else:
                    h[part].append(lines[i])
                i += 1
            out.append((s, i, h))
        i += 1
    return lines, out


def candidates(h):
    o, b, t = ("".join(h[k]) for k in "obt")
    seen, out = set(), []
    tm = token_merge(b, o, t) if (o or t) else None
    tu = token_merge(b, o, t, "union") if (o and t and b) else None
    tr = token_merge(b, t, o, "union") if (o and t and b) else None
    for name, c in (("ours", o), ("theirs", t), ("both", o + t),
                    ("theirs+ours", t + o), ("words", tm),
                    ("words, ours first", tu), ("words, theirs first", tr),
                    ("base", b)):
        if c is not None and c not in seen:
            seen.add(c)
            out.append((name, c))
    return out


def distance(a, b):
    """How far a is from b: the lines that differ, then how unlike each line
    of a that b lacks is the likest line b has that a lacks."""
    gone, come = [], []
    for l in difflib.unified_diff(a.splitlines(), b.splitlines(),
                                  lineterm="", n=0):
        if l.startswith(("+++", "---")):
            continue
        if l[:1] == "-":
            gone.append(l[1:])
        elif l[:1] == "+":
            come.append(l[1:])
    unlike = sum(1 - max((difflib.SequenceMatcher(None, g, c).ratio()
                          for c in come), default=0) for g in gone)
    return (len(gone) + len(come), round(unlike, 6))


def resolve_toward(text, oracle):
    lines, hs = hunks_of(text)
    choice = [candidates(h)[0][1] for _, _, h in hs]
    log = []

    def build(ch):
        res, last = [], 0
        for (s, e, _), c in zip(hs, ch):
            res.append("".join(lines[last:s]))
            res.append(c)
            last = e + 1
        res.append("".join(lines[last:]))
        return "".join(res)

    for n, (_, _, h) in enumerate(hs):
        scored = []
        for name, c in candidates(h):
            trial = list(choice)
            trial[n] = c
            scored.append((distance(build(trial), oracle), name, c))
        scored.sort(key=lambda x: x[0])
        choice[n] = scored[0][2]
        tie = len(scored) > 1 and scored[1][0] == scored[0][0]
        log.append(f"hunk {n + 1}: {scored[0][1]} ({scored[0][0]}"
                   f"{', tie with ' + scored[1][1] if tie else ''})")
    return build(choice), log


def autoresolve(work, oracle, logf):
    status = git(work, "status", "--porcelain")
    stuck = []
    for line in status.splitlines():
        code, path = line[:2], line[3:]
        in_oracle = subprocess.run(["git", "-C", work, "cat-file", "-e",
                                    f"{oracle}:{path}"]).returncode == 0
        if code in ("DU", "UD"):
            # one side deleted what the other changed: as the oracle has it
            if in_oracle:
                side = "3" if code == "DU" else "2"
                blob = subprocess.run(["git", "-C", work, "show",
                                       f":{side}:{path}"],
                                      capture_output=True, check=True).stdout
                with open(os.path.join(work, path), "wb") as f:
                    f.write(blob)
                git(work, "add", path)
                logf.write(f"  {path}: {code}, kept (the oracle has it)\n")
            else:
                git(work, "rm", "-q", "--cached", "--ignore-unmatch", path)
                with contextlib.suppress(FileNotFoundError):
                    os.remove(os.path.join(work, path))
                logf.write(f"  {path}: {code}, removed (the oracle has not)\n")
            continue
        if code in ("DD", "AU", "UA"):
            # a rename both sides made otherwise: which name is not a merge
            stuck.append(line)
            continue
        if code not in ("UU", "AA"):
            continue  # merged: what the patch brought as it was
        stages = {}
        for st in (1, 2, 3):
            r = subprocess.run(["git", "-C", work, "show", f":{st}:{path}"],
                               capture_output=True, text=True)
            stages[st] = r.stdout if r.returncode == 0 else ""
        r = subprocess.run(["git", "-C", work, "show", f"{oracle}:{path}"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            stuck.append(line + "  (not in the oracle)")
            continue
        code_, merged = merge_file(stages[1], stages[2], stages[3])
        text, log = resolve_toward(merged, r.stdout)
        with open(os.path.join(work, path), "w", encoding="utf-8") as f:
            f.write(text)
        git(work, "add", path)
        logf.write(f"  {path}: " + "; ".join(log) + "\n")
    return stuck


def settle(work, oracle, logf, what):
    """Conflicts resolved toward oracle and the operation continued, until
    it is done; stops the program at what it cannot resolve."""
    while True:
        cont = in_progress(work)
        if not cont:
            return
        logf.write(what + "\n")
        if not oracle:
            print("stopped:", git(work, "status", "--short"),
                  f"resolve, git add, then git -C {work} -c core.editor=true "
                  + " ".join(cont), sep="\n")
            sys.exit(1)
        stuck = autoresolve(work, oracle, logf)
        if stuck:
            logf.flush()
            print("left to resolve by hand:", *stuck, sep="\n  ")
            sys.exit(1)
        if staged_nothing(work):
            # the resolution leaves nothing of the commit: git would refuse
            # to continue with it, every time
            cont = [cont[0], "--skip"]
            logf.write("  nothing is left of it: skipped\n")
        logf.flush()
        before = where(work)
        r = subprocess.run(["git", "-C", work, "-c", "core.editor=true", *cont],
                           text=True, capture_output=True)
        if r.returncode != 0 and (not in_progress(work) or where(work) == before):
            print(r.stdout[-1500:], r.stderr[-1500:])
            sys.exit(1)


DIFFHUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def hunks_between(work, a, b, path):
    """The -U0 hunks of path from a to b: (start, count, new lines)."""
    out, cur, last = [], None, ""
    # read as it is: git() strips, and a last line of spaces would lose them
    diff = subprocess.run(["git", "-C", work, "diff", "-U0", "--no-color", a, b,
                           "--", path], capture_output=True, text=True,
                          check=True).stdout
    for l in diff.split("\n"):
        m = DIFFHUNK.match(l)
        if m:
            cur = [int(m.group(1)), 1 if m.group(2) is None else int(m.group(2)), []]
            out.append(cur)
        elif cur is not None and l.startswith("+") and not l.startswith("+++"):
            cur[2].append(l[1:] + "\n")
        elif l.startswith("\\") and last.startswith("+") and not last.startswith("+++"):
            # "\ No newline at end of file" after a line b has: it ends so
            cur[2][-1] = cur[2][-1][:-1]
        last = l
    return out


def blame_lines(work, rev, path, ignore=()):
    out = {}
    skip = [x for r in ignore for x in ("--ignore-rev", r)]
    for l in git(work, "blame", "--porcelain", *skip, rev, "--", path).splitlines():
        m = re.match(r"^([0-9a-f]{40}) \d+ (\d+)", l)
        if m:
            out[int(m.group(2))] = m.group(1)
    return out


def absorb(a):
    """What makes HEAD the oracle (or the working tree, without one), laid
    into the patches: each hunk into the newest patch whose lines it touches
    or borders, unless a --to rule (SUBJECT=PATH[#N,..]) says where; then
    squashed in."""
    work = a.work
    if in_progress(work):
        sys.exit("an operation is under way")
    unfinished(work)
    uncommitted = not a.oracle
    if uncommitted:
        # what is uncommitted: a commit the patches must end at, made through
        # an index of its own, so that the working tree is left as it is
        # until the plan is made (a dry run or a refusal loses nothing)
        index = os.path.join(work, ".git", STATE + "-index")
        env = dict(os.environ, GIT_INDEX_FILE=index)
        try:
            for args in (["read-tree", "HEAD"], ["add", "-A"]):
                subprocess.run(["git", "-C", work, *args], env=env, check=True)
            tree = subprocess.run(["git", "-C", work, "write-tree"], env=env,
                                  check=True, capture_output=True,
                                  text=True).stdout.strip()
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.remove(index)
        a.oracle = git(work, "commit-tree", tree, "-p", "HEAD", "-m", "absorbed")
        print(f"absorbing {a.oracle[:10]}")
    anchor = state(work, "anchor")
    order = new_series(work)
    pos = {c: i for i, c in enumerate(order)}
    by_subject = {subject_of(work, c): c for c in order}
    base = git(work, "rev-parse", "HEAD")
    target_tree = git(work, "rev-parse", a.oracle + "^{tree}")
    rules = []
    for spec in a.to or []:
        subject, sel = spec.split("=", 1)
        path, _, idx = sel.partition("#")
        if subject not in by_subject:
            sys.exit(f"no patch is called: {subject}")
        rules.append((by_subject[subject], path,
                      {int(i) for i in idx.split(",")} if idx else None))
    files = git(work, "diff", "--name-only", base, a.oracle).splitlines()
    plan, unplaced = {}, []
    for path in files:
        def rule_for(n):
            for c, p, idx in rules:
                if p == path and (idx is None or n in idx):
                    return c
        in_base = subprocess.run(["git", "-C", work, "cat-file", "-e",
                                  f"{base}:{path}"]).returncode == 0
        in_new = subprocess.run(["git", "-C", work, "cat-file", "-e",
                                 f"{a.oracle}:{path}"]).returncode == 0
        if not (in_base and in_new):
            c = rule_for(1) or (git(work, "log", "-1", "--format=%H",
                                    f"{anchor}..{base}", "--", path) or None)
            (plan.setdefault(c, []).append((path, "file", None)) if c
             else unplaced.append(f"{path} (whole file)"))
            continue
        blame = blame_lines(work, base, path)
        for n, h in enumerate(hunks_between(work, base, a.oracle, path), 1):
            c = rule_for(n)
            if not c:
                # its lines and the one on either side: a hunk next to a
                # later patch's lines would not go past that patch
                start, count = h[0], h[1]
                lines = range(start - 1, start + count + 1) if count else \
                    (start, start + 1)
                ours = sorted((blame[x] for x in lines if blame.get(x) in pos),
                              key=pos.get)
                if not ours and a.near:
                    # bogdanfinn's lines: the newest patch among those
                    # that wrote lines around them
                    around = range(max(1, start - a.near), start + count + a.near)
                    ours = sorted((blame[x] for x in around
                                   if blame.get(x) in pos), key=pos.get)
                c = ours[-1] if ours else None
            if c:
                plan.setdefault(c, []).append((path, "hunk", n))
            else:
                unplaced.append(f"{path}#{n} (lines {h[0]},{h[1]})")
    if unplaced:
        print("no patch for:", *unplaced, sep="\n  ")
        sys.exit(1)
    for c in sorted(plan, key=pos.get):
        print(f"{subject_of(work, c)[:60]}: " +
              ", ".join(p + (f"#{n}" if n else "") for p, _, n in plan[c]))
    if a.dry_run:
        return
    if uncommitted:
        git(work, "reset", "-q", "--hard", "HEAD")
    # one fixup commit per patch, each over the one before
    chosen = {}
    for c in sorted(plan, key=pos.get):
        for path, kind, n in plan[c]:
            chosen.setdefault(path, {})[n] = c
        for path in {p for p, _, _ in plan[c]}:
            full = os.path.join(work, path)
            if kind_of := [k for p, k, _ in plan[c] if p == path and k == "file"]:
                r = subprocess.run(["git", "-C", work, "show",
                                    f"{a.oracle}:{path}"], capture_output=True)
                if r.returncode == 0:
                    os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
                    with open(full, "wb") as f:
                        f.write(r.stdout)
                    git(work, "add", path)
                else:
                    git(work, "rm", "-q", path)
                continue
            text = subprocess.run(["git", "-C", work, "show", f"{base}:{path}"],
                                  capture_output=True, text=True, check=True).stdout
            lines = text.splitlines(keepends=True)
            hs = hunks_between(work, base, a.oracle, path)
            for n in sorted(chosen[path], reverse=True):
                start, count, new = hs[n - 1]
                at = start - 1 if count else start
                lines[at:at + count] = new
            with open(full, "w", encoding="utf-8") as f:
                f.write("".join(lines))
            git(work, "add", path)
        # by the commit's name, not its subject: two patches may share one
        git(work, "commit", "-q", "--no-verify", "-m", "fixup! " + c)
    if git(work, "rev-parse", "HEAD^{tree}") != target_tree:
        sys.exit("the fixups do not make the oracle's tree")
    r = subprocess.run(["git", "-C", work, "-c", "sequence.editor=true",
                        "rebase", "-q", "-i", "--autosquash", anchor],
                       text=True, capture_output=True)
    if r.returncode != 0:
        with open(os.path.join(work, ".git", STATE + "-log"), "a") as logf:
            settle(work, a.oracle, logf, "absorb")
    same = git(work, "rev-parse", "HEAD^{tree}") == target_tree
    print(f"squashed in; tree {'is' if same else 'is NOT'} the oracle's")
    sys.exit(0 if same else 1)


def fix(a):
    """The patch called --at changed by --cmd (a shell command run in WORK
    at that patch), the patches after it laid over again, conflicts
    resolved toward the oracle."""
    work = a.work
    unfinished(work)
    anchor = state(work, "anchor")
    target = [c for c in new_series(work) if subject_of(work, c) == a.at]
    if len(target) != 1:
        sys.exit(f"{len(target)} patches are called: {a.at}")
    t = target[0]
    todo = os.path.join(work, ".git", STATE + "-todo.py")
    with open(todo, "w") as f:
        f.write("import sys\n"
                f"t = {t!r}\n"
                "p = sys.argv[1]\n"
                "def edit(l):\n"
                "    w = l.split()\n"
                "    return 'edit' + l[4:] if len(w) > 1 and w[0] == 'pick' "
                "and t.startswith(w[1]) else l\n"
                "s = open(p).read().split('\\n')\n"
                "open(p, 'w').write('\\n'.join(edit(l) for l in s))\n")
    r = subprocess.run(["git", "-C", work, "-c",
                        "sequence.editor=" + shlex.join([sys.executable, todo]),
                        "rebase", "-q", "-i", anchor], text=True,
                       capture_output=True)
    if git(work, "rev-parse", "HEAD") != t and not in_progress(work):
        sys.exit("the rebase did not stop at the patch: " + r.stderr[-500:])
    subprocess.run(a.command, shell=True, cwd=work, check=True)
    git(work, "add", "-A")
    git(work, "commit", "-q", "--amend", "--no-edit")
    r = subprocess.run(["git", "-C", work, "-c", "core.editor=true",
                        "rebase", "--continue"], text=True, capture_output=True)
    if r.returncode != 0:
        with open(os.path.join(work, ".git", STATE + "-log"), "a") as logf:
            settle(work, a.oracle, logf, f"fix {a.at}")
    if a.oracle:
        same = git(work, "rev-parse", "HEAD^{tree}") == \
            git(work, "rev-parse", a.oracle + "^{tree}")
        print(f"fixed; tree {'is' if same else 'is NOT'} the oracle's")
    else:
        print("fixed")


def check(a):
    """go build and go vet at every commit of the new series, each exported
    to a directory of its own (HEAD stays where it is); go test at the last
    with --test."""
    import shutil
    commits = [state(a.work, "anchor")] + new_series(a.work)
    if a.last_only:
        commits = commits[-1:]
    bad = []
    tmp = tempfile.mkdtemp(prefix="fork-sync-check-")
    try:
        for c in commits:
            d = os.path.join(tmp, c[:12])
            os.makedirs(d)
            pack = subprocess.Popen(["git", "-C", a.work, "archive", c],
                                    stdout=subprocess.PIPE)
            unpacked = subprocess.run(["tar", "-x", "-C", d], stdin=pack.stdout,
                                      capture_output=True, text=True)
            pack.stdout.close()
            if pack.wait() or unpacked.returncode:
                sys.exit(f"{c[:10]} could not be exported: {unpacked.stderr.strip()}")
            build = a.build
            if a.with_:
                build = (shlex.join(["go", "work", "init", ".",
                                     *map(os.path.abspath, a.with_)])
                         + " && " + build)
            r = subprocess.run(build, shell=True, cwd=d,
                               capture_output=True, text=True)
            ok = r.returncode == 0
            print(f"{c[:10]} {'ok' if ok else 'FAILS':5} {subject_of(a.work, c)}",
                  flush=True)
            if not ok:
                bad.append(c)
                print("   " + " | ".join((r.stderr or r.stdout).strip()
                                         .splitlines()[:3])[:400], flush=True)
            if a.test and c == commits[-1]:
                r = subprocess.run(["go", "test", "-count=1", *a.test.split()],
                                   cwd=d)
                if r.returncode:
                    bad.append("tests")
            shutil.rmtree(d)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{len(commits) - len([b for b in bad if b != 'tests'])} of "
          f"{len(commits)} build{'; tests fail' if 'tests' in bad else ''}")
    sys.exit(1 if bad else 0)


def trivial(line):
    """A line too slight to tell one change from another: a brace, a comma,
    an empty comment."""
    return len(line) < 4 or re.fullmatch(r"[\s{}()\[\],;]*|//\s*|/\*|\*/|\*",
                                         line) is not None


def counted(repo, rev, path, cache):
    """path's lines at rev, renamed as the anchor renames them and trimmed,
    counted; none where rev has no such file."""
    if (rev, path) not in cache:
        shown = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"],
                               capture_output=True, text=True).stdout
        cache[rev, path] = collections.Counter(
            rename_text(l).strip() for l in shown.splitlines())
    return cache[rev, path]


def changed_lines(repo, c):
    """(path, sign, line) of every line c adds or removes against its first
    parent, renamed and trimmed; a file it removes is its old path's."""
    # git quotes a name past ASCII unless told not to, and ends one with a
    # space in a tab
    diff = subprocess.run(["git", "-C", repo, "-c", "core.quotePath=false",
                           "diff", "-U0", "--no-renames", "--no-color", c + "^", c],
                          capture_output=True, text=True, check=True).stdout
    old = path = None
    header = False
    for l in diff.split("\n"):
        if l.startswith("diff --git "):
            header = True
        elif header and l.startswith("--- "):
            old = l[6:].rstrip("\t")
        elif header and l.startswith("+++ "):
            path = old if l == "+++ /dev/null" else l[6:].rstrip("\t")
        elif l.startswith("@@"):
            header = False
        elif l[:1] in ("+", "-"):
            yield path, l[0], rename_text(l[1:]).strip()


def overlap(repo, fresh, anchor, c):
    """Of the lines patch c rewrites (an insertion: the lines on either side),
    those the author's fresh commits wrote last, by commit and file:
    [rewritten, beside], the anchor's rename passed over."""
    per = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
    paths = git(repo, "diff", "--name-only", "-z", "--no-renames",
                "--diff-filter=MD", c + "^", c).split("\0")
    for path in filter(None, paths):
        blamed = blame_lines(repo, c + "^", path, ignore=[anchor])
        for start, n, _ in hunks_between(repo, c + "^", c, path):
            lines = [(0, x) for x in range(start, start + n)] or \
                [(1, x) for x in (start, start + 1) if x in blamed]
            for kind, x in lines:
                if blamed[x] in fresh:
                    per[blamed[x]][path][kind] += 1
    return per


def survival(repo, onto, tip, u, cache):
    """What author's commit u added that onto still has and tip lacks, and
    what it removed that onto still lacks and tip has again, file by file."""
    files = collections.defaultdict(lambda: {"added": 0, "kept": 0, "removed": 0,
                                             "back": 0, "lost": [], "returned": []})
    for path, sign, text in changed_lines(repo, u):
        if trivial(text) or path.endswith("go.sum"):
            continue
        f = files[path]
        if sign == "+" and counted(repo, onto, path, cache)[text]:
            f["added"] += 1
            if counted(repo, tip, path, cache)[text]:
                f["kept"] += 1
            else:
                f["lost"].append(text)
        elif sign == "-" and not counted(repo, onto, path, cache)[text]:
            f["removed"] += 1
            if counted(repo, tip, path, cache)[text]:
                f["back"] += 1
                f["returned"].append(text)
    return {p: f for p, f in files.items() if f["added"] or f["removed"]}


def review(a):
    """Where the fork's patches meet what the author changed since --since:
    the author's fresh lines each patch rewrites, and the lines of each of the
    author's commits the branch's head lacks or has again."""
    anchor, patches = series(a.fork, a.head)
    onto = git(a.fork, "rev-parse", anchor + "^")
    tip = git(a.fork, "rev-parse", a.head)
    since = git(a.fork, "rev-parse", a.since + "^{commit}")
    fresh = set(git(a.fork, "rev-list", f"{since}..{onto}").split())
    subject = lambda c: subject_of(a.fork, c)
    report = {"since": since[:9], "onto": onto[:9], "anchor": anchor[:9],
              "patches": [], "upstream": []}
    for c in patches:
        per = overlap(a.fork, fresh, anchor, c)
        if per:
            report["patches"].append({
                "patch": c[:9], "subject": subject(c),
                "upstream": {u[:9]: {"subject": subject(u),
                                     "files": {p: {"rewritten": v[0], "beside": v[1]}
                                               for p, v in sorted(fs.items())}}
                             for u, fs in per.items()}})
    cache = {}
    for u in git(a.fork, "rev-list", "--reverse", "--no-merges",
                 f"{since}..{onto}").split():
        files = survival(a.fork, onto, tip, u, cache)
        if files:
            report["upstream"].append({
                "commit": u[:9], "subject": subject(u),
                **{k: sum(f[k] for f in files.values())
                   for k in ("added", "kept", "removed", "back")},
                "files": dict(sorted(files.items()))})
    json.dump(report, sys.stdout, indent=1, ensure_ascii=False)
    print()


def make_anchor(a):
    fork_dir = a.fork
    head = git(fork_dir, "rev-parse", a.head)
    if not os.path.isdir(a.work):
        git(".", "clone", "-q", "--no-checkout", fork_dir, a.work)
    upstream = git(fork_dir, "remote", "get-url", "upstream")
    git(a.work, "fetch", "-q", fork_dir, head)
    git(a.work, "fetch", "-q", "--tags", upstream)
    anchor, patches = series(a.work, head)
    onto = git(a.work, "rev-parse", a.ref + "^{commit}")
    for k, v in (("rerere.enabled", "true"), ("rerere.autoupdate", "true"),
                 ("merge.conflictStyle", "zdiff3"),
                 ("merge.gomod.name", "go.mod, module by module"),
                 ("merge.gomod.driver",
                  shlex.join([sys.executable, os.path.abspath(__file__)])
                  + " gomod %O %A %B")):
        git(a.work, "config", k, v)
    info = os.path.join(a.work, ".git", "info")
    os.makedirs(info, exist_ok=True)
    with open(os.path.join(info, "attributes"), "w") as f:
        f.write("go.mod merge=gomod\ngo.sum merge=union\n")
    git(a.work, "checkout", "-q", "--detach", onto)
    pins = {m: v for m, v in requirements(
        git(a.work, "show", f"{head}:go.mod")).items() if m.startswith(NEW)}
    rename(a.work, pins)
    # the anchor's own files: what the recipe does not make (LEMON.md, a
    # LICENSE upstream lacks, a file the fork took away). A Go file, go.mod
    # or go.sum the old base had is the release's renamed, nested ones too:
    # a copy of the old anchor's go.mod kept the old base's versions
    # (tls-client's cffi_dist, 2026-11-10).
    changes = git(a.work, "diff-tree", "--no-commit-id", "--name-status",
                  "--no-renames", "-z", "-r", anchor).split("\0")
    for status, path in zip(changes[0::2], changes[1::2]):
        if status == "M" and (path.endswith(".go") or
                              os.path.basename(path) in ("go.mod", "go.sum")):
            continue
        was, now = blob(a.work, f"{anchor}^", path), blob(a.work, onto, path)
        full = os.path.join(a.work, path)
        if now is not None and now != (b"" if was is None else was):
            print(f"warning: {path}: the release changed it since the old base; "
                  + ("the old anchor took it away, and so does the new"
                     if status == "D" else
                     "the old anchor's copy replaces it, see that nothing of "
                     "the release's is lost"), file=sys.stderr)
        if status == "D":
            if os.path.lexists(full):
                os.remove(full)
            continue
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(blob(a.work, anchor, path))
    git(a.work, "add", "-A")
    env = dict(os.environ,
               GIT_AUTHOR_NAME=git(a.work, "log", "-1", "--format=%an", anchor),
               GIT_AUTHOR_EMAIL=git(a.work, "log", "-1", "--format=%ae", anchor),
               GIT_AUTHOR_DATE=git(a.work, "log", "-1", "--format=%aI", anchor))
    subprocess.run(["git", "-C", a.work, "commit", "-q", "-m",
                    subject_of(a.work, anchor)], env=env, check=True)
    state(a.work, "head", head)
    state(a.work, "onto", onto)
    state(a.work, "anchor", git(a.work, "rev-parse", "HEAD"))
    state(a.work, "oracle", a.oracle or "")
    state(a.work, "dropped", "")
    print(f"{os.path.basename(os.path.normpath(fork_dir))}: {len(patches)} "
          f"patches over {a.ref} ({onto[:10]}), old anchor {anchor[:10]}")


def renames_only(work):
    """Conflicts where the release's side differs from the base only by the
    rename (a patch moved or dropped an import the rename changed) settled
    as the patch has it: the rename is made of the patch afterwards. True
    when no conflict is left."""
    left = False
    for line in git(work, "status", "--porcelain").splitlines():
        code, path = line[:2], line[3:]
        if code != "UU":
            left = left or (code[0] in "UAD" and code[1] in "UAD")
            continue
        stages = {}
        for st in (1, 2, 3):
            r = subprocess.run(["git", "-C", work, "show", f":{st}:{path}"],
                               capture_output=True, text=True)
            stages[st] = r.stdout if r.returncode == 0 else ""
        # diff3: zdiff3 takes a line both sides have out of the hunk, the
        # renamed line among them, and ours is then no longer the base renamed
        _, merged = merge_file(stages[1], stages[2], stages[3], "diff3")
        lines, hs = hunks_of(merged)
        if not hs or any(rename_text("".join(h["b"])) != "".join(h["o"])
                         for _, _, h in hs):
            left = True
            continue
        res, last = [], 0
        for s_, e, h in hs:
            res.append("".join(lines[last:s_]))
            res.append("".join(h["t"]))
            last = e + 1
        res.append("".join(lines[last:]))
        with open(os.path.join(work, path), "w", encoding="utf-8") as f:
            f.write("".join(res))
        git(work, "add", path)
    return not left


def lay_over(work, oracle, inject=(), run=()):
    """The old series' patches not laid over yet, one at a time."""
    head = state(work, "head")
    _, patches = series(work, head)
    injects, runs = {}, {}
    for spec in inject:
        subject, rest = spec.split("=", 1)
        injects.setdefault(subject, []).append(rest.rsplit("@", 1))
    for spec in run:
        subject, cmd = spec.split("=", 1)
        runs.setdefault(subject, []).append(cmd)
    with open(os.path.join(work, ".git", STATE + "-log"), "a") as logf:
        # laid over already: as many of a subject as the new series has (two
        # patches may share one), and those nothing was left of
        done = collections.Counter(subject_of(work, c) for c in new_series(work))
        gone = dropped(work)
        for c in patches:
            s = subject_of(work, c)
            if c in gone:
                continue
            if done[s]:
                done[s] -= 1
                continue
            logf.write(f"{c[:10]} {s}\n")
            before = git(work, "rev-parse", "HEAD")
            r = subprocess.run(["git", "-C", work, "cherry-pick", "--empty=drop", c],
                               text=True, capture_output=True)
            if r.returncode != 0 and renames_only(work):
                r = subprocess.run(["git", "-C", work, "-c", "core.editor=true",
                                    "cherry-pick", "--continue"],
                                   text=True, capture_output=True)
                logf.write("  conflicts of the rename alone: the patch's side\n")
            if r.returncode != 0 and in_progress(work):
                if not oracle:
                    print(f"stopped at {c[:10]} {s}:", git(work, "status", "--short"),
                          "resolve, git add, then: continue", sep="\n")
                    sys.exit(1)
                settle(work, oracle, logf, f"{c[:10]} {s}")
            if git(work, "rev-parse", "HEAD") == before:
                # nothing of it is left over the release: what was asked to be
                # done after it would change the patch before it
                drop(work, c)
                logf.write("  nothing is left of it over the release: dropped\n")
                continue
            after_pick(work, s, injects, runs, oracle, logf)
        if injects or runs:
            sys.exit(f"no patch is called: {', '.join(list(injects) + list(runs))}")
    print(f"{len(new_series(work))} patches over the anchor; now check, then finish")


def after_pick(work, s, injects, runs, oracle, logf):
    rename_patch(work, logf)
    for cmd in runs.pop(s, []):
        subprocess.run(cmd, shell=True, cwd=work, check=True)
        git(work, "add", "-A")
        git(work, "commit", "-q", "--amend", "--no-edit")
        logf.write(f"  ran: {cmd}\n")
    for path, rev in injects.pop(s, []):
        rev = oracle if rev == "oracle" else rev
        blob = subprocess.run(["git", "-C", work, "show", f"{rev}:{path}"],
                              capture_output=True, check=True).stdout
        full = os.path.join(work, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(blob)
        git(work, "add", path)
        git(work, "commit", "-q", "--amend", "--no-edit")
        logf.write(f"  {path}: laid in from {rev[:10]}\n")
    logf.flush()


def start(a):
    make_anchor(a)
    if not a.anchor_only:
        lay_over(a.work, a.oracle, a.inject or (), a.run or ())


def cont(a):
    if in_progress(a.work):
        picked = git(a.work, "rev-parse", "-q", "--verify", "CHERRY_PICK_HEAD",
                     check=False)
        if picked and staged_nothing(a.work):
            # resolved to nothing of the patch: dropped, for good
            git(a.work, "cherry-pick", "--skip")
            drop(a.work, picked)
        else:
            r = subprocess.run(["git", "-C", a.work, "-c", "core.editor=true",
                                "cherry-pick", "--continue"], text=True,
                               capture_output=True)
            if r.returncode != 0 and in_progress(a.work):
                sys.exit(r.stdout + r.stderr)
            with open(os.path.join(a.work, ".git", STATE + "-log"), "a") as logf:
                rename_patch(a.work, logf)
    lay_over(a.work, state(a.work, "oracle"), a.inject or (), a.run or ())


def finish(a):
    head = state(a.work, "head")
    if in_progress(a.work):
        sys.exit("an operation is under way")
    tip = git(a.work, "rev-parse", "HEAD")
    git(a.work, "merge", "-q", "-s", "ours", "--no-ff", "-m", a.message, head)
    old_anchor, old = series(a.work, head)
    # The old series as series() reads it: a merge in it (a patch made after
    # an earlier finish) would bring in, through its second parent, every
    # commit of the branch's history, which range-diff then said were gone
    # (83 of fhttp's on 2026-11-11), and itself. In this clone, for the
    # while, a patch whose parent is not the patch before it is grafted
    # onto that one.
    grafts = [c for p, c in zip([old_anchor] + old, old)
              if git(a.work, "rev-parse", c + "^1") != p]
    for p, c in zip([old_anchor] + old, old):
        if c in grafts:
            git(a.work, "replace", "--graft", c, p)
    try:
        rd = git(a.work, "range-diff", "--no-color", "--no-dual-color",
                 f"{old_anchor}..{old[-1]}" if old else old_anchor,
                 f"{state(a.work, 'anchor')}..{tip}", check=False)
    finally:
        for c in grafts:
            git(a.work, "replace", "-d", c)
    with open(os.path.join(a.work, ".git", STATE + "-range-diff"), "w") as f:
        f.write(rd)
    kinds = {}
    for line in rd.splitlines():
        m = re.match(r"^\s*(?:\d+|-):\s+\S+\s+([=!<>])\s", line)
        if m:
            kinds[m.group(1)] = kinds.get(m.group(1), 0) + 1
    same = git(a.work, "rev-parse", "HEAD^{tree}") == \
        git(a.work, "rev-parse", head + "^{tree}")
    print(f"patches as they were {kinds.get('=', 0)}, changed {kinds.get('!', 0)}, "
          f"gone {kinds.get('<', 0)}, new {kinds.get('>', 0)} "
          f"(.git/{STATE}-range-diff); the tree is "
          f"{'the old head' + chr(39) + 's' if same else 'not the old head' + chr(39) + 's'}")
    print(f"new head {git(a.work, 'rev-parse', 'HEAD')}; to move the branch: "
          f"git -C FORK fetch {a.work} HEAD && git -C FORK merge --ff-only FETCH_HEAD")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "gomod":
        return gomod_driver(sys.argv[2:5])
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("fork", help="the fork's checkout")
    s.add_argument("ref", help="bogdanfinn's release, a tag or a commit")
    s.add_argument("--head", default="tls-forge")
    s.add_argument("--anchor-only", action="store_true")
    s.set_defaults(func=start)
    c = sub.add_parser("continue")
    c.set_defaults(func=cont)
    ab = sub.add_parser("absorb")
    ab.add_argument("--to", action="append")
    ab.add_argument("--near", type=int, default=0)
    ab.add_argument("--dry-run", action="store_true")
    ab.set_defaults(func=absorb)
    fx = sub.add_parser("fix")
    fx.add_argument("--at", required=True)
    fx.add_argument("--cmd", dest="command", required=True)
    fx.set_defaults(func=fix)
    ck = sub.add_parser("check")
    ck.add_argument("--build", default="go build ./... && go vet ./...")
    ck.add_argument("--with", dest="with_", action="append", default=[])
    ck.add_argument("--test", default="", help="packages to test at the last commit")
    ck.add_argument("--last-only", action="store_true")
    ck.set_defaults(func=check)
    fi = sub.add_parser("finish")
    fi.add_argument("-m", "--message", required=True)
    fi.set_defaults(func=finish)
    rv = sub.add_parser("review")
    rv.add_argument("fork", help="the fork's checkout, or a WORK laid over a release")
    rv.add_argument("--since", required=True, help="the release the patches were over before")
    rv.add_argument("--head", default="tls-forge")
    rv.set_defaults(func=review)
    se = sub.add_parser("series")
    se.add_argument("fork")
    se.add_argument("--head", default="tls-forge")
    se.set_defaults(func=lambda a: [print(git(a.fork, "log", "-1", "--format=%h %s", x))
                                    for x in [series(a.fork, a.head)[0]] + series(a.fork, a.head)[1]])
    for sp in (s, c, ab, fx, ck, fi):
        sp.add_argument("--work", required=True)
    for sp in (s, ab, fx):
        sp.add_argument("--oracle")
    for sp in (s, c):
        sp.add_argument("--inject", action="append")
        sp.add_argument("--run", action="append")
    a = p.parse_args()
    if a.cmd in ("fix",) and not a.oracle:
        a.oracle = state(a.work, "oracle") or None
    a.func(a)


if __name__ == "__main__":  # pragma: no cover: the tests call main
    main()
