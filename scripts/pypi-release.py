#!/usr/bin/env python3
"""Assemble the Python distributions for a release.

One wheel per platform, each carrying a single binary and tagged so that pip
picks exactly the one that matches the machine. Python needs no equivalent of
npm's optional dependencies for this: a wheel filename already says which
platform it is for, so `pip install tls-forge` downloads one file and is done —
no Go on the user's machine, and nothing fetched during install.

    python scripts/pypi-release.py --version 0.1.0 --binaries dist/bin --out dist/pypi

The binaries are expected to be named tls-forge-<goos>-<goarch>[.exe], which is
what the release workflow's cross-compile step produces.

An sdist is built as well. It carries no binary, and that is deliberate: it is
the source, for anyone packaging this downstream, and installing it lands a
client that looks for a binary on PATH and says so clearly when there is none.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / "python"

# Wheel platform tags, against Go's build targets.
#
# macOS is tagged 12_0 rather than the customary 10_9 because that is the truth:
# The Go toolchain targets macOS 12 and later, and a wheel tagged 10_9 would install
# happily on a machine its binary cannot run on.
#
# Linux gets both a manylinux and a musllinux tag on one wheel. The binary is
# static — the whole project builds with CGO_ENABLED=0 — so it runs on Alpine
# too, and without the second tag pip there would skip the wheel and fall back
# to the sdist, which carries no binary at all.
TARGETS = [
    ("darwin", "arm64", "macosx_12_0_arm64"),
    ("darwin", "amd64", "macosx_12_0_x86_64"),
    ("linux", "arm64", "manylinux2014_aarch64.musllinux_1_1_aarch64"),
    ("linux", "amd64", "manylinux2014_x86_64.musllinux_1_1_x86_64"),
    ("windows", "amd64", "win_amd64"),
]

# Apache-2.0 section 4 requires these to travel with any redistribution, and a
# wheel containing a compiled binary is a redistribution — of this project and
# of everything statically linked into it.
LEGAL = ["LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt"]

# The same subset accepted by scripts/npm-release.mjs. Generic SemVer
# pre-release identifiers are unsafe here: Python interprets ``1.2.3-1`` as the
# stable post-release ``1.2.3.post1``. Build metadata is excluded as well.
SEMVER = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:a|alpha|b|beta|c|rc|pre|preview|dev)(?:\.?(?:0|[1-9]\d*))?)?$"
)
VERSION_LINE = re.compile(r'^__version__ = ".*"$', re.MULTILINE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--binaries", default="dist/bin")
    parser.add_argument("--out", default="dist/pypi")
    args = parser.parse_args()

    if not SEMVER.fullmatch(args.version):
        parser.error(f"--version {args.version} is not a registry-compatible SemVer version")

    binaries = Path(args.binaries).resolve()
    out = Path(args.out).resolve()
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)

    # Staged outside `out`, which must end up holding distributions and nothing
    # else: the publishing step uploads what it finds there.
    workspace = Path(tempfile.mkdtemp(prefix="tls-forge-pypi-"))
    try:
        staging = workspace / "project"
        stage_project(staging, args.version)

        build(staging, out, sdist=True)
        for goos, goarch, tag in TARGETS:
            wheel = build_for(staging, out, binaries, goos, goarch, tag)
            check(wheel, tag)
            print(f"{tag}\t{wheel.name}")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
    return 0


def stage_project(staging: Path, version: str) -> None:
    """A copy of python/ with the version stamped and the notices alongside.

    A copy rather than the tree itself: a release must not depend on the working
    directory being clean afterwards, and five wheels are built from five
    different contents of the same directory.
    """
    shutil.copytree(
        PROJECT,
        staging,
        # .coverage is a SQLite database holding the build machine's absolute
        # paths. It was shipping inside every sdist: junk in the artifact, and a
        # small amount of the build host described to anyone who unpacks it.
        ignore=shutil.ignore_patterns(
            "__pycache__",
            "*.egg-info",
            ".pytest_cache",
            "dist",
            ".coverage",
            ".coverage.*",
        ),
    )

    init = staging / "src" / "tlsforge" / "__init__.py"
    stamped, count = VERSION_LINE.subn(f'__version__ = "{version}"', init.read_text())
    if count != 1:
        raise SystemExit(f"{init} does not have exactly one __version__ line to stamp")
    init.write_text(stamped)

    for name in LEGAL:
        source = ROOT / name
        if not source.exists():
            raise SystemExit(f"{name} is missing; a published binary must carry it")
        shutil.copy2(source, staging / name)


def build_for(staging: Path, out: Path, binaries: Path, goos: str, goarch: str, tag: str) -> Path:
    """One platform's wheel: drop its binary in, build, retag."""
    windows = goos == "windows"
    source = binaries / f"tls-forge-{goos}-{goarch}{'.exe' if windows else ''}"
    if not source.exists():
        raise SystemExit(f"no binary at {source}")

    bindir = staging / "src" / "tlsforge" / "bin"
    shutil.rmtree(bindir, ignore_errors=True)
    bindir.mkdir(parents=True)
    landed = bindir / ("tls-forge.exe" if windows else "tls-forge")
    shutil.copy2(source, landed)
    # copy2 preserves the mode, but a binary that arrives from an artifact
    # download may have lost its exec bit, and a wheel packs the mode it finds.
    landed.chmod(0o755)

    built = build(staging, out)
    # Built as py3-none-any, because hatchling has no reason to think otherwise;
    # retagged here, which rewrites the filename and the RECORD together.
    retagged = subprocess.run(
        [sys.executable, "-m", "wheel", "tags", "--remove",
         "--python-tag", "py3", "--abi-tag", "none", "--platform-tag", tag, str(built)],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return out / retagged


def build(staging: Path, out: Path, sdist: bool = False) -> Path:
    """Run the build backend and return the one file it produced."""
    before = set(out.glob("*"))
    subprocess.run(
        [sys.executable, "-m", "build", "--sdist" if sdist else "--wheel",
         "--outdir", str(out), str(staging)],
        check=True, stdout=subprocess.DEVNULL,
    )
    made = [p for p in out.glob("*") if p.is_file() and p not in before]
    if len(made) != 1:
        raise SystemExit(f"expected one file from the build, got {[p.name for p in made]}")
    return made[0]


def check(wheel: Path, tag: str) -> None:
    """Is what was built actually usable?

    Three things go wrong quietly here and all three make a wheel that installs
    and then does not work: the binary left out, the binary present but not
    executable, and the licence notices missing from a redistribution.
    """
    if tag not in wheel.name:
        raise SystemExit(f"{wheel.name} is not tagged {tag}")

    with zipfile.ZipFile(wheel) as packed:
        names = packed.namelist()
        binaries = [n for n in names if n.startswith("tlsforge/bin/")]
        if len(binaries) != 1:
            raise SystemExit(f"{wheel.name} carries {binaries} where one binary was expected")

        if not wheel.name.endswith("win_amd64.whl"):
            # The mode lives in the zip's external attributes, and pip restores
            # it. Lose it and the client raises PermissionError on first use.
            mode = packed.getinfo(binaries[0]).external_attr >> 16
            if not mode & 0o111:
                raise SystemExit(f"{wheel.name}: {binaries[0]} is not executable ({mode:o})")

        for name in LEGAL:
            if not any(n.endswith(f".dist-info/licenses/{name}") or n.endswith(f"/{name}")
                       for n in names):
                raise SystemExit(f"{wheel.name} does not carry {name}")


if __name__ == "__main__":
    raise SystemExit(main())
