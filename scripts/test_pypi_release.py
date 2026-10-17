"""Tests of scripts/pypi-release.py: what each distribution carries, and what
stops one from being made.

The build backend is stood in for, so that no test reaches the network for
hatchling: the stand-in packs what the backend would, from the staged project,
and `wheel tags` renames as the real one does.
"""

from __future__ import annotations

import importlib.util
import re
import runpy
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional

import pytest

SCRIPT = Path(__file__).resolve().parent / "pypi-release.py"
LEGAL = ["LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt"]
TAGS = [
    "macosx_12_0_arm64",
    "macosx_12_0_x86_64",
    "manylinux2014_aarch64.musllinux_1_1_aarch64",
    "manylinux2014_x86_64.musllinux_1_1_x86_64",
    "win_amd64",
]


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pypi_release", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The script, its repository a small one in tmp_path with the junk a
    working tree gathers, and its temporary files kept apart."""
    module = load()
    root = tmp_path / "repo"
    project = root / "python"
    (project / "src" / "tlsforge").mkdir(parents=True)
    (project / "src" / "tlsforge" / "__init__.py").write_text('"""tls-forge."""\n__version__ = "0.0.0"\n')
    (project / "pyproject.toml").write_text("[project]\nname = 'tls-forge'\n")
    for junk in [".coverage", ".coverage.host.1", "__pycache__/x.pyc", "dist/old.whl", "src/tls_forge.egg-info/PKG-INFO",
                 ".pytest_cache/v"]:
        (project / junk).parent.mkdir(parents=True, exist_ok=True)
        (project / junk).write_text("junk")
    for name in LEGAL:
        (root / name).write_text(f"the {name}")
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "PROJECT", project)
    temporary = tmp_path / "tmp"
    temporary.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temporary))
    return module


@pytest.fixture
def binaries(tmp_path: Path) -> Path:
    """The five binaries a release builds, none executable, as an artifact
    download leaves them."""
    directory = tmp_path / "bin"
    directory.mkdir()
    for goos, goarch in [("darwin", "arm64"), ("darwin", "amd64"), ("linux", "arm64"), ("linux", "amd64"), ("windows", "amd64")]:
        name = f"tls-forge-{goos}-{goarch}{'.exe' if goos == 'windows' else ''}"
        (directory / name).write_text(f"binary {name}")
        (directory / name).chmod(0o644)
    return directory


class Backend:
    """Stands in for `python -m build` and `python -m wheel tags`, noting what
    each build was given. made says how many files a build leaves, mode the
    binary's mode in a wheel, and legal which notices a wheel carries."""

    def __init__(self, made: int = 1, mode: Optional[int] = None, legal: Optional[List[str]] = None) -> None:
        self.made, self.mode, self.legal = made, mode, legal
        self.staged: List[Dict[str, Any]] = []

    def __call__(self, args: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
        assert args[0] == sys.executable
        if args[1:3] == ["-m", "build"]:
            assert kwargs["check"] is True
            kind, out, staging = args[3], Path(args[5]), Path(args[6])
            version = re.search(r'^__version__ = "(.*)"$', (staging / "src" / "tlsforge" / "__init__.py").read_text(), re.M)
            assert version is not None
            files = sorted(str(p.relative_to(staging)) for p in staging.rglob("*") if p.is_file())
            self.staged.append({"kind": kind, "version": version.group(1), "files": files})
            for n in range(self.made):
                suffix = "" if n == 0 else f"-{n}"
                if kind == "--sdist":
                    (out / f"tls_forge-{version.group(1)}{suffix}.tar.gz").write_text("sdist")
                    continue
                with zipfile.ZipFile(out / f"tls_forge-{version.group(1)}{suffix}-py3-none-any.whl", "w") as wheel:
                    wheel.writestr("tlsforge/__init__.py", "")
                    for binary in sorted((staging / "src" / "tlsforge" / "bin").iterdir()):
                        info = zipfile.ZipInfo(f"tlsforge/bin/{binary.name}")
                        info.external_attr = (self.mode if self.mode is not None else binary.stat().st_mode & 0o777) << 16
                        wheel.writestr(info, binary.read_bytes())
                    legal = [name for name in (self.legal if self.legal is not None else LEGAL) if (staging / name).exists()]
                    for name in legal:
                        wheel.writestr(f"tls_forge-{version.group(1)}.dist-info/licenses/{name}", (staging / name).read_text())
                    wheel.writestr(f"tls_forge-{version.group(1)}.dist-info/METADATA", metadata(legal))
            return subprocess.CompletedProcess(args, 0)
        assert args[1:5] == ["-m", "wheel", "tags", "--remove"]
        built = Path(args[-1])
        tag = args[args.index("--platform-tag") + 1]
        retagged = built.name.replace("-any.whl", f"-{tag}.whl")
        built.rename(built.parent / retagged)
        return subprocess.CompletedProcess(args, 0, stdout=f"{retagged}\n")


def metadata(legal: List[str], expression: str = "Apache-2.0", body: str = "") -> str:
    """A wheel's METADATA as hatchling 1.27 and later write it."""
    lines = ["Metadata-Version: 2.4", "Name: tls-forge", "Version: 1"]
    lines += [f"License-Expression: {expression}"] if expression else ["License: Apache-2.0"]
    lines += [f"License-File: {name}" for name in legal]
    return "\n".join(lines) + "\n\n" + body


def build_with(monkeypatch: pytest.MonkeyPatch, backend: Callable[..., subprocess.CompletedProcess]) -> None:
    monkeypatch.setattr(subprocess, "run", backend)


def test_a_release_is_a_source_distribution_and_a_wheel_for_each_platform(
    release: ModuleType, binaries: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    backend = Backend()
    build_with(monkeypatch, backend)
    out = tmp_path / "pypi"
    out.mkdir()
    (out / "stale.whl").write_text("from before")
    monkeypatch.setattr(sys, "argv", ["pypi-release.py", "--version", "1.2.3-rc.1", "--binaries", str(binaries), "--out", str(out)])
    assert release.main() == 0
    made = sorted(p.name for p in out.iterdir())
    assert made == sorted(["tls_forge-1.2.3-rc.1.tar.gz"] + [f"tls_forge-1.2.3-rc.1-py3-none-{tag}.whl" for tag in TAGS])
    # One line for each wheel, its tag and its name.
    assert capsys.readouterr().out.splitlines() == [f"{tag}\ttls_forge-1.2.3-rc.1-py3-none-{tag}.whl" for tag in TAGS]
    # Each build saw the version stamped, the notices beside the project and
    # none of the working tree's junk; each wheel, its own binary only.
    assert [s["kind"] for s in backend.staged] == ["--sdist"] + ["--wheel"] * 5
    for staged in backend.staged:
        assert staged["version"] == "1.2.3-rc.1"
        assert set(LEGAL) <= set(staged["files"])
        assert not any(".coverage" in f or "__pycache__" in f or f.startswith("dist") or "egg-info" in f or ".pytest_cache" in f
                       for f in staged["files"]), staged["files"]
    assert not any(f.startswith("src/tlsforge/bin/") for f in backend.staged[0]["files"])
    assert [f for f in backend.staged[5]["files"] if f.startswith("src/tlsforge/bin/")] == ["src/tlsforge/bin/tls-forge.exe"]
    assert [f for f in backend.staged[1]["files"] if f.startswith("src/tlsforge/bin/")] == ["src/tlsforge/bin/tls-forge"]
    # Executable in the wheel, whatever mode the binary arrived with.
    with zipfile.ZipFile(out / f"tls_forge-1.2.3-rc.1-py3-none-{TAGS[3]}.whl") as wheel:
        assert wheel.getinfo("tlsforge/bin/tls-forge").external_attr >> 16 == 0o755
        assert wheel.read("tlsforge/bin/tls-forge") == b"binary tls-forge-linux-amd64"
    # The repository is as it was, and nothing is left where it worked.
    assert '__version__ = "0.0.0"' in (release.PROJECT / "src" / "tlsforge" / "__init__.py").read_text()
    assert list(Path(tempfile.gettempdir()).iterdir()) == []


@pytest.mark.parametrize("version", ["1.2.3-1", "v1.2.3", "1.2.3+build", "1.2", "1.2.3-gamma", "01.2.3"])
def test_a_version_npm_and_pypi_would_read_apart_is_refused(
    release: ModuleType, binaries: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    build_with(monkeypatch, Backend())
    monkeypatch.setattr(sys, "argv", ["pypi-release.py", "--version", version, "--binaries", str(binaries), "--out", str(tmp_path / "o")])
    with pytest.raises(SystemExit) as stopped:
        release.main()
    assert stopped.value.code == 2
    assert not (tmp_path / "o").exists()


def run_main(release: ModuleType, binaries: Path, out: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["pypi-release.py", "--version", "1.2.3", "--binaries", str(binaries), "--out", str(out)])
    release.main()


def test_a_repository_without_a_notice_publishes_nothing(
    release: ModuleType, binaries: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_with(monkeypatch, Backend())
    (release.ROOT / "NOTICE").unlink()
    with pytest.raises(SystemExit, match="NOTICE is missing; a published binary must carry it"):
        run_main(release, binaries, tmp_path / "o", monkeypatch)
    assert list(Path(tempfile.gettempdir()).iterdir()) == []


@pytest.mark.parametrize("text", ['"""tls-forge."""\n', '__version__ = "0.0.0"\n__version__ = "0.0.1"\n'])
def test_a_version_line_that_is_not_exactly_one_is_not_stamped(
    release: ModuleType, binaries: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    build_with(monkeypatch, Backend())
    (release.PROJECT / "src" / "tlsforge" / "__init__.py").write_text(text)
    with pytest.raises(SystemExit, match="does not have exactly one __version__ line to stamp"):
        run_main(release, binaries, tmp_path / "o", monkeypatch)


def test_a_missing_binary_builds_no_wheel_of_it(
    release: ModuleType, binaries: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_with(monkeypatch, Backend())
    (binaries / "tls-forge-linux-arm64").unlink()
    with pytest.raises(SystemExit, match=f"no binary at {re.escape(str(binaries / 'tls-forge-linux-arm64'))}"):
        run_main(release, binaries, tmp_path / "o", monkeypatch)


@pytest.mark.parametrize("made", [0, 2])
def test_a_build_that_leaves_other_than_one_file_stops(
    release: ModuleType, binaries: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, made: int
) -> None:
    build_with(monkeypatch, Backend(made=made))
    with pytest.raises(SystemExit, match="expected one file from the build, got"):
        run_main(release, binaries, tmp_path / "o", monkeypatch)


def test_a_wheel_whose_binary_lost_its_mode_or_notices_stops(
    release: ModuleType, binaries: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_with(monkeypatch, Backend(mode=0o644))
    with pytest.raises(SystemExit, match=r"tlsforge/bin/tls-forge is not executable \(644\)"):
        run_main(release, binaries, tmp_path / "o", monkeypatch)
    build_with(monkeypatch, Backend(legal=["LICENSE", "THIRD-PARTY-NOTICES.txt"]))
    with pytest.raises(SystemExit, match="does not carry NOTICE"):
        run_main(release, binaries, tmp_path / "p", monkeypatch)


def wheel(path: Path, entries: Dict[str, int], meta: Optional[List[str]] = None) -> Path:
    """A wheel at path holding entries, each name with its mode, and METADATA
    files with what meta says, one naming every notice unless told."""
    with zipfile.ZipFile(path, "w") as packed:
        for name, mode in entries.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            packed.writestr(info, name)
        for n, text in enumerate(meta if meta is not None else [metadata(LEGAL)]):
            packed.writestr(f"tls_forge-{n + 1}.dist-info/METADATA", text)
    return path


NOTICES = {f"tls_forge-1.dist-info/licenses/{name}": 0o644 for name in LEGAL}


def test_a_wheel_is_checked_for_its_tag_its_one_binary_its_mode_and_its_notices(release: ModuleType, tmp_path: Path) -> None:
    linux = TAGS[3]
    good = wheel(tmp_path / f"tls_forge-1-py3-none-{linux}.whl", {"tlsforge/bin/tls-forge": 0o755, **NOTICES})
    release.check(good, linux)
    with pytest.raises(SystemExit, match=f"is not tagged {re.escape(TAGS[0])}"):
        release.check(good, TAGS[0])
    none = wheel(tmp_path / f"none-{linux}.whl", dict(NOTICES))
    with pytest.raises(SystemExit, match=r"carries \[\] where one binary was expected"):
        release.check(none, linux)
    two = wheel(tmp_path / f"two-{linux}.whl", {"tlsforge/bin/tls-forge": 0o755, "tlsforge/bin/extra": 0o755, **NOTICES})
    with pytest.raises(SystemExit, match="where one binary was expected"):
        release.check(two, linux)
    # Executable by anyone at all is executable, as pip reads it: any execute
    # bit, and pip makes the file executable on install.
    for mode in (0o700, 0o650, 0o601):
        release.check(wheel(tmp_path / f"m{mode:o}-{linux}.whl", {"tlsforge/bin/tls-forge": mode, **NOTICES}), linux)
    flat = wheel(tmp_path / f"flat-{linux}.whl", {"tlsforge/bin/tls-forge": 0o644, **NOTICES})
    with pytest.raises(SystemExit, match=r"is not executable \(644\)"):
        release.check(flat, linux)
    # Windows keeps no mode, and none is asked of it.
    release.check(wheel(tmp_path / "w-py3-none-win_amd64.whl", {"tlsforge/bin/tls-forge.exe": 0, **NOTICES}), "win_amd64")
    # A notice anywhere in the wheel is carried; one nowhere is not.
    release.check(wheel(tmp_path / f"top-{linux}.whl", {"tlsforge/bin/tls-forge": 0o755, "tlsforge/LICENSE": 0o644,
                                                         "tlsforge/NOTICE": 0o644, "tlsforge/THIRD-PARTY-NOTICES.txt": 0o644}), linux)
    without = {k: v for k, v in NOTICES.items() if not k.endswith("/THIRD-PARTY-NOTICES.txt")}
    with pytest.raises(SystemExit, match="does not carry THIRD-PARTY-NOTICES.txt"):
        release.check(wheel(tmp_path / f"short-{linux}.whl", {"tlsforge/bin/tls-forge": 0o755, **without}), linux)
    # A name that only ends like a notice is not one.
    lookalike = {**without, "tlsforge/MY-THIRD-PARTY-NOTICES.txt": 0o644}
    with pytest.raises(SystemExit, match="does not carry THIRD-PARTY-NOTICES.txt"):
        release.check(wheel(tmp_path / f"like-{linux}.whl", {"tlsforge/bin/tls-forge": 0o755, **lookalike}), linux)


def test_a_wheel_says_its_licence_and_names_its_notices_in_its_metadata(release: ModuleType, tmp_path: Path) -> None:
    linux = TAGS[3]
    files = {"tlsforge/bin/tls-forge": 0o755, **NOTICES}
    for n, (meta, says) in enumerate([
        ([], "carries 0 METADATA files where one was expected"),
        ([metadata(LEGAL), metadata(LEGAL)], "carries 2 METADATA files where one was expected"),
        # What hatchling 1.26 wrote: the licence as text, the files unnamed.
        ([metadata([], expression="")], "does not say License-Expression: Apache-2.0 in its metadata"),
        ([metadata(LEGAL, expression="MIT")], "does not say License-Expression: Apache-2.0 in its metadata"),
        ([metadata(["LICENSE", "THIRD-PARTY-NOTICES.txt"])], "does not name NOTICE as a License-File in its metadata"),
        # Fields count only in the headers, not in the description below them.
        ([metadata(["LICENSE", "NOTICE"], body="License-File: THIRD-PARTY-NOTICES.txt\n")],
         "does not name THIRD-PARTY-NOTICES.txt as a License-File in its metadata"),
    ]):
        with pytest.raises(SystemExit, match=says):
            release.check(wheel(tmp_path / f"m{n}-{linux}.whl", files, meta), linux)
    # A file of the package called METADATA is no metadata of the wheel's.
    release.check(wheel(tmp_path / f"ok-{linux}.whl", {**files, "tlsforge/data/METADATA": 0o644},
                        [metadata(LEGAL, body="A description.\n")]), linux)


def test_the_script_runs_as_a_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["pypi-release.py", "--version", "nope", "--out", str(tmp_path / "o")])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert stopped.value.code == 2
