"""The fake transport is injected as the BINARY, not by reaching into the client.

Substituting at the process boundary means these tests exercise the spawn, the
pipes and the reader threads — which is where the interesting failures live. The
client builds its own argv, so the stand-in is a wrapper script that ignores
whatever flags it is handed, apart from passing them on so a test can see them.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
FAKE_DAEMON = HERE / "fake_daemon.py"


def make_executable(path: Path, script: str) -> Path:
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture(scope="session")
def wrapper(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A binary that execs the fake daemon, passing the client's argv through."""
    configured = os.environ.get("TLSFORGE_TEST_DAEMON")
    if configured:
        return Path(configured).resolve()
    if sys.platform == "win32":
        raise RuntimeError("TLSFORGE_TEST_DAEMON must name the native fake daemon on Windows")
    return make_executable(
        tmp_path_factory.mktemp("bin") / "wrapper.sh",
        f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_DAEMON}" "$@"\n',
    )


@pytest.fixture
def deaf(tmp_path: Path, wrapper: Path) -> Path:
    """A transport that answers once and then stops reading, without dying.

    The write path exists for the gap between "the process is alive" and "the
    bytes reached it", and that gap cannot be produced from Python: closing
    stdin leaves the descriptor open, so the pipe keeps a reader. A shell closes
    fd 0 and nothing else.
    """
    if os.environ.get("TLSFORGE_TEST_DAEMON"):
        return wrapper
    return make_executable(
        tmp_path / "deaf.sh",
        "#!/bin/sh\n"
        "read -r line\n"
        'id=$(printf \'%s\' "$line" | sed \'s/.*"id":\\([0-9]*\\).*/\\1/\')\n'
        "printf '{\"id\":%s,\"status\":200,\"url\":\"https://deaf/first\","
        '"body":"","headers":{},"cookies":[]}\\n\' "$id"\n'
        "exec 0<&-\n"
        "sleep 30\n",
    )


@pytest.fixture(autouse=True)
def no_ambient_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test may be steered by a TLSFORGE_BIN the developer happens to have set."""
    monkeypatch.delenv("TLSFORGE_BIN", raising=False)


@pytest.fixture
def sterile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A world with no binary in any of the places resolution looks.

    Every source is taken away at once, including the two that a checkout
    supplies for free: an editable install leaves this package inside the
    repository, so `bundled_binary` and the checkout build both resolve against
    a tree that has a real `bin/tls-forge` in it. Moving the package's notion of
    where it lives is what takes those away.
    """
    from tlsforge import _binary

    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.delenv("TLSFORGE_BIN", raising=False)
    monkeypatch.setattr(_binary, "__file__", str(tmp_path / "nowhere" / "_binary.py"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def client(wrapper: Path):
    """A client on the fake transport, closed however the test ends."""
    import tlsforge

    made = []

    def build(**options):
        made.append(tlsforge.Client(binary=os.fspath(wrapper), **options))
        return made[-1]

    yield build
    for one in made:
        one.close()
