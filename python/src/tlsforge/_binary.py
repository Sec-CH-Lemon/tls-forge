"""Where is the tls-forge binary?

Four answers, in order, and the order is the point: an explicit path beats the
environment beats the binary shipped inside this package beats a local build
beats whatever is on PATH. A package that silently preferred a system-wide
binary over the one it shipped with would run a different version from the one
it was tested against.

The binary normally arrives inside the wheel. Python has no equivalent of npm's
optional dependencies and needs none: a wheel is already platform-tagged, so
`pip install tls-forge` on macOS arm64 fetches the macOS arm64 wheel with the
macOS arm64 binary in it, and no Go, no compiler and no download-on-install are
involved.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from ._errors import BinaryNotFound

#: The environment variable that overrides every other source.
ENV_VAR = "TLSFORGE_BIN"

#: Where the wheel keeps the binary, relative to this package.
BUNDLED_DIR = "bin"


def exe_name(platform: str = sys.platform) -> str:
    """The executable's name, which is the command's name, not the package's."""
    return "tls-forge.exe" if platform == "win32" else "tls-forge"


def bundled_binary(platform: str = sys.platform) -> Path:
    """The binary shipped inside this package, whether or not it is there."""
    return Path(__file__).resolve().parent / BUNDLED_DIR / exe_name(platform)


def resolve_binary(explicit: str | os.PathLike[str] | None = None) -> str:
    """Find the transport binary.

    :param explicit: a path to use as given, ahead of everything else.
    :raises BinaryNotFound: when nothing was found, or when a path that was
        named does not exist.
    """
    candidate = explicit or os.environ.get(ENV_VAR)
    if candidate:
        # Named explicitly and missing is an error rather than a reason to look
        # elsewhere: falling through would run a different binary than the one
        # asked for, which is the one bug this order exists to prevent.
        if not Path(candidate).is_file():
            raise BinaryNotFound(f"tls-forge: no binary at {candidate}")
        return str(candidate)

    shipped = bundled_binary()
    if shipped.is_file():
        return str(shipped)

    built = _repository_build()
    if built is not None:
        return str(built)

    on_path = shutil.which(exe_name())
    if on_path:
        return on_path

    raise BinaryNotFound(_nothing_anywhere())


def _repository_build() -> Path | None:
    """A binary built from a checkout this package is sitting inside.

    `make build` writes `bin/tls-forge` at the repository root, and working on
    the Python client from that checkout is common enough that finding it is
    worth four lines. Absent from an installed wheel, where the parents are
    site-packages and no `Makefile` is in sight.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / "Makefile").exists() and (parent / "go.mod").exists():
            built = parent / "bin" / exe_name()
            return built if built.is_file() else None
    return None


def _nothing_anywhere() -> str:
    return (
        f"tls-forge: no binary for {sys.platform}.\n"
        "  None shipped with this package, none built in a checkout, none on PATH.\n"
        "  If you installed with --no-binary, install the wheel instead. Otherwise\n"
        "  this platform has no prebuilt binary yet — build one with Go 1.25.13+\n"
        "    go build -o tls-forge ./cmd/tls-forge\n"
        "  and point at it\n"
        f"    {ENV_VAR}=/path/to/tls-forge"
    )
