"""Where the binary is found, and in what order.

The order is the point: an explicit path beats the environment beats the binary
shipped in the wheel beats a local build beats PATH. A package that silently
preferred a system-wide binary over the one it shipped with would run a
different version from the one it was tested against.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tlsforge import BinaryNotFound, ENV_VAR, bundled_binary, exe_name, resolve_binary
from tlsforge import _binary


def executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_an_explicit_path_is_used_as_given(wrapper):
    assert resolve_binary(wrapper) == os.fspath(wrapper)


def test_an_explicit_path_may_be_a_path_object(wrapper):
    assert resolve_binary(Path(wrapper)) == os.fspath(wrapper)


def test_the_environment_variable_is_read(wrapper, monkeypatch):
    monkeypatch.setenv(ENV_VAR, os.fspath(wrapper))
    assert resolve_binary() == os.fspath(wrapper)


def test_an_explicit_path_beats_the_environment(wrapper, tmp_path, monkeypatch):
    other = executable(tmp_path / "other")
    monkeypatch.setenv(ENV_VAR, os.fspath(other))
    assert resolve_binary(wrapper) == os.fspath(wrapper)


def test_a_path_that_does_not_exist_is_an_error_rather_than_a_fallback(sterile):
    # Falling through would run a different binary than the one asked for, which
    # is the one bug this order exists to prevent.
    with pytest.raises(BinaryNotFound, match="no binary at"):
        resolve_binary("/definitely/not/here")


def test_a_directory_is_not_a_binary(tmp_path):
    with pytest.raises(BinaryNotFound, match="no binary at"):
        resolve_binary(tmp_path)


def test_an_environment_variable_pointing_nowhere_is_the_same_error(sterile, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "/definitely/not/here")
    with pytest.raises(BinaryNotFound, match="no binary at"):
        resolve_binary()


def test_the_binary_shipped_in_the_wheel_is_preferred_over_path(sterile, monkeypatch):
    shipped = executable(sterile / "wheel" / "bin" / exe_name())
    on_path = executable(sterile / "onpath" / exe_name())
    monkeypatch.setenv("PATH", str(on_path.parent))
    monkeypatch.setattr(_binary, "bundled_binary", lambda *_: shipped)
    assert resolve_binary() == str(shipped)


def test_a_build_in_the_checkout_is_used_when_the_wheel_has_none(sterile, monkeypatch):
    # Working on this client from a checkout is common enough to be worth
    # finding `make build`'s output.
    checkout = sterile / "checkout"
    (checkout / "bin").mkdir(parents=True)
    (checkout / "Makefile").write_text("")
    (checkout / "go.mod").write_text("")
    built = executable(checkout / "bin" / exe_name())
    monkeypatch.setattr(_binary, "__file__", str(checkout / "src" / "tlsforge" / "_binary.py"))
    assert resolve_binary() == str(built)


def test_a_checkout_without_a_build_falls_through(sterile, monkeypatch):
    checkout = sterile / "checkout"
    checkout.mkdir()
    (checkout / "Makefile").write_text("")
    (checkout / "go.mod").write_text("")
    on_path = executable(sterile / "onpath" / exe_name())
    monkeypatch.setenv("PATH", str(on_path.parent))
    monkeypatch.setattr(_binary, "__file__", str(checkout / "src" / "tlsforge" / "_binary.py"))
    assert resolve_binary() == str(on_path)


def test_the_binary_is_found_on_path_when_nothing_else_has_one(sterile, monkeypatch):
    on_path = executable(sterile / "onpath" / exe_name())
    monkeypatch.setenv("PATH", str(on_path.parent))
    assert resolve_binary() == str(on_path)


def test_no_binary_anywhere_is_an_error_that_says_what_to_do(sterile):
    with pytest.raises(BinaryNotFound) as caught:
        resolve_binary()
    message = str(caught.value)
    # A message that says "broken install" and leaves someone there is not a
    # message. Both ways out have to be in it.
    assert "no binary for" in message
    assert ENV_VAR in message
    assert "go build" in message


def test_the_executable_is_named_after_the_command_not_the_package():
    assert exe_name("darwin") == "tls-forge"
    assert exe_name("linux") == "tls-forge"
    assert exe_name("win32") == "tls-forge.exe"


def test_the_bundled_path_sits_inside_this_package():
    inside = bundled_binary("linux")
    assert inside.parent.parent == Path(_binary.__file__).resolve().parent
    assert inside.name == "tls-forge"
    assert bundled_binary("win32").name == "tls-forge.exe"


def test_the_default_platform_is_this_one():
    import sys

    assert exe_name() == exe_name(sys.platform)
    assert bundled_binary() == bundled_binary(sys.platform)
