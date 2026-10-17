"""The fake is held to testdata/fake-daemon/scenarios.json, which every fake —
this one, Node's and the native one both suites run on Windows — answers alike:
a scenario added to one and not the others fails here, or in theirs."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import tlsforge

ROOT = Path(__file__).resolve().parents[2]
TABLE = json.loads((ROOT / "testdata" / "fake-daemon" / "scenarios.json").read_text(encoding="utf-8"))


def ask(wrapper: Path, line: dict, *args: str, **env: str) -> dict:
    """One line to a fake started with args and env, and its first answer."""
    # The context closes the pipes and waits for the process, once killed.
    with subprocess.Popen(
        [os.fspath(wrapper), "daemon", *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env={**os.environ, "TLSFORGE_PROTOCOL_FIXTURES": os.fspath(ROOT / "testdata" / "protocol"), **env},
    ) as process:
        try:
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(json.dumps(line) + "\n")
            process.stdin.flush()
            return json.loads(process.stdout.readline())
        finally:
            process.kill()


def test_the_fake_answers_every_scenario_scenarios_json_names(wrapper: Path) -> None:
    declared = ask(wrapper, {"id": 1, "control": "scenarios"})
    assert declared["requests"] == sorted(TABLE["requests"])
    assert declared["protocols"] == sorted(TABLE["protocols"])
    assert declared["inits"] == sorted(TABLE["inits"])


def test_a_scenario_a_protocol_mode_or_an_init_mode_no_fake_has_is_an_error_naming_it(client, wrapper: Path) -> None:
    with pytest.raises(tlsforge.RequestFailed, match='unknown scenario "no-such-scenario"'):
        client().get("https://no-such-scenario/")
    answer = ask(wrapper, {"id": 2, "control": "hello"}, TLSFORGE_TEST_PROTOCOL="no-such-mode")
    assert answer["id"] == 2 and answer["error"] == 'unknown protocol mode "no-such-mode"'
    init = ask(
        wrapper,
        {"id": 3, "control": "init", "proxy": "http://proxy.test:8080"},
        "--proxy-stdin",
        TLSFORGE_TEST_INIT="no-such-mode",
    )
    assert init["id"] == 3 and init["error"] == 'unknown init mode "no-such-mode"'
