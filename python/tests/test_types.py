"""tlsforge.BrowserContext holds to the browser context the Go daemon reads:
its keys are the daemon's fields by this package's names, in the daemon's
order, kind the one it needs, and each value one the Go code takes. The
Node.js package's index.d.ts is held to the same source by
node/test/types.test.js."""

from __future__ import annotations

import re
import typing
from pathlib import Path

import tlsforge
from tlsforge import _client

ROOT = Path(__file__).resolve().parents[2]


def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def block(text: str, head: str) -> str:
    """The body of the Go declaration that opens with head, to its closing
    brace at the start of a line."""
    opening = re.search(rf"^{head} \{{$", text, re.M)
    assert opening, head
    return text[opening.start() : text.index("\n}", opening.start())]


def go_tags(text: str, struct: str) -> list[str]:
    """The JSON names of a Go struct's fields, in order."""
    return re.findall(r'json:"(\w+)', block(text, f"type {struct} struct"))


def listed(text: str, pattern: str) -> list[str]:
    """The values of the constants a Go list names, sorted."""
    named = re.search(pattern, text, re.M)
    assert named, pattern
    values = dict(re.findall(r'^\t(\w+) += "([^"]*)"', text, re.M))
    return sorted(values[name] for name in re.split(r"[\s,]+", named.group(1)) if name)


def test_a_browser_context_is_the_daemons_by_this_packages_names() -> None:
    hints = typing.get_type_hints(tlsforge.BrowserContext)
    assert list(_client._CONTEXT_FIELDS) == list(hints)
    assert [_client._CONTEXT_FIELDS[key] for key in hints] == go_tags(source("daemon/daemon.go"), "BrowserContext")
    assert tlsforge.BrowserContext.__required_keys__ == frozenset({"kind"})
    assert hints["initiator"] is str


def test_each_value_of_a_browser_context_is_one_the_go_code_takes() -> None:
    hints = typing.get_type_hints(tlsforge.BrowserContext)
    browser = source("browser.go")
    kinds = sorted(re.findall(r'^\tKind\w+ RequestKind = "([^"]+)"', browser, re.M))
    assert sorted(typing.get_args(hints["kind"])) == kinds
    assert sorted(typing.get_args(hints["referrer_policy"])) == listed(
        source("site.go"), r"^var referrerPolicies = \[\]string\{([^}]*)\}"
    )
    assert sorted(typing.get_args(hints["mode"])) == listed(browser, r"\[\]string\{([^}]*)\}, r\.mode\)")
    assert sorted(typing.get_args(hints["credentials"])) == listed(
        browser, r"\[\]string\{([^}]*)\}, r\.credentials\)"
    )
