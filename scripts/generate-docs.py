#!/usr/bin/env python3
"""Generate public reference pages from the executable and SDK source.

Run with --write before editing docs; --check detects stale committed references.
The generator only reads source and writes files under docs/reference/.
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "reference"
GO_PACKAGES = (".", "./profile", "./proxy", "./cookie", "./capture", "./fingerprint", "./echo", "./daemon", "./browser")
GO_DESCRIPTIONS = {
    "tlsforge": "Client, requests, responses, and options",
    "profile": "Profile loading, inspection, and migration",
    "proxy": "Local proxy implementation",
    "cookie": "Cookie parsing and storage",
    "capture": "Browser capture and measurement",
    "fingerprint": "Fingerprint comparison types",
    "echo": "Local echo and diagnostic server",
    "daemon": "JSON Lines daemon protocol",
    "browser": "Browser process integration",
}


def run(args: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed ({result.returncode}):\n{result.stdout}{result.stderr}")
    return result.stdout


def source_env(cache: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["GOWORK"] = "off"
    env["GOCACHE"] = str(cache)
    return env


def cli_page(binary: Path) -> str:
    intro = subprocess.run([str(binary), "--help"], cwd=ROOT, text=True, capture_output=True, check=True).stdout
    commands = re.findall(r"^  ([a-z]+)\s{2,}", intro, re.MULTILINE)
    if not commands or len(commands) != len(set(commands)):
        raise RuntimeError("could not parse the command list from tls-forge --help")
    page = ["# CLI commands and flags", "", "Generated from the current CLI executable. Every command's `--help` output is included below.", "", "```text", intro.rstrip(), "```", ""]
    for command in commands:
        help_result = subprocess.run([str(binary), command, "--help"], cwd=ROOT, text=True, capture_output=True, check=False)
        if help_result.returncode not in (0, 2):
            raise RuntimeError(f"{command} --help failed: {help_result.stderr}")
        help_text = (help_result.stdout + help_result.stderr).strip()
        if not help_text.startswith(f"usage: tls-forge {command}"):
            raise RuntimeError(f"unexpected help output for {command}: {help_text[:100]}")
        page += [f"## `{command}`", "", "```text", help_text, "```", ""]
    return "\n".join(page)


def go_pages(env: dict[str, str]) -> dict[str, str]:
    overview = ["# Go API", "", "Generated from exported Go declarations and Go doc comments. Start with the [Go integration guide](../integrations/go.md), then choose a package below.", "", "| Package | Use it for |", "| --- | --- |"]
    pages: dict[str, str] = {}
    for package in GO_PACKAGES:
        label = "tlsforge" if package == "." else package[2:]
        output = run(["go", "doc", "-all", package], env).strip()
        overview += [f"| [`{label}`](go/{label}.md) | {GO_DESCRIPTIONS[label]} |"]
        pages[f"go/{label}.md"] = "\n".join((f"# Go package `{label}`", "", "Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).", "", "```text", output, "```", ""))
    overview.append("")
    pages["go-api.md"] = "\n".join(overview)
    return pages


def node_page() -> str:
    types = (ROOT / "node" / "index.d.ts").read_text()
    return "\n".join(("# Node.js API", "", "Generated from the package's public TypeScript declarations. See the [Node.js integration guide](../integrations/node.md) for examples.", "", "```typescript", types.rstrip(), "```", ""))


def python_page() -> str:
    sys.path.insert(0, str(ROOT / "python" / "src"))
    module = importlib.import_module("tlsforge")
    page = ["# Python API", "", "Generated from the public `tlsforge` exports and their runtime signatures. See the [Python integration guide](../integrations/python.md) for examples.", ""]
    for name in module.__all__:
        value = getattr(module, name)
        page += [f"## `{name}`", ""]
        if inspect.isclass(value):
            doc = inspect.getdoc(value)
            if doc:
                page += [doc, ""]
            if not hasattr(value, "__required_keys__"):
                try:
                    page += ["```python", f"{name}{inspect.signature(value)}", "```", ""]
                except (TypeError, ValueError):
                    pass
            annotations = getattr(value, "__annotations__", {})
            if annotations:
                page += ["| Field | Type |", "| --- | --- |"]
                page += [f"| `{key}` | `{typ}` |" for key, typ in annotations.items()]
                page += [""]
            for method_name, method in vars(value).items():
                if method_name.startswith("_") and method_name != "__init__":
                    continue
                if isinstance(method, property):
                    page += [f"### `{name}.{method_name}`", "", inspect.getdoc(method) or "Property.", ""]
                elif inspect.isfunction(method):
                    page += [f"### `{name}.{method_name}{inspect.signature(method)}`", "", inspect.getdoc(method) or "", ""]
        elif inspect.isfunction(value):
            page += ["```python", f"{name}{inspect.signature(value)}", "```", "", inspect.getdoc(value) or "", ""]
        else:
            page += [f"`{value!r}`", ""]
    return "\n".join(page)


def fields_page() -> str:
    files = sorted((ROOT / "profile" / "data").rglob("*.json"))
    if not files:
        raise RuntimeError("no shipped profiles found")
    found: dict[str, set[str]] = {}

    def visit(value: object, path: str) -> None:
        kind = "object" if isinstance(value, dict) else "array" if isinstance(value, list) else type(value).__name__
        if path:
            found.setdefault(path, set()).add(kind)
        if isinstance(value, dict):
            for key, item in value.items():
                if path == "behavior":
                    # Behavior policy keys contain literal dots; they are not
                    # nested JSON objects like the other profile sections.
                    address = f'behavior["{key}"]'
                else:
                    address = f"{path}.{key}" if path else key
                visit(item, address)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, list)):
                    visit(item, path + "[]")

    for file in files:
        visit(json.loads(file.read_text()), "")
    page = ["# Shipped profile fields", "", f"Generated from the {len(files)} bundled JSON profile files. This is an inventory of fields **present in shipped profiles**, not a schema of every permitted extension or evidence of browser equivalence. `behavior[\"h2.retries\"]` means the literal dotted key `h2.retries` inside the flat `behavior` object; other dotted addresses show nested objects. See [profile behavior](profile-behavior.md) for configuration groups and [profiles and compatibility](../guides/profiles.md) for execution rules.", "", "| Field address | Value kind |", "| --- | --- |"]
    page += [f"| `{path}` | {', '.join(sorted(kinds))} |" for path, kinds in sorted(found.items())]
    page += [""]
    return "\n".join(page)


def generate() -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="tls-forge-docs-") as temporary:
        temporary_path = Path(temporary)
        env = source_env(temporary_path / "go-cache")
        binary = temporary_path / "tls-forge"
        run(["go", "build", "-o", str(binary), "./cmd/tls-forge"], env)
        pages = {
            "cli.md": cli_page(binary),
            "node-api.md": node_page(),
            "python-api.md": python_page(),
            "profile-fields.md": fields_page(),
        }
        pages.update(go_pages(env))
        return pages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    pages = generate()
    stale = []
    for name, content in pages.items():
        file = OUTPUT / name
        if args.write:
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
            print(f"generated {file.relative_to(ROOT)}")
        elif not file.exists() or file.read_text() != content:
            stale.append(name)
    if stale:
        print("stale documentation references: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
