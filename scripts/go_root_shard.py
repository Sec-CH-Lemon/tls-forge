#!/usr/bin/env python3
"""Run one complete partition of a Go package's compiled race-test inventory.

The root package and the CLI's are each too long under race for one runner
within the 20m every test binary keeps, so each is cut in parts, each part
its own runner. The package defaults to the root, ".".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def runnable_names(output: str) -> list[str]:
    """Keep tests, examples and fuzz seeds; benchmarks are not ordinary tests."""
    names = []
    for line in output.splitlines():
        if line.startswith(("Test", "Fuzz", "Example")):
            if not line.isidentifier():
                raise ValueError(f"invalid compiled test name: {line!r}")
            names.append(line)
    if not names or len(names) != len(set(names)):
        raise ValueError("compiled test inventory is empty or duplicated")
    return sorted(names)


def select(names: list[str], index: int, count: int) -> list[str]:
    """Every discovered name belongs to one nonempty, deterministic partition."""
    if count < 1 or not 0 <= index < count:
        raise ValueError("shard index must be within its positive count")
    if len(names) < count or len(names) != len(set(names)):
        raise ValueError("compiled inventory cannot fill every shard uniquely")
    return sorted(names)[index::count]


def commands(package: str, pattern: str) -> tuple[list[str], list[str]]:
    """What lists a package's compiled names, and what runs a selection of them."""
    if not re.fullmatch(r"\.(/[A-Za-z0-9_.-]+)*", package) or "/.." in package:
        raise ValueError(f"not a package of this module: {package!r}")
    # Discovery must use the same race build tags as execution. Otherwise a
    # race-only test can disappear from the selection before it ever runs.
    discovery = ["go", "test", "-race", "-list", ".", "-timeout", "20m", package]
    return discovery, ["go", "test", "-race", "-count=1", "-timeout", "20m", "-run", pattern, package]


def verify(folder: Path, count: int, source: str, package: str = ".") -> None:
    """Refuse missing, duplicated, filtered or foreign successful partitions."""
    files = sorted(folder.glob("*.json"))
    if count < 1 or len(files) != count or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("missing shard manifests or invalid source commit")
    receipts = [json.loads(file.read_text(encoding="utf-8")) for file in files]
    if any(type(r["index"]) is not int for r in receipts) or {r["index"] for r in receipts} != set(range(count)):
        raise ValueError("shard indices are incomplete or duplicated")
    inventory = receipts[0]["inventory"]
    if not inventory or len(inventory) != len(set(inventory)):
        raise ValueError("invalid complete inventory")
    if runnable_names("\n".join(inventory)) != inventory:
        raise ValueError("inventory does not contain canonical runnable names")
    digest = hashlib.sha256("\n".join(inventory).encode()).hexdigest()
    observed: set[str] = set()
    for receipt in receipts:
        chosen = receipt["selected"]
        pattern = "^(" + "|".join(re.escape(name) for name in chosen) + ")$"
        discovery, command = commands(package, pattern)
        if (receipt["source_commit"] != source or type(receipt["count"]) is not int
                or receipt["count"] != count or type(receipt["returncode"]) is not int
                or receipt["returncode"] != 0 or receipt["inventory"] != inventory
                or receipt["inventory_sha256"] != digest or not chosen
                or len(chosen) != len(set(chosen)) or observed.intersection(chosen)
                or receipt["command"] != command or receipt["discovery_command"] != discovery):
            raise ValueError("foreign, failed, overlapping or filtered shard")
        observed.update(chosen)
    if observed != set(inventory):
        raise ValueError("compiled inventory was not executed completely")


def run(index: int, count: int, manifest: Path, package: str = ".") -> int:
    if count < 1 or not 0 <= index < count:
        raise ValueError("shard index must be within its positive count")
    discovery_command, _ = commands(package, "")
    discovery = subprocess.run(discovery_command, capture_output=True, text=True, check=False)
    if discovery.returncode:
        sys.stdout.write(discovery.stdout)
        sys.stderr.write(discovery.stderr)
        return discovery.returncode
    names = runnable_names(discovery.stdout)
    chosen = select(names, index, count)
    pattern = "^(" + "|".join(re.escape(name) for name in chosen) + ")$"
    _, command = commands(package, pattern)
    receipt = {
        "source_commit": os.environ.get("GITHUB_SHA"),
        "index": index,
        "count": count,
        "inventory": names,
        "inventory_sha256": hashlib.sha256("\n".join(names).encode()).hexdigest(),
        "selected": chosen,
        "discovery_command": discovery_command,
        "command": command,
        "returncode": None,
    }
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"race shard {index + 1}/{count} of {package}: {len(chosen)}/{len(names)} compiled names", flush=True)
    # Preserve Go's normal, quiet output rather than exposing verbose successful
    # test logs. Only the manifest contains the selected source-level names.
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, check=False)
    sys.stdout.write(result.stdout)
    code = result.returncode
    if code == 0 and "[no tests to run]" in result.stdout:
        code = 1
        print("compiled selection executed no tests", file=sys.stderr)
    receipt["returncode"] = code
    manifest.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--source", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--package", default=".")
    args = parser.parse_args(argv)
    try:
        if args.verify is not None:
            verify(args.verify, args.count, args.source, args.package)
            print(f"all {args.count} race partitions of {args.package} cover one complete compiler inventory")
            return 0
        if args.index is None or args.manifest is None:
            raise ValueError("running requires index and manifest")
        return run(args.index, args.count, args.manifest, args.package)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"race shard: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
