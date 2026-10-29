#!/usr/bin/env python3
"""Download a pinned official Google Chrome installer and verify its SHA-256."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from urllib.request import urlopen


def download(manifest, platform, directory, fetch=urlopen):
    entry = manifest["platforms"][platform]
    url = urlsplit(entry["url"])
    if url.scheme != "https" or url.netloc != "dl.google.com" or url.query or url.fragment:
        raise ValueError("archive must be pinned at official dl.google.com HTTPS")
    if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
        raise ValueError("archive needs exact SHA-256")
    if not re.fullmatch(str(manifest["major"]) + r"\.[0-9]+\.[0-9]+\.[0-9]+", entry["version"]):
        raise ValueError("archive version/major mismatch")
    if entry["kind"] not in ("dmg", "deb", "exe"):
        raise ValueError("unsupported archive kind")
    directory.mkdir(parents=True, exist_ok=True)
    partial = directory / "chrome.partial"
    digest = hashlib.sha256()
    try:
        with fetch(entry["url"], timeout=120) as source, partial.open("wb") as target:
            while block := source.read(1024 * 1024):
                digest.update(block)
                target.write(block)
        if digest.hexdigest() != entry["sha256"]:
            raise ValueError("archive SHA-256 mismatch")
        path = directory / ("chrome." + entry["kind"])
        partial.replace(path)
        return path, entry["version"]
    finally:
        partial.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path, version = download(json.loads(args.manifest.read_text()), args.platform, args.output)
    print(f"path={path.resolve().as_posix()}\nversion={version}")


if __name__ == "__main__":
    main()
