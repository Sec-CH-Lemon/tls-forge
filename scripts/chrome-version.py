#!/usr/bin/env python3
"""Which Chrome should a capture measure?

Not the newest one. The newest published stable build and the one people are
actually running are different things, and for this project it is the second
that matters: a profile is worth having because it looks like everybody else,
and a fingerprint that 0.5% of Chrome sends is nearly as identifying as a
home-made one.

Measured on 2026-08-16, with 152 sitting in the stable channel:

    151.0.7922.138    99.00%
    151.0.7922.139     0.50%
    152.0.7977.42      0.50%

`browser-actions/setup-chrome` with `chrome-version: stable` installs Chrome for
Testing's newest stable, which was 152 — the half-a-percent one. This resolves
the other one instead.

    python scripts/chrome-version.py                 # what most people run
    python scripts/chrome-version.py --channel beta  # look ahead instead

It prints the version to standard output and its reasoning to standard error, so
a workflow can capture the first and show the second.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import defaultdict

# Chrome's own release data. `endtime=none` leaves the releases still being
# served, and each carries the fraction of users it is served to.
VERSION_HISTORY = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/{platform}"
    "/channels/{channel}/versions/all/releases?filter=endtime=none&pageSize=50"
)

# What Chrome for Testing actually has to download, which is not every build:
# 151.0.7922.139 is served to real users and is not here.
KNOWN_GOOD = "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions.json"

# The desktop platforms this project captures on. Aggregated rather than taken
# one at a time, because one run measures all three and a run that captured 152
# on macOS and 151 on Linux would file two versions for one browser.
PLATFORMS = ["mac_arm64", "win64", "linux"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--platforms", nargs="*", default=PLATFORMS)
    args = parser.parse_args()

    builds = rollout(args.channel, args.platforms)
    if not builds:
        raise SystemExit(f"chrome-version: nothing is being served on the {args.channel} channel")

    major = dominant_major(builds)
    build, why = pick(builds, major)
    note(builds, major, build, why)
    print(build)
    return 0


def rollout(channel: str, platforms: list[str]) -> dict[str, float]:
    """How much of each build is being served, summed over platforms."""
    shares: dict[str, float] = defaultdict(float)
    for platform in platforms:
        url = VERSION_HISTORY.format(platform=platform, channel=channel)
        for release in fetch(url).get("releases", []):
            shares[release["version"]] += release.get("fraction", 0.0)
    return dict(shares)


def major_of(version: str) -> str:
    return version.split(".")[0]


def dominant_major(builds: dict[str, float]) -> str:
    """The release line most of them are on.

    The line first, and only then a build within it, because a rollout is
    routinely spread over several builds of the same line: on the day this was
    written 151 was being served as .109 to 49.5%, .110 to 24.75% and .137 to
    24.75%, so no single build had a majority while the line plainly did.
    """
    lines: dict[str, float] = defaultdict(float)
    for version, share in builds.items():
        lines[major_of(version)] += share
    return max(lines, key=lambda line: (lines[line], int(line)))


def pick(builds: dict[str, float], major: str) -> tuple[str, str]:
    """The build to measure: the most-served one of that line, if it can be had.

    Chrome for Testing publishes a subset of the builds Google serves —
    151.0.7922.139 was being served and was not downloadable — so the most
    widely served build is the first choice and the newest of the same line is
    the fallback. Within a line the handshake does not move, which is what makes
    the fallback a fallback rather than a different measurement.
    """
    available = downloadable(major)
    line = {v: s for v, s in builds.items() if major_of(v) == major}

    served = max(line, key=lambda v: (line[v], version_key(v)))
    if served in available:
        return served, "the most widely served build"

    newest = max(available, key=version_key)
    return newest, (
        f"the newest build of {major} that can be downloaded; "
        f"the most served one, {served}, cannot be"
    )


def downloadable(major: str) -> set[str]:
    builds = {
        version["version"]
        for version in fetch(KNOWN_GOOD)["versions"]
        if major_of(version["version"]) == major
    }
    if not builds:
        raise SystemExit(
            f"chrome-version: Chrome for Testing has no build of {major} to download"
        )
    return builds


def version_key(version: str) -> list[int]:
    return [int(part) for part in version.split(".")]


def note(builds: dict[str, float], major: str, build: str, why: str) -> None:
    total = sum(builds.values()) or 1.0
    # The line's share rather than the build's: when the build is a fallback it
    # is not in the served list at all, and "0.00% of what is served" reads as a
    # warning about a browser nobody has when it means the opposite.
    line = sum(share for v, share in builds.items() if major_of(v) == major)

    print("  serving now:", file=sys.stderr)
    for version in sorted(builds, key=lambda v: (-builds[v], version_key(v))):
        mark = "<" if version == build else " "
        print(f"    {version:>16}  {builds[version] / total * 100:6.2f}%  {mark}", file=sys.stderr)
    print(f"  measuring {build} — {why}", file=sys.stderr)
    print(f"  Chrome {major} is {line / total * 100:.2f}% of what is served", file=sys.stderr)


def fetch(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https URLs
        return json.load(response)


if __name__ == "__main__":
    raise SystemExit(main())
