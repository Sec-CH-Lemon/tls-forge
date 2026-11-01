#!/usr/bin/env python3
"""Check internal /docs/ links in the built MkDocs HTML, including raw HTML cards."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit


SITE_URL = "https://tls-forge.com/docs/"


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


def source_url(relative: Path) -> str:
    name = relative.as_posix()
    if name == "index.html":
        return SITE_URL
    if name.endswith("/index.html"):
        return SITE_URL + name[: -len("index.html")]
    return SITE_URL + name


def check(site_dir: Path) -> list[str]:
    if not (site_dir / "index.html").is_file():
        raise ValueError(f"no built documentation at {site_dir}")
    broken: list[str] = []
    for page in sorted(site_dir.rglob("*.html")):
        links = Links()
        links.feed(page.read_text())
        for href in links.hrefs:
            target = urlsplit(urljoin(source_url(page.relative_to(site_dir)), href))
            if target.netloc != "tls-forge.com" or not target.path.startswith("/docs/"):
                continue
            path = site_dir / target.path.removeprefix("/docs/")
            if target.path.endswith("/") or path.is_dir():
                path /= "index.html"
            if not path.is_file():
                broken.append(f"{page.relative_to(site_dir)}: {href}")
    return broken


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site_dir", nargs="?", type=Path, default=Path("site/docs"))
    args = parser.parse_args()
    try:
        broken = check(args.site_dir.resolve())
    except ValueError as error:
        parser.error(str(error))
    for item in broken:
        print(item)
    if broken:
        print(f"{len(broken)} broken internal documentation links")
        return 1
    print("internal documentation links: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
