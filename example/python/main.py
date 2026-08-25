from __future__ import annotations

import os
import sys
from pathlib import Path

import tlsforge


DEFAULT_URL = "https://tls.browserleaks.com/json"


def repository_binary() -> Path:
    executable = "tls-forge.exe" if sys.platform == "win32" else "tls-forge"
    return Path(__file__).resolve().parents[2] / "bin" / executable


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    binary = os.environ.get("TLSFORGE_BIN")
    local_binary = repository_binary()
    if binary is None and local_binary.is_file():
        binary = str(local_binary)

    with tlsforge.Client(profile="chrome", binary=binary) as client:
        response = client.get(target)

    print(f"status: {response.status}")
    print(f"url: {response.url}\n")
    print(response.body)


if __name__ == "__main__":
    main()
