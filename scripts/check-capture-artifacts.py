#!/usr/bin/env python3
"""Verify a drift candidate's exact provenance without promoting it."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def verify(directory, major):
    profiles = []
    for artifact in sorted(directory.iterdir()):
        if not artifact.is_dir() or artifact.name.startswith("capture-provenance_"):
            continue
        for path in sorted(artifact.glob("*/*.json")):
            raw = path.read_bytes()
            candidate = json.loads(raw)
            name = candidate.get("name", "")
            if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name) or ".." in name:
                raise ValueError("invalid candidate name")
            if artifact.name != name:
                raise ValueError("candidate/artifact identity mismatch")
            declared = candidate.get("engine_major")
            if type(declared) is not int or declared != major or candidate.get("schema") != 4:
                raise ValueError("candidate engine/schema mismatch")
            provenance_path = directory / ("capture-provenance_" + name) / path.relative_to(artifact)
            provenance = json.loads(provenance_path.read_text())
            digest = hashlib.sha256(raw).hexdigest()
            if provenance.get("profile_sha256") != digest:
                raise ValueError("candidate bytes differ from provenance")
            if provenance.get("provenance_schema") != 1 or not provenance.get("basis_name"):
                raise ValueError("missing explicit policy provenance")
            fields = provenance.get("fields", {})
            policies = candidate.get("behavior", {})
            if not policies or any(fields.get("behavior." + key, {}).get("class") != "inherited" for key in policies):
                raise ValueError("unmeasured policy lost its inherited origin")
            if provenance.get("acceptance") != "candidate; browser/wire acceptance not established by capture":
                raise ValueError("capture falsely promoted to browser acceptance")
            profiles.append((name, digest, provenance["basis_name"], len(policies)))
    if not profiles:
        raise ValueError("no candidate profiles with provenance")
    return profiles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    version = json.loads(args.engine.read_text())["version"]
    candidates = verify(args.directory, int(version.split(".")[0]))
    print("Candidate artifacts verified; native browser/wire acceptance is still required.\n")
    print("| candidate | exact SHA-256 | basis | inherited policies |\n|---|---|---|---|")
    for name, digest, basis, count in candidates:
        # These cells are data, not Markdown instructions supplied by a browser.
        safe_basis = str(basis).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("`", "")
        print(f"| `{name}` | `{digest}` | `{safe_basis}` | {count} |")


if __name__ == "__main__":
    main()
