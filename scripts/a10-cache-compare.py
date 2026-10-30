#!/usr/bin/env python3
"""Compare A10 ordered request sections and response semantics, retaining input."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit


def normalize(fields, origin):
    result = []
    authority = urlsplit(origin).netloc
    for name, value in fields:
        if name.lower() in ("host", ":authority"):
            if value != authority:
                raise ValueError("wire authority differs from the declared owned origin")
            value = "<owned-origin>"
        if name.lower() == "referer" and value.startswith(origin + "/"):
            value = "<owned-origin>" + value[len(origin):]
        result.append([name, value])
    return result


def sections(root, actor, cohort):
    path = root / f"{actor}-{cohort}-h3/peer/headers.ndjson"
    result = {}
    for line in path.read_text().splitlines():
        row = json.loads(line)
        fields = [(f["Name"], f["Value"]) for f in row["fields"]]
        target = next((value for name, value in fields if name == ":path"), "")
        if target.startswith("/case/"):
            result.setdefault(target, []).append(fields)
    return result


def signature(row, h3=None):
    requests = row["requests"]
    if not requests:
        raise ValueError("no origin request: a fresh positive control cannot be empty")
    expected = {"h1": "1.1", "h2": "2.0", "h3": "HTTP/3.0"}[row["protocol"]]
    if any(request["protocol"] != expected for request in requests):
        raise ValueError("protocol fallback or missing protocol evidence")
    if row["protocol"] == "h3":
        fields = h3["/case/" + row["id"]]
        if len(fields) != len(requests):
            raise ValueError("H3 decoded sections do not cover all origin requests")
    else:
        fields = []
        for request in requests:
            flat = request["headers"]
            if len(flat) % 2:
                raise ValueError("incomplete ordered header pair")
            fields.append(list(zip(flat[::2], flat[1::2])))
    return {
        "api": row["api"],
        "wire_statuses": [request["response"]["status"] for request in requests],
        "ordered_headers": [normalize(part, row["origin"]) for part in fields],
    }


def compare(chrome, client, chrome_h3=None, client_h3=None):
    def indexed(rows):
        out = {}
        for row in rows:
            key = (row["cohort"], row["protocol"], row["id"])
            if key in out:
                raise ValueError("duplicate pair identity")
            out[key] = row
        return out
    browser, candidate = indexed(chrome), indexed(client)
    if not browser or browser.keys() != candidate.keys():
        raise ValueError("missing or additional pairs")
    pairs = []
    for key, row in browser.items():
        left = signature(row, (chrome_h3 or {}).get(key[0]))
        right = signature(candidate[key], (client_h3 or {}).get(key[0]))
        pairs.append({"key": key, "matched": left == right,
                      "chrome": left if left != right else None,
                      "client": right if left != right else None})
    return {"accepted": all(row["matched"] for row in pairs),
            "matched": sum(row["matched"] for row in pairs), "pairs": pairs,
            "normalization": {"Host/:authority": "validated owned origin host/port only",
                              "Referer": "owned origin prefix only; path and suffix remain exact"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--scenarios", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    chrome = json.loads((args.chrome / "results.json").read_text())
    client = json.loads((args.client / "results.json").read_text())
    ids = {row["id"] for row in json.loads(args.scenarios.read_text())}
    protocols = {row["protocol"] for row in chrome}
    expected = {(cohort, protocol, case) for cohort in (1, 2) for protocol in protocols for case in ids}
    if {(row["cohort"], row["protocol"], row["id"]) for row in chrome} != expected:
        raise ValueError("incomplete independent cohorts or scenario matrix")
    chrome_h3 = {i: sections(args.chrome, "chrome", i) for i in (1, 2)} if "h3" in protocols else None
    client_h3 = {i: sections(args.client, "client", i) for i in (1, 2)} if "h3" in protocols else None
    report = compare(chrome, client, chrome_h3, client_h3)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"accepted": report["accepted"], "matched": report["matched"], "pairs": len(report["pairs"])}))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
