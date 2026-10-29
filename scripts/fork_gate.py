#!/usr/bin/env python3
"""Run source-pinned fork suites; tolerate only named, evidenced old failures."""

import argparse
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time


def failure_transcript(text):
    """Hash all diagnostic lines, retaining duplicates and rejecting added output.

    Only harness metadata, source-export roots, loopback port numbers and the
    resolver address in a sandbox-denied DNS dial are normalized. Supporting
    Framer traces retain distinct values and report repeat counts separately.
    Original test events remain in the private evidence archive.
    """
    lines = []
    frames = {}
    for line in text.splitlines():
        if re.fullmatch(r"\s*(?:=== (?:RUN|PAUSE|CONT) +\S+|--- (?:FAIL|PASS|SKIP): \S+ \([0-9.]+s\))", line):
            continue
        line = re.sub(r"/[^\s\"]*/fork-gate-[^/\s]+/", "<source>/", line)
        def resolver(match):
            first, second = match[2], match[4]
            try:
                if ipaddress.ip_address(first.strip("[]")) != ipaddress.ip_address(second.strip("[]")):
                    return match[0]
            except ValueError:
                return match[0]
            return match[1] + "<resolver>" + match[3] + "<resolver>" + match[5]
        line = re.sub(r"(lookup \S+ on )(\[[0-9a-fA-F:]+\]|[0-9.]+)(:53: dial udp )(\[[0-9a-fA-F:]+\]|[0-9.]+)(:53: connect: operation not permitted)", resolver, line)
        line = re.sub(r"(127\.0\.0\.1|localhost|\[::1\]):[0-9]+", r"\1:<port>", line)
        # The socket-capability warning can be emitted by any first QUIC
        # caller. Only its wall clock is metadata: sizes and URL remain exact
        # diagnostic values and still require a reviewed transcript hash.
        line = re.sub(r"^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?= failed to sufficiently increase receive buffer size \(was: [0-9]+ kiB, wanted: [0-9]+ kiB, got: [0-9]+ kiB\)\. See https://github\.com/igor-lemon/quic-go-utls/wiki/UDP-Buffer-Sizes for details\.$)", "<clock>", line)
        frame = re.fullmatch(r"\s+[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]+(?:\.[0-9]+)? Framer 0x[0-9a-f]+: ((?:read|wrote) .+)", line)
        if frame:
            event = frame[1]
            frames[event] = frames.get(event, 0) + 1
            continue
        lines.append(line)
    # Framer trace multiplicity depends on scheduling of this flood test.
    # Preserve every event kind/value in the fingerprint and all counts in the
    # report; only repeated identical supporting trace events are collapsed.
    digest = hashlib.sha256(json.dumps([sorted(lines), sorted(frames)], ensure_ascii=True).encode()).hexdigest()
    return digest, frames


def failure_digest(text):
    return failure_transcript(text)[0]


def evaluate(events, returncodes, known, graph, require_self=False, requested_packages=None):
    failed = {(e["Package"], e["Test"]) for e in events
              if e.get("Action") == "fail" and e.get("Test")}
    package_failures = {e.get("Package", e.get("ImportPath", "unknown build target")) for e in events
                        if e.get("Action") in ("fail", "build-fail") and not e.get("Test")}
    outputs = {}
    for e in events:
        if e.get("Action") == "output":
            outputs.setdefault(e["Package"], []).append(e)
    allowed = {(x["package"], x["test"]): x for x in known if graph in x["graphs"]}
    unexpected = []
    trace_counts = []
    for package, test in sorted(failed):
        row = allowed.get((package, test))
        text = "".join(e.get("Output", "") for e in outputs.get(package, [])
                       if e.get("Test") == test or e.get("Test", "").startswith(test + "/"))
        digest, frames = failure_transcript(text)
        if frames:
            trace_counts.append({"package": package, "test": test, "frames": frames})
        if (row is None or not re.search(row["failure_pattern"], text, re.S)
                or digest not in row.get("failure_output_sha256", {}).get(graph, [])):
            unexpected.append({"package": package, "test": test, "reason": "new failure or signature"})
    for package in sorted(package_failures):
        if not any(p == package for p, _ in failed):
            unexpected.append({"package": package, "reason": "unnamed package/build failure"})
    for package, rows in outputs.items():
        if re.search(r"(?m)^(panic:|fatal error:|WARNING: DATA RACE)", "".join(e.get("Output", "") for e in rows)):
            unexpected.append({"package": package, "reason": "panic, timeout, or data race"})
    runs = [e for e in events if e.get("Action") == "run" and e.get("Test")]
    if not runs:
        unexpected.append({"reason": "no tests executed"})
    if require_self and not any("/integrationtests/self" in e["Package"] for e in runs):
        unexpected.append({"reason": "QUIC self integration did not execute"})
    if any(c not in (0, 1) for c in returncodes) or (any(returncodes) and not package_failures):
        unexpected.append({"reason": "process failure without complete named test evidence"})
    if failed and not any(returncodes):
        unexpected.append({"reason": "inconsistent test/process result"})
    if requested_packages is not None:
        completed = {e["Package"] for e in events if not e.get("Test") and e.get("Action") in ("pass", "fail", "skip")}
        for package in sorted(set(requested_packages) - completed):
            unexpected.append({"package": package, "reason": "requested package did not complete"})
    return {"accepted": not unexpected, "test_runs": len(runs), "trace_counts": trace_counts, "known_failures": [list(x) for x in sorted(failed & allowed.keys())],
            "not_observed_now": [list(x) for x in sorted(allowed.keys() - failed)], "unexpected": unexpected,
            "meaning": "Known-debt regression gate only; not a green fork suite, F09 stage2, or browser verdict."}


def module_graph(cwd, env):
    raw = subprocess.check_output(["go", "list", "-m", "-json", "all"], cwd=cwd, env=env, text=True)
    decoder, result = json.JSONDecoder(), []
    while raw.strip():
        raw = raw.lstrip()
        value, end = decoder.raw_decode(raw)
        result.append(value)
        raw = raw[end:]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fork", required=True, choices=["utls", "fhttp", "tls-client", "quic-go-utls"])
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--graph", required=True, choices=["standalone", "production"])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    inventory = json.loads((args.root / "verification/fork-failures.json").read_text())
    spec = inventory["forks"][args.fork]
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.source, text=True).strip()
    if actual != spec["commit"]:
        raise RuntimeError("fork source commit differs from the pinned inventory")
    args.output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOWORK="off", GONOSUMDB="github.com/igor-lemon/*")
    for key in list(env):
        if key.upper() == "SSLKEYLOGFILE":
            del env[key]
    env["GODEBUG"] = env.get("GODEBUG", "") + ",netdns=go"
    env["GOTOOLCHAIN"] = "go" + re.search(r"(?m)^go (\S+)", (args.root / "go.mod").read_text()).group(1)
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        raise RuntimeError("this measured gate requires the macOS loopback-only sandbox")
    policy = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
    sandbox = ["sandbox-exec", "-p", policy]
    # EPERM/EACCES proves the deny rule, rather than relying on an unreachable
    # public host. No application data is sent. TestWeb remains a named red test.
    probe = '''import socket, errno
for family, address in [(socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "::ffff:192.0.2.1")]:
    with socket.socket(family) as blocked:
        blocked.settimeout(1)
        result = blocked.connect_ex((address, 9))
        assert result in (errno.EPERM, errno.EACCES), (address, result)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(1)
    client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    client.bind(("::", 0))
    client.sendto(b"loopback-probe", ("::ffff:127.0.0.1", peer.getsockname()[1]))
    assert peer.recv(64) == b"loopback-probe"
'''
    subprocess.run(sandbox + [sys.executable, "-c", probe], env=env, check=True)
    with tempfile.TemporaryDirectory(prefix="fork-gate-") as directory:
        work = Path(directory)
        archive = args.output / "source.tar"
        with archive.open("wb") as out:
            subprocess.run(["git", "archive", actual], cwd=args.source, stdout=out, check=True)
        with tarfile.open(archive) as source:
            source.extractall(work, filter="data")
        expected, owner_graph = [], []
        if args.graph == "production":
            owner_graph = module_graph(args.root, env)
            owner_module = next(m["Path"] for m in owner_graph if m.get("Main"))
            # Match the modules actually linked into the owner's CLI/library.
            # go list -m all also contains latent tool/test requirements; making
            # those direct requirements changes lazy graph pruning and is not
            # the production runtime graph.
            linked = set(subprocess.check_output(
                ["go", "list", "-deps", "-f", "{{with .Module}}{{.Path}}{{end}}", owner_module + "/cmd/tls-forge"],
                cwd=args.root, env=env, text=True).splitlines())
            expected = [m for m in owner_graph if m["Path"] in linked]
            for item in expected:
                if item.get("Version") and item["Path"] != spec["module"]:
                    subprocess.run(["go", "mod", "edit", "-require=" + item["Path"] + "@" + item["Version"]], cwd=work, env=env, check=True)
        # Hydrate compiler/test dependencies outside the network-restricted test
        # process. Test execution itself has only owned loopback networking.
        subprocess.run(["go", "mod", "download", "all"], cwd=work, env=env, check=True)
        packages = subprocess.check_output(["go", "list", "./..."], cwd=work, env=env, text=True).splitlines()
        batches = [[spec["module"]], [p for p in packages if p != spec["module"]]] if args.fork == "fhttp" else [packages]
        events, codes = [], []
        for i, batch in enumerate(batches):
            if not batch:
                continue
            command = ["go", "test", "-json", "-p", "1", "-count=1", "-timeout", "12m"]
            if args.fork == "utls":
                command.append("-race")
            if args.fork == "fhttp" and i == 0:
                stamp = args.output.parent / "fhttp-last-root.json"
                if stamp.exists():
                    time.sleep(max(0, 45 - (time.time() - json.loads(stamp.read_text())["ended"])))
                command += ["-skip", "^TestOmitHTTP2$"]
            log = args.output / (str(i) + ".jsonl")
            with log.open("w") as out, (args.output / (str(i) + ".stderr")).open("w") as err:
                result = subprocess.run(sandbox + command + batch, cwd=work, env=env, stdout=out, stderr=err)
            codes.append(result.returncode)
            if args.fork == "fhttp" and i == 0:
                stamp.write_text(json.dumps({"ended": time.time()}))
            for line in log.read_text().splitlines():
                events.append(json.loads(line))
        selected = module_graph(work, env)
        (args.output / "module-graphs.json").write_text(json.dumps({"owner_all": owner_graph, "production_linked": expected, "tested": selected}, indent=2) + "\n")
        selected_versions = {m["Path"]: m.get("Version") for m in selected}
        for item in expected:
            if item.get("Version") and item["Path"] != spec["module"] and selected_versions.get(item["Path"]) != item["Version"]:
                raise RuntimeError("production module graph drift: " + item["Path"])
        known = [x for x in inventory["known_failures"] if x["package"] == spec["module"] or x["package"].startswith(spec["module"] + "/")]
        report = evaluate(events, codes, known, args.graph, args.fork == "quic-go-utls", packages)
        report.update({"fork": args.fork, "source_commit": actual, "toolchain": env["GOTOOLCHAIN"], "graph": args.graph, "returncodes": codes,
                       "network": "loopback only; external TestWeb cannot issue its POST", "modules": selected, "production_linked": expected,
                       "source_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "skips": ["TestOmitHTTP2"] if args.fork == "fhttp" else []})
        (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k not in ("modules", "production_linked", "known_failures", "not_observed_now", "trace_counts")}))
        return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
