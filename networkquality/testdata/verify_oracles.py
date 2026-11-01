"""Replay committed inputs against independent C++ arithmetic/hash harnesses."""
from pathlib import Path
import json
import subprocess
import tempfile

p = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="tls-forge-nqe-oracles-") as out:
    out = Path(out)
    subprocess.run(["c++", "-std=c++17", "-O2", str(p / "weighted-buffer-oracle.cc"), "-o", str(out / "buffer")], check=True)
    fixture = json.loads((p / "weighted-buffer-oracle.json").read_text())
    rows = []
    expected = []
    for case in fixture["cases"]:
        rule = case["policy"]
        observations = case["observations"]
        rows.append(" ".join(map(str, [rule["capacity"], rule["half_life_seconds"], rule["signal_weight"], case["now_ms"], case["begin_ms"], case["signal"], case["percentile"], len(observations)])))
        rows.extend(" ".join(map(str, [o["at_ms"], o["value"], o["signal"]])) for o in observations)
        result = case["expected"]
        expected.append(f'{int(result["available"])} {result["value"]} {result["count"]}')
    actual = subprocess.check_output([str(out / "buffer")], input="\n".join(rows) + "\n", text=True).splitlines()
    assert actual == expected, "weighted buffer oracle differs"
    fixture = json.loads((p / "libcxx-hosthash-oracle.json").read_text())
    for fixed in (False, True):
        binary = out / ("hash-fixed" if fixed else "hash-original")
        args = ["c++", "-std=c++17", "-O2"]
        if fixed:
            args.append("-D_LIBCPP_ABI_FIX_CITYHASH_IMPLEMENTATION")
        subprocess.run([*args, str(p / "libcxx-hosthash-oracle.cc"), "-o", str(binary)], check=True)
        cases = [case for case in fixture["cases"] if case["fixed"] == fixed]
        actual = subprocess.check_output([str(binary), *[case["host"] for case in cases]], text=True).splitlines()
        assert len(actual) == len(cases)
        for line, case in zip(actual, cases):
            host, value, _native_system_variant = line.rsplit(" ", 2)
            assert host == case["host"] and value == case["value"], (fixed, case, line)
print("128 weighted buffer +188 libc++ hash oracle cases replayed")
