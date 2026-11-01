"""The compiler inventory must cover every real test exactly once."""

from __future__ import annotations

from collections import Counter
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import go_root_shard as shard


class InventoryTests(unittest.TestCase):
    def test_names_cover_examples_fuzz_and_tests_without_benchmarks(self):
        self.assertEqual(shard.runnable_names(
            "TestZulu\nBenchmarkIgnored\nFuzzURL\nExample\nok example.test 0.1s\n"),
            ["Example", "FuzzURL", "TestZulu"])

    def test_empty_duplicated_or_corrupted_inventories_fail_closed(self):
        for output in ["ok example.test 0.1s", "TestA\nTestA", "Test bad name"]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                shard.runnable_names(output)

    def test_partitions_are_disjoint_and_cover_the_complete_inventory(self):
        names = ["TestD", "Example", "TestA", "FuzzX", "TestB"]
        for count in [1, 2, 3, 5]:
            parts = [shard.select(names, index, count) for index in range(count)]
            self.assertTrue(all(parts))
            self.assertEqual(Counter(name for part in parts for name in part), Counter(names))

    def test_invalid_or_empty_partitions_fail_closed(self):
        for index, count, names in [(-1, 2, ["TestA"]), (2, 2, ["TestA"]),
                                    (0, 0, ["TestA"]), (0, 2, ["TestA"]),
                                    (0, 1, []), (0, 1, ["TestA", "TestA"])]:
            with self.subTest(index=index, count=count), self.assertRaises(ValueError):
                shard.select(names, index, count)

    def test_discovery_and_execution_failures_are_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / "result.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                failed = subprocess.CompletedProcess([], 7, "compiler failed", "stderr")
                with mock.patch.object(shard.subprocess, "run", return_value=failed) as run:
                    self.assertEqual(shard.run(0, 1, manifest), 7)
                    self.assertEqual(run.call_count, 1)
                listed = subprocess.CompletedProcess([], 0, "TestA\n", "")
                for output, code, want in [("FAIL\n", 1, 1),
                                            ("ok example.test [no tests to run]\n", 0, 1),
                                            ("ok example.test 0.1s\n", 0, 0)]:
                    with mock.patch.object(shard.subprocess, "run", side_effect=[
                        listed, subprocess.CompletedProcess([], code, output),
                    ]):
                        self.assertEqual(shard.run(0, 1, manifest), want)
                        receipt = json.loads(manifest.read_text())
                        self.assertEqual(receipt["returncode"], want)
                        self.assertIn("-race", receipt["discovery_command"])
                        self.assertEqual(receipt["selected"], ["TestA"])

    def test_invalid_cli_or_missing_tool_fails_without_running_tests(self):
        with tempfile.TemporaryDirectory() as folder:
            args = ["--index", "0", "--count", "0", "--manifest", folder + "/x.json"]
            with contextlib.redirect_stderr(io.StringIO()):
                with mock.patch.object(shard.subprocess, "run") as run:
                    self.assertEqual(shard.main(args), 2)
                    run.assert_not_called()
                args[3] = "1"
                with mock.patch.object(shard.subprocess, "run", side_effect=OSError("no Go")):
                    self.assertEqual(shard.main(args), 2)


class RealGoTests(unittest.TestCase):
    def test_real_compiler_and_runner_execute_every_kind_once(self):
        script = Path(shard.__file__).resolve()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "go.mod").write_text("module shardfixture\n\ngo 1.26.10\n")
            (root / "shard_test.go").write_text('''package shardfixture
import ("fmt"; "os"; "testing")
func record(name string) {
 f, err := os.OpenFile(os.Getenv("SHARD_SEEN"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
 if err != nil { panic(err) }; defer f.Close(); fmt.Fprintln(f, name)
}
func TestAlpha(t *testing.T) { record("TestAlpha"); t.Run("child", func(t *testing.T) { record("TestAlpha/child") }) }
func TestBeta(t *testing.T) { record("TestBeta") }
func FuzzGamma(f *testing.F) { record("FuzzGamma"); f.Add("seed"); f.Fuzz(func(t *testing.T, value string) { record("FuzzGamma/seed") }) }
func Example() { record("Example"); fmt.Println("hello")
// Output: hello
}
func BenchmarkIgnored(b *testing.B) { record("BenchmarkIgnored") }
''')
            (root / "race_only_test.go").write_text('''//go:build race
package shardfixture
import "testing"
func TestRaceOnly(t *testing.T) { record("TestRaceOnly") }
''')
            seen = root / "seen.txt"
            source = "a" * 40
            env = dict(os.environ, GOWORK="off", SHARD_SEEN=str(seen), GITHUB_SHA=source)
            env.pop("GIT_DIR", None)
            env.pop("GIT_WORK_TREE", None)
            receipts = []
            for index in range(2):
                manifest = root / f"shard-{index}.json"
                result = subprocess.run([sys.executable, str(script), "--index", str(index),
                                         "--count", "2", "--manifest", str(manifest)],
                                        cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                receipts.append(json.loads(manifest.read_text()))
            expected = {"TestAlpha", "TestBeta", "FuzzGamma", "Example", "TestRaceOnly"}
            self.assertEqual(set(receipts[0]["inventory"]), expected)
            self.assertEqual(receipts[0]["inventory_sha256"], receipts[1]["inventory_sha256"])
            self.assertFalse(set(receipts[0]["selected"]) & set(receipts[1]["selected"]))
            self.assertEqual(Counter(seen.read_text().splitlines()), Counter([
                "TestAlpha", "TestAlpha/child", "TestBeta", "FuzzGamma",
                "FuzzGamma/seed", "Example", "TestRaceOnly",
            ]))
            shard.verify(root, 2, source)
            manifest = root / "shard-1.json"
            original = manifest.read_text()
            mutations = [
                lambda r: r.update(index=0),
                lambda r: r.update(index=True),
                lambda r: r.update(source_commit="b" * 40),
                lambda r: r.update(returncode=1),
                lambda r: r.update(returncode=False),
                lambda r: r.update(inventory_sha256="0" * 64),
                lambda r: r.update(selected=[]),
                lambda r: r["selected"].append(r["selected"][0]),
                lambda r: r["command"].__setitem__(-2, "^Never$"),
                lambda r: r["discovery_command"].remove("-race"),
                lambda r: r.update(count=1),
                lambda r: r.update(inventory=["TestOther"]),
            ]
            def drop_a_real_test(r):
                r["selected"].pop()
                r["command"][-2] = "^(" + "|".join(r["selected"]) + ")$"

            def overlap_another_shard(r):
                r["selected"].append(receipts[0]["selected"][0])
                r["command"][-2] = "^(" + "|".join(r["selected"]) + ")$"

            mutations.extend([drop_a_real_test, overlap_another_shard])
            try:
                for mutation in mutations:
                    changed = copy.deepcopy(receipts[1])
                    mutation(changed)
                    manifest.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        shard.verify(root, 2, source)
                manifest.unlink()
                with self.assertRaises(ValueError):
                    shard.verify(root, 2, source)
            finally:
                manifest.write_text(original)


if __name__ == "__main__":
    unittest.main()
