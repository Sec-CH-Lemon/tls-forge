import unittest

from fork_gate import evaluate, failure_digest


class ForkGateTests(unittest.TestCase):
    def rows(self, test="TestOld", text="old assertion", action="fail"):
        return [
            {"Package": "fork", "Test": test, "Action": "run"},
            {"Package": "fork", "Test": test, "Action": "output", "Output": text},
            {"Package": "fork", "Test": test, "Action": action},
            {"Package": "fork", "Action": action},
        ]

    def known(self):
        return [{"package": "fork", "test": "TestOld", "graphs": ["standalone"], "failure_pattern": "old assertion", "failure_output_sha256": {"standalone": [failure_digest("old assertion")] }}]

    def test_known_failure_remains_explicit_debt(self):
        got = evaluate(self.rows(), [1], self.known(), "standalone", requested_packages=["fork"])
        self.assertTrue(got["accepted"])
        self.assertEqual(got["known_failures"], [["fork", "TestOld"]])
        self.assertIn("not a green fork suite", got["meaning"])

    def test_new_name_subtest_or_signature_is_red(self):
        for rows in [self.rows("TestNew"), self.rows("TestOld/new-child"), self.rows(text="new reason")]:
            self.assertFalse(evaluate(rows, [1], self.known(), "standalone")["accepted"])

    def test_new_diagnostic_cannot_hide_in_known_failure(self):
        for text in ["old assertion\nnew regression", "old assertion plus new regression", "old assertion\nold assertion"]:
            self.assertFalse(evaluate(self.rows(text=text), [1], self.known(), "standalone")["accepted"])

    def test_missing_transcript_is_red(self):
        known = self.known()
        del known[0]["failure_output_sha256"]
        self.assertFalse(evaluate(self.rows(), [1], known, "standalone")["accepted"])

    def test_only_denied_resolver_address_is_normalized(self):
        first = "lookup example.com on 192.168.100.1:53: dial udp 192.168.100.1:53: connect: operation not permitted"
        self.assertEqual(failure_digest(first), failure_digest(first.replace("192.168.100.1", "1.1.1.1")))
        self.assertEqual(failure_digest(first), failure_digest(first.replace("192.168.100.1", "[2001:db8::1]")))
        for changed in [first.replace("example.com", "other.test"), first.replace(":53", ":54"), first.replace("operation not permitted", "connection refused"), first.replace("on 192.168.100.1", "on 1.1.1.1")]:
            self.assertNotEqual(failure_digest(first), failure_digest(changed))

    def test_transcript_normalization_is_bounded(self):
        first = '=== RUN   TestOld\n    file_test.go:1: Get "https://127.0.0.1:123/a" at /tmp/fork-gate-abc/path/file_test.go:2\n--- FAIL: TestOld (0.01s)\n'
        second = first.replace(":123/", ":456/").replace("/tmp/fork-gate-abc/", "/private/tmp/fork-gate-def/").replace("0.01s", "2.99s")
        self.assertEqual(failure_digest(first), failure_digest(second))
        self.assertNotEqual(failure_digest(first), failure_digest(first.replace("/a", "/b")))
        self.assertNotEqual(failure_digest(first), failure_digest(first.replace("--- FAIL: TestOld (0.01s)", "--- FAIL: TestOld (0.01s) new error")))

    def test_other_graph_cannot_borrow_an_exception(self):
        self.assertFalse(evaluate(self.rows(), [1], self.known(), "production")["accepted"])

    def test_compile_failure_and_truncated_runs_are_red(self):
        self.assertFalse(evaluate([{"Package": "fork", "Action": "build-fail"}], [1], [], "standalone")["accepted"])
        self.assertFalse(evaluate(self.rows(), [1], self.known(), "standalone", requested_packages=["fork", "missing"])["accepted"])
        self.assertFalse(evaluate(self.rows()[:2], [1], [], "standalone")["accepted"])

    def test_panics_timeouts_and_races_cannot_hide_in_a_known_test(self):
        for text in ["old assertion\npanic: runtime error", "old assertion\npanic: test timed out", "old assertion\nWARNING: DATA RACE"]:
            self.assertFalse(evaluate(self.rows(text=text), [1], self.known(), "standalone")["accepted"])

    def test_process_failure_and_inconsistent_success_are_red(self):
        for code in [-9, 2, 0]:
            self.assertFalse(evaluate(self.rows(), [code], self.known(), "standalone")["accepted"])

    def test_empty_or_missing_self_suite_is_red(self):
        self.assertFalse(evaluate([], [0], [], "standalone")["accepted"])
        self.assertFalse(evaluate(self.rows(action="pass"), [0], [], "standalone", require_self=True)["accepted"])

    def test_go126_build_events_without_package_are_red(self):
        rows = [{"Action": "build-output", "ImportPath": "fork [fork.test]", "Output": "bad printf"},
                {"Action": "build-fail", "ImportPath": "fork [fork.test]"}]
        self.assertFalse(evaluate(rows, [1], [], "production")["accepted"])

    def test_current_pass_does_not_erase_old_obligation(self):
        got = evaluate(self.rows(action="pass"), [0], self.known(), "standalone")
        self.assertTrue(got["accepted"])
        self.assertEqual(got["not_observed_now"], [["fork", "TestOld"]])


if __name__ == "__main__":
    unittest.main()
