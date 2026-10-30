import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("a10_compare", Path(__file__).with_name("a10-cache-compare.py"))
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


class CacheComparisonTests(unittest.TestCase):
    def fixture(self, port, protocol="h1"):
        return {"cohort": 1, "protocol": protocol, "id": "both", "origin": f"https://127.0.0.1:{port}",
                "api": [{"status": 200, "body": "page"}], "requests": [{"protocol": "1.1", "response": {"status": 304},
                "headers": ["Host", f"127.0.0.1:{port}", "Referer", f"https://127.0.0.1:{port}/start", "If-None-Match", '"v1"', "If-Modified-Since", "date"]}]}

    def test_only_declared_origin_normalization_matches(self):
        self.assertTrue(compare.compare([self.fixture(1)], [self.fixture(2)])["accepted"])

    def test_wire_mutations_are_not_normalized_away(self):
        original = self.fixture(2)
        for mutation in ("order", "value", "missing", "path", "body", "status"):
            with self.subTest(mutation=mutation):
                row = copy.deepcopy(original)
                fields = row["requests"][0]["headers"]
                if mutation == "order": fields[4:8] = fields[6:8] + fields[4:6]
                if mutation == "value": fields[5] = '"different"'
                if mutation == "missing": del fields[4:6]
                if mutation == "path": fields[3] += "/different"
                if mutation == "body": row["api"][0]["body"] = "stale"
                if mutation == "status": row["requests"][0]["response"]["status"] = 200
                self.assertFalse(compare.compare([self.fixture(1)], [row])["accepted"])

    def test_invalid_evidence_is_rejected(self):
        for mutation in ("empty", "authority", "protocol", "odd", "missingpair", "duplicate"):
            with self.subTest(mutation=mutation):
                row = self.fixture(2)
                rows = [row]
                if mutation == "empty": row["requests"] = []
                if mutation == "authority": row["requests"][0]["headers"][1] = "other.test"
                if mutation == "protocol": row["requests"][0]["protocol"] = "2.0"
                if mutation == "odd": row["requests"][0]["headers"].pop()
                if mutation == "missingpair": rows = []
                if mutation == "duplicate": rows.append(row)
                with self.assertRaises(ValueError): compare.compare([self.fixture(1)], rows)

    def test_h3_order_requires_decoded_sections(self):
        chrome, client = self.fixture(1, "h3"), self.fixture(2, "h3")
        for row in (chrome, client): row["requests"][0]["protocol"] = "HTTP/3.0"
        def sections(port): return {1: {"/case/both": [[(":authority", f"127.0.0.1:{port}"), ("if-none-match", '"v1"'), ("if-modified-since", "date")]]}}
        self.assertTrue(compare.compare([chrome], [client], sections(1), sections(2))["accepted"])
        changed = sections(2)
        changed[1]["/case/both"][0].reverse()
        self.assertFalse(compare.compare([chrome], [client], sections(1), changed)["accepted"])
        with self.assertRaises(ValueError): compare.compare([chrome], [client], sections(1), {1:{"/case/both":[]}})
