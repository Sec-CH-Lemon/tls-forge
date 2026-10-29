import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("capture_artifacts", Path(__file__).with_name("check-capture-artifacts.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CaptureArtifactsTests(unittest.TestCase):
    def test_exact_bytes_origin_and_major_reject_negative_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "chrome_156_linux/chrome_156/linux.json"
            path.parent.mkdir(parents=True)
            candidate = {"name": "chrome_156_linux", "schema": 4, "engine_major": 1, "behavior": {"h3.qpack.dynamic": True}}
            raw = json.dumps(candidate).encode()
            path.write_bytes(raw)
            meta = root / "capture-provenance_chrome_156_linux/chrome_156/linux.json"
            meta.parent.mkdir(parents=True)
            provenance = {"provenance_schema": 1, "profile_sha256": hashlib.sha256(raw).hexdigest(), "basis_name": "chrome_155_linux", "fields": {"behavior.h3.qpack.dynamic": {"class": "inherited"}}, "acceptance": "candidate; browser/wire acceptance not established by capture"}
            meta.write_text(json.dumps(provenance))
            self.assertEqual(len(module.verify(root, 1)), 1)
            path.write_bytes(raw + b"\n")
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                module.verify(root, 1)
            path.write_bytes(raw)
            for key, value, message in [("engine_major", 0, "engine/schema"), ("engine_major", True, "engine/schema"), ("schema", 1, "engine/schema"), ("name", "../escape", "invalid candidate")]:
                bad = dict(candidate, **{key: value})
                path.write_text(json.dumps(bad))
                with self.assertRaisesRegex(ValueError, message):
                    module.verify(root, 1)
            path.write_bytes(raw)
            provenance["fields"]["behavior.h3.qpack.dynamic"]["class"] = "measured"
            meta.write_text(json.dumps(provenance))
            with self.assertRaisesRegex(ValueError, "inherited origin"):
                module.verify(root, 1)
            meta.unlink()
            with self.assertRaises(FileNotFoundError):
                module.verify(root, 1)

    def test_empty_collection_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "no candidate"):
                module.verify(Path(directory), 1)
