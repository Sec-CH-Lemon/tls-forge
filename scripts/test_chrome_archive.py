import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("chrome_archive", Path(__file__).with_name("chrome-archive.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ChromeArchiveTests(unittest.TestCase):
    def test_hash_and_origin_must_match_before_installation(self):
        data = b"official artifact fixture"
        entry = {"url": "https://dl.google.com/release2/chrome/pinned.exe", "sha256": hashlib.sha256(data).hexdigest(), "kind": "exe", "version": "156.0.1.2"}
        manifest = {"major": 156, "platforms": {"Windows": entry}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, version = module.download(manifest, "Windows", root, lambda *a, **k: io.BytesIO(data))
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(version, "156.0.1.2")
            path.unlink()
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                module.download(manifest, "Windows", root, lambda *a, **k: io.BytesIO(b"changed"))
            self.assertEqual(list(root.iterdir()), [])
            for key, value, message in [("url", "http://dl.google.com/x", "official"), ("url", "https://dl.google.com.evil/x", "official"), ("url", "https://dl.google.com/x?changed=1", "official"), ("sha256", "missing", "exact SHA"), ("kind", "script", "unsupported"), ("version", "157.0.1.2", "version/major")]:
                bad = dict(entry, **{key: value})
                with self.assertRaisesRegex(ValueError, message):
                    module.download({"major": 156, "platforms": {"Windows": bad}}, "Windows", root, lambda *a, **k: self.fail("must reject before download"))
