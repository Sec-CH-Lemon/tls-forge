import base64
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('packets', Path(__file__).with_name('a8-h3-packets.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CausalDecoderInputTests(unittest.TestCase):
    def test_late_cid_introduction_moves_only_original_record(self):
        def record(direction, destination, source, clock):
            raw = b'\xc0\0\0\0\1' + bytes([len(destination)]) + destination + bytes([len(source)]) + source
            return {'direction': direction, 'remote': '127.0.0.1:1', 'local': '127.0.0.1:2', 'time_ns': clock, 'data': base64.b64encode(raw).decode()}
        original = [record('client', b'original', b'', 1), record('client', b'cid4', b'', 2), record('server', b'', b'cid4', 3)]
        ordered, moves = module.causal_records(original)
        self.assertEqual(ordered, [original[0], original[2], original[1]])
        self.assertEqual(len(moves), 1)
        self.assertEqual([v['time_ns'] for v in ordered], [1, 3, 2])
        self.assertTrue(all(any(value is actual for actual in original) for value in ordered))
        self.assertEqual(module.causal_records(original[:2]), (original[:2], []))
        self.assertEqual(module.causal_records(ordered), (ordered, []))
        with self.assertRaisesRegex(ValueError, 'truncated'):
            module.long_header_ids({'data':base64.b64encode(b'\xc0\0\0\0\1\x14\0').decode()})
