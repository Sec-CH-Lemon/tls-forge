import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('a8_h3_analyze', Path(__file__).with_name('a8-h3-analyze.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class H3EvidenceParserTests(unittest.TestCase):
    def test_truncation_duplicate_and_state_statistics_controls(self):
        self.assertEqual(module.integer(b'\x40\x21'), (33, 2))
        self.assertEqual(module.frames(b'\x04\x02\x01\x00'), [(4, b'\x01\x00')])
        self.assertEqual(module.pairs(b'\x01\x00'), [(1, 0)])
        for data in [b'', b'\x40', b'\xc0\0\0']:
            with self.assertRaisesRegex(ValueError, 'truncated'):
                module.integer(data)
        for data in [b'\x04\x03\x01\x00', b'\x04\x40']:
            with self.assertRaises(ValueError):
                module.frames(data)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            module.pairs(b'\x01\x00\x01\x01')
        self.assertEqual(module.grease_n(33), 0)
        self.assertEqual(module.grease_n(31 * 4294967295 + 33), 4294967295)
        with self.assertRaises(ValueError):
            module.grease_n(34)
        self.assertEqual(module.pearson([32] * 16), 0)
        self.assertGreater(module.pearson([512] + [0] * 15), 60)
        self.assertEqual(module.two_sample([32] * 16, [32] * 16), 0)
        self.assertGreater(module.two_sample([512] + [0] * 15, [0, 512] + [0] * 14), 60)
        with self.assertRaises(ValueError):
            module.pearson([0] * 16)
        with self.assertRaises(ValueError):
            module.two_sample([1], [2])
