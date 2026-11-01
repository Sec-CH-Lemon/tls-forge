"""Public reference output must describe source, independently of build host."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).with_name("generate-docs.py")
SPEC = importlib.util.spec_from_file_location("docs_generator", SCRIPT)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


def first(value: int = 41, *, enabled: bool = False) -> int:
    return value


def changed(value: int = 42, *, enabled: bool = False) -> int:
    return value


class DocumentationSourceTests(unittest.TestCase):
    def test_real_sdk_defaults_are_host_expressions(self):
        # Independent processes import the actual SDK after selecting the
        # platform. No SDK calls, browser or network operations are performed.
        program = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('docs_generator', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.platform = sys.argv[2]
print(module.python_page(), end='')
"""
        pages = [subprocess.check_output([sys.executable, "-c", program, str(SCRIPT), platform], text=True)
                 for platform in ("darwin", "linux", "win32")]
        self.assertEqual(pages[0], pages[1])
        self.assertEqual(pages[0], pages[2])
        self.assertIn("bundled_binary(platform: 'str' = sys.platform)", pages[0])
        self.assertIn("exe_name(platform: 'str' = sys.platform)", pages[0])

    def test_source_default_changes_remain_visible(self):
        before = GENERATOR.python_signature(first)
        after = GENERATOR.python_signature(changed)
        self.assertIn("value: int = 41", before)
        self.assertIn("value: int = 42", after)
        self.assertNotEqual(before, after)
        self.assertIn("*, enabled: bool = False", before)
        self.assertTrue(before.endswith("-> int"))


if __name__ == "__main__":
    unittest.main()
