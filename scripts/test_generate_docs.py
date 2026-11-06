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


def long_one(address: str, *, attempts: int = 3, timeout: float = 30.0, label: str = "a label") -> str:
    return address


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
        self.assertIn("bundled_binary(platform: str = sys.platform) -> Path", pages[0])
        self.assertIn("exe_name(platform: str = sys.platform) -> str", pages[0])
        # Module values are their source's expressions too, not the host's.
        self.assertIn("MAX_REQUEST_BYTES = 16 * 1024 * 1024", pages[0])

    def test_source_default_changes_remain_visible(self):
        before = GENERATOR.python_signature(first)
        after = GENERATOR.python_signature(changed)
        self.assertIn("value: int = 41", before)
        self.assertIn("value: int = 42", after)
        self.assertNotEqual(before, after)
        self.assertIn("*, enabled: bool = False", before)
        self.assertTrue(before.endswith("-> int"))

    def test_a_long_signature_goes_one_parameter_a_line(self):
        self.assertEqual(GENERATOR.python_signature(long_one, "long_one"), "\n".join((
            "long_one(",
            "    address: str,",
            "    *,",
            "    attempts: int = 3,",
            "    timeout: float = 30.0,",
            "    label: str = 'a label',",
            ") -> str",
        )))


class TextTests(unittest.TestCase):
    def test_prose_is_literal_but_for_code_and_emphasis(self):
        self.assertEqual(GENERATOR.inline_md("a_b <x> & [y] `c_d` *you*"), "a\\_b &lt;x> &amp; \\[y\\] `c_d` *you*")
        self.assertEqual(GENERATOR.inline_md("the part of *tlsforge.Client it needs"),
                         "the part of \\*tlsforge.Client it needs")
        self.assertEqual(GENERATOR.inline_md("``x`` and :class:`Hello`"), "`x` and `Hello`")
        self.assertEqual(GENERATOR.inline_html("a <b> `c<d>` *e*"), "a &lt;b&gt; <code>c&lt;d&gt;</code> <em>e</em>")

    def test_a_line_that_markdown_would_read_as_a_block_stays_text(self):
        for line, expected in (("# no heading", "\\# no heading"), ("- no item", "\\- no item"),
                               ("1. no item", "1\\. no item"), ("> no quote", "\\> no quote")):
            self.assertEqual(GENERATOR.inline_md(line), expected)

    def test_entries_have_anchors_of_their_own(self):
        ids = GENERATOR.Ids()
        self.assertEqual([ids("Client", "proxy"), ids("client", "proxy"), ids("fetch", "--proxy")],
                         ["client-proxy", "client-proxy-2", "fetch-proxy"])


class CLITests(unittest.TestCase):
    def test_flags_are_read_with_alias_value_and_default(self):
        rows = GENERATOR.flag_rows([
            '  -X, --method string              HTTP method (default "GET")',
            "  -H, --header name: value         extra header, repeatable",
            "      --clicked                    a person's click sends the request",
            '  -R, --report string[="auto"]     write a report (default: next to the output)',
        ], "fetch", GENERATOR.Ids())
        self.assertEqual([(row.name, row.aliases, row.type, row.labels, row.text) for row in rows], [
            ("--method", ("-X",), "string", ('default `"GET"`',), "HTTP method"),
            ("--header", ("-H",), "name: value", (), "extra header, repeatable"),
            ("--clicked", (), "", (), "a person's click sends the request"),
            ("--report", ("-R",), 'string[="auto"]', (), "write a report (default: next to the output)"),
        ])

    def test_a_line_that_is_no_flag_is_refused(self):
        with self.assertRaises(RuntimeError):
            GENERATOR.flag_rows(["something else"], "fetch", GENERATOR.Ids())


class GoTests(unittest.TestCase):
    OUTPUT = "\n".join((
        'package demo // import "example.com/demo-pkg"',
        "",
        "Package demo shows *a* thing.",
        "",
        "# Scope",
        "",
        "    code()",
        "",
        "CONSTANTS",
        "",
        "const (",
        "\tFirst = 1",
        "\tSecond = 2",
        ")",
        "    Numbers.",
        "",
        "",
        "TYPES",
        "",
        "type Options struct {",
        "\t// Addr (and port) to listen on: \"(\" is no bracket.",
        "\tAddr string",
        "}",
        "    Options configure it.",
        "",
        "      - one item",
        "        goes on",
        "",
        "func New(opts Options) (*Options, error)",
        "    New makes one.",
        "",
        "func (o *Options) Close() error",
    ))

    def test_a_package_is_read_symbol_by_symbol(self):
        page = GENERATOR.go_page("demo", self.OUTPUT)
        self.assertIn('import demo "example.com/demo-pkg"', page)
        self.assertIn("## Scope", page)
        self.assertIn("### First, Second { .tf-symbol }", page)
        self.assertIn("### Options { .tf-symbol }", page)
        self.assertIn("#### New() { .tf-member }", page)
        self.assertIn("#### Options.Close() { .tf-member }", page)
        self.assertIn("- one item goes on", page)
        self.assertIn('```text linenums="0"\ncode()\n```', page)
        # The struct's comment with a bracket in it is the struct's, not the end of it.
        self.assertIn("\tAddr string\n}\n```\n\nOptions configure it.", page)

    def test_a_declaration_it_does_not_know_is_refused(self):
        with self.assertRaises(RuntimeError):
            GENERATOR.go_page("demo", 'package demo // import "example.com/demo"\n\nFUNCTIONS\n\nmacro Thing')


class NodeTests(unittest.TestCase):
    def test_declarations_are_read_with_their_doc_comments(self):
        found = GENERATOR.statements("\n".join((
            "/** One. */",
            "export const ONE: number;",
            "/** Options. */",
            "export interface Options {",
            "  /** A union over lines. */",
            "  mode?:",
            "    | 'a'",
            "    | 'b';",
            "  run(input: { cause?: unknown }): void;",
            "}",
            "export class Empty extends Error {}",
        )))
        self.assertEqual([statement.split(" {")[0] for _, statement in found],
                         ["export const ONE: number;", "export interface Options", "export class Empty extends Error"])
        members = GENERATOR.statements(found[1][1].split("{", 1)[1].rsplit("}", 1)[0])
        self.assertEqual([member for _, member in members], ["mode?: | 'a' | 'b';", "run(input: { cause?: unknown }): void;"])

    def test_a_tag_it_does_not_know_is_refused(self):
        with self.assertRaises(RuntimeError):
            GENERATOR.jsdoc("/** Text.\n * @deprecated */")


if __name__ == "__main__":
    unittest.main()
