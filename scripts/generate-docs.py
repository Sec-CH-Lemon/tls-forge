#!/usr/bin/env python3
"""Generate public reference pages from the executable and SDK source.

Run with --write before editing docs; --check detects stale committed references.
The generator only reads source and writes files under docs/reference/.

Each reference page goes one symbol at a time: a heading with its name, its
signature or declaration in a code panel without line numbers, what its
documentation says, and its parameters, fields or flags as a list of name,
type and description. A construct the parsers below do not know is an error,
not something left out.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import html
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import typing


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "reference"
GO_PACKAGES = (".", "./profile", "./proxy", "./cookie", "./capture", "./fingerprint", "./echo", "./daemon", "./browser")
GO_DESCRIPTIONS = {
    "tlsforge": "Client, requests, responses, and options",
    "profile": "Profile loading, inspection, and migration",
    "proxy": "Local proxy implementation",
    "cookie": "Cookie parsing and storage",
    "capture": "Browser capture and measurement",
    "fingerprint": "Fingerprint comparison types",
    "echo": "Local echo and diagnostic server",
    "daemon": "JSON Lines daemon protocol",
    "browser": "Browser process integration",
}
GO_SECTIONS = {"CONSTANTS": "Constants", "VARIABLES": "Variables", "FUNCTIONS": "Functions", "TYPES": "Types"}
# A signature longer than this goes one parameter a line.
SIGNATURE_WIDTH = 72


def run(args: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed ({result.returncode}):\n{result.stdout}{result.stderr}")
    return result.stdout


def source_env(cache: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["GOWORK"] = "off"
    env["GOCACHE"] = str(cache)
    return env


# What the sources say, as Markdown and as HTML.

ROLE = re.compile(r":(?:class|meth|func|attr|mod|data|exc|obj):`~?([^`]+)`")
CODE_SPAN = re.compile(r"``(.+?)``|`([^`]+)`")
MARKDOWN_SPECIAL = re.compile(r"([\\*_\[\]])")
# *word* is emphasis; a lone star, as in *Client, is not.
EMPHASIS = re.compile(r"(?<![\w*])\*(?=[^\s*])([^*]*?[^\s*])\*(?![\w*])")


def code_spans(text: str) -> list[tuple[bool, str]]:
    """Text in pieces: (True, code) for each code span, (False, text) between them."""
    text = ROLE.sub(lambda match: f"`{match.group(1)}`", " ".join(text.split()))
    pieces, at = [], 0
    for match in CODE_SPAN.finditer(text):
        pieces.append((False, text[at:match.start()]))
        pieces.append((True, match.group(1) or match.group(2)))
        at = match.end()
    pieces.append((False, text[at:]))
    return [piece for piece in pieces if piece[1]]


def literal_md(text: str) -> str:
    return MARKDOWN_SPECIAL.sub(r"\\\1", text).replace("&", "&amp;").replace("<", "&lt;")


def prose_md(text: str) -> str:
    """Text with its emphasis kept and everything else literal."""
    out, at = [], 0
    for match in EMPHASIS.finditer(text):
        out += [literal_md(text[at:match.start()]), f"*{literal_md(match.group(1))}*"]
        at = match.end()
    return "".join(out + [literal_md(text[at:])])


def prose_html(text: str) -> str:
    out, at = [], 0
    for match in EMPHASIS.finditer(text):
        out += [html.escape(text[at:match.start()]), f"<em>{html.escape(match.group(1))}</em>"]
        at = match.end()
    return "".join(out + [html.escape(text[at:])])


def inline_md(text: str) -> str:
    """Prose as one line of Markdown: its code spans kept, everything else literal."""
    out = []
    for code, piece in code_spans(text):
        if code:
            fence = "``" if "`" in piece else "`"
            pad = " " if piece.startswith("`") or piece.endswith("`") else ""
            out.append(f"{fence}{pad}{piece}{pad}{fence}")
        else:
            out.append(prose_md(piece))
    line = "".join(out)
    if re.match(r"^\d+[.)] ", line):
        digits = re.match(r"^\d+", line).end()
        return line[:digits] + "\\" + line[digits:]
    return "\\" + line if re.match(r"^(#|>|[-+] )", line) else line


def inline_html(text: str) -> str:
    """Prose as HTML: its code spans as code, everything else escaped."""
    return "".join(f"<code>{html.escape(piece)}</code>" if code else prose_html(piece)
                   for code, piece in code_spans(text))


def paragraphs_md(paragraphs: list[str]) -> list[str]:
    """Paragraphs as Markdown; one whose lines begin with "- " is a list."""
    out: list[str] = []
    for paragraph in paragraphs:
        lines = paragraph.split("\n")
        if lines[0].lstrip().startswith("- "):
            items: list[str] = []
            for line in lines:
                if line.lstrip().startswith("- "):
                    items.append(line.lstrip()[2:])
                else:
                    items[-1] += " " + line.strip()
            out += [f"- {inline_md(item)}" for item in items] + [""]
        else:
            out += [inline_md(paragraph), ""]
    return out


def split_paragraphs(text: str) -> list[str]:
    return [part.strip("\n") for part in re.split(r"\n\s*\n", text) if part.strip()]


def heading(level: int, text: str, kind: str = "tf-symbol") -> str:
    return f"{'#' * level} {literal_md(text)} {{ .{kind} }}"


def panel(language: str, code: str) -> list[str]:
    """A signature or declaration: a code panel without line numbers."""
    return [f'```{language} linenums="0"', code.rstrip(), "```", ""]


class Ids:
    """The anchors of one page's list entries, each its own."""

    def __init__(self) -> None:
        self.taken: set[str] = set()

    def __call__(self, *parts: str) -> str:
        base = re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")
        anchor, n = base, 1
        while anchor in self.taken:
            n += 1
            anchor = f"{base}-{n}"
        self.taken.add(anchor)
        return anchor


class Row:
    """One entry of a list of parameters, fields or flags.

    A plain class: the tests load this file as a module of no name, which a
    dataclass refuses.
    """

    def __init__(self, name: str, type: str = "", labels: tuple[str, ...] = (), text: str = "",
                 aliases: tuple[str, ...] = (), anchor: str = "", link: str = "") -> None:
        self.name, self.type, self.labels, self.text = name, type, labels, text
        self.aliases, self.anchor, self.link = aliases, anchor, link


def linked(rows: list[Row], symbols: set[str]) -> list[Row]:
    """Rows whose names are symbols of the page, each linked to its heading."""
    for row in rows:
        if row.name in symbols:
            row.link = "#" + re.sub(r"[^\w-]", "", row.name.lower())
    return rows


def rows_html(title: str, rows: list[Row]) -> list[str]:
    """A list of entries as one block of HTML, which Markdown leaves as it is."""
    if not rows:
        return []
    out = ['<div class="tf-params">', f'<p class="tf-params__title">{html.escape(title)}</p>']
    for row in rows:
        anchor = f' id="{row.anchor}"' if row.anchor else ""
        name = f'<code class="tf-param__name">{html.escape(row.name)}</code>'
        if row.link:
            name = f'<a href="{html.escape(row.link)}">{name}</a>'
        head = [name] + [f'<code class="tf-param__alias">{html.escape(alias)}</code>' for alias in row.aliases]
        if row.type:
            head.append(f'<span class="tf-param__type">{html.escape(row.type)}</span>')
        head += [f'<span class="tf-param__label">{inline_html(label)}</span>' for label in row.labels]
        text = f'<div class="tf-param__text">{inline_html(row.text)}</div>' if row.text else ""
        out.append(f'<div class="tf-param"{anchor}><div class="tf-param__head">{"".join(head)}</div>{text}</div>')
    out += ["</div>", ""]
    return out


# The CLI, from what each command's --help says.

FLAG = re.compile(r"^\s+(?:(-[A-Za-z0-9]), )?(--[A-Za-z0-9][A-Za-z0-9-]*)(?: ((?:\S| (?! ))+))?\s{2,}(\S.*)$")
FLAG_DEFAULT = re.compile(r"\s*\(default (.+)\)$")
COMMAND = re.compile(r"^  ([a-z]+)\s{2,}(\S.*)$")


def help_blocks(text: str) -> list[tuple[str, list[str]]]:
    """A help text by blank lines: (heading, lines) for a group, ("", lines) otherwise."""
    blocks = []
    for block in re.split(r"\n\s*\n", text.strip()):
        lines = block.split("\n")
        if lines[0].endswith(":") and not lines[0].startswith(" "):
            blocks.append((lines[0][:-1], lines[1:]))
        else:
            blocks.append(("", lines))
    return blocks


def flag_rows(lines: list[str], command: str, ids: Ids) -> list[Row]:
    rows: list[Row] = []
    for line in lines:
        match = FLAG.match(line)
        if not match:
            if rows and line.startswith(" " * 8):
                rows[-1].text += " " + line.strip()
                continue
            raise RuntimeError(f"{command} --help: a line that is no flag: {line!r}")
        alias, name, value, text = match.groups()
        labels: tuple[str, ...] = ()
        default = FLAG_DEFAULT.search(text)
        if default:
            text = text[:default.start()]
            labels = (f"default `{default.group(1)}`",)
        rows.append(Row(name=name, type=value or "", labels=labels, text=text, aliases=(alias,) if alias else (),
                        anchor=ids(command, name)))
    return rows


def help_page(text: str, command: str, ids: Ids) -> list[str]:
    page: list[str] = []
    for title, lines in help_blocks(text):
        if not title and lines[0].startswith("usage: "):
            if len(lines) != 1:
                raise RuntimeError(f"{command} --help: a usage of more than one line")
            page += panel("bash", lines[0][len("usage: "):])
        elif command == "tls-forge" and all(COMMAND.match(line) for line in lines):
            rows = []
            for line in lines:
                name, description = COMMAND.match(line).groups()
                rows.append(Row(name=name, text=description, link=f"#{name}", anchor=ids("command", name)))
            page += rows_html("Commands", rows)
        elif title:
            page += rows_html("Flags" if title == "flags" else title[:1].upper() + title[1:], flag_rows(lines, command, ids))
        else:
            page += [inline_md(" ".join(lines)), ""]
    return page


def cli_page(binary: Path) -> str:
    intro = subprocess.run([str(binary), "--help"], cwd=ROOT, text=True, capture_output=True, check=True).stdout
    commands = re.findall(r"^  ([a-z]+)\s{2,}", intro, re.MULTILINE)
    if not commands or len(commands) != len(set(commands)):
        raise RuntimeError("could not parse the command list from tls-forge --help")
    ids = Ids()
    page = ["# CLI commands and flags", "",
            "Generated from the current CLI executable: what `tls-forge --help` and each command's `--help` say.", ""]
    page += help_page(intro, "tls-forge", ids)
    for command in commands:
        help_result = subprocess.run([str(binary), command, "--help"], cwd=ROOT, text=True, capture_output=True, check=False)
        if help_result.returncode not in (0, 2):
            raise RuntimeError(f"{command} --help failed: {help_result.stderr}")
        help_text = (help_result.stdout + help_result.stderr).strip()
        if not help_text.startswith(f"usage: tls-forge {command}"):
            raise RuntimeError(f"unexpected help output for {command}: {help_text[:100]}")
        page += [heading(2, command), ""] + help_page(help_text, command, ids)
    return "\n".join(page)


# Go, from what go doc -all prints.

def bracket_depth(line: str) -> int:
    """How many brackets a line of Go opens, less those it closes."""
    depth, quote, i = 0, "", 0
    while i < len(line):
        char = line[i]
        if quote:
            if char == "\\" and quote != "`":
                i += 1
            elif char == quote:
                quote = ""
        elif line.startswith("//", i):
            break
        elif char in "\"'`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        i += 1
    return depth


def go_entries(lines: list[str]) -> list[tuple[str, list[str]]]:
    """The declarations of one go doc section, each with its documentation."""
    entries, i = [], 0
    while i < len(lines):
        if not lines[i].strip():
            i += 1
            continue
        if lines[i].startswith(" "):
            raise RuntimeError(f"go doc: documentation without a declaration: {lines[i]!r}")
        declaration, depth = [lines[i]], bracket_depth(lines[i])
        i += 1
        while depth > 0 and i < len(lines):
            declaration.append(lines[i])
            depth += bracket_depth(lines[i])
            i += 1
        doc = []
        while i < len(lines) and (not lines[i].strip() or lines[i].startswith("    ")):
            doc.append(lines[i][4:])
            i += 1
        entries.append(("\n".join(declaration), doc))
    return entries


def go_doc_md(lines: list[str], level: int) -> list[str]:
    """Documentation as go doc prints it, as Markdown: paragraphs, lists, headings and code."""
    out: list[str] = []
    code: list[str] = []

    def flush() -> None:
        if code:
            out.extend(panel("text", textwrap.dedent("\n".join(code))))
            code.clear()

    for block in split_paragraphs("\n".join(lines)):
        block_lines = block.split("\n")
        if all(line.startswith("    ") for line in block_lines):
            code.extend(([""] if code else []) + block_lines)
            continue
        flush()
        first = block_lines[0]
        if len(block_lines) == 1 and first.startswith("# "):
            out += [f"{'#' * level} {inline_md(first[2:])}", ""]
        elif re.match(r"^  (-|\d+\.) ", first):
            items: list[tuple[str, str]] = []
            for line in block_lines:
                marker = re.match(r"^  (-|\d+\.) (.*)$", line)
                if marker:
                    items.append((marker.group(1), marker.group(2)))
                else:
                    items[-1] = (items[-1][0], items[-1][1] + " " + line.strip())
            out += [f"{marker} {inline_md(text)}" for marker, text in items] + [""]
        else:
            out += [inline_md(block), ""]
    flush()
    return out


def go_name(declaration: str) -> tuple[str, str]:
    """A declaration's heading and kind: type, const, var, func or method."""
    first = declaration.split("\n", 1)[0]
    method = re.match(r"^func \(\w*\s*\*?(\w+)(?:\[[^\]]*\])?\) (\w+)", first)
    if method:
        return f"{method.group(1)}.{method.group(2)}()", "method"
    function = re.match(r"^func (\w+)", first)
    if function:
        return f"{function.group(1)}()", "func"
    single = re.match(r"^(type|const|var) (\w+)", first)
    if single and not first.endswith("("):
        return single.group(2), single.group(1)
    group = re.match(r"^(const|var) \($", first)
    if group:
        names = [re.match(r"^\t(\w+)", line).group(1) for line in declaration.split("\n")[1:] if re.match(r"^\t\w", line)]
        if not names:
            raise RuntimeError(f"go doc: a group with no names: {first!r}")
        return ", ".join(names[:3]) + (", …" if len(names) > 3 else ""), group.group(1)
    raise RuntimeError(f"go doc: a declaration it does not know: {first!r}")


def go_page(label: str, output: str) -> str:
    lines = output.split("\n")
    header = re.match(r'^package (\w+) // import "(.+)"$', lines[0])
    if not header:
        raise RuntimeError(f"go doc {label}: an unexpected first line {lines[0]!r}")
    name, path = header.groups()
    alias = f"{name} " if path.rsplit("/", 1)[-1] != name else ""
    page = [f"# Go package `{label}`", "",
            "Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).", ""]
    page += panel("go", f'import {alias}"{path}"')
    sections: list[tuple[str, list[str]]] = [("", [])]
    for line in lines[1:]:
        if line in GO_SECTIONS:
            sections.append((GO_SECTIONS[line], []))
        else:
            sections[-1][1].append(line)
    page += go_doc_md(sections[0][1], 2)
    for title, body in sections[1:]:
        page += [f"## {title}", ""]
        for declaration, doc in go_entries(body):
            symbol, kind = go_name(declaration)
            member = title == "Types" and kind != "type"
            page += [heading(4 if member else 3, symbol, "tf-member" if member else "tf-symbol"), ""]
            page += panel("go", declaration) + go_doc_md(doc, 5 if member else 4)
    return "\n".join(page)


def go_pages(env: dict[str, str]) -> dict[str, str]:
    overview = ["# Go API", "", "Generated from exported Go declarations and Go doc comments. Start with the [Go integration guide](../integrations/go.md), then choose a package below.", "", "| Package | Use it for |", "| --- | --- |"]
    pages: dict[str, str] = {}
    for package in GO_PACKAGES:
        label = "tlsforge" if package == "." else package[2:]
        output = run(["go", "doc", "-all", package], env).strip()
        overview += [f"| [`{label}`](go/{label}.md) | {GO_DESCRIPTIONS[label]} |"]
        pages[f"go/{label}.md"] = go_page(label, output)
    overview.append("")
    pages["go-api.md"] = "\n".join(overview)
    return pages


# Node.js, from the declarations tsc emits from node/src.

def jsdoc(comment: str) -> tuple[list[str], list[Row]]:
    """A /** */ comment's paragraphs and its @throws."""
    prose: list[str] = []
    throws: list[Row] = []
    for line in (re.sub(r"^\s*\* ?", "", line) for line in comment[3:-2].split("\n")):
        tag = re.match(r"^\s*@(\w+)\s*(.*)$", line)
        if tag:
            kind = re.match(r"^\{(\w+)\}\s*(.*)$", tag.group(2))
            if tag.group(1) != "throws" or not kind:
                raise RuntimeError(f"Node.js declarations: a tag it does not know: {line.strip()!r}")
            throws.append(Row(name=kind.group(1), text=kind.group(2)))
        elif throws:
            throws[-1].text += " " + line.strip()
        else:
            prose.append(line)
    return split_paragraphs("\n".join(prose)), throws


def split_top(text: str, separator: str) -> list[str]:
    """Text split at each separator that is inside no bracket."""
    parts, depth, start = [], 0, 0
    for i, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [" ".join(part.split()) for part in parts if part.strip()]


def statements(source: str) -> list[tuple[str, str]]:
    """Each declaration of a block of TypeScript, with the doc comment before it.

    An interface or a class ends with its closing brace; anything else with a
    semicolon outside brackets.
    """
    out, doc, i = [], "", 0
    while i < len(source):
        if source[i].isspace():
            i += 1
        elif source.startswith("/**", i):
            end = source.index("*/", i) + 2
            doc, i = source[i:end], end
        elif source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
        else:
            block = re.match(r"(export )?(declare )?(interface|class) ", source[i:]) is not None
            depth, j = 0, i
            while j < len(source):
                char = source[j]
                j += 1
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    depth -= 1
                    if block and depth == 0 and char == "}":
                        break
                elif char == ";" and depth == 0 and not block:
                    break
            text = source[i:j].strip()
            out.append((doc, text if block else " ".join(text.split())))
            doc, i = "", j
    return out


def ts_signature(call: str, params: str, returns: str) -> str:
    parts = split_top(params, ",")
    line = f"{call}({', '.join(parts)}){returns}"
    if len(line) <= SIGNATURE_WIDTH or not parts:
        return line
    return f"{call}(\n" + "".join(f"  {part},\n" for part in parts) + f"){returns}"


# A declaration of a name the package exports, as tsc writes one.
NODE_DECLARED = re.compile(r"^export (?:declare )?(?:const|function|interface|class) (\w+)", re.MULTILINE)


def node_reexported(index: str, module: typing.Callable[[str], str]) -> str:
    """index with each `export { names } from './m.js'` replaced by what module("m")
    declares of those names, doc comments and all, in m's order."""

    def declared_in(match: re.Match[str]) -> str:
        names = [name.strip() for name in match.group(1).split(",")]
        found = [(doc, statement) for doc, statement in statements(module(match.group(2)))
                 if (declared := NODE_DECLARED.match(statement)) and declared.group(1) in names]
        missing = set(names) - {declared.group(1) for _, statement in found if (declared := NODE_DECLARED.match(statement))}
        if missing:
            raise RuntimeError(f"Node.js declarations: {match.group(2)}.d.ts declares no {', '.join(sorted(missing))}")
        return "\n".join(f"{doc}\n{statement}" for doc, statement in found)

    return re.sub(r"^export \{ ([^}]+) \} from '\./([\w-]+)\.js';$", declared_in, index, flags=re.MULTILINE)


def node_declarations(out: Path, env: dict[str, str]) -> str:
    """The package's declarations as its compile script emits them into out, read
    as one module."""
    run(["node", str(ROOT / "node" / "scripts" / "compile.ts"), "--out", str(out)], env)
    return node_reexported((out / "index.d.ts").read_text(), lambda name: (out / f"{name}.d.ts").read_text())


def node_page(source: str) -> str:
    ids = Ids()
    symbols = set(NODE_DECLARED.findall(source))
    page = ["# Node.js API", "",
            "Generated from the package's public TypeScript declarations. See the [Node.js integration guide](../integrations/node.md) for examples.", ""]
    for doc, statement in statements(source):
        prose, throws = jsdoc(doc) if doc else ([], [])
        constant = re.match(r"^export (?:declare )?const (\w+): (.+);$", statement)
        function = re.match(r"^export (?:declare )?function (\w+)\((.*)\): (.+);$", statement)
        declared = re.match(r"^export (?:declare )?(interface|class) (\w+)(?: extends (\w+))? \{(.*)\}$", statement, re.DOTALL)
        default = re.match(r"^export default (\w+);$", statement)
        if constant:
            page += [heading(2, constant.group(1)), ""] + panel("typescript", f"const {constant.group(1)}: {constant.group(2)}")
            page += paragraphs_md(prose)
        elif function:
            name, params, returns = function.groups()
            page += [heading(2, f"{name}()"), ""] + panel("typescript", ts_signature(name, params, f": {returns}"))
            page += paragraphs_md(prose) + rows_html("Throws", linked(throws, symbols))
        elif declared:
            kind, name, base, body = declared.groups()
            page += [heading(2, name), ""] + panel("typescript", f"{kind} {name}" + (f" extends {base}" if base else ""))
            page += paragraphs_md(prose)
            properties: list[Row] = []
            members: list[str] = []
            for member_doc, member in statements(body):
                if member == "#private;":
                    # What tsc says of a class with private fields: nothing a caller can use.
                    continue
                member_prose, member_throws = jsdoc(member_doc) if member_doc else ([], [])
                member = member.rstrip(";")
                field = re.match(r"^(\w+)(\?)?: (.+)$", member)
                method = re.match(r"^(\w+)\((.*)\)(?:: (.+))?$", member)
                if field:
                    properties.append(Row(name=field.group(1), type=field.group(3).lstrip("| "), text=" ".join(member_prose),
                                          labels=("optional",) if field.group(2) else (), anchor=ids(name, field.group(1))))
                elif method:
                    member_name, params, returns = method.groups()
                    # An object type as tsc writes it in one, { cause?: unknown; }, as a person would.
                    params = re.sub(r";\s*\}", " }", params)
                    constructor = member_name == "constructor"
                    call = f"new {name}" if constructor else f"{name[:1].lower()}{name[1:]}.{member_name}"
                    members += [heading(3, f"new {name}()" if constructor else f"{name}.{member_name}()", "tf-member"), ""]
                    members += panel("typescript", ts_signature(call, params, f": {returns}" if returns else ""))
                    members += paragraphs_md(member_prose) + rows_html("Throws", linked(member_throws, symbols))
                else:
                    raise RuntimeError(f"Node.js declarations: a member it does not know: {member!r}")
            page += rows_html("Properties", properties) + members
        elif default:
            page += [f"The package's default export is `{default.group(1)}`.", ""]
        else:
            raise RuntimeError(f"Node.js declarations: a declaration it does not know: {statement[:80]!r}")
    return "\n".join(page)


# Python, from the package itself and its source.

class SourceDefault:
    """A documented default expression, without evaluating it on the build host."""

    def __init__(self, expression: ast.expr) -> None:
        self.expression = ast.unparse(expression)

    def __repr__(self) -> str:
        return self.expression


def annotation_text(annotation: object) -> str:
    """An annotation as its source wrote it, without the quotes of a postponed one."""
    if annotation is inspect.Parameter.empty:
        return ""
    if isinstance(annotation, str):
        return annotation
    if isinstance(annotation, typing.ForwardRef):
        return annotation.__forward_arg__
    return inspect.formatannotation(annotation)


def class_fields(value: type) -> dict[str, tuple[SourceDefault | None, str]]:
    """Each annotated field of a class and its bases: its default as written, and the string after it."""
    fields: dict[str, tuple[SourceDefault | None, str]] = {}
    for cls in reversed(value.__mro__):
        try:
            body = ast.parse(textwrap.dedent(inspect.getsource(cls))).body[0].body
        except (OSError, TypeError):
            continue
        for statement, after in zip(body, body[1:] + [None]):
            if not isinstance(statement, ast.AnnAssign) or not isinstance(statement.target, ast.Name):
                continue
            default = None
            if statement.value is not None:
                default = statement.value
                if isinstance(default, ast.Call) and getattr(default.func, "id", "") == "field":
                    keywords = {keyword.arg: keyword.value for keyword in default.keywords}
                    if "default_factory" in keywords:
                        default = ast.Call(func=keywords["default_factory"], args=[], keywords=[])
                    else:
                        default = keywords.get("default")
            text = ""
            if isinstance(after, ast.Expr) and isinstance(after.value, ast.Constant) and isinstance(after.value.value, str):
                text = inspect.cleandoc(after.value.value)
            fields[statement.target.id] = (SourceDefault(default) if default is not None else None, text)
    return fields


def python_parameters(value: object) -> inspect.Signature:
    """A callable's signature with the defaults its source writes."""
    signature = inspect.signature(value)
    if inspect.isclass(value) and dataclasses.is_dataclass(value):
        written = class_fields(value)
        return signature.replace(parameters=[
            parameter.replace(default=written[name][0]) if written.get(name, (None, ""))[0] is not None else parameter
            for name, parameter in signature.parameters.items()])
    source = value.__init__ if inspect.isclass(value) else value
    try:
        function = ast.parse(textwrap.dedent(inspect.getsource(source))).body[0]
    except (OSError, TypeError):
        return signature
    positional = function.args.posonlyargs + function.args.args
    defaults = dict(zip([arg.arg for arg in positional][-len(function.args.defaults):], function.args.defaults))
    defaults.update((arg.arg, default) for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults) if default is not None)
    parameters = [parameter.replace(default=SourceDefault(defaults[name])) if name in defaults else parameter
                  for name, parameter in signature.parameters.items()]
    return signature.replace(parameters=parameters)


def own_parameters(signature: inspect.Signature) -> list[inspect.Parameter]:
    parameters = list(signature.parameters.values())
    return parameters[1:] if parameters and parameters[0].name in ("self", "cls") else parameters


def python_signature(value: object, name: str = "") -> str:
    """How a callable is called, as its source declares it; one parameter a line when that is long."""
    signature = python_parameters(value)
    parameters = own_parameters(signature)
    parts: list[str] = []
    for index, parameter in enumerate(parameters):
        if parameter.kind == parameter.KEYWORD_ONLY and all(
                earlier.kind not in (earlier.KEYWORD_ONLY, earlier.VAR_POSITIONAL) for earlier in parameters[:index]):
            parts.append("*")
        prefix = {parameter.VAR_POSITIONAL: "*", parameter.VAR_KEYWORD: "**"}.get(parameter.kind, "")
        annotation = annotation_text(parameter.annotation)
        part = prefix + parameter.name + (f": {annotation}" if annotation else "")
        if parameter.default is not parameter.empty:
            part += f" = {parameter.default!r}" if annotation else f"={parameter.default!r}"
        parts.append(part)
        if parameter.kind == parameter.POSITIONAL_ONLY and (index + 1 == len(parameters) or parameters[index + 1].kind != parameter.kind):
            parts.append("/")
    returns = "" if inspect.isclass(value) else annotation_text(signature.return_annotation)
    returns = f" -> {returns}" if returns else ""
    line = f"{name}({', '.join(parts)}){returns}"
    if len(line) <= SIGNATURE_WIDTH:
        return line
    return f"{name}(\n" + "".join(f"    {part},\n" for part in parts) + f"){returns}"


FIELD = re.compile(r"^:(param|raises|returns?)(?:\s+([^:]+?))?:\s*(.*)$")


def docstring(value: object) -> tuple[list[str], dict[str, str], list[Row], str]:
    """A docstring's paragraphs, its :param texts, its :raises and its :returns."""
    prose: list[str] = []
    fields: list[tuple[str, str, list[str]]] = []
    current: list[str] | None = None
    for line in (inspect.getdoc(value) or "").split("\n"):
        match = FIELD.match(line)
        if match:
            current = [match.group(3)]
            fields.append((match.group(1), match.group(2) or "", current))
        elif current is not None and line.startswith(" ") and line.strip():
            current.append(line.strip())
        else:
            current = None
            prose.append(line)
    params = {name: " ".join(text) for kind, name, text in fields if kind == "param"}
    raises = [Row(name=name, text=" ".join(text)) for kind, name, text in fields if kind == "raises"]
    returns = " ".join(" ".join(text) for kind, _, text in fields if kind.startswith("return"))
    return split_paragraphs("\n".join(prose)), params, raises, returns


def parameter_rows(signature: inspect.Signature, texts: dict[str, str], owner: str, ids: Ids) -> list[Row]:
    rows = []
    for parameter in own_parameters(signature):
        prefix = {parameter.VAR_POSITIONAL: "*", parameter.VAR_KEYWORD: "**"}.get(parameter.kind, "")
        labels = (f"default `{parameter.default!r}`",) if parameter.default is not parameter.empty else ()
        rows.append(Row(name=prefix + parameter.name, type=annotation_text(parameter.annotation), labels=labels,
                        text=texts.get(parameter.name, ""), anchor=ids(owner, parameter.name)))
    return rows


def python_callable(value: object, name: str, ids: Ids, symbols: set[str], doc_of: object | None = None,
                    lead: list[str] | None = None) -> list[str]:
    """A function, method or constructor: its signature, documentation, parameters, result and errors.

    A constructor's documentation follows its class's, given as lead.
    """
    paragraphs, params, raises, returns = docstring(value if doc_of is None else doc_of)
    signature = python_parameters(value)
    page = panel("python", python_signature(value, name)) + paragraphs_md((lead or []) + paragraphs)
    if params:
        page += rows_html("Parameters", parameter_rows(signature, params, name, ids))
    if returns:
        page += rows_html("Returns", [Row(name=annotation_text(signature.return_annotation) or "value", text=returns)])
    page += rows_html("Raises", linked(raises, symbols))
    return page


def module_values() -> dict[str, tuple[str, str]]:
    """Each module-level assignment of the package: its value as written, and the #: comment above it."""
    values: dict[str, tuple[str, str]] = {}
    for file in sorted((ROOT / "python" / "src" / "tlsforge").glob("*.py")):
        source = file.read_text()
        lines = source.split("\n")
        for statement in ast.parse(source).body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target, value = statement.targets[0], statement.value
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                target, value = statement.target, statement.value
            else:
                continue
            if not isinstance(target, ast.Name):
                continue
            above: list[str] = []
            for earlier in reversed(lines[:statement.lineno - 1]):
                if not earlier.startswith("#:"):
                    break
                above.insert(0, earlier[2:].strip())
            values[target.id] = (ast.unparse(value), " ".join(above))
    return values


def python_page() -> str:
    sys.path.insert(0, str(ROOT / "python" / "src"))
    module = importlib.import_module("tlsforge")
    values = module_values()
    symbols = {name for name in module.__all__ if inspect.isclass(getattr(module, name))}
    ids = Ids()
    page = ["# Python API", "", "Generated from the public `tlsforge` exports and their runtime signatures. See the [Python integration guide](../integrations/python.md) for examples.", ""]
    for name in module.__all__:
        value = getattr(module, name)
        if inspect.isfunction(value):
            page += [heading(2, f"{name}()"), ""] + python_callable(value, name, ids, symbols)
            continue
        page += [heading(2, name), ""]
        if not inspect.isclass(value):
            written, comment = values.get(name, (repr(value), ""))
            page += panel("python", f"{name} = {written}")
            page += paragraphs_md([comment]) if comment else []
            continue
        paragraphs, _, _, _ = docstring(value)
        if issubclass(value, BaseException):
            bases = ", ".join(base.__name__ for base in value.__bases__)
            page += panel("python", f"class {name}({bases})") + paragraphs_md(paragraphs)
            continue
        if hasattr(value, "__required_keys__"):
            fields = class_fields(value)
            optional = getattr(value, "__optional_keys__", frozenset())
            page += panel("python", f"class {name}(TypedDict)") + paragraphs_md(paragraphs)
            page += rows_html("Keys", [Row(name=key, type=annotation_text(kind), labels=("optional",) if key in optional else (),
                                           text=fields.get(key, (None, ""))[1], anchor=ids(name, key))
                                       for key, kind in value.__annotations__.items()])
            continue
        constructor = vars(value).get("__init__")
        if dataclasses.is_dataclass(value):
            fields = class_fields(value)
            page += panel("python", python_signature(value, name)) + paragraphs_md(paragraphs)
            page += rows_html("Fields", parameter_rows(python_parameters(value), {key: text for key, (_, text) in fields.items()}, name, ids))
        elif inspect.isfunction(constructor):
            page += python_callable(value, name, ids, symbols, doc_of=constructor, lead=paragraphs)
        else:
            page += paragraphs_md(paragraphs)
        for member_name, member in vars(value).items():
            if member_name.startswith("_"):
                continue
            if isinstance(member, property):
                result = annotation_text(inspect.signature(member.fget).return_annotation) if member.fget else ""
                member_paragraphs, _, _, _ = docstring(member)
                page += [heading(3, f"{name}.{member_name}", "tf-member"), ""]
                page += panel("python", f"{name}.{member_name}" + (f": {result}" if result else ""))
                page += paragraphs_md(member_paragraphs)
            elif inspect.isfunction(member):
                page += [heading(3, f"{name}.{member_name}()", "tf-member"), ""]
                page += python_callable(member, f"{name}.{member_name}", ids, symbols)
    return "\n".join(page)


def fields_page() -> str:
    files = sorted((ROOT / "profile" / "data").rglob("*.json"))
    if not files:
        raise RuntimeError("no shipped profiles found")
    found: dict[str, set[str]] = {}

    def visit(value: object, path: str) -> None:
        kind = "object" if isinstance(value, dict) else "array" if isinstance(value, list) else type(value).__name__
        if path:
            found.setdefault(path, set()).add(kind)
        if isinstance(value, dict):
            for key, item in value.items():
                if path == "behavior":
                    # Behavior policy keys contain literal dots; they are not
                    # nested JSON objects like the other profile sections.
                    address = f'behavior["{key}"]'
                else:
                    address = f"{path}.{key}" if path else key
                visit(item, address)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, list)):
                    visit(item, path + "[]")

    for file in files:
        visit(json.loads(file.read_text()), "")
    page = ["# Shipped profile fields", "", f"Generated from the {len(files)} bundled JSON profile files. This is an inventory of fields **present in shipped profiles**, not a schema of every permitted extension or evidence of browser equivalence. `behavior[\"h2.retries\"]` means the literal dotted key `h2.retries` inside the flat `behavior` object; other dotted addresses show nested objects. See [profile behavior](profile-behavior.md) for configuration groups and [profiles and compatibility](../guides/profiles.md) for execution rules.", "", "| Field address | Value kind |", "| --- | --- |"]
    page += [f"| `{path}` | {', '.join(sorted(kinds))} |" for path, kinds in sorted(found.items())]
    page += [""]
    return "\n".join(page)


def generate() -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="tls-forge-docs-") as temporary:
        temporary_path = Path(temporary)
        env = source_env(temporary_path / "go-cache")
        binary = temporary_path / "tls-forge"
        run(["go", "build", "-o", str(binary), "./cmd/tls-forge"], env)
        pages = {
            "cli.md": cli_page(binary),
            "node-api.md": node_page(node_declarations(temporary_path / "node", env)),
            "python-api.md": python_page(),
            "profile-fields.md": fields_page(),
        }
        pages.update(go_pages(env))
        return pages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    pages = generate()
    stale = []
    for name, content in pages.items():
        file = OUTPUT / name
        if args.write:
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
            print(f"generated {file.relative_to(ROOT)}")
        elif not file.exists() or file.read_text() != content:
            stale.append(name)
    if stale:
        print("stale documentation references: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
