#!/usr/bin/env python3
"""Strip comments and docstrings from the Python files in a tree, in place.

The release artifacts ship compiled modules, but the entrypoints and the
per-module .py fallbacks still ship as source so the package runs on a
Python the extension modules were not built for. Those files get the same
treatment as the compiled ones: no commentary, no docstrings, no dead
prose. Nothing else changes — statements, names and line positions stay
where they are, so a traceback from an installed copy still points at the
line you would edit in the repo.

    strip-source.py PATH [PATH ...]

Each rewritten file is compile-checked before it replaces the original;
a file that would not parse (or that stops parsing once stripped) is
reported and left alone.
"""
from __future__ import annotations

import ast
import io
import pathlib
import sys
import tokenize

# Lines that must survive even though they are comments: an interpreter
# directive on line 1 or 2 is behaviour, not commentary.
_KEEP = ("#!", "# -*- coding", "# coding:", "# vim:", "# fmt:")


def _docstring_nodes(tree: ast.AST):
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            yield node, first


def _strip_docstrings(text: str, tree: ast.AST) -> str:
    lines = text.splitlines(keepends=True)
    for owner, node in _docstring_nodes(tree):
        start = node.lineno - 1
        end = node.end_lineno            # exclusive after -1 + 1
        indent = " " * node.col_offset
        if isinstance(owner, ast.Module):
            # blank it: a module docstring may sit before `from __future__`,
            # and only a docstring may; a `pass` there is a SyntaxError
            lines[start] = "\n"
        else:
            # `pass` keeps a docstring-only body a valid block
            lines[start] = f"{indent}pass\n"
        for i in range(start + 1, min(end, len(lines))):
            lines[i] = "\n"
    return "".join(lines)


def _strip_comments(text: str) -> str:
    cut = {}
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT:
            cut[tok.start[0]] = tok.start[1]
    if not cut:
        return text
    out = []
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        col = cut.get(number)
        if col is not None and not line.lstrip().startswith(_KEEP):
            body = line[:col].rstrip()
            out.append(body + ("\n" if line.endswith("\n") else ""))
        else:
            out.append(line)
    return "".join(out)


def _collapse_blank(text: str) -> str:
    """One blank line between blocks, none at the top of the file."""
    kept: list[str] = []
    blank = False
    for line in text.splitlines():
        if line.strip():
            blank = False
            kept.append(line)
        elif not blank:
            blank = True
            kept.append("")
    while kept and not kept[0].strip():
        kept.pop(0)
    return "\n".join(kept) + "\n" if kept else ""


def strip_text(text: str, name: str = "<file>") -> str:
    tree = ast.parse(text, filename=name)
    text = _strip_docstrings(text, tree)
    text = _strip_comments(text)
    text = _collapse_blank(text)
    compile(text, name, "exec")         # never write a file that cannot load
    return text


def strip_tree(root: pathlib.Path) -> tuple[int, int]:
    changed = failed = 0
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            original = path.read_text(encoding="utf-8")
            new = strip_text(original, str(path))
        except (OSError, SyntaxError, ValueError, tokenize.TokenError) as exc:
            print(f"skipped {path}: {exc}", file=sys.stderr)
            failed += 1
            continue
        if new != original:
            path.write_text(new, encoding="utf-8")
            changed += 1
    return changed, failed


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.splitlines()[1], file=sys.stderr)
        return 2
    total_changed = total_failed = 0
    for arg in argv:
        root = pathlib.Path(arg)
        if not root.is_dir():
            print(f"not a directory: {root}", file=sys.stderr)
            return 2
        changed, failed = strip_tree(root)
        total_changed += changed
        total_failed += failed
    print(f"stripped {total_changed} file(s), {total_failed} skipped")
    return 1 if total_failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
