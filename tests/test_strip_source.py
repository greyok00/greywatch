"""The shipped artifacts carry no commentary.

packaging/strip-source.py rewrites the .py files in the .deb, the wheel and
the tarball. The compiled modules drop their docstrings in build-cython.sh;
this covers the source files that still ship.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "strip-source.py"

spec = importlib.util.spec_from_file_location("strip_source", SCRIPT)
strip_source = importlib.util.module_from_spec(spec)
sys.modules["strip_source"] = strip_source
spec.loader.exec_module(strip_source)


SAMPLE = '''"""Module docstring.

Two paragraphs of it.
"""
from __future__ import annotations

import os  # a trailing comment


def helper(value):
    """Explain the helper."""
    # an interior comment
    return os.sep + value


class Box:
    """A class docstring."""

    def empty(self):
        """Docstring-only body."""
'''


def test_comments_and_docstrings_are_gone():
    out = strip_source.strip_text(SAMPLE, "sample.py")
    assert "Module docstring" not in out
    assert "Explain the helper" not in out
    assert "trailing comment" not in out
    assert "interior comment" not in out
    assert "class docstring" not in out
    assert "Docstring-only body" not in out


def test_the_module_still_runs_and_keeps_its_behaviour():
    out = strip_source.strip_text(SAMPLE, "sample.py")
    namespace = {"__name__": "stripped_sample"}
    exec(compile(out, "sample.py", "exec"), namespace)
    assert namespace["helper"]("x") == "/x"
    assert namespace["Box"]().empty() is None


def test_future_imports_survive_a_module_docstring():
    # `from __future__` may follow a docstring but not a `pass`
    out = strip_source.strip_text(SAMPLE, "sample.py")
    assert out.splitlines()[0] == "from __future__ import annotations"


def test_line_count_only_shrinks_and_no_comment_tokens_remain():
    import io
    import tokenize

    out = strip_source.strip_text(SAMPLE, "sample.py")
    assert len(out.splitlines()) < len(SAMPLE.splitlines())
    kinds = [t.type for t in tokenize.generate_tokens(io.StringIO(out).readline)]
    assert tokenize.COMMENT not in kinds


def test_tree_rewrite_leaves_an_unparseable_file_alone(tmp_path):
    good = tmp_path / "good.py"
    bad = tmp_path / "bad.py"
    good.write_text('"""doc"""\nx = 1\n')
    bad.write_text("def broken(:\n")
    changed, failed = strip_source.strip_tree(tmp_path)
    assert changed == 1 and failed == 1
    assert good.read_text().strip() == "x = 1"
    assert bad.read_text() == "def broken(:\n"
