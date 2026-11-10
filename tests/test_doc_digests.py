"""Pins for the assistant's tool digest corpus (spec §5, plan Task 14)."""
import io
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from build_digests import DIGEST_TOOLS, DIGESTS, check  # noqa: E402


def test_every_tool_has_a_digest():
    names = {p.stem for p in DIGESTS.glob("*.md")}
    assert set(DIGEST_TOOLS) <= names


def test_digests_are_complete_and_heuristic():
    for tool in DIGEST_TOOLS:
        text = (DIGESTS / f"{tool}.md").read_text(encoding="utf-8")
        assert len(text.splitlines()) >= 20, tool
        assert "HEURISTICS:" in text, tool
        assert "ollama" not in text.lower(), tool


def test_check_reports_all_compressed():
    out = io.StringIO()
    rows, bad = check(out=out)
    assert bad == []
    states = dict((t, s) for t, s in rows)
    # COMPRESSED-DB: the gw-tools lane is on this machine and verified
    # it. COMPRESSED-DB-CITED: the lane is absent here, the digest
    # names its lane and certifies itself. Both read as compressed.
    assert all(s in ("COMPRESSED-DB", "COMPRESSED-DB-CITED")
               for s in states.values())
