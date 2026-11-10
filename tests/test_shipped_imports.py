"""The shipped code never imports the dev tree.

The deb ships ui/, assistant/, hunter/, appfw/ and the root modules - it
does NOT ship tools/ (checker) or tests/. One import of a tools. module
from shipped code kept the app from ever mounting Overview on an
installed copy (v0.4.0 root cause); this pin is the structural net.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Shipped modules: everything the deb payload could carry.
SHIPPED_DIRS = ("ui", "assistant", "hunter", "appfw", "wiz", "hardening")
_SHIPPED_PYS = [ROOT / d for d in SHIPPED_DIRS]
TOP_PYS = sorted(p for p in ROOT.glob("*.py"))
GUARD = re.compile(r"^\s*(from|import)\s+tools(\.| \b|$)", re.M)


def _offenders():
    hits = []
    for base in _SHIPPED_PYS:
        for py in sorted(base.rglob("*.py")):
            if GUARD.search(py.read_text(encoding="utf-8")):
                hits.append(str(py.relative_to(ROOT)))
    for py in TOP_PYS:
        if GUARD.search(py.read_text(encoding="utf-8")):
            hits.append(py.name)
    return hits


def test_shipped_code_never_imports_the_tools_package():
    assert _offenders() == []


def test_assistant_digests_constants_stay_in_the_shipped_module():
    # The constants live in assistant/digests.py and the checker imports
    # them - the reverse direction is the packaging bug that killed the
    # v0.4.0 launch; both directions stay pinned.
    import assistant.digests as digests
    import tools.build_digests as checker
    assert digests.DIGEST_TOOLS == checker.DIGEST_TOOLS
    assert digests.DIGESTS == checker.DIGESTS
    assert (digests.DIGESTS / "psad.md").exists()


def test_shipped_digests_dir_travels_with_the_tree():
    import assistant.digests as digests
    for tool in digests.DIGEST_TOOLS:
        assert (digests.DIGESTS / f"{tool}.md").exists(), tool
