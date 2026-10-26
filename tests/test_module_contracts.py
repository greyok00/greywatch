"""Cross-module attribute contracts the headless battery cannot see.

The GUI test modules skip without a real display, so a lint sweep that
removes a "unused" module-level import silently breaks every call site
that reaches a name through that module (example: ui/window.py reads
daemon_mod.load_status). This test parses the consumer sources for
module-attribute accesses and asserts each name still exists — no
display needed.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CONTRACTS = {
    "ui/window.py": {"greywatch_daemon": "daemon_mod"},
}


def test_consumed_module_attributes_exist():
    import greywatch_daemon
    used = set()
    for src_file, mod_to_alias in CONTRACTS.items():
        src = (ROOT / src_file).read_text(encoding="utf-8")
        for mod, alias in mod_to_alias.items():
            for name in re.findall(rf"\b{alias}\.([A-Za-z_][A-Za-z0-9_]*)\b", src):
                used.add((mod, name))
    assert used, "no cross-module usages parsed — parser stale?"
    for mod, name in sorted(used):
        obj = {"greywatch_daemon": greywatch_daemon}[mod]
        assert hasattr(obj, name), (
            f"{mod}.{name} no longer exists — a lint sweep removed a "
            f"re-export the GUI depends on")