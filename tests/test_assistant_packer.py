# tests/test_assistant_packer.py
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from assistant.packer import bm25_top, build_pack, load_index

IDX = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures"

CHUNKS = [
    {"id": "a", "source": "s", "title": "A", "text": "apparmor denies reads for the lynis profile"},
    {"id": "b", "source": "s", "title": "B", "text": "fail2ban bans ssh brute force attempts"},
    {"id": "c", "source": "s", "title": "C", "text": "the app firewall appfw queues packets in nftables"},
]

STATUS = {"tools": {
    "apparmor": {"state": "GREEN", "label": "AppArmor (MAC profile)", "installed": True},
    "fail2ban": {"state": "RED", "label": "Fail2ban (bans)", "installed": True},
    "auditd": {"state": "GREEN", "label": "Auditd (audit log)", "installed": True}}}

EVENTS = [
    {"from_tool": "apparmor", "severity": "MEDIUM",
     "text": "AppArmor DENIED profile=lynis comm=lynis", "ts": "2026-10-27T02:31:00+00:00"},
    {"from_tool": "fail2ban", "severity": "HIGH",
     "text": "fail2ban banned 3.2.1.1 (sshd)", "ts": "2026-10-27T02:30:00+00:00"},
]


def test_bm25_ranks_apparmor_chunk_first_for_apparmor_query():
    top = bm25_top(CHUNKS, "why did apparmor deny lynis", k=2)
    assert top[0]["id"] == "a"
    assert len(top) == 2


def test_load_index_missing_file_returns_empty(tmp_path):
    assert load_index(tmp_path / "nope.json") == []


def test_build_pack_shape_and_budget():
    pack = build_pack(STATUS, EVENTS, "what needs attention?", registry=None)
    assert pack["status_line"].count("2") >= 1        # 2 green of 3
    assert {t["name"] for t in pack["tools"]} >= {"apparmor", "fail2ban"}
    assert len(pack["recent"]) == 2
    assert sum(len(s["text"]) for s in pack["snippets"]) <= 8000