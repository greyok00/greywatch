# tests/test_assistant_packer.py
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import assistant.packer as packer
from assistant.packer import bm25_top, build_pack, load_index

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


def test_bm25_min_score_floor_excludes_unmatched_chunks():
    assert [c["id"] for c in
            bm25_top(CHUNKS, "why did apparmor deny lynis", k=2, min_score=0.01)] == ["a"]
    assert len(bm25_top(CHUNKS, "why did apparmor deny lynis", k=2)) == 2


def test_build_pack_snippets_truncate_and_rank(monkeypatch):
    long_text = ("apparmor denies unconfined writes for profiles " * 10)[:400]
    monkeypatch.setattr(packer, "load_index", lambda: [
        {"id": "x", "source": "runbooks/aa.md", "title": "AppArmor", "text": long_text},
        {"id": "y", "source": "runbooks/f2b.md", "title": "Fail2ban",
         "text": "fail2ban bans ssh brute force attempts"}])
    pack = build_pack(STATUS, EVENTS, "apparmor denied writes", registry=None)
    assert [s["title"] for s in pack["snippets"]] == ["AppArmor", "Fail2ban"]
    assert pack["snippets"][0]["text"] == long_text[:300]
    assert pack["snippets"][1] == {"title": "Fail2ban", "source": "runbooks/f2b.md",
                                   "text": "fail2ban bans ssh brute force attempts"}
    assert sum(len(s["text"]) for s in pack["snippets"]) <= packer.CHAR_BUDGET


def test_build_pack_budget_break(monkeypatch):
    long_text = ("the app firewall queues packets in nftables rules " * 12)[:600]
    monkeypatch.setattr(packer, "CHAR_BUDGET", 350)
    monkeypatch.setattr(packer, "load_index", lambda: [
        {"id": "n1", "source": "runbooks/nft.md", "title": "Nftables", "text": long_text},
        {"id": "n2", "source": "runbooks/nft2.md", "title": "Nftables 2", "text": long_text}])
    pack = build_pack(STATUS, EVENTS, "app firewall nftables packets", registry=None)
    # first snippet (300 chars) passes the 350 budget; the second would push
    # `used` to 600 > 350, so the loop must break after exactly one snippet
    assert [len(s["text"]) for s in pack["snippets"]] == [300]


def test_build_pack_passes_through_installed_and_paused():
    status = {"tools": {
        "f2b": {"state": "YELLOW", "installed": False},
        "watch": {"state": "GREEN", "paused": True},
        "plain": {"state": "GREEN"}}}
    pack = build_pack(status, [], "what is running?", registry=None)
    tools = {t["name"]: t for t in pack["tools"]}
    assert tools["f2b"]["installed"] is False
    assert tools["f2b"]["paused"] is False          # absent → default False
    assert tools["watch"]["paused"] is True
    assert tools["watch"]["installed"] is True      # absent → default True
    assert tools["plain"]["installed"] is True
    assert tools["plain"]["paused"] is False


def build_pack_for_tests():
    return build_pack(STATUS, EVENTS, "overview")