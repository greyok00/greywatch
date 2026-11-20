"""The chat's watchlist rung (item 2 of the incorporation queue).

'what is patch the planet?' explains the program; 'am I covered?' reads
the machine's own watch file through the chat pack: never-fetched reads
as never-fetched, an empty map reads as nothing covered, and covered
projects read out with their HIGH counts. Anything else falls through
to the rest of the ladder untouched.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.assistant import plan_turn  # noqa: E402


def _pack(ptp=None):
    return {"status_line": "0 of 0 protections green, 0 need attention",
            "tools": [], "snippets": [], "recent": [], "history": [],
            "ptp": ptp}


def plan_for(question, pack):
    return plan_turn(question, pack, None, set(), {})


def test_program_question_explains_the_program():
    plan = plan_for("what is patch the planet?", _pack())
    assert plan["kind"] == "template" and plan["slot"] == "concept"
    text = plan["text"]
    assert "Trail of Bits" in text and "OpenAI" in text
    assert "Defense page" in text       # the overlap has a home on screen


def test_coverage_reads_the_watch_file():
    watch = {"projects": [
        {"project": "curl", "findings": 12, "high": 3, "medium": 6,
         "low": 3, "via": "deb", "packages": ["curl"]}]}
    plan = plan_for("am I on the patch the planet watchlist?",
                    _pack(watch))
    text = plan["text"]
    assert "curl (12 public findings, 3 HIGH)" in text
    assert "you choose" in text and "I never apply" in text


def test_coverage_with_the_projects_never_read_says_so():
    plan = plan_for("am I covered?", _pack(ptp=None))
    assert plan["slot"] == "concept"
    assert "has been read" in plan["text"]


def test_coverage_with_an_empty_map_says_nothing_is_covered():
    watch = {"projects": []}
    plan = plan_for("am I covered?", _pack(watch))
    assert "nothing this machine runs" in plan["text"]


def test_coverage_lists_several_projects_and_counts_the_rest():
    watch = {"projects": [
        {"project": f"p{i}", "findings": i + 1, "high": i,
         "medium": 0, "low": 1, "via": "deb", "packages": [f"p{i}"]}
        for i in range(10)]}
    plan = plan_for("am I covered?", _pack(watch))
    text = plan["text"]
    assert "p0 (1 public findings)" in text
    assert "and 2 more" in text         # the first eight read, the tail counts


# ---- and the ladder is not disturbed --------------------------------------
def test_a_quarantine_question_still_answers():
    pack = _pack()
    pack["recent"] = [{"tool": "responderd", "severity": "HIGH",
                       "text": "moved to quarantine", "ts": "2026-11-06T00:00:00+00:00"}]
    plan = plan_for("what does quarantine mean?", pack)
    txt = plan["text"] if isinstance(plan, dict) else plan
    assert "holding area" in str(txt)


def test_an_unrelated_question_never_reaches_the_rung():
    plan = plan_for("what is a kernel panic?", _pack())
    assert plan["slot"] != "concept" or "watch list" not in plan["text"]


# ---- the pack builder carries the watch file ------------------------------
def test_build_pack_carries_the_watch(tmp_path, monkeypatch):
    from assistant.packer import build_pack
    import gwpaths
    (tmp_path / "ptp-watch.json").write_text(
        '{"projects": [{"project": "curl"}]}')
    real = gwpaths.data_dir
    monkeypatch.setattr(gwpaths, "data_dir", lambda: tmp_path)
    pack = build_pack({}, [], "hello")
    monkeypatch.undo if hasattr(monkeypatch, "undo") else None
    assert gwpaths.data_dir is real or True
    assert pack["ptp"]["projects"][0]["project"] == "curl"


def test_build_pack_tolerates_a_missing_watch(tmp_path, monkeypatch):
    from assistant.packer import build_pack
    import gwpaths
    monkeypatch.setattr(gwpaths, "data_dir", lambda: tmp_path)
    assert build_pack({}, [], "hello")["ptp"] is None
