"""The bulk-fix intents (owner 2026-11-12: 'the ai assistant can't just
fix all issues'), each confirm-gated, each reversible or honest."""
import json
import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


def _plan(question, names=frozenset({"ufw"}), pack=None):
    import gi
    gi.require_version("Gtk", "4.0")
    import importlib
    from ui.assistant import plan_turn
    pack = pack or {"status_line": "17 protections are green",
                    "tools": [], "recent": []}
    return plan_turn(question, pack, None, set(names) | {"_x"}, {})


def test_fix_all_issues_routes_to_clear_decisions():
    plan = _plan("fix all the issues")
    assert plan["kind"] == "intent"
    assert plan["intent"].action == "clear_decisions"


def test_purge_phrasings_route_to_purge():
    for q in ("purge the quarantine", "delete all quarantined files",
              "delete the quarantined docs zip", "purge quarantined"):
        plan = _plan(q)
        assert plan["kind"] == "intent" and \
            plan["intent"].action == "purge_quarantine", q


def test_findings_and_watch_list_phrasings():
    for q in ("dismiss all browser watch findings",
              "clear the watch list", "clear the hidden list"):
        plan = _plan(q)
        assert plan["kind"] == "intent" and \
            plan["intent"].action == "dismiss_all_findings", q


def test_turn_everything_back_on_still_beats_the_bulk_family():
    plan = _plan("turn everything back on")
    assert plan["kind"] == "intent" and \
        plan["intent"].action == "enable_all"


def test_new_actions_validate_without_tools():
    from assistant.intents import Intent, validate, INTENTS
    for action in ("clear_decisions", "dismiss_all_findings",
                   "purge_quarantine"):
        assert action in INTENTS
        assert validate(Intent(action), set()) is None


def test_describe_names_the_bulk_actions():
    from assistant.intents import Intent, describe
    assert "Keep" in describe(Intent("clear_decisions"), {})
    assert "cannot be undone" in describe(Intent("purge_quarantine"), {})
    assert "retrievable" in describe(Intent("dismiss_all_findings"), {})


def test_bulk_off_stays_refused():
    plan = _plan("turn everything off")
    text = str(plan.get("text") or "")
    assert "not" in text or plan.get("kind") == "template"
