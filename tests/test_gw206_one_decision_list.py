"""Rebuild Phase 1: ONE decision list, published whole, rendered everywhere.

The old mismatch class: the header pill counted 12 pending decisions
while the Defense page carried only reviewer-sourced asks (a 12-vs-0
split). Now the daemon publishes the FULL pending list in status.json
(every source, each with id/source/kind/title/options), the pill counts
that list's length, the Action Gate drawer renders it, and the Firewall
page stops reading reviewer-only digest asks. These pins hold the
parity at the three surfaces that could drift again.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import greywatch_daemon as gd  # noqa: E402
from greywatch_daemon import Daemon  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A data dir the desktop-side readers steer into (the env is the
    runtime resolution path, GW-166)."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def _reviewer_event(spec_id="block-reviewer:abc123",
                    ts="2026-11-06T09:00:00+00:00"):
    return {"from_tool": "block-reviewer", "severity": "MEDIUM",
            "text": "asks", "ts": ts,
            "interaction": {"id": spec_id, "eyebrow": "Block Reviewer check",
                            "subject": "192.168.0.44 is blocked",
                            "question": "Keep blocking, or lift it?",
                            "detail": "auto block, sustained attack",
                            "options": [{"id": "keep", "helper":
                                         "block-review"}]}}


def _quarantine_event(spec_id="responderd:def456",
                      ts="2026-11-06T09:05:00+00:00"):
    return {"from_tool": "responderd", "severity": "CRITICAL",
            "text": "quarantine: (sha256:aa11) evil.bin", "ts": ts,
            "interaction": {"id": spec_id, "eyebrow": "Threat found",
                            "subject": "'evil.bin' was quarantined",
                            "detail": "signature · /tmp/evil.bin",
                            "question": "Keep it locked away?",
                            "options": [{"id": "keep", "label": "Keep",
                                         "helper": "keep-quarantine"}]}}


def _advisory_event(ts="2026-11-06T09:07:00+00:00"):
    return {"from_tool": "hunter", "severity": "LOW", "text": "observed",
            "ts": ts,
            "interaction": {"id": "hunter:aa11", "eyebrow": "Browser Watch",
                            "subject": "CDP session noted",
                            "options": [{"id": "note", "label": "Noted"}]}}


def _write_events(store, events):
    (store / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n")


def _count_cards(host):
    n, child = 0, host.get_first_child()
    while child is not None:
        n += 1
        child = child.get_next_sibling()
    return n


# ---- the list builder -------------------------------------------------------
def test_pending_list_is_every_source(store):
    _write_events(store, [_reviewer_event(), _quarantine_event(),
                          _advisory_event(),
                          {"from_tool": "clamav", "text": "plain event",
                           "ts": "t", "severity": "INFO"}])
    (store / "decisions.jsonl").write_text(
        json.dumps({"id": "block-reviewer:gone", "answer": "x"}) + "\n")
    from decisions_factory import pending_decision_list
    items = pending_decision_list(store)
    ids = [i["id"] for i in items]
    assert ids == ["block-reviewer:abc123", "responderd:def456",
                   "hunter:aa11"]
    # parity with the GUI row rule: same rule, same list, same length
    from ui.decisionlist import pending_rows
    pairs = pending_rows(store)
    assert [s["id"] for s, _t in pairs] == ids


def test_items_carry_source_kind_and_the_render_spec(store):
    _write_events(store, [_reviewer_event(), _advisory_event()])
    from decisions_factory import pending_decision_list
    items = {i["id"]: i for i in pending_decision_list(store)}
    rev = items["block-reviewer:abc123"]
    assert rev["source"] == "block-reviewer" and rev["kind"] == "question"
    assert rev["title"] == "192.168.0.44 is blocked"
    assert rev["detail"] == "auto block, sustained attack"
    assert rev["options"][0] == {"id": "keep", "helper": "block-review"}
    assert rev["spec"]["eyebrow"] == "Block Reviewer check"
    adv = items["hunter:aa11"]
    assert adv["source"] == "browser-watch"    # hunter maps to its face
    assert adv["kind"] == "advisory"           # no helper, not a question


# ---- the daemon publishes it ------------------------------------------------
def test_daemon_publishes_list_and_pill_parity(tmp_path):
    d = Daemon(data_dir=tmp_path / "data", registry=gd.load_registry())
    with open(d.events_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(_reviewer_event()) + "\n")
        f.write(json.dumps(_quarantine_event()) + "\n")
    d.write_status()
    snap = json.loads((d.data_dir / "status.json").read_text())
    ids = [i["id"] for i in snap["pending_list"]]
    assert ids == ["block-reviewer:abc123", "responderd:def456"]
    # the pill's number IS the list's length: the mismatch class is dead
    assert snap["pending_decisions"] == len(snap["pending_list"])
    # an answered id leaves the list and the count together
    with open(d.data_dir / "decisions.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"id": "responderd:def456", "answer": "keep"})
                + "\n")
    d.write_status()
    snap = json.loads((d.data_dir / "status.json").read_text())
    assert [i["id"] for i in snap["pending_list"]] == ["block-reviewer:abc123"]
    assert snap["pending_decisions"] == 1


# ---- the drawer ---------------------------------------------------------------
def test_actiongate_reads_the_published_list(store):
    _write_events(store, [_reviewer_event(), _quarantine_event()])
    from gi.repository import GLib
    from ui.actiongate import ActionGateWindow
    w = ActionGateWindow()
    w.set_default_size(760, 540)
    w.build_rows()
    for _ in range(40):
        GLib.main_context_default().iteration(False)
    rows = w._rows()
    ids = [s["id"] for s, _t in rows]
    assert ids == ["block-reviewer:abc123", "responderd:def456"]
    headline, _meta = w._headline_copy(len(rows))
    assert headline.startswith(f"{len(rows)} decision")
    assert w.get_title() == "greywatch: action gate"
    w.destroy()


def test_actiongate_falls_back_when_unpublished(store):
    _write_events(store, [_quarantine_event()])            # no status.json
    from ui.actiongate import ActionGateWindow
    w = ActionGateWindow()
    rows = w._rows()
    assert [s["id"] for s, _t in rows] == ["responderd:def456"]
    w.destroy()


# ---- the Firewall page renders the one list -----------------------------------
def test_defense_renders_every_pending_source(store):
    from ui import defense
    v = defense.DefenseView()
    snap = {"defense": {"blocked": []},
            "pending_list": [
                {"id": "block-reviewer:abc123", "source": "block-reviewer",
                 "kind": "question", "title": "t", "detail": "", "ts": "",
                 "options": [{"id": "keep", "helper": "block-review"}],
                 "spec": _reviewer_event()["interaction"]},
                {"id": "responderd:def456", "source": "responderd",
                 "kind": "question", "title": "t", "detail": "", "ts": "",
                 "options": [{"id": "keep", "helper": "keep-quarantine"}],
                 "spec": _quarantine_event()["interaction"]}]}
    v.refresh(snap)
    # both sources render side by side: no reviewer-only filter remains
    assert _count_cards(v._asks) == 2
    v.unparent()


def test_defense_falls_back_to_digest_asks_without_a_list():
    from ui import defense
    v = defense.DefenseView()
    doc = {"asks": [{"id": "block-reviewer:abc123", "ts": "",
                     "spec": _reviewer_event()["interaction"]}]}
    v.refresh({"defense": doc})                    # no pending_list key
    assert _count_cards(v._asks) == 1
    v.unparent()
