"""Pins for the Timeline page: merges the four action sources, orders
newest first, and puts the evidence - the log line, the file path, the
rule, the restore command - behind the selected row."""

from __future__ import annotations

import json

import gi
import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from tests.test_ui_v4 import _ShellStub, _all_texts


def _texts(w) -> str:
    return " ".join(_all_texts(w))


def _stores(tmp_path):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "quarantine.jsonl").write_text(
        json.dumps({"ts": "2026-11-14 20:15:05",
                    "orig": "/tmp/pytest-of-grey/sample.bin",
                    "file": "/home/grey/security-hardening/quarantine/"
                            "sample.bin.20261114-201505.quar",
                    "sha256_16": "275a021bbfb6489e",
                    "tag": "clamav:Eicar-Test-Signature"}) + "\n")
    (d / "events.jsonl").write_text("\n".join([
        json.dumps({"ts": "2026-11-15T08:30:00+00:00",
                    "from_tool": "fail2ban", "severity": "HIGH",
                    "text": "Ban 203.0.113.9 (jail sshd)"}),
        json.dumps({"ts": "2026-11-15T08:31:00+00:00",
                    "from_tool": "appfw", "severity": "MEDIUM",
                    "text": "appfw: deny firefox to reach example.com"}),
        json.dumps({"ts": "2026-11-15T08:32:00+00:00",
                    "from_tool": "tetragon", "severity": "INFO",
                    "text": "exec /usr/bin/python3 pid=9 -rn ok"}),
    ]) + "\n")
    (d / "status.json").write_text(json.dumps({
        "updated": "2026-11-15T08:40:00+00:00", "tools": {},
        "defense": {"blocked": [{"ip": "198.51.100.7",
                                 "ts": "2026-11-15 08:35:00",
                                 "reason": "nft deny"}]}}))
    return d


@pytest.fixture
def timeline(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_stores(tmp_path)))
    import ui.timeline as timeline
    return timeline


def test_four_sources_merge_in_order(timeline):
    rows = timeline._timeline_rows()
    kinds = [r["kind"] for r in rows]
    assert set(kinds) == {"quarantine", "ban", "block", "rule"}
    keys = [timeline._sort_key(r) for r in rows]
    assert keys == sorted(keys, reverse=True), "rows land newest first"
    assert keys[0][0].startswith("2026-11-15"), "the 11-15 rows lead"


def test_quarantine_evidence_carries_copy_and_restore(timeline):
    rep = timeline._timeline_rows()
    q = [r for r in rep if r["kind"] == "quarantine"][0]
    assert "sample.bin" in q["original file"]
    assert q["quarantined copy"].startswith("/home/grey/security")
    assert q["sha256 (first 16)"] == "275a021bbfb6489e"
    assert q["restore command"].endswith(
        "restore-quarantine.sh /tmp/pytest-of-grey/sample.bin")


def test_block_row_carries_the_rule(timeline):
    rep = timeline._timeline_rows()
    b = [r for r in rep if r["kind"] == "block"][0]
    assert b["address"] == "198.51.100.7"
    assert "nft" in b["rule"]


def test_page_renders_rows_and_filter(timeline):
    page = timeline.build(_ShellStub())
    body = getattr(page, "_gw_body", page)
    texts = " ".join(_all_texts(body)).lower()
    assert "action rows newest first" in texts
    # the quarantined subject rides the row table
    rows = getattr(body, "_gw_rows")
    assert any(r["kind"] == "quarantine" for r in rows)
    body._gw_filter = "ban"
    timeline._refresh_into(body)
    rows = getattr(body, "_gw_rows")
    assert {r["kind"] for r in rows} == {"ban"}


def test_quiet_case_is_honest(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(d))
    import ui.timeline as timeline
    page = timeline.build(_ShellStub())
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page))).lower()
    assert "nothing logged yet" in texts


def test_allow_noise_is_excluded(monkeypatch):
    from ui import timeline
    monkeypatch.setattr(timeline, "_events", lambda: [
        {"ts": "2026-11-19T12:00:00+00:00", "from_tool": "appfw",
         "text": "appfw: 93 allow events in the previous minute"},
        {"ts": "2026-11-19T12:01:00+00:00", "from_tool": "appfw",
         "text": "appfw: deny 10.0.0.9 to 1.2.3.4"},
    ])
    rows = timeline._rule_rows()
    assert len(rows) == 1
    assert "deny" in rows[0]["subject"]


def test_identical_rule_rows_in_one_minute_collapse(monkeypatch):
    from ui import timeline
    same = {"ts": "2026-11-19T12:00:00+00:00", "from_tool": "appfw",
            "text": "appfw: deny 10.0.0.9"}
    monkeypatch.setattr(timeline, "_events", lambda: [same, dict(same)])
    assert len(timeline._rule_rows()) == 1


def test_the_page_states_shown_of_total(monkeypatch):
    from ui import timeline
    monkeypatch.setattr(timeline, "_timeline_rows",
                        lambda: [{"kind": "rule", "when": f"2026-11-19T12:00:{i:02d}+00:00",
                                  "tool": "appfw", "subject": f"deny {i}"}
                                 for i in range(450)])
    body = Gtk.Box()
    timeline._refresh_into(body)
    assert "400 of 450" in _texts(body)


def test_routine_filter_narrows_to_restored_routine_rows(monkeypatch):
    from ui import timeline
    monkeypatch.setattr(timeline, "_events", lambda: [
        {"ts": "2026-11-19T12:00:00+00:00", "from_tool": "appfw",
         "text": "appfw: 93 allow events in the previous minute"},
        {"ts": "2026-11-19T12:01:00+00:00", "from_tool": "appfw",
         "text": "appfw: deny 10.0.0.9 to 1.2.3.4"},
        {"ts": "2026-11-19T12:02:00+00:00", "from_tool": "fail2ban",
         "text": "Ban 203.0.113.9"},
    ])
    body = Gtk.Box()
    body._gw_filter = "routine"
    timeline._refresh_into(body)
    rows = body._gw_rows
    assert [r["subject"] for r in rows] == [
        "appfw: 93 allow events in the previous minute"]
    assert {r["kind"] for r in rows} == {"rule"}
    assert len(body._gw_shown) == len(rows) == 1
    assert "Showing 1 of 1 action rows." in _texts(body)


def test_config_changes_stay_in_the_default_view(monkeypatch):
    from ui import timeline
    monkeypatch.setattr(timeline, "_events", lambda: [
        {"ts": "2026-11-19T12:00:00+00:00", "from_tool": "policy",
         "text": "config updated: dns"},
    ])
    rows = timeline._rule_rows()
    assert len(rows) == 1
    assert "config" in rows[0]["subject"]


def test_full_text_decides_routine_membership(monkeypatch):
    from ui import timeline
    text = "appfw: allow " + ("x" * 240) + " deny 10.0.0.9"
    monkeypatch.setattr(timeline, "_events", lambda: [
        {"ts": "2026-11-19T12:00:00+00:00", "from_tool": "appfw",
         "text": text},
    ])
    assert len(timeline._rule_rows()) == 1
    assert timeline._routine_rows() == []
