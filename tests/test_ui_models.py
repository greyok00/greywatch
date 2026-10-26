"""T6b: UI MODEL tests (headless — GTK is never imported in tests)."""
import json

from ui.models import (DecisionView, EventRow, filter_events, pending_badge,
                       rows_from, state_mark)

import greywatch_daemon as gd
from registry import load_registry


def test_row_transform_full_render():
    raw = {"from_tool": "fail2ban", "severity": "HIGH", "ts": "2026-10-22T00:01:00+00:00",
           "text": "Ban in jail [sshd] — 1.2.3.4", "nist_func": "RESPOND",
           "nist_control": ["AC-7", "SI-4"], "cves": ["CVE-2026-0001"]}
    row = EventRow(raw)
    assert row.mark == "🔴" and row.nist == "RESPOND/AC-7,SI-4"
    assert row.cves == "CVE-2026-0001"
    assert row.as_list()[0] == "🔴" and "Ban" in row.as_list()[6]


def test_rows_newest_first_capped():
    raws = [{"from_tool": "ufw", "severity": "INFO", "ts": f"t{i}",
             "nist_func": "PROTECT", "nist_control": [], "cves": [], "text": str(i)}
            for i in range(2500)]
    rows = rows_from(raws, limit=2000)
    assert len(rows) == 2000
    assert rows[0].text == "2499"          # newest first


def test_decision_view_and_badge():
    spec = {"id": "x:1", "question": "q", "options": [{"id": "keep", "label": "K", "helper": "none"}]}
    dv = DecisionView(spec)
    assert dv.unanswered(set())
    assert not dv.unanswered({"x:1"})
    assert pending_badge([spec], {"x:1"}) == 0
    assert pending_badge([spec, {"id": "y:2", "options": []}], set()) == 2


def test_filter_events_lazy_cap():
    events = [{"from_tool": f"t{i % 3}", "severity": "HIGH" if i % 2 else "INFO",
               "text": f"hit-{i} needle"} for i in range(300)]
    assert len(filter_events(events, tool="t1")) == 100
    assert len(filter_events(events, severity="HIGH")) == 150
    assert len(filter_events(events, text_needle="needle")) == 300
    capped = filter_events(events, text_needle="", limit=50)
    assert len(capped) == 50


def test_state_marks():
    assert state_mark("GREEN") == "🟢" and state_mark("RED") == "🔴"
    assert state_mark("WAT") == "⚫"


def test_registry_sixteen_plus_in_gui_sidebar_model():
    names = {t["name"] for t in load_registry()}
    assert len(names) == 17

def test_feed_hides_routine_shows_bad_and_scans():
    from ui.models import feed_worthy
    assert feed_worthy({"severity": "HIGH", "from_tool": "responderd"})
    assert feed_worthy({"severity": "MEDIUM", "from_tool": "ufw"})
    assert not feed_worthy({"severity": "INFO", "from_tool": "auditd",
                            "text": "routine activity"})
    assert feed_worthy({"severity": "INFO", "from_tool": "clamav",
                        "text": "scan summary: infected files 0"})
    assert feed_worthy({"severity": "INFO", "from_tool": "arpwatch",
                        "text": "new station 10.0.0.1"})
    assert not feed_worthy({"severity": "INFO", "from_tool": "appfw",
                            "text": "rule allow: process.path is '/usr/bin/curl'"})


def test_dedupe_collapses_identical_runs():
    from ui.models import dedupe
    same = {"from_tool": "responderd", "text": "tetragon_watch: routine echo",
            "severity": "MEDIUM"}
    evs = [same] * 10 + [{"from_tool": "responderd",
                          "text": "quarantine: eicar moved", "severity": "HIGH"}]
    out = dedupe(evs)
    assert len(out) == 2
    assert out[1]["text"].startswith("quarantine")
