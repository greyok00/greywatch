"""baseline: streaming ledger profiles (plan Task 5, design §6.1 [4]).

L1 verdicts ("this app normally talks there") and anomaly inputs come
from the app's OWN history. The builder streams the events ledger
(months of history) with bounded memory, tolerates garbage lines by
counting them, and never loads the file whole.
"""
from __future__ import annotations

import json
import pathlib

import baseline


def _event(app: str, dst: str, port: int, action: str, ts: str) -> str:
    return json.dumps({"from_tool": "appfw", "severity": "MEDIUM",
                       "text": f"{action} {app} → {dst}:{port}",
                       "ts": ts}) + "\n"


def _ledger(tmp_path: pathlib.Path, lines: list[str]) -> pathlib.Path:
    path = tmp_path / "events.jsonl"
    path.write_text("".join(lines))
    return tmp_path


def test_parses_appfw_shaped_lines(tmp_path):
    _ledger(tmp_path, [
        _event("firefox", "93.184.216.34", 443, "allow", "2026-11-01T10:00:00+00:00"),
        _event("firefox", "93.184.216.34", 443, "allow", "2026-11-05T10:00:00+00:00"),
        _event("chromium", "3.5.97.31", 443, "deny", "2026-11-07T10:00:00+00:00"),
    ])
    base = baseline.build(tmp_path, now=1.0)
    assert base.count_for("firefox", "93.184.216.34", 443) == 2
    assert base.count_for("chromium", "3.5.97.31", 443) == 1


def test_garbage_lines_counted_not_fatal(tmp_path):
    _ledger(tmp_path, [
        "{not json at all\n",
        json.dumps({"from_tool": "appfw", "text": 12345}) + "\n",
        _event("firefox", "93.184.216.34", 443, "allow", "2026-11-01T10:00:00+00:00"),
        "x" * 300 + "\n",
        json.dumps({"from_tool": "clamav", "text": "FOUND something"}) + "\n",
    ])
    base = baseline.build(tmp_path, now=1.0)
    # the clamav row is out of scope (M6 ruling on record): not "bad",
    # merely not our ledger. Four garbage lines + one other-tool row.
    assert base.bad_lines == 4 - 1, base.bad_lines
    assert base.count_for("firefox", "93.184.216.34", 443) == 1


def test_streams_both_rotation_files(tmp_path):
    old = tmp_path / "events.jsonl.old-20261109"
    old.write_text(_event("app-old", "1.2.3.4", 443, "allow",
                          "2026-10-01T10:00:00+00:00"))
    _ledger(tmp_path, [_event("app-new", "5.6.7.8", 443, "allow",
                              "2026-11-01T10:00:00+00:00")])
    base = baseline.build(tmp_path, now=1.0)
    assert base.count_for("app-old", "1.2.3.4", 443) == 1
    assert base.count_for("app-new", "5.6.7.8", 443) == 1


def test_caps_hold_at_10k_apps(tmp_path):
    lines = []
    for i in range(11_000):
        lines.append(_event(f"app-{i}", "10.0.0.1", 443, "allow",
                            "2026-11-01T10:00:00+00:00"))
    _ledger(tmp_path, lines)
    base = baseline.build(tmp_path, now=1.0)
    assert len(base.apps) == baseline.MAX_APPS
    assert base.caps_evicted > 0


def test_caps_hold_at_2k_dests_per_app(tmp_path):
    lines = [_event("firefox", f"10.1.{(i // 254) % 255}.{(i % 254) + 1}",
                    443, "allow", "2026-11-01T10:00:00+00:00")
             for i in range(2_100)]
    _ledger(tmp_path, lines)
    base = baseline.build(tmp_path, now=1.0)
    assert len(base.apps["firefox"]) == baseline.MAX_DESTS


def test_profile_verdict_seen_pair(tmp_path):
    _ledger(tmp_path, [
        _event("firefox", "93.184.216.34", 443, "allow", "2026-11-05T10:00:00+00:00"),
        _event("firefox", "93.184.216.34", 443, "allow", "2026-11-06T10:00:00+00:00"),
    ])
    base = baseline.build(tmp_path, now=1.0)
    verdict = baseline.profile_verdict(base, "firefox", "93.184.216.34", 443)
    assert verdict is not None
    assert verdict["action"] == "allow" and verdict["basis"] == "baseline"
    assert verdict["count"] == 2


def test_profile_verdict_unseen_pair_is_none(tmp_path):
    _ledger(tmp_path, [
        _event("firefox", "93.184.216.34", 443, "allow", "2026-11-05T10:00:00+00:00"),
    ])
    base = baseline.build(tmp_path, now=1.0)
    assert baseline.profile_verdict(base, "firefox", "6.6.6.6", 443) is None
    assert baseline.profile_verdict(base, "curl", "93.184.216.34", 443) is None


def test_profile_never_allows_from_a_deny_history_alone(tmp_path):
    """Three denies are history, not permission: a baseline verdict
    requires the pair to have been ALLOWED before."""
    _ledger(tmp_path, [
        _event("app", "9.9.9.9", 443, "deny", "2026-11-01T10:00:00+00:00"),
        _event("app", "9.9.9.9", 443, "deny", "2026-11-02T10:00:00+00:00"),
        _event("app", "9.9.9.9", 443, "deny", "2026-11-03T10:00:00+00:00"),
    ])
    base = baseline.build(tmp_path, now=1.0)
    assert baseline.profile_verdict(base, "app", "9.9.9.9", 443) is None
    assert base.count_for("app", "9.9.9.9", 443) == 3


def test_anomaly_inputs_shapes(tmp_path):
    _ledger(tmp_path, [
        _event("quiet-app", "1.1.1.1", 443, "allow", "2026-09-01T10:00:00+00:00"),
        _event("busy-app", "2.2.2.2", 443, "allow", "2026-11-10T10:00:00+00:00"),
    ])
    base = baseline.build(tmp_path, now=1_763_200_000.0)   # ~2026-11-15
    a = baseline.anomaly_inputs(base, "quiet-app", "8.8.4.4", 443)
    assert a["first_contact"] is True
    assert a["quiet_app"] is True                      # no contact for ~75 days
    b = baseline.anomaly_inputs(base, "busy-app", "3.3.3.3", 53)
    assert b["first_contact"] is True
    assert b["quiet_app"] is False                     # talked 5 days ago


def test_empty_ledger_empty_baseline(tmp_path):
    base = baseline.build(tmp_path, now=1.0)
    assert base.apps == {} and base.bad_lines == 0
    assert baseline.profile_verdict(base, "x", "1.1.1.1", 443) is None


def test_accepts_production_engine_row_action_last(tmp_path):
    """Review C4: the repo producer (engine.py:640) writes
    `appfw <app> → <dst>:<port> <action> [note]` — action LAST. Also
    accept the live-ledger writer's `deny <app> → …` (action first).
    Both are real rows; none may be miscounted as garbage."""
    (tmp_path / "events.jsonl").write_text(
        '{"from_tool":"appfw","text":"appfw chromium → 3.5.97.31:443 deny '
        '[answered: deny]","ts":"2026-11-11T11:19:51+00:00"}\n'
        '{"from_tool":"appfw","text":"deny chromium → 3.5.64.219:443 '
        '(headless: deny (no dashboard open))","ts":"2026-11-11T11:20:00+00:00"}\n')
    base = baseline.build(tmp_path, now=1.0)
    assert base.bad_lines == 0
    assert base.count_for("chromium", "3.5.97.31", 443) == 1
    assert base.count_for("chromium", "3.5.64.219", 443) == 1
    assert baseline.profile_verdict(base, "chromium", "3.5.97.31", 443) is None
    assert baseline.profile_verdict(base, "chromium", "3.5.64.219", 443) is None


def test_disabled_scan_timer_counts_as_healthy(monkeypatch):
    """The automatic scan timers stay off (owner order 2026-11-19): a
    disabled clam timer is the healthy state, so the verifier reports
    ENABLED instead of degrading the antivirus lane."""
    import subprocess

    def fake(argv, **kwargs):
        unit = argv[-1]
        if unit == "greywatch-clam-scan.timer":
            out = "inactive" if argv[-2] == "is-active" else "disabled"
        else:
            out = "active" if argv[-2] == "is-active" else "enabled"
        return subprocess.CompletedProcess(argv, 0, out + "\n", "")

    monkeypatch.setattr(baseline.subprocess, "run", fake)
    rows = baseline.baseline_verifier()
    clam = [r for r in rows if r[0] in ("clamav", "clam-scan")]
    assert clam and all(r[2] == "OFF-BY-DESIGN" for r in clam), clam
