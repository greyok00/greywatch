"""GW-160: the CLI and the UI read the same state the same way.

`gw hunter` counted unread notes with the frozen counter inside live.json
(a past hunt's number), the cfg-* findings fell back to the "suite events"
channel tag, and the CLI printed raw UTC ISO stamps while the dashboard
printed local words. All three now agree with the UI's surfaces.
"""
import json
import pathlib
import sys


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import cli


def run(argv):
    try:
        rc = cli.main(argv)
        return rc
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0


def _unread_fixture(data_dir):
    """live.json says 7 unread; the read pointer says 1 of 2 notes are
    unread. The UI's words come from the pointer, so the CLI must too."""
    from hunter import store
    store.live_path(data_dir).parent.mkdir(parents=True, exist_ok=True)
    store.write_live(data_dir, {
        "ts": "2026-11-04T10:00:00+00:00", "findings_total": 3,
        "unread": 7, "interval_s": 300})
    store.append_defender(data_dir, {"ts": "2026-11-04T09:00:00+00:00",
                                     "text": "note one"})
    store.append_defender(data_dir, {"ts": "2026-11-04T09:30:00+00:00",
                                     "text": "note two"})
    cfg = store.config_path(data_dir)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"read_until": "2026-11-04T09:00:00+00:00"}))


def test_cli_counts_unread_like_the_ui(tmp_path, monkeypatch, capsys):
    _unread_fixture(tmp_path)
    monkeypatch.setattr(cli, "DATA_DIR", tmp_path)
    rc = run(["hunter"])
    out = capsys.readouterr().out
    assert rc == 0
    # The read pointer, not the frozen counter in live.json (7).
    assert "1 unread note(s)" in out, out
    assert "7 unread" not in out, out


def test_cli_hunter_stamp_prints_local_words(tmp_path, monkeypatch, capsys):
    _unread_fixture(tmp_path)
    monkeypatch.setattr(cli, "DATA_DIR", tmp_path)
    run(["hunter"])
    out = capsys.readouterr().out
    from ui import updates
    want = updates.human_stamp("2026-11-04T10:00:00+00:00")
    assert f"last hunt {want}" in out, out
    assert "2026-11-04T10" not in out, out


def test_status_stamp_prints_local_words(tmp_path, monkeypatch, capsys):
    (tmp_path / "status.json").write_text(json.dumps(
        {"updated": "2026-10-22T00:00:00+00:00", "dropped": 0,
         "pending_decisions": 0,
         "tools": {"ufw": {"label": "UFW", "state": "GREEN",
                           "last_event": None}}}))
    monkeypatch.setattr(cli, "DATA_DIR", tmp_path)
    rc = run(["status"])
    out = capsys.readouterr().out
    assert rc == 0
    from ui import updates
    want = updates.human_stamp("2026-10-22T00:00:00+00:00")
    assert f"updated {want}" in out, out
    assert "2026-10-22T00:00" not in out, out


def test_event_lines_print_local_words_not_utc_iso():
    from cli import _render
    line = _render({"from_tool": "ufw", "severity": "MEDIUM",
                    "text": "BLOCK 203.0.113.9 -> 192.168.77.50",
                    "ts": "2026-10-22T00:02:00+00:00", "nist_func": "PROTECT",
                    "nist_control": [], "cves": [], "interaction": None})
    from ui import updates
    want = updates.human_stamp("2026-10-22T00:02:00+00:00")
    assert want in line, line
    assert "2026-10-22T00:02" not in line, line


def test_cfg_findings_own_channel():
    from ui.hunterview import _channel_of
    assert _channel_of("cfg-1") == ("browser config", "browser")
    assert _channel_of("cfg-browser-history") == ("browser config", "browser")
    assert _channel_of("browser-history-3") == ("browser history", "browser")
    assert _channel_of("never-seen") == ("suite events", "detections")
