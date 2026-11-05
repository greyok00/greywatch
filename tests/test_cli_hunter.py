"""`gw hunter`: the CLI reads the same hunter files, and --hunt runs the
same deterministic cycle the resident loop runs — against a redirected
data dir and a redirected HOME so the test never touches the real store."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import cli  # noqa: E402
import hunter.store as store  # noqa: E402
from hunter import web  # noqa: E402


def _redirect(tmp_path, monkeypatch):
    data = tmp_path / "data"
    home = tmp_path / "home"
    data.mkdir(exist_ok=True)          # tests reuse the same tree
    (data / "hunter").mkdir(exist_ok=True)
    home.mkdir()
    monkeypatch.setattr(cli, "DATA_DIR", data)
    monkeypatch.setattr(pathlib.Path, "home", lambda: home)
    import hunter.main as hunter_main
    monkeypatch.setattr(hunter_main, "HAR_INBOX_CYCLE", 1)
    monkeypatch.setattr(web, "_crontab_lines", lambda: [])
    return data


def test_cli_hunter_prints_the_live_summary_and_findings(
        tmp_path, monkeypatch, capsys):
    data = _redirect(tmp_path, monkeypatch)
    store.write_live(data, {"hunter": 1, "ts": "2026-11-03T10:00:00Z",
                            "findings_total": 1, "unread": 0})
    store.append_finding(data, {
        "id": "x", "rule": "download-double-extension",
        "title": "A download tried to look like a document",
        "what": "w", "next": "n", "severity": "HIGH",
        "facts": [], "evidence": [], "hunter": "1"})
    rc = cli.main(["hunter"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 finding(s)" in out
    assert "download-double-extension" in out


def test_cli_hunter_stamp_prints_local_time(tmp_path, monkeypatch, capsys):
    """GW-160: the CLI's stamp is the owner's local clock, not the raw
    UTC ISO the JSON keeps."""
    import datetime as dt
    data = _redirect(tmp_path, monkeypatch)
    store.write_live(data, {"hunter": 1, "ts": "2026-11-03T10:00:00+00:00"})
    cli.main(["hunter"])
    out = capsys.readouterr().out
    line = out.splitlines()[0]
    when = dt.datetime.fromisoformat("2026-11-03T10:00:00+00:00").astimezone()
    assert when.strftime("%b %d") in line
    assert "+00:00" not in line and "2026-11-03T" not in line


def test_cli_hunter_unread_follows_the_read_pointer(tmp_path, monkeypatch,
                                                    capsys):
    """GW-160: `gw hunter` counts unread by the user's read pointer like
    the dashboard does, not by the frozen counter a past hunt wrote into
    live.json."""
    import datetime as dt
    from hunter import explain
    data = _redirect(tmp_path, monkeypatch)
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    store.write_live(data, {"hunter": 1, "ts": "t", "unread": 9})
    store.append_defender(data, {
        "ts": now, "kind": "rule", "severity": "HIGH",
        "text": "A note the owner has not read yet.", "hint": "Read it."})
    cli.main(["hunter"])
    out = capsys.readouterr().out
    assert "1 unread note(s)" in out, out
    explain.mark_read(data, now)
    cli.main(["hunter"])
    out = capsys.readouterr().out
    assert "0 unread note(s)" in out, out
    store.write_live(data, {"hunter": 1, "ts": "t"})
    store.append_defender(data, {
        "ts": "2026-11-03T10:00:01+00:00", "kind": "rule",
        "severity": "HIGH", "text": "A file named like a document is a "
                                    "program.", "hint": "Delete it."})
    rc = cli.main(["hunter", "--notes"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Delete it." in out


def test_cli_hunt_runs_one_cycle_in_process(tmp_path, monkeypatch, capsys):
    data = _redirect(tmp_path, monkeypatch)
    inbox = store.inbox_dir(data)
    import os
    import time
    inbox.joinpath("c.har").write_text(json.dumps(
        {"log": {"entries": [{"request": {"url": "https://e/f"},
                              "response": {"status": 200, "headers": [
                                  {"name": "Content-Disposition",
                                   "value": "attachment; filename=a.pdf.exe"}],
                              "content": {"mimeType": "application/x-msdownload"}}}]}}))
    # Age the capture past the producer-hold: a freshly written capture
    # waits a cycle before the hunter answers it.
    old = time.time() - 10.0
    os.utime(inbox.joinpath("c.har"), (old, old))
    rc = cli.main(["hunter", "--hunt", "--no-ai"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "hunted: 1 new finding(s)" in out
    assert not list(inbox.glob("*"))     # the capture retired itself
    findings = store.read_findings(data, limit=5)
    assert findings[0]["rule"] == "har-double-extension"