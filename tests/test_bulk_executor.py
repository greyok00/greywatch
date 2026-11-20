"""The window's bulk-action executors (owner 2026-11-12): the assistant's
clear/purge/dismiss intents run the app's own record paths and say the
outcome honestly."""
import json
import os
import sys
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip("GUI tests run on an explicit test display only",
                allow_module_level=True)


def pump(n=20):
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def _seed_decisions(data_dir: pathlib.Path, n=3):
    now = "2026-11-12T12:00:00+00:00"
    lines = []
    for i in range(n):
        lines.append(json.dumps({
            "ts": now, "from_tool": "responderd", "severity": "HIGH",
            "text": f"\"f{i}.bin\" was quarantined",
            "interaction": {
                "id": f"responderd:bulk{i}", "kind": "file",
                "subject": f"f{i}.bin was quarantined",
                "options": [{"id": "keep", "label": "Keep",
                             "helper": "keep-quarantine",
                             "args": [f"/tmp/d/f{i}.bin"]}]}}))
    (data_dir / "events.jsonl").write_text("\n".join(lines) + "\n")


def _seed_findings(data_dir: pathlib.Path, n=4):
    from hunter import store
    for i in range(n):
        f = {"id": f"bulk-f{i}", "rule": "cfg-new-extension",
             "title": f"Extension {i}", "what": "x", "severity": "LOW",
             "ts": "2026-11-12T12:00:00+00:00"}
        store.append_finding(data_dir, f)


@pytest.fixture
def isolated_win(monkeypatch, tmp_path):
    from gi.repository import GLib
    import ui.window as W
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(W, "snapshot_stale", lambda *a, **k: False)
    W.DATA_DIR = tmp_path
    win = W.MainWindow()
    monkeypatch.setattr(win, "data_dir", tmp_path, raising=False)
    for m in getattr(win, "_monitors", None) or []:
        try:
            m.cancel()
        except Exception:
            pass
    win._monitors = []
    if getattr(win, "_glib_ids", None):
        for gid in list(win._glib_ids):
            GLib.source_remove(gid)
        win._glib_ids = []
    pump(20)
    yield win, tmp_path
    win.destroy()


def test_clear_decisions_records_every_id(isolated_win):
    import ui.window as W
    win, tmp = isolated_win
    _seed_decisions(tmp, 3)
    before = len([1 for _ in (tmp / "decisions.jsonl").open()] ) \
        if (tmp / "decisions.jsonl").exists() else 0
    W.MainWindow._assistant_intent(win, "clear_decisions", "", "")
    rows = [json.loads(l) for l in
            (tmp / "decisions.jsonl").read_text().splitlines() if l.strip()]
    ids = {r["id"] for r in rows}
    assert {"responderd:bulk0", "responderd:bulk1",
            "responderd:bulk2"} <= ids
    assert all(r["option"] == "keep" for r in rows)


def test_dismiss_all_findings_then_show_again(isolated_win):
    import ui.window as W
    win, tmp = isolated_win
    _seed_findings(tmp, 4)
    ok, n = W.MainWindow._dismiss_all_findings(win)
    assert ok and n == 4
    from hunter import store
    quiet = store.quieted_findings(tmp)
    assert {q["id"] for q in quiet} == {f"bulk-f{i}" for i in range(4)}
    # the way back: one unquiet returns one row to the feed
    store.unquiet_finding(tmp, "bulk-f1")
    quiet = {q["id"] for q in store.quieted_findings(tmp)}
    assert "bulk-f1" not in quiet and "bulk-f0" in quiet


def test_purge_quarantine_reports_the_helper_count(isolated_win,
                                                   monkeypatch):
    import ui.window as W
    win, tmp = isolated_win
    calls = []

    def fake_exec(helper, args):
        calls.append((helper, list(args)))
        rows = (tmp / "quarantine.jsonl") \
            .read_text().splitlines() if (tmp / "quarantine.jsonl") \
            .exists() else []
        return 0

    (tmp / "quarantine.jsonl").write_text("\n".join([
        json.dumps({"ts": "t", "orig": "/d/x", "file": "/q/x"}),
        json.dumps({"ts": "t2", "action": "deleted", "orig": "/d/x"}),
    ]) + "\n")
    import cli
    monkeypatch.setattr(cli, "helper_exec", fake_exec)
    ok, n = W.MainWindow._purge_quarantine(win)
    assert ok and calls[0][0] == "purge-quarantine"
    assert n == 1
