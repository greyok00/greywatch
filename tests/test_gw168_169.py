"""GW-168 + GW-169 pins (owner reports 2026-11-04).

GW-168: the pending queue walked itself - a dismissed popup pulled the
        next one up 200 ms later, and the 60 s status pump kept feeding
        the walk, so every window on the desktop flinched in focus churn
        while a backlog of decisions existed. Popups answer one subject
        and stop; the decisions list owns everything else.
GW-169: every answer button ran pkexec on its own, and polkit's exec
        action re-prompts every call - a backlog cost a password per
        row. Shared answers now apply under ONE password, and the
        repeat-answer helper actions keep polkit's short authorization.
"""
import datetime as _dt
import json
import pathlib
import shutil
import subprocess
import time as _time

import gi
import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

import greywatch_daemon as dm  # noqa: E402
import ui.decisions as UD  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "DATA_DIR", tmp_path)
    # GW-166: call-time resolution reads this env, so tests steer it the
    # way the runtime does.
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("GREYWATCH_HELPER_CMD", raising=False)
    return tmp_path


def _spec(i, oid="keep"):
    return {"id": f"responderd:{i}", "question": "Keep or restore?",
            "options": [{"id": oid, "label": "Keep quarantined",
                         "helper": "keep-quarantine",
                         "args": [f"/tmp/file{i}"]}]}


def _ev(i, oid="keep"):
    return {"from_tool": "responderd",
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "text": "x", "interaction": _spec(i, oid)}


def _pump():
    ctx = GLib.main_context_default()
    while ctx.pending():
        ctx.iteration(False)


class _FakeDlg:
    def destroy(self):
        pass


class WatchBroker(UD.DecisionBroker):
    """Records what got served without touching GTK."""

    def __init__(self):
        super().__init__()
        self.shown = []

    def _show_dialog(self, spec, eyebrow="Protection", resolve=None,
                     tag=None):
        self.shown.append(spec["id"])

    def _notify_denies(self, events):
        pass

    def _notify_critical(self, events):
        pass


# -- GW-168: no chaining ---------------------------------------------------

def test_dismiss_stops_the_queue_walk(store):
    b = WatchBroker()
    b.pump([_ev(i) for i in range(5)])
    assert b.shown == ["responderd:4"] and len(b._queue) > 0
    b._on_response(_FakeDlg(), Gtk.ResponseType.DELETE_EVENT,
                   _spec(4), _spec(4)["options"])
    assert b._queue == [] and b._active is None
    assert b.shown == ["responderd:4"], "the next popup must not appear"


def test_answer_records_without_pulling_the_next_popup(store):
    b = WatchBroker()
    b.pump([_ev(i) for i in range(3)])
    sid = b._active
    b._on_response(_FakeDlg(), 0, _spec(2), _spec(2)["options"])
    assert b.shown == ["responderd:2"], "answering must not chain either"
    assert b._active is None
    rec = json.loads((store / "decisions.jsonl").read_text().splitlines()[0])
    assert rec["id"] == sid and rec["option"] == "keep"


def test_queue_leftovers_lose_their_popup_privilege(store):
    b = WatchBroker()
    b._queue.append({"spec": _spec(9), "eyebrow": "Protection",
                     "at": _time.monotonic() - 999.0})
    assert b._serve_next() == 0
    assert b.shown == [] and b._queue == []


def test_fresh_popup_still_serves(store):
    b = WatchBroker()
    b._queue.append({"spec": _spec(9), "eyebrow": "Protection",
                     "at": _time.monotonic()})
    assert b._serve_next() == 1 and b.shown == ["responderd:9"]


def test_ask_lane_items_never_age_out_of_the_slot(store):
    b = WatchBroker()
    b._queue.append({"spec": {"id": "appfw:live", "question": "Allow?",
                              "options": [{"id": "allow", "label": "A"}]},
                     "eyebrow": "App firewall", "resolve": lambda r: None,
                     "at": _time.monotonic() - 999.0})
    assert b._serve_next() == 1
    assert b.shown == ["appfw:live"]


# -- GW-169: one password per batch ----------------------------------------

def _override(monkeypatch, tmp_path, code):
    helper = tmp_path / "fake.sh"
    helper.write_text(f"#!/bin/sh\nexit {code}\n")
    helper.chmod(0o755)
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", str(helper))


def test_helper_batch_test_mode_applies_one_code_to_all(store, monkeypatch,
                                                        tmp_path):
    _override(monkeypatch, tmp_path, 0)
    from cli import helper_batch
    rcs = helper_batch([("keep-quarantine", ["a"]), ("keep-quarantine", ["b"])])
    assert rcs == [0, 0]


def test_helper_batch_failure_keeps_everything_open(store, monkeypatch,
                                                    tmp_path):
    _override(monkeypatch, tmp_path, 3)
    from cli import helper_batch
    assert helper_batch([("keep-quarantine", ["a"])]) == [3]


def test_helper_batch_parses_real_script_output(store, monkeypatch,
                                                tmp_path):
    # No override: the real batch.sh runs under the redirected ROOT (as
    # this user, no pkexec) and its allowlist refuses a name that is not
    # a helper script. That is the guard keeping arbitrary commands out
    # of the root pass.
    import cli as _cli
    apply_dir = tmp_path / "apply"
    apply_dir.mkdir()
    shutil.copy(_cli.ROOT / "apply" / "batch.sh", apply_dir / "batch.sh")
    (apply_dir / "batch.sh").chmod(0o755)
    monkeypatch.setattr(_cli, "ROOT", tmp_path)
    monkeypatch.delenv("GREYWATCH_HELPER_CMD", raising=False)
    assert _cli.helper_batch([("no-such-helper-xyz", ["/etc/passwd"])]) == [-1]


def test_batch_script_runs_real_helpers_in_order(tmp_path):
    # Exercise apply/batch.sh directly in a sandbox tree: two fake
    # helpers that touch marker files, proving order and rc plumbing
    # without pkexec or any real tool.
    gw = tmp_path / "tree"
    (gw / "apply").mkdir(parents=True)
    batch_src = pathlib.Path(__file__).resolve().parents[1] / "apply" \
        / "batch.sh"
    for name, code, marker in (("aaa.sh", 0, "ok1"), ("bbb.sh", 3, "ok2")):
        p = gw / "apply" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"#!/bin/sh\ntouch \"{tmp_path / marker}\"\n"
                     f"exit {code}\n")
        p.chmod(0o755)
    shutil.copy(batch_src, gw / "apply" / "batch.sh")
    (gw / "apply" / "batch.sh").chmod(0o755)
    inp = tmp_path / "b.json"
    inp.write_text(json.dumps({"items": [
        {"helper": "aaa", "args": []}, {"helper": "bbb", "args": []},
        {"helper": "aaa", "args": []}]}))
    proc = subprocess.run([str(gw / "apply" / "batch.sh"), str(inp)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    rcs = json.loads(proc.stdout.strip().splitlines()[-1])["rcs"]
    assert rcs == [0, 3, 0]
    assert (tmp_path / "ok1").exists() and (tmp_path / "ok2").exists()


def _buttons(box):
    out = []
    stack = [box]
    while stack:
        w = stack.pop(0)
        if isinstance(w, Gtk.Button):
            out.append(w)
        k = w.get_first_child()
        while k is not None:
            stack.append(k)
            k = k.get_next_sibling()
    return out


def _bulk_buttons(w):
    return [b for b in _buttons(w._bulk)
            if "one password" in (b.get_label() or "")]


@pytest.mark.gtk
def test_decisions_window_offers_bulk_when_shares_exist(store):
    (store / "events.jsonl").write_text("\n".join(
        json.dumps(_ev(i)) for i in range(3)) + "\n")
    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow()
    assert "to 3" in _bulk_buttons(w)[0].get_label()
    w.destroy()


@pytest.mark.gtk
def test_decisions_window_no_bulk_for_unshared_answers(store):
    (store / "events.jsonl").write_text(json.dumps(_ev(1)) + "\n")
    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow()
    assert _bulk_buttons(w) == []
    w.destroy()


@pytest.mark.gtk
def test_bulk_click_applies_and_records_with_one_password(store,
                                                          monkeypatch,
                                                          tmp_path):
    _override(monkeypatch, tmp_path, 0)
    (store / "events.jsonl").write_text("\n".join(
        json.dumps(_ev(i)) for i in range(3)) + "\n")
    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow()
    _bulk_buttons(w)[0].emit("clicked")
    deadline = 0.0
    while not (store / "decisions.jsonl").exists() and deadline < 5.0:
        _pump()
        _time.sleep(0.05)   # actually yield: without this the 5s "budget"
        deadline += 0.05    # drained in one spin before the helper ran
    recs = [json.loads(r) for r in
            (store / "decisions.jsonl").read_text().splitlines()]
    assert len(recs) == 3 and all(r["option"] == "keep" for r in recs)
    w.destroy()


@pytest.mark.gtk
def test_bulk_failure_records_nothing(store, monkeypatch, tmp_path):
    _override(monkeypatch, tmp_path, 3)
    (store / "events.jsonl").write_text(
        json.dumps(_ev(1)) + "\n" + json.dumps(_ev(2)) + "\n")
    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow()
    _bulk_buttons(w)[0].emit("clicked")
    deadline = 0.0
    while deadline < 5.0:
        _pump()
        assert not (store / "decisions.jsonl").exists(), \
            "a failed batch must not record answers"
        deadline += 0.05
    w.destroy()
