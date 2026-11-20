"""Pins for the Updates card: the true cache total is disclosed, the
primary action patches only the affected packages, and the full upgrade
is a separate, confirmed, secondary action."""

from __future__ import annotations

import json
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from tests.test_ui_v4 import _ShellStub


def _texts(w) -> str:
    """Every text a widget tree carries, button labels included."""
    out = []
    if isinstance(w, Gtk.Button):
        out.append(w.get_label() or "")
    label = w.get_label() if isinstance(w, Gtk.Label) else None
    if label:
        out.append(label)
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        out.append(_texts(child))
        child = child.get_next_sibling()
    return " ".join(out)


def _buttons(w) -> list:
    out = []
    if isinstance(w, Gtk.Button):
        return [w]
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        out.extend(_buttons(child))
        child = child.get_next_sibling()
    return out


def _button(root, label):
    for button in _buttons(root):
        if button.get_label() == label:
            return button
    raise AssertionError(f"button {label!r} missing")


def _pump(iterations=400):
    """The patch worker lands through GLib.idle_add."""
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(iterations):
        ctx.iteration(False)
        time.sleep(0.002)


def _page(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 100, "total_entries": 2, "capped": False,
        "entries": [{"package": "openssl", "id": "CVE-2026-1",
                     "severity": "HIGH", "installed": "1",
                     "fixed": "2"}]}))
    from ui import security
    page = Gtk.Box()
    page._gw_window = _ShellStub()
    return security, page


def test_the_primary_sends_the_affected_verb(tmp_path, monkeypatch):
    security, page = _page(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(security.cliapi, "call",
                        lambda *a, **k: calls.append(a) or (0, "done", ""))
    card = security.updates_card(page._gw_window, page)
    _button(card, "Patch affected packages").emit("clicked")
    _pump()
    assert calls and calls[0][:2] == ("patch", "--affected")


def test_the_upgrade_sends_all_only_after_confirmation(tmp_path,
                                                       monkeypatch):
    security, page = _page(tmp_path, monkeypatch)
    calls, asked = [], []
    monkeypatch.setattr(security.cliapi, "call",
                        lambda *a, **k: calls.append(a) or (0, "done", ""))
    monkeypatch.setattr(security.actions, "ask",
                        lambda *a, **k: asked.append(a) or False)
    card = security.updates_card(page._gw_window, page)
    upgrade = _button(card, "Upgrade the system")
    upgrade.emit("clicked")
    assert asked                       # the confirmation was asked
    assert calls == []                 # and nothing ran
    monkeypatch.setattr(security.actions, "ask", lambda *a, **k: True)
    upgrade.emit("clicked")
    _pump()
    assert calls and calls[0][:2] == ("patch", "--all")


def _rebuild_mid_run(tmp_path, monkeypatch, label, args):
    security, page = _page(tmp_path, monkeypatch)
    started, release = threading.Event(), threading.Event()
    calls = []

    def fake_call(*a, **k):
        calls.append(a)
        started.set()
        release.wait(5)
        return (0, "done", "")

    monkeypatch.setattr(security.cliapi, "call", fake_call)
    monkeypatch.setattr(security.actions, "ask", lambda *a, **k: True)
    card = security.updates_card(page._gw_window, page)
    _button(card, label).emit("clicked")
    assert started.wait(5)
    assert calls and calls[0] == ("patch", *args)
    # a rebuild while the worker runs makes fresh widgets
    security.updates_card(page._gw_window, page)
    live = page._gw_slots["updates"]
    assert not live["button"].get_sensitive()
    assert not live["secondary"].get_sensitive()
    if args == ["--all"]:
        assert live["button"].get_label() == "Upgrading..."
    else:
        assert live["button"].get_label() == "Patching..."
    release.set()
    deadline = time.time() + 5
    while not live["secondary"].get_sensitive() and time.time() < deadline:
        _pump(20)
    assert live["button"].get_sensitive()
    assert live["secondary"].get_sensitive()
    assert live["button"].get_label() == "Patch affected packages"
    assert live["secondary"].get_label() == "Upgrade the system"


def test_a_rebuild_mid_patch_leaves_both_buttons_live(tmp_path, monkeypatch):
    _rebuild_mid_run(tmp_path, monkeypatch, "Patch affected packages",
                     ["--affected"])


def test_a_rebuild_mid_upgrade_leaves_both_buttons_live(tmp_path,
                                                        monkeypatch):
    _rebuild_mid_run(tmp_path, monkeypatch, "Upgrade the system", ["--all"])


def test_patch_calls_outlast_the_cli_helper_budget(tmp_path, monkeypatch):
    security, page = _page(tmp_path, monkeypatch)
    seen = []

    def fake_call(*args, **kwargs):
        seen.append((args, kwargs.get("timeout")))
        return (0, "done", "")

    monkeypatch.setattr(security.cliapi, "call", fake_call)
    monkeypatch.setattr(security.actions, "ask", lambda *a, **k: True)
    card = security.updates_card(page._gw_window, page)
    _button(card, "Patch affected packages").emit("clicked")
    _pump()
    _button(card, "Upgrade the system").emit("clicked")
    _pump()
    affected = [t for a, t in seen if "--affected" in a]
    upgrade = [t for a, t in seen if "--all" in a]
    assert affected and affected[0] > 3600
    assert upgrade and upgrade[0] > 1800


def test_updates_card_offers_targeted_patch_and_a_separate_upgrade(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 100, "total_entries": 7, "capped": True,
        "entries": [{"package": "openssl", "id": "CVE-2026-1",
                     "severity": "HIGH", "installed": "1",
                     "fixed": "2"}]}))
    from ui import security
    page = Gtk.Box()
    page._gw_window = _ShellStub()
    card = security.updates_card(page._gw_window, page)
    labels = [b.get_label() for b in _buttons(card)]
    assert "Patch affected packages" in labels
    assert "Upgrade the system" in labels
    text = _texts(card)
    assert "1 of 100" in text
    assert "1 of 7" in text or "7 total" in text
