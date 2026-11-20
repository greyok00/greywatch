"""Pins for the Baseline detail tab: the standard's table, the hardening
catalog rows, the CVE rows with their patch states - and the actions
through the CLI's own verbs."""

from __future__ import annotations

import json

from tests.test_ui_v4 import _ShellStub


def _pump(iterations=400):
    """The verify read rides a worker and lands through GLib.idle_add."""
    import time
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(iterations):
        ctx.iteration(False)
        time.sleep(0.002)


def _texts(w) -> list:
    """Every text a widget tree carries, button labels included."""
    from gi.repository import Gtk
    out = []
    if isinstance(w, Gtk.Button):
        out.append(w.get_label() or "")
    label = w.get_label() if isinstance(w, Gtk.Label) else None
    if label:
        out.append(label)
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        out.extend(_texts(child))
        child = child.get_next_sibling()
    return out


def _button(w, label: str):
    from gi.repository import Gtk
    if isinstance(w, Gtk.Button) and w.get_label() == label:
        return w
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        found = _button(child, label)
        if found is not None:
            return found
        child = child.get_next_sibling()
    return None


def test_baseline_detail_does_not_run_a_verifier_on_build(tmp_path,
                                                          monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import baseline_detail, cliapi
    calls = []
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, **k: calls.append(a) or {"tool_baseline": []})
    page = baseline_detail.build(_ShellStub())
    assert calls == []
    assert "Run baseline checks" in _texts(page)


def test_a_patch_button_runs_on_a_worker_and_restores_its_label(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import baseline_detail, cliapi
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 10, "suite": "trixie",
        "entries": [{"package": "openssl", "id": "CVE-2026-1",
                     "severity": "HIGH", "installed": "1.0",
                     "fixed": "2.0"}]}))
    monkeypatch.setattr(cliapi, "call",
                        lambda *a, **k: (0, "patched openssl 1.0 -> 2.0", ""))
    page = baseline_detail.build(_ShellStub())
    button = _button(page, "Patch openssl")
    button.emit("clicked")
    assert button.get_label() == "Installing..."
    assert not button.get_sensitive()
    _pump()
    assert button.get_label() == "Patch openssl"
    assert button.get_sensitive()


def test_a_second_patch_is_refused_while_one_is_in_flight(tmp_path,
                                                          monkeypatch):
    import threading
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import baseline_detail, cliapi
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 10, "suite": "trixie",
        "entries": [
            {"package": "openssl", "id": "CVE-2026-1",
             "severity": "HIGH", "installed": "1.0", "fixed": "2.0"},
            {"package": "libc6", "id": "CVE-2026-2",
             "severity": "HIGH", "installed": "1.0", "fixed": "2.0"}]}))
    release = threading.Event()
    started = threading.Event()
    calls = []

    def fake_call(*args, **kwargs):
        calls.append(args)
        started.set()
        release.wait(5)
        return (0, "patched", "")

    monkeypatch.setattr(cliapi, "call", fake_call)
    page = baseline_detail.build(_ShellStub())
    first = _button(page, "Patch libc6")
    first.emit("clicked")
    assert started.wait(5)
    second = _button(page, "Patch openssl")
    assert not second.get_sensitive()
    second.emit("clicked")
    assert len(calls) == 1
    release.set()
    _pump()
    assert page._gw_patching is False
    reopened = _button(page, "Patch openssl")
    reopened.emit("clicked")
    _pump()
    assert len(calls) == 2


def test_patch_calls_outlast_the_cli_helper_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import actions, baseline_detail, cliapi
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 10, "suite": "trixie",
        "entries": [{"package": "openssl", "id": "CVE-2026-1",
                     "severity": "HIGH", "installed": "1.0",
                     "fixed": "2.0"}]}))
    seen = []

    def fake_call(*args, **kwargs):
        seen.append((args, kwargs.get("timeout")))
        return (0, "patched", "")

    monkeypatch.setattr(cliapi, "call", fake_call)
    monkeypatch.setattr(actions, "ask", lambda *a, **k: True)
    page = baseline_detail.build(_ShellStub())
    _button(page, "Patch affected packages").emit("clicked")
    _pump()
    _button(page, "Upgrade the system").emit("clicked")
    _pump()
    affected = [t for a, t in seen if "--affected" in a]
    upgrade = [t for a, t in seen if "--all" in a]
    assert affected and affected[0] > 3600
    assert upgrade and upgrade[0] > 1800


def test_cve_eyebrow_has_no_parenthetical(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import baseline_detail
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 10, "suite": "trixie",
        "entries": [{"package": "openssl", "id": "CVE-2026-1",
                     "severity": "HIGH", "installed": "1.0",
                     "fixed": "2.0"}]}))
    page = baseline_detail.build(_ShellStub())
    lines = [t for t in _texts(page) if "cve rows -" in t.lower()]
    assert lines
    assert all("(" not in t for t in lines)
    assert "1 open package row" in " ".join(lines).lower()
