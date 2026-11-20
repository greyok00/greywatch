"""Pins for the app tail: Settings (theme, advanced mode), the
Assistant (the standing law, the ask onto the CLI), and Help (the tour
plus every digest)."""

from __future__ import annotations

import json
import pathlib

import pytest

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from tests.test_ui_v4 import _ShellStub, _all_texts


@pytest.fixture
def tail_stubs(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "knowledge-index.json").write_text(json.dumps({
        "version": 2, "built_at": "2026-11-15T08:00:00+00:00",
        "sources": {}, "chunks": [{"id": str(i), "source": "x.md",
                                   "title": "x.md", "text": "passage"}
                                  for i in range(4)]}))
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(d))
    return d


def test_assistant_carries_the_standing_law(tail_stubs, monkeypatch):
    # The restored panel (ui/assistant.py) hosted by the v4 page
    # (ui/assistant_page.py): the standing law reads through the page's
    # own copy and the panel header.
    import ui.assistant_page as assistant
    from ui import cliapi
    monkeypatch.setattr(cliapi, "jcall", lambda *a, **k: None)
    page = assistant.build(_ShellStub())
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page))).lower()
    assert "machine's own facts" in texts
    assert "local model on your toggle" in texts
    assert "asks before changing" in texts
    assert "4 passages" in texts


def test_assistant_ask_answers_in_the_thread(tail_stubs, monkeypatch):
    # The panel answers from its own brain (build_pack + plan_turn), not
    # by shelling the assist verb; the question lands as a bubble and
    # the plan lands as an answer bubble in the same transcript.
    import ui.assistant_page as assistant
    from ui import cliapi
    monkeypatch.setattr(cliapi, "read_state", lambda name: {"tools": {}})
    shell = _ShellStub()
    page = assistant.build(shell)
    body = getattr(page, "_gw_body", page)
    panel = getattr(body, "_gw_panel", None)
    assert panel is not None
    panel.entry.set_text("what is watching my ports?")
    from gi.repository import GLib
    panel._send()
    ctx = GLib.main_context_default()
    for _ in range(400):
        ctx.iteration(False)
    texts = " ".join(_all_texts(panel.stream)).lower()
    assert "what is watching my ports?" in texts
    assert "..." not in texts.strip()[-3:]


class _Entry:
    def __init__(self, text: str):
        self._t = text

    def get_text(self) -> str:
        return self._t


def test_help_lists_every_digest_on_the_tree(tail_stubs, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR",
                       str(tail_stubs.parent / "state"))
    import ui.helpdesk as helpdesk
    shell = _ShellStub()

    def has_page(name: str) -> bool:
        return name in ("Security Center", "Network", "Tools",
                        "Timeline", "Response", "Baseline")

    shell.has_page = has_page
    page = helpdesk.build(shell)
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page))).lower()
    assert "the tour" in texts
    assert "tool digests" in texts
    buttons = _buttons(getattr(page, "_gw_body", page))
    labels = {b.get_label() for b in buttons}
    assert any("aide" in lb for lb in labels), sorted(labels)[:6]


def test_a_digest_opens_inside_help(tmp_path, monkeypatch):
    from ui import helpdesk
    page = helpdesk.build(_ShellStub())
    button = next(b for b in _buttons(page)
                  if b.get_label() in ("aide", "appfw", "arpwatch"))
    button.emit("clicked")
    texts = _texts(page)
    assert "Back" in texts
    assert "Tool digest" in texts or "No digest" in texts


def test_help_has_no_extra_window(tmp_path, monkeypatch):
    import gi
    from gi.repository import Gtk
    before = set(Gtk.Window.get_toplevels())
    from ui import helpdesk
    page = helpdesk.build(_ShellStub())
    _button(page, "aide").emit("clicked") if _has(page, "aide") else None
    after = set(Gtk.Window.get_toplevels())
    assert after == before


def _texts(w) -> list:
    return _all_texts(w)


def _has(w, label: str) -> bool:
    return any(b.get_label() == label for b in _buttons(w))


def _button(w, label: str):
    return next(b for b in _buttons(w) if b.get_label() == label)


def _buttons(w) -> list:
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
    out = []
    if isinstance(w, Gtk.Button):
        out.append(w)
        return out
    c = w.get_first_child() if hasattr(w, "get_first_child") else None
    while c is not None:
        out.extend(_buttons(c))
        c = c.get_next_sibling()
    return out


def test_settings_page_is_gone_and_appearance_lives_in_the_header(
        monkeypatch, tmp_path):
    from ui import app as app_mod
    from ui import themes
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(themes, "SETTINGS_PATH", tmp_path / "prefs.json")
    win = app_mod.Window(_AppStub())
    assert not win.has_page("Settings")
    assert "Settings" not in win._rail_rows
    assert win._appearance_button is not None
    win.show_page("Security Center")
    before = win._stack.get_visible_child()
    win._set_theme("paper")
    assert themes.active_theme() == "paper"
    # the theme changes in place; the current screen does not disappear
    assert win._stack.get_visible_child() is before
    win._set_theme("graphite")


class _AppStub(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.greywatch.test2")
