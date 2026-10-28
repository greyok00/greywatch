"""The decision popup must name the program and the destination.

Display-guarded like the rest of the GUI suite: it builds a real window
on the private Xvfb, never on the owner's desktop.
"""

import os
import sys
import pathlib
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib  # noqa: E402


def _gtk_ready() -> bool:
    try:
        if not Gtk.init_check():
            return False
        from gi.repository import Gdk
        return Gdk.Display.get_default() is not None
    except Exception:
        return False


if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip("needs a test display (private Xvfb)", allow_module_level=True)
if not _gtk_ready():
    pytest.skip("no display available", allow_module_level=True)

from ui import decisions, identity  # noqa: E402


def _labels(widget):
    out = []

    def walk(w):
        if isinstance(w, Gtk.Label):
            out.append(w.get_text())
        child = w.get_first_child()
        while child is not None:
            walk(child)
            child = child.get_next_sibling()
    walk(widget)
    return out


def _pump(seconds=2.0):
    ctx = GLib.main_context_default()
    deadline = time.time() + seconds
    while time.time() < deadline:
        ctx.iteration(False)
        time.sleep(0.02)


SPEC = {
    "id": "appfw:chromium:42:5555",
    "eyebrow": "App firewall",
    "subject": "chromium wants internet access",
    "detail": "/usr/bin/chromium\n→ 57.144.134.145:443 (tcp) · pid 42",
    "question": "",
    "host": "57.144.134.145",
    "app_name": "chromium",
    "path": "/usr/bin/chromium",
    "port": 443,
    "proto": "tcp",
    "pid": 42,
    "options": [
        {"id": "deny-once", "label": "Block once", "tone": "danger",
         "helper": "none", "args": ["deny", "once"]},
        {"id": "allow-once", "label": "Allow once", "tone": "primary",
         "helper": "none", "args": ["allow", "once"]},
        {"id": "block-always", "label": "Always block this program",
         "tone": "danger", "helper": "none", "args": ["deny", "always"]},
    ],
}


def test_popup_shows_who_asked_and_who_answers(monkeypatch):
    monkeypatch.setattr(identity, "describe_connection",
                        lambda host, path, app="": {
                            "host_card": {
                                "title": "Facebook",
                                "sentence": "This is Facebook — a network "
                                            "registered in Ireland.",
                                "rows": [("Country", "Ireland (IE)"),
                                         ("Registered to",
                                          "Meta Platforms Ireland Limited")],
                                "warning": ""},
                            "program_card": {
                                "title": "Chromium",
                                "sentence": "This is Chromium, part of the "
                                            "chromium package that came with "
                                            "your system.",
                                "rows": [("Real program", "chromium")],
                                "warning": "", "icon": ""}})
    dlg = decisions._decision_dialog(SPEC, modal=False)
    try:
        _pump()
        text = "\n".join(_labels(dlg.get_content_area()))
        assert "Facebook" in text
        assert "Ireland" in text
        assert "Chromium" in text
        assert "Meta Platforms Ireland Limited" in text
        # The plain-words line and the address line both survive.
        assert "57.144.134.145" in text
        assert "secure web" in text
    finally:
        dlg.destroy()


def test_popup_without_host_has_no_identity_card():
    plain = {"id": "yara-watch:abc", "eyebrow": "Threat found",
             "subject": "Block “x.so”?", "detail": "sig · /tmp/x.so",
             "question": "Keep it?", "options": [
                 {"id": "keep", "label": "Keep", "tone": "primary",
                  "helper": "keep-scan-ban", "args": ["/tmp/x.so"]},
                 {"id": "unban", "label": "Unblock", "tone": "danger",
                  "helper": "unban-ip", "args": ["1.2.3.4"]}]}
    dlg = decisions._decision_dialog(plain, modal=False)
    try:
        text = "\n".join(_labels(dlg.get_content_area()))
        assert "Looking up this address" not in text
        assert "Checking which program" not in text
    finally:
        dlg.destroy()


def test_six_answers_wrap_instead_of_clipping():
    spec = dict(SPEC)
    spec["options"] = [
        {"id": f"o{i}", "label": f"Answer {i}", "tone": "quiet",
         "helper": "none", "args": ["allow", "once"]} for i in range(6)]
    dlg = decisions._decision_dialog(spec, modal=False)
    try:
        _pump(0.2)
        text = "\n".join(_labels(dlg.get_content_area()))
        assert all(f"Answer {i}" in text for i in range(6))
    finally:
        dlg.destroy()


def test_popup_can_stop_the_flood_and_keep_recording():
    called, answers = [], []

    def on_learn(minutes):
        called.append(minutes)

    dlg = decisions._decision_dialog(SPEC, modal=False, on_learn=on_learn)
    try:
        _pump(0.2)
        seen = {}
        for label in _labels(dlg.get_content_area()):
            pass

        def walk(w):
            if isinstance(w, Gtk.Button):
                seen[w.get_label()] = w
            child = w.get_first_child()
            while child is not None:
                walk(child)
                child = child.get_next_sibling()
        walk(dlg.get_content_area())
        button = seen["Stop asking for 15 minutes (learning mode)"]
        dlg.connect("response", lambda _d, rid: answers.append(rid))
        button.emit("clicked")
        assert called == [15]
        # The connection on screen is allowed once so learning can start
        # from a working connection, not a blocked one.
        assert answers == [1]
    finally:
        dlg.destroy()


def test_other_popups_do_not_offer_learning_mode():
    plain = {"id": "responderd:abc", "eyebrow": "Threat found",
             "subject": "“x.so” was quarantined", "detail": "sig",
             "question": "Keep it?", "options": [
                 {"id": "keep", "label": "Keep", "tone": "primary",
                  "helper": "keep-quarantine", "args": ["/tmp/x.so"]}]}
    dlg = decisions._decision_dialog(plain, modal=False,
                                     on_learn=lambda m: None)
    try:
        text = "\n".join(_labels(dlg.get_content_area()))
        assert "learning mode" not in text
    finally:
        dlg.destroy()
