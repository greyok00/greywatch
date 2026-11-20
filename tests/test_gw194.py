"""GW-194 (owner 2026-11-05, over a live screenshot: "why can't i update
from here?").

The registry record panel was deliberately reads-only - state, activity,
next-step words, and no lever - so a 'state: not running' freshclam
record sent the reader walking to find a button somewhere else. The
record now carries its tool's own control when the record itself says it
needs one: Resume for a paused tool, Run scan for the unit-less scanners,
Update now for the definition updaters, Start tool for everything else.
The powers live in the window (the same levers the strip rows carry);
the panel only grows the button that reaches them."""
import os
import pathlib
import sys
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

from gi.repository import Gtk  # noqa: E402

from ui.toolsdesk import ToolsDesk  # noqa: E402
from ui import window as winmod  # noqa: E402

_REG = ("freshclam", "clamav", "rkhunter", "lynis")


def _registry():
    return [{"name": "freshclam", "unit": "clamav-freshclam.service",
             "scope": "root", "logs": ()},
            {"name": "clamav", "unit": "clamav-daemon.service",
             "scope": "root", "logs": ()},
            {"name": "rkhunter", "unit": None, "scope": "root",
             "logs": ()},
            {"name": "lynis", "unit": None, "scope": "root",
             "logs": ()}]


def _fact(name, state="GREEN", paused=False):
    return {"name": name, "state": state, "paused": paused,
            "quiet": False,
            "unit": (None if name in ("rkhunter", "lynis")
                     else f"{name}.service"),
            "installed": True, "label": name.upper(), "event": None,
            "last_scan": {}, "live_scan": None}


def _buttons(widget):
    if hasattr(widget, "observe_children"):
        for child in widget.observe_children():
            if isinstance(child, Gtk.Button):
                yield child
            yield from _buttons(child)


def _desk(facts, pressed):
    desk = ToolsDesk(_registry(), on_control=pressed.append)
    desk.paint(facts, [], "2026-11-05T18:00:00+00:00")
    return desk


def test_down_record_carries_its_update_button():
    pressed = []
    facts = {n: _fact(n) for n in _REG}
    facts["freshclam"] = _fact("freshclam", state="RED")
    desk = _desk(facts, pressed)
    desk.fill_dossier("freshclam")
    btn = next(b for b in _buttons(desk.dossier)
               if b.get_label() == "Update now")
    btn.emit("clicked")
    assert pressed == ["freshclam"]


def test_healthy_record_grows_no_control():
    pressed = []
    facts = {n: _fact(n) for n in _REG}
    desk = _desk(facts, pressed)
    desk.fill_dossier("clamav")
    labels = [b.get_label() for b in _buttons(desk.dossier)]
    assert "Start tool" not in labels and "Update now" not in labels


def test_unitless_scanner_offers_run_scan():
    pressed = []
    facts = {n: _fact(n) for n in _REG}
    facts["rkhunter"] = _fact("rkhunter", state="RED")
    desk = _desk(facts, pressed)
    desk.fill_dossier("rkhunter")
    btn = next(b for b in _buttons(desk.dossier)
               if b.get_label() == "Run scan")
    btn.emit("clicked")
    assert pressed == ["rkhunter"]


def test_paused_record_says_resume():
    pressed = []
    facts = {n: _fact(n) for n in _REG}
    facts["clamav"] = _fact("clamav", paused=True)
    desk = _desk(facts, pressed)
    desk.fill_dossier("clamav")
    btn = next(b for b in _buttons(desk.dossier)
               if b.get_label() == "Resume")
    btn.emit("clicked")
    assert pressed == ["clamav"]


def test_window_routes_unitless_to_the_scan_runner():
    """The window's own routing: rkhunter and lynis never reach the
    unit controls (there is no unit); everything else resumes through
    the existing toggle path."""
    seen = []
    fake = SimpleNamespace(
        by_name={"rkhunter": {"name": "rkhunter", "unit": None},
                 "clamav": {"name": "clamav",
                            "unit": "clamav-daemon.service"}},
        SCAN_RUN=winmod.MainWindow.SCAN_RUN)
    fake._scan_pressed = lambda name: seen.append(("scan", name))
    fake._toggle_tool = lambda name, pause=True: seen.append(("toggle",
                                                              name))
    winmod.MainWindow._control_requested(fake, "rkhunter")
    winmod.MainWindow._control_requested(fake, "clamav")
    assert seen == [("scan", "rkhunter"), ("toggle", "clamav")]
