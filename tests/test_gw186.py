"""GW-186 (owner 2026-11-05, over a screenshot: "i can't copy logs or
info from the tools").

Two halves on the desks: the dossier grows a "Copy details" button that
puts its plain-text twin - the same words the dossier paints, nothing
summarised away - on the clipboard and says "Copied"; and the shared
prose/facts/units labels become selectable, so any desk's text can be
copied by hand too (Tools desk uses the same factories)."""
import os
import pathlib
import sys

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

from types import SimpleNamespace  # noqa: E402

from gi.repository import Gtk  # noqa: E402

from ui.desk import DeskDossier  # noqa: E402
from ui.protectdesk import ProtectDesk  # noqa: E402
import ui.protectdesk as pd  # noqa: E402
from tests.test_hunter_page import pump  # noqa: E402

_REG = ("clamav", "rkhunter", "lynis", "aide")


def _registry():
    return [{"name": n, "unit": f"{n}.service", "logs": ()} for n in _REG]


def _fact(name, counter=False):
    sc = ({"state": "done", "detail": "Infected files: 0",
           "exit_code": 0, "count": 4744, "counter_label": "folders swept",
           "started_at": "2026-11-05T03:52:00+00:00",
           "ended_at": "2026-11-05T04:01:00+00:00"} if counter else {})
    return {"name": name, "state": "GREEN", "paused": False,
            "quiet": False, "unit": f"{name}.service",
            "installed": True, "label": name.upper(), "event": None,
            "last_scan": sc, "live_scan": None}


def _desk(counter=False):
    desk = ProtectDesk(_registry(), runset=set())
    facts = {"clamav": _fact("clamav", counter=counter),
             "rkhunter": _fact("rkhunter", counter=counter)}
    desk.paint(facts, "2026-11-05T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    desk.fill_dossier("clamav")
    return desk


def _buttons(widget):
    if hasattr(widget, "observe_children"):
        for child in widget.observe_children():
            if isinstance(child, Gtk.Button):
                yield child
            yield from _buttons(child)


def _walk(widget):
    if hasattr(widget, "observe_children"):
        for child in widget.observe_children():
            yield child
            yield from _walk(child)


# -------------------------------------------------- the copy button

def test_the_text_twin_carries_the_whole_dossier():
    desk = _desk(counter=True)
    text = desk._dossier_text
    for piece in ("CLAMAV", "state:", "Infected files: 0",
                  "real tool: clamav", "RAW FACTS",
                  "LAST RUN IN ITS OWN UNITS",
                  "4,744 folders swept", "SUGGESTED NEXT STEP"):
        assert piece in text, (piece, text)
    # And the words match what the dossier actually painted: the evline
    # on file and the text twin agree.
    labels = [w.get_text() for w in _walk(desk.dossier)
              if isinstance(w, Gtk.Label)]
    assert any("4,744 folders swept" in lab for lab in labels), labels


def test_copy_details_lands_on_the_clipboard(monkeypatch):
    desk = _desk(counter=True)
    saved = {}

    class _Clip:
        def set_text(self, value):
            saved["text"] = value

    fake_gdk = SimpleNamespace(Display=SimpleNamespace(
        get_default=lambda: SimpleNamespace(get_clipboard=lambda: _Clip())))
    monkeypatch.setattr(pd, "Gdk", fake_gdk)
    btn = next(b for b in _buttons(desk.dossier)
               if b.get_label() == "Copy details")
    btn.emit("clicked")
    pump(5)
    assert saved["text"] == desk._dossier_text, "the dossier's twin copied"
    assert btn.get_label() == "Copied", "the button says what happened"


def test_copy_details_is_fresh_for_every_refill():
    desk = _desk(counter=True)
    first = next(b for b in _buttons(desk.dossier)
                 if b.get_label() == "Copy details")
    desk.fill_dossier("clamav")          # a refill rebuilds the row
    second = next(b for b in _buttons(desk.dossier)
                  if b.get_label() == "Copy details")
    assert second is not first, ("the button is rebuilt per refill, so a "
                                 "stale Copied label never sticks")


# -------------------------------------------------- selectable labels

def test_desk_label_factories_are_selectable():
    d = DeskDossier("test eyebrow")
    for made in (d.prose("what this does"),
                 d.facts(["real tool: x", "unit: x.service"]),
                 d.evline("4,744 folders swept")):
        assert made.get_selectable() is True, made.get_css_classes()


def test_the_painted_dossiers_labels_are_selectable():
    desk = _desk(counter=True)
    painted = [w for w in _walk(desk.dossier) if isinstance(w, Gtk.Label)]
    assert painted, "the dossier painted words at all"
    for lab in painted:
        css = set(lab.get_css_classes())
        if css & {"gw-prose", "gw-facts", "gw-facts-line"}:
            assert lab.get_selectable() is True, (lab.get_text(), css)
