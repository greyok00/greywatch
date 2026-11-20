"""Pins for the element layer (ui/kit.py): the shared chips, tables,
bars and icons every screen composes from."""

from __future__ import annotations

import pathlib

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import kit, toolicons


def test_table_stores_rows():
    scroller, _s = kit.table(columns=(("Tool", 120), ("State", 80)),
                             rows=[("clamav", "green"),
                                   ("aide", "yellow")])
    assert list(scroller._gw_rows[0]) == ["clamav", "green"]
    assert isinstance(scroller, Gtk.ScrolledWindow)


def test_chip_levels_css():
    ok = kit.chip("Armed", "ok")
    warn = kit.chip("Stale", "warn")
    fail = kit.chip("Down", "fail")
    assert "gw-chip-ok" in ok.get_css_classes()
    assert "gw-chip-warn" in warn.get_css_classes()
    assert "gw-chip-fail" in fail.get_css_classes()


def test_level_bar_marks_direction():
    # a higher-is-better input at 85 sits in the upper band
    bar_hi = kit.level_bar(85)
    assert bar_hi.get_value() == 0.85
    # a lower-is-better exposure at 85 is BAD: the bar shows the level
    # the machine sits at (the risk), not the raw value
    bar_lo = kit.level_bar(85, lower_is_better=True)
    assert bar_lo.get_value() == 0.85


def test_icon_uses_installed_symbolic():
    name = toolicons.icon_name("clamav")
    svg = (pathlib.PosixPath.home() / ".local/share/icons/hicolor"
           / "scalable/apps" / f"{name}.svg")
    assert svg.exists(), "the installed symbolic icon must be on disk"
    image = kit.icon("clamav")
    assert isinstance(image, Gtk.Image)


def test_icon_falls_back_for_unknown_tools():
    assert toolicons.icon_name("not-a-tool") == \
        toolicons.icon_name("responderd")      # the shipped fallback


def test_section_card_titles_and_rows():
    card = kit.section_card("Baseline table", "row one")
    child = card.get_child()
    labels = [c.get_label() for c in _labels(child)
              if c.get_label()]
    joined = " ".join(labels)
    import re as _re
    stripped = _re.sub(r"<[^>]+>", "", joined)
    assert "Baseline table".upper() in stripped
    assert "row one" in stripped


def _labels(w):
    out = []
    c = w.get_first_child() if hasattr(w, "get_first_child") else None
    while c is not None:
        out.append(c)
        out.extend(_labels(c))
        c = c.get_next_sibling()
    return out
