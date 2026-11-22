"""Pins for the shared card builders: a class string may carry several
class names separated by whitespace, and each one lands as its own
class on the frame."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui.kit import section_card
from ui.widgets import card


def test_card_adds_each_class_in_a_compound_string():
    frame = card(Gtk.Label(label="x"), cls="gw-card gw-card-quiet")
    assert frame.has_css_class("gw-card")
    assert frame.has_css_class("gw-card-quiet")
    assert not frame.has_css_class("gw-card gw-card-quiet")


def test_section_card_adds_each_class_in_a_compound_string():
    frame = section_card("Title", Gtk.Label(label="x"),
                         cls="gw-card gw-card-quiet")
    assert frame.has_css_class("gw-card")
    assert frame.has_css_class("gw-card-quiet")


def test_state_pill_with_target_is_a_clickable_button():
    """GW-10: a pill with a target is a button in pill dress; clicking
    it calls the target."""
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
    from ui.widgets import state_pill
    hits = []
    pill = state_pill("Needs attention", "warn", target=lambda: hits.append(1))
    assert isinstance(pill, Gtk.Button)
    assert pill.has_css_class("gw-pill")
    assert pill.has_css_class("gw-pill-warn")
    assert pill.has_css_class("gw-pill-link")
    pill.emit("clicked")
    assert hits == [1]


def test_state_pill_without_target_stays_a_label():
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
    from ui.widgets import state_pill
    pill = state_pill("All green", "ok")
    assert isinstance(pill, Gtk.Label)
    assert not pill.has_css_class("gw-pill-link")
