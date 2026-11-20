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
