"""Regression pins for the page crashes found in the 4K sweep."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import gi
gi.require_version("Gtk", "4.0")


def test_timeline_filter_handler_receives_the_page(monkeypatch):
    # The page was carried as an attribute on the widget. GTK can pass a
    # different Python wrapper to the signal handler, which lost it; the
    # page now travels as signal user_data.
    from ui import timeline
    monkeypatch.setattr(timeline, "_refresh_into", lambda _p: None)
    page = type("P", (), {"_gw_filter": "all"})()

    class Combo:
        def get_active_text(self):
            return "aide"

    timeline._on_pick(Combo(), page)
    assert page._gw_filter == "aide"
