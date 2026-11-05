# tests/test_rail_scrollbar.py
# Wave note (2026-11-03): the left-rail scroller this file used to pin is
# gone with the new tab shell; the general scrollbar rules it carried
# still hold for every page that scrolls.
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_scrollbar_trough_is_transparent_everywhere():
    from ui import themes
    css = themes.gtk_css(themes.load_themes()["aperture"])
    assert "scrollbar trough { background: transparent;" in css