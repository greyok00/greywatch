# tests/test_rail_scrollbar.py
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_rail_scroller_drops_the_overlay_scrollbar():
    """The rail ends on its own pause/play buttons; the GTK4 floating
    grey pill painted over them reads as a broken overlay (owner report
    2026-10-29). Structural pin, in the spirit of the Gtk3-era API ban
    list checks."""
    assert "sc.set_overlay_scrolling(False)" in (
        ROOT / "ui" / "window.py").read_text()


def test_rail_scroller_is_hidden_by_css_not_just_layout():
    """Layout alone was not enough: the Adwaita trough still painted the
    grey slab over the rail's right edge after set_overlay_scrolling
    (owner: "the overlay you said was the scrollbar is still there").
    The bar must be off by class, with wheel scrolling left alone."""
    win = (ROOT / "ui" / "window.py").read_text()
    assert 'sc.add_css_class("gw-rail-scroll")' in win
    from ui import themes
    css = themes.gtk_css(themes.load_themes()["obsidian"])
    assert ".gw-rail-scroll scrollbar" in css
    assert "opacity: 0" in css


def test_rail_rows_are_compact_without_touching_global_rows():
    win = (ROOT / "ui" / "window.py").read_text()
    assert 'self.rail_list.add_css_class("gw-rail-rows")' in win
    from ui import themes
    css = themes.gtk_css(themes.load_themes()["obsidian"])
    assert ".gw-rail-rows row { min-height: 30px" in css
    assert "row, treeview row { min-height: 40px" in css     # tables unchanged


def test_scrollbar_trough_is_transparent_everywhere():
    from ui import themes
    css = themes.gtk_css(themes.load_themes()["obsidian"])
    assert "scrollbar trough { background: transparent;" in css
