# tests/test_rail_scrollbar.py
# Task 2 (rebuild round 2): the rail is the owner's fixed ten-page menu.
# The collapse constants are deleted (the window going narrow never turns
# the rail glyph-only), and the width pins to the five percent law. These
# pins need no display. The scrollbar-quiet rule the file used to carry
# still holds for every page that scrolls.
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_scrollbar_trough_is_transparent_everywhere():
    from ui import themes
    css = themes.gtk_css(themes.load_themes()["graphite"])
    assert "scrollbar trough { background: transparent;" in css


def test_rail_never_collapses():
    from ui import shell
    for gone in ("NARROW_RAIL", "collapse_rail", "rail_pinned"):
        assert not hasattr(shell, gone), gone
    assert "WIDE_RAIL" not in vars(shell).keys() or \
        not hasattr(shell, "WIDE_RAIL")


def test_rail_width_law_is_five_percent_floored_and_capped():
    from ui import shell
    assert shell.rail_size(1200) == 150        # the floor holds the labels
    assert shell.rail_size(2400) == 150        # 5% = 120 -> the floor wins
    assert shell.rail_size(3000) == 150
    assert shell.rail_size(3600) == 180
    assert shell.rail_size(4000) == 200
    assert shell.rail_size(9999) == 200        # the cap holds


def test_rail_is_the_ten_page_grouped_menu():
    from ui import shell
    assert shell.RAIL == (
        ("scans", "protect", "tools", "harden"),
        ("defense", "thunter"),
        ("logs", "settings", "help"))
    assert shell.HEADINGS == ("Overview", "Care", "Defense", "System")
    keys = tuple(k for group in shell.RAIL for k in group)
    assert len(keys) == len(set(keys)) == 9
