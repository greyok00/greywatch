import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ui import metrics
from ui.themes import gtk_css, load_themes


def test_window_opens_larger_and_never_smaller_than_before():
    assert metrics.WINDOW_MIN_W >= 1140
    assert metrics.WINDOW_MIN_H >= 760
    assert metrics.WINDOW_FRACTION_W >= 0.80
    assert metrics.WINDOW_FRACTION_H >= 0.86


def test_one_page_margin_scale():
    assert metrics.PAGE_X == 30
    assert metrics.PAGE_TOP == 24
    assert metrics.PAGE_BOTTOM == 18
    assert metrics.PAGE_SPACING == 12


def test_css_carries_the_padding_scale():
    css = gtk_css(load_themes()["obsidian"])
    assert "button { padding: 8px 16px;" in css
    assert "padding: 9px 13px;" in css
    assert ".gw-card { padding: 16px; }" in css
    # the winning rule near the end of the sheet, not just the base block
    assert "border-radius: 14px; padding: 16px;" in css


def test_every_page_starts_at_the_same_inset():
    # Source-level: no page builder may keep a one-off margin of its own.
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "ui" / "window.py").read_text(encoding="utf-8")
    for stale in ("set_margin_start(34)", "set_margin_end(34)",
                  "set_margin_top(26); box.set_margin_start(30)"):
        assert stale not in src, stale
    assert src.count("metrics.PAGE_X") >= 8
