# tests/test_ui_metrics.py
"""Screen-relative sizing: the same build runs on 1366px, 1080p and 4K."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ui import metrics


def test_column_grows_with_the_window_but_stays_readable():
    """A 4K window must not leave the page a narrow strip, and a 4K column
    must not become a 2800px line of prose."""
    small = metrics.column_width(900)
    laptop = metrics.column_width(1440)
    wide = metrics.column_width(3840)
    assert small <= laptop < wide
    assert wide <= metrics.COLUMN_MAX
    assert laptop > 900                     # wider than the old fixed cap


def test_span_never_asks_for_more_than_the_screen_has():
    """A 1024px netbook cannot honour a 1100px floor."""
    assert metrics.span(1024, 0.76, 1100, 2200) <= 1024 - 40
    assert metrics.span(3840, 0.76, 1100, 2200) == 2200
    assert metrics.span(0, 0.76, 1100, 2200) == 1100   # no display


def test_window_and_wizard_fit_common_screens():
    for width, height in ((1366, 768), (1920, 1080), (3840, 2160)):
        w = metrics.span(width, metrics.WINDOW_FRACTION_W,
                         metrics.WINDOW_MIN_W, metrics.WINDOW_MAX_W)
        h = metrics.span(height, metrics.WINDOW_FRACTION_H,
                         metrics.WINDOW_MIN_H, metrics.WINDOW_MAX_H)
        assert w <= width - 40 and h <= height - 40
        assert w >= 1100 and h >= 720


def test_wizard_is_wider_than_the_old_fixed_dialog():
    w, h = (metrics.span(3840, 0.62, 860, 1320),
            metrics.span(2160, 0.88, 560, 1040))
    assert w > 880 and h > 760
