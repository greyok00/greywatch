"""Screen-relative sizing: one rule for every window and content column.

The same build runs on a 1366px laptop, a 1080p monitor and a 4K panel, so
a fixed pixel size is wrong on at least one of them. Everything here takes
a fraction of the space that is actually available and clamps it to a floor
and a ceiling: the floor keeps text readable, the ceiling keeps a line of
prose from running the full width of a 4K screen.

Pure arithmetic except `screen_size()`, so the rules are testable without a
display.
"""
from __future__ import annotations

# Share of the window used by a settings/help column. Wide enough that a
# 4K screen does not hide the page behind two empty margins, narrow enough
# that a line of text still reads left to right.
COLUMN_FRACTION = 0.74
COLUMN_MAX = 1500
COLUMN_MIN = 720

# The main window opens at four fifths of the monitor and never smaller
# than a laptop can show. The floor rose with the padded layout: at 1100
# the three-column Settings page had no room left for its detail pane.
WINDOW_FRACTION_W = 0.80
WINDOW_FRACTION_H = 0.86
WINDOW_MIN_W = 1140
WINDOW_MIN_H = 760
WINDOW_MAX_W = 2400
WINDOW_MAX_H = 1600

# One page inset for every top-level page. The old values drifted between
# 26/30/34 px, which read as three different apps rather than one window.
PAGE_X = 30
PAGE_TOP = 24
PAGE_BOTTOM = 18
PAGE_SPACING = 12


def span(available: int, fraction: float, minimum: int, maximum: int) -> int:
    """`fraction` of `available`, kept between `minimum` and `maximum`.

    A monitor smaller than the floor wins over the floor: the result never
    asks for more than the screen can give (minus a 40px edge)."""
    if available <= 0:
        return minimum
    want = int(round(available * fraction))
    limit = max(1, available - 40)
    return max(min(want, maximum, limit), min(minimum, limit))


def column_width(width: int) -> int:
    """Content width for a page column inside a window of `width`."""
    if width <= 0:
        return COLUMN_MIN
    return span(width, COLUMN_FRACTION, COLUMN_MIN, COLUMN_MAX)


def window_size() -> tuple[int, int]:
    """Default size for the dashboard window, as a share of the monitor."""
    sw, sh = screen_size()
    return (span(sw or 1920, WINDOW_FRACTION_W, WINDOW_MIN_W, WINDOW_MAX_W),
            span(sh or 1080, WINDOW_FRACTION_H, WINDOW_MIN_H, WINDOW_MAX_H))


def wizard_size() -> tuple[int, int]:
    """The setup wizard: task-dialog scale, not dashboard scale.

    The pages are short forms over a fixed reading column, so a window wider
    or taller than the content just means dead space — and when the default
    sat near the full screen height the last rows clipped off the bottom."""
    sw, sh = screen_size()
    width = span(sw or 1920, 0.50, 800, 1020)
    height = span(sh or 1080, 0.64, 560, 820)
    return width, height


def screen_size() -> tuple[int, int]:
    """Logical pixels of the primary monitor, or (0, 0) with no display."""
    try:
        from gi.repository import Gdk
        display = Gdk.Display.get_default()
        if display is None:
            return (0, 0)
        monitors = display.get_monitors()
        if monitors is None or monitors.get_n_items() < 1:
            return (0, 0)
        geo = monitors.get_item(0).get_geometry()
        return (geo.width, geo.height)
    except Exception:              # noqa: BLE001 - size is cosmetic
        return (0, 0)
