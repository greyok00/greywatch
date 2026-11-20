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

# Titlebar/panel allowance subtracted before a window is placed: marco's
# frame and the panel are the WM's to keep, not ours.
FRAME_W = 40
FRAME_H = 60

# The main window opens a large-but-not-everything share of the monitor and
# never smaller than a laptop can show. The floor rose with the padded
# layout: at 1100 the three-column Settings page had no room left for its
# detail pane.
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

# Width of the service-state column on a Security Tools row. It is a fixed
# column so Pause and Scan line up down the list, and it must be wide
# enough for the longest phrase `service_words` can produce. At the old
# 150 px the label ellipsised to "service needs attenti…" on every warned
# row.
#
# Sized for the widest font that actually renders the phrase, not just the
# bundled look: Inter draws "● service needs attention" at 184 px, but a
# machine without Inter falls back to DejaVu Sans at 191 px (measured in
# CI). 200 clears both with room for a wider fallback.
STATE_COLUMN_PX = 200


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
    """Default size for the dashboard window, as a share of the monitor,
    always keeping a 16:10 or 16:9 ratio.

    The ratio is taken from the monitor when it sits inside the band and
    clipped to one of the band's ends when it does not, so an unusual
    panel never opens an off-ratio window that reads as squeezed."""
    width, height = sized_window(WINDOW_FRACTION_W, WINDOW_MIN_W,
                                 WINDOW_MAX_W, 1.6, 1.78)
    return width, height


def sized_window(fraction_w: float, min_w: int, max_w: int,
                 ratio_lo: float, ratio_hi: float) -> tuple[int, int]:
    """A window at `fraction_w` of the screen, height from a ratio band.

     rule for every top-level window: the width is a share of the
    monitor as the user sees it, never the monitor minus an allowance,
    and the height comes from a ratio band (16:10 to 16:9)
    so the same fractions land the same shape on a 1080p panel and on
    4K. fit_window then hard-clamps both axes against the real screen."""
    sw, sh = screen_size()
    if not sw or not sh:
        return (min_w, round(min_w / ratio_hi))
    ratio = max(ratio_lo, min(sw / sh, ratio_hi))
    limit = max(1, sh - FRAME_H)
    width = span(sw, fraction_w, min_w, max_w)
    height = round(width / ratio)
    if height > limit:
        height = min(limit, sh)
        width = round(height * ratio)
    return fit_window(width, height, sw, sh)


def wizard_size() -> tuple[int, int]:
    """The setup wizard and every task window: far under half the screen
    on any panel; it must not extend across the screen.

    The pages are short forms over a fixed reading column, so a window
    wider or taller than the content just means dead space. Fractions do
    the adapting - a 1080p screen gets the same share of its panel as a
    4K one - and 4K only raises the numbers, never the shape."""
    sw, sh = screen_size()
    if not sw or not sh:
        return (640, 540)
    return (span(sw, 0.36, 640, 760), span(sh, 0.62, 540, 700))


def chooser_size() -> tuple[int, int]:
    """The wizard hub: a picker, not a page. Same task-dialog scale."""
    sw, sh = screen_size()
    if not sw or not sh:
        return (600, 460)
    return (span(sw, 0.34, 600, 680), span(sh, 0.56, 460, 640))


def popup_size() -> tuple[int, int]:
    """Ask/confirm popups (the 560px family): a card, height from content.

    The old fixed 560 was a 4K screen's postage stamp and fine on a
    laptop, so it takes a share of the panel with the same floors; the
    height stays content-driven."""
    sw, sh = screen_size()
    if not sw or not sh:
        return (560, -1)
    return (span(sw, 0.30, 520, 640), -1)


def dialog_size() -> tuple[int, int]:
    """Reading dialogs that show a real page of information: the answers
    backlog, the findings list, an engine detail. Same share of the
    screen as the wizard's taller sibling; never wider than needed."""
    sw, sh = screen_size()
    if not sw or not sh:
        return (760, 540)
    return (span(sw, 0.40, 660, 980), span(sh, 0.58, 540, 720))


def fit_window(w: int, h: int, sw: int, sh: int) -> tuple[int, int]:
    """Hard clamp any size against the screen it opens on.

    The last word belongs to the panel, whatever else wants to be wider:
    nothing greywatch opens may stick out of the screen, and no width ever
    needs to exceed the 4K ceiling even on a huge monitor. On a screen
    without geometry (test lane) the size is returned untouched."""
    if sw <= 0 or sh <= 0:
        return (w, h)
    return (max(1, min(w, sw - FRAME_W, WINDOW_MAX_W)),
            max(1, min(h, sh - FRAME_H, WINDOW_MAX_H)))


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
