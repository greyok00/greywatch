"""The GreyWatch charts layer: the canvas widgets the screens draw
their evidence with. A sparkline, bar columns, a labelled donut, the
posture ring gauge, and the hour-of-day x day-of-week density grid for
event stamps. Two laws hold everything here together:

  - charts never read files; the pages pass plain series in, so every
    number on the screen stays the page's own provenance problem;
  - an empty series draws the quiet track and nothing else: a chart
    refuses to invent data.
"""

from __future__ import annotations

import datetime

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import themes


def _colour(name, fallback):
    from ui.themes import _hex_rgba
    return _hex_rgba(themes.CURRENT.get(name, fallback))


def _mark_area(area) -> None:
    area.add_css_class("gw-chart")


def sparkline(series, w: int = 240, h: int = 52,
              filled: bool = True) -> Gtk.DrawingArea:
    area = Gtk.DrawingArea()
    area.set_size_request(w, h)
    area.set_hexpand(True)
    _mark_area(area)
    data = [v for v in (series or []) if isinstance(v, (int, float))]

    def _draw(_a, cr, width, height):
        track = _colour("line", "#2e323b")
        ink = _colour("accent", "#b5b3ab")
        pad = 4.0
        cr.set_line_width(1.2)
        cr.set_source_rgba(*track)
        cr.rectangle(pad, height / 2, width - 2 * pad, 1)
        cr.fill()
        if not data:
            return
        top = max(data) or 1.0
        n = len(data)
        step = (width - 2 * pad) / max(1, n - 1)
        pts = []
        for i, v in enumerate(data):
            x = pad + i * step
            y = height - pad - (height - 2 * pad) * (v / top)
            pts.append((x, y))
        if filled and n > 1:
            cr.set_source_rgba(*ink[:3], 0.25)   # _hex_rgba carries alpha
            cr.move_to(pad, height - pad)
            for x, y in pts:
                cr.line_to(x, y)
            cr.line_to(pts[-1][0], height - pad)
            cr.close_path()
            cr.fill()
        cr.set_line_width(2.0)
        cr.set_source_rgba(*ink[:3], 0.95)
        cr.move_to(*pts[0])
        for x, y in pts[1:]:
            cr.line_to(x, y)
        cr.stroke()

    area.set_draw_func(_draw)
    return area


def bars(series, w: int = 240, h: int = 64) -> Gtk.DrawingArea:
    area = Gtk.DrawingArea()
    area.set_size_request(w, h)
    _mark_area(area)
    data = [v for v in (series or []) if isinstance(v, (int, float))]

    def _draw(_a, cr, width, height):
        track = _colour("line", "#2e323b")
        ink = _colour("accent", "#b5b3ab")
        pad = 3.0
        n = len(data)
        slot = (width - 2 * pad) / max(1, len(data) or 1)
        top = max(data) or 1.0
        for i, v in enumerate(data):
            x = pad + i * slot + slot * 0.15
            bw = slot * 0.7
            bh = (h - 2 * pad) * (v / top)
            y = h - pad - bh
            cr.set_source_rgba(*track)
            cr.rectangle(x, pad, bw, max(1.0, h - 2 * pad))
            cr.fill()
            cr.set_source_rgba(*ink)
            cr.rectangle(x, y, bw, max(1.5, bh))
            cr.fill()
        if not n:
            cr.set_source_rgba(*track)
            cr.rectangle(pad, h / 2, width - 2 * pad, 2)
            cr.fill()

    area.set_draw_func(_draw)
    return area


def progress_chart(w: int = 640, h: int = 140) -> Gtk.DrawingArea:
    """The job progress line: quarter tracks behind, the reached
    fraction filled under the curve. The page feeds (elapsed, fraction)
    pairs. When the job cannot report a total the chart switches to a
    hatched band and plots no series at all: a point whose fraction is
    None is never drawn as zero, because that would invent a number."""
    area = Gtk.DrawingArea()
    area.set_size_request(w, h)
    area.set_hexpand(True)
    _mark_area(area)
    state = {"points": [], "indeterminate": False}
    area._gw_state = {"points": [], "indeterminate": False}

    def _band(cr, ink, width, height, pad):
        """The indeterminate mark: a hatched band across the full width,
        carrying no fraction from left to right."""
        band_h = max(16.0, (height - 2 * pad) * 0.16)
        top = (height - band_h) / 2
        left, right = pad, width - pad
        cr.save()
        cr.rectangle(left, top, right - left, band_h)
        cr.clip()
        cr.set_source_rgba(*ink[:3], 0.10)
        cr.rectangle(left, top, right - left, band_h)
        cr.fill()
        cr.set_line_width(2.0)
        cr.set_source_rgba(*ink[:3], 0.55)
        x = left - band_h
        while x < right:
            cr.move_to(x, top + band_h)
            cr.line_to(x + band_h, top)
            cr.stroke()
            x += 16.0
        cr.restore()

    def draw(_a, cr, width, height):
        track = _colour("line", "#2e323b")
        ink = _colour("accent", "#b5b3ab")
        pad = 8.0
        cr.set_line_width(1.0)
        cr.set_source_rgba(*track)
        for frac in (0.25, 0.5, 0.75):
            y = height - pad - (height - 2 * pad) * frac
            cr.move_to(pad, y)
            cr.line_to(width - pad, y)
            cr.stroke()
        if state["indeterminate"]:
            _band(cr, ink, width, height, pad)
            return
        points = [(elapsed, value) for elapsed, value in
                  state["points"][-240:] if value is not None]
        if not points:
            return
        step = (width - 2 * pad) / max(1, len(points) - 1)
        pts = []
        for i, (_elapsed, value) in enumerate(points):
            v = max(0.0, min(1.0, value))
            pts.append((pad + i * step,
                        height - pad - (height - 2 * pad) * v))
        cr.set_source_rgba(*ink[:3], 0.22)
        cr.move_to(pad, height - pad)
        for x, y in pts:
            cr.line_to(x, y)
        cr.line_to(pts[-1][0], height - pad)
        cr.close_path()
        cr.fill()
        cr.set_line_width(2.0)
        cr.set_source_rgba(*ink[:3], 0.95)
        cr.move_to(*pts[0])
        for x, y in pts[1:]:
            cr.line_to(x, y)
        cr.stroke()

    def set_history(points, indeterminate=False):
        state["points"] = list(points or [])
        state["indeterminate"] = bool(indeterminate)
        area._gw_state = {"points": list(state["points"]),
                          "indeterminate": state["indeterminate"]}
        area.queue_draw()

    area.set_draw_func(draw)
    area.set_history = set_history
    return area


def donut(parts, size: int = 140) -> tuple:
    """A labelled share ring: parts = [(label, value, colour-key), ...].
    Returns the DrawingArea plus a legend box."""
    drawing = Gtk.DrawingArea()
    drawing.set_size_request(size, size)
    _mark_area(drawing)
    clean = [(str(l), float(v), k) for l, v, k in (parts or [])]
    total = sum(v for _l, v, _k in clean) or 1.0

    def _draw(_a, cr, width, height):
        import math
        cx, cy = width / 2, height / 2
        r_outer = min(width, height) / 2 - 6
        r_inner = r_outer * 0.62
        if not clean:
            cr.set_source_rgba(*_colour("line", "#2e323b"))
            cr.set_line_width(r_outer - r_inner)
            cr.arc(cx, cy, (r_outer + r_inner) / 2, 0, 2 * math.pi)
            cr.stroke()
            return
        start = -math.pi / 2
        colmap = {"ok": "ok", "warn": "warn", "fail": "fail",
                  "accent": "accent", "info": "info"}
        for level, (label, value, key) in enumerate(clean):
            span = 2 * math.pi * (value / total)
            colour = _colour(colmap.get(key, "accent"), "#b5b3ab")
            cr.set_source_rgba(*colour)
            cr.move_to(cx, cy)
            cr.arc(cx, cy, r_outer, start, start + span - 0.01)
            cr.arc_negative(cx, cy, r_inner,
                            start + span - 0.01, start)
            cr.close_path()
            cr.fill()
            start += span

    drawing.set_draw_func(_draw)
    legend = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    for label, value, key in clean:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        text = Gtk.Label(label=f"{label}  {int(value)}")
        text.set_xalign(0.0)
        row.append(text)
        legend.append(row)
    return drawing, legend


def heatmap_cells(stamps) -> list:
    """The hour-of-day (24) x day-of-week (7) density grid behind the
    heatmap widget. Monday = 0; bad stamps are ignored, never counted."""
    grid = [[0] * 7 for _ in range(24)]
    for stamp in stamps or []:
        try:
            when = datetime.datetime.fromisoformat(str(stamp))
        except (ValueError, TypeError):
            continue
        try:
            d = when.weekday()
            grid[when.hour][d] += 1
        except (IndexError, AttributeError):
            continue
    return grid


def heatmap(stamps, w: int = 320, h: int = 90,
            title: str = "") -> tuple:
    """The density grid widget: a cairo grid of the hour x day counts,
    with the weekday letters on the side. Returns (widget, grid)."""
    grid = heatmap_cells(stamps)
    peak = max((v for row in grid for v in row), default=0) or 1
    area = Gtk.DrawingArea()
    area.set_size_request(w, h)
    _mark_area(area)

    def _draw(_a, cr, width, height):
        track = _colour("line", "#2e323b")
        cold = _colour("accent", "#b5b3ab")
        hot = _colour("fail", "#d05f5f")
        ox, oy = 22.0, 4.0
        cw = (width - ox - 4) / 24.0
        ch = (height - oy - 14) / 7.0
        for hour in range(24):
            for day in range(7):
                v = grid[hour][day]
                if not v:
                    cr.set_source_rgba(*track[:3], 0.55)
                else:
                    f = min(1.0, v / peak) ** 0.7
                    r = cold[0] + (hot[0] - cold[0]) * f
                    g = cold[1] + (hot[1] - cold[1]) * f
                    b = cold[2] + (hot[2] - cold[2]) * f
                    cr.set_source_rgba(r, g, b, 0.55 + 0.45 * f)
                cr.rectangle(ox + hour * cw, oy + day * ch,
                             cw - 1.4, ch - 1.4)
                cr.fill()
        cr.set_source_rgba(*_colour("mute", "#8b8a84"))
        layout = _a.create_pango_layout("")
        layout.set_markup("<span font_size='7000'>Mon</span>", -1)
        tw, th = layout.get_pixel_size()
        cr.move_to(0, oy + 0.5 * ch - th / 2)
        from gi.repository import PangoCairo
        PangoCairo.show_layout(cr, layout)
        layout2 = _a.create_pango_layout("")
        layout2.set_markup("<span font_size='7000'>Sun</span>", -1)
        tw, th = layout2.get_pixel_size()
        cr.move_to(0, oy + 6.5 * ch - th / 2)
        PangoCairo.show_layout(cr, layout2)
        for hour in (0, 6, 12, 18):
            cr.move_to(ox + hour * cw, height - 12)
            layout3 = _a.create_pango_layout("")
            layout3.set_markup(
                f"<span font_size='7000'>{hour:02d}</span>", -1)
            PangoCairo.show_layout(cr, layout3)

    area.set_draw_func(_draw)
    return area, grid


def ring_gauge(score, size: int = 196) -> Gtk.DrawingArea:
    """The posture ring: the track is the line colour, the value arc
    takes the level colour, the number or the withheld reason sits in
    the middle."""
    area = Gtk.DrawingArea()
    area.set_size_request(size, size)
    _mark_area(area)

    def _draw(_a, cr, w, h) -> None:
        import math
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 14
        track = _colour("line", "#2e323b")
        ok = _colour("ok", "#5fae7e")
        warn = _colour("warn", "#d9a34a")
        fail = _colour("fail", "#d05f5f")
        ink = _colour("ink", "#e9e7e2")
        mute = _colour("mute", "#8b8a84")

        cr.set_line_width(14)
        cr.set_source_rgba(*track)
        cr.arc(cx, cy, r, 0, 2 * math.pi)
        cr.stroke()

        if score is not None:
            colour = ok if score >= 80 else (
                warn if score >= 60 else fail)
            start = -math.pi / 2
            end = start + 2 * math.pi * max(0.01, min(1.0, score / 100))
            cr.set_source_rgba(*colour)
            cr.arc(cx, cy, r, start, end)
            cr.stroke()

        layout = _a.create_pango_layout("")
        text = "" if score is None else str(score)
        layout.set_markup(
            f"<span font_family='Inter' font_size='36000' "
            f"weight='ultrabold'>{text}</span>", -1)
        tw, th = layout.get_pixel_size()
        cr.set_source_rgba(*(ink if score is not None else mute))
        cr.move_to(cx - tw / 2, cy - th / 2)
        from gi.repository import PangoCairo
        PangoCairo.show_layout(cr, layout)

        if score is None:
            note = _a.create_pango_layout("")
            note.set_markup(
                "<span font_family='Inter' font_size='9000'>run as root"
                " for the score</span>")
            note.set_width(int(w) * 950)
            nw, nh = note.get_pixel_size()
            cr.set_source_rgba(*mute)
            cr.move_to(cx - nw / 2, cy + th / 2 + 6)
            PangoCairo.show_layout(cr, note)

    area.set_draw_func(_draw)
    return area
