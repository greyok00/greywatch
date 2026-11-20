"""Pins for the GreyWatch charts layer: sparklines, bars, donuts, the
hour-of-day heatmap and the posture ring gauge. Every chart handles an
empty series honestly and never crashes on it."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import charts


def test_sparkline_empty_series_draws_quiet():
    s = charts.sparkline([])          # no data: no crash, still a widget
    assert isinstance(s, Gtk.DrawingArea)
    s2 = charts.sparkline(None)
    assert isinstance(s2, Gtk.DrawingArea)


def test_heatmap_counts_hour_by_day():
    stamps = ["2026-11-15T01:15:00+00:00",
              "2026-11-15T13:45:00+00:00",
              "2026-11-15T13:50:00+00:00",
              "2026-11-14T13:00:00+00:00"]
    grid = charts.heatmap_cells(stamps)
    # the grid is hour-of-day (24) x day-of-week (7); the two 13:00
    # entries on different days land in different day columns
    assert grid[13][6] >= 1          # 2026-11-15 is a Sunday (index 6)
    assert sum(sum(row) for row in grid) == 4


def test_heatmap_ignores_bad_stamps():
    grid = charts.heatmap_cells(["2026-11-15T13:00:00+00:00", "junk",
                                 "", None])
    assert sum(sum(row) for row in grid) == 1


def test_donut_normalizes_parts():
    drawing, legend = charts.donut([("High", 2, "warn")])
    assert isinstance(drawing, Gtk.DrawingArea)
    # one part at 100% is a full ring; the legend names it
    text = _labels(legend)
    assert any("High" in t for t in text)


def test_ring_gauge_builds_with_and_without_score():
    assert isinstance(charts.ring_gauge(72), Gtk.DrawingArea)
    assert isinstance(charts.ring_gauge(None), Gtk.DrawingArea)


def test_bars_builds():
    assert isinstance(charts.bars([1, 2, 3]), Gtk.DrawingArea)
    assert isinstance(charts.bars([]), Gtk.DrawingArea)


def _labels(w) -> list:
    out = []
    c = w.get_first_child() if hasattr(w, "get_first_child") else None
    while c is not None:
        try:
            if c.get_label():
                out.append(c.get_label())
        except AttributeError:
            pass
        out.extend(_labels(c))
        c = c.get_next_sibling()
    return out
