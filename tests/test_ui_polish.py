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


def test_the_scroll_thumb_is_a_tint_not_a_slab():
    # An opaque 10px band down the page edge read as the "grey overlay" in
    # the 2026-10-30 pass; the thumb is a thin rounded bar in the theme's
    # own hairline tone, and the trough stays clear. (The 2026-10-31 pass
    # raised its alpha from 0.22 to 0.85, which was too faint to find.)
    css = gtk_css(load_themes()["obsidian"])
    assert "background-color: alpha(#55595f, 0.85)" in css
    assert "scrollbar trough { background: transparent;" in css
    assert "min-width: 5px; min-height: 28px; margin: 3px;" in css


def test_css_carries_the_padding_scale():
    css = gtk_css(load_themes()["obsidian"])
    assert "button { padding: 8px 16px;" in css
    assert "padding: 9px 13px;" in css
    assert ".gw-card { padding: 16px; }" in css
    # the winning rule near the end of the sheet, not just the base block
    assert "border-radius: 10px; padding: 16px; box-shadow: none;" in css


def test_the_protection_pill_names_the_service_it_describes():
    # The Security Tools row carries both a service state and the scan's
    # own sentence. A bare "running" beside "Last scan failed" read as a
    # contradiction (owner, 2026-10-31), so the pill carries the noun; the
    # tree and tiles keep the short word.
    from ui.models import service_words, status_words

    assert status_words("GREEN", True, False) == "running"
    assert service_words("GREEN", True, False) == "service running"
    assert service_words("RED", True, False) == "service not running"
    assert service_words("YELLOW", True, False) == "service needs attention"
    assert service_words("YELLOW", False, False) == "not installed"
    assert service_words("GREEN", True, True) == "service paused"
    assert service_words("UNKNOWN", None, False) == "could not check"


def test_a_scan_is_never_called_clean_over_its_own_warning_summary():
    from ui.scanview import card_text

    live = {"scanners": {"rkhunter": {
        "state": "done", "count": 34, "counter_label": "checks completed",
        "findings": 0, "warned": True}}}
    assert card_text("rkhunter", live) == \
        "Last scan done · 34 checks · warnings logged"
    live["scanners"]["rkhunter"]["warned"] = False
    assert card_text("rkhunter", live) == "Last scan done · 34 checks · clean"


def test_every_page_starts_at_the_same_inset():
    # Source-level: no page builder may keep a one-off margin of its own.
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "ui" / "window.py").read_text(encoding="utf-8")
    for stale in ("set_margin_start(34)", "set_margin_end(34)",
                  "set_margin_top(26); box.set_margin_start(30)"):
        assert stale not in src, stale
    assert src.count("metrics.PAGE_X") >= 8
