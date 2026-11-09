"""GW-171 pins: screen-fit sizing + zero modal grabs, at 1080p and 4K.

Owner's rule (2026-11-04): nothing greywatch opens may extend across the
screen, 4K is the limit on max width, every size adapts to 1080p, and no
greywatch window is modal - a modal grab extends across the whole screen
and under marco it answered the dashboard's close clicks at the child.
"""
import os
import pathlib

import ui.metrics as metrics

PANELS = ((1920, 1080), (3840, 2160), (1920, 1200))


def _with_screen(sw, sh, fn):
    saved = metrics.screen_size
    metrics.screen_size = lambda: (sw, sh)
    try:
        return fn()
    finally:
        metrics.screen_size = saved


def test_fit_window_never_exceeds_a_1080p_screen():
    assert metrics.fit_window(5000, 3000, 1920, 1080) == (1880, 1020), \
        "the clamp has the last word on the panel"


def test_fit_window_four_k_is_the_width_ceiling():
    assert metrics.fit_window(5000, 3000, 3840, 2160) == (2400, 1600), \
        "no width past the 4K ceiling whatever the panel is"


def test_fit_window_leaves_the_displayless_lane_alone():
    assert metrics.fit_window(700, 480, 0, 0) == (700, 480)


def test_dashboard_fits_every_panel():
    for sw, sh in PANELS:
        w, h = _with_screen(sw, sh, metrics.window_size)
        assert w <= sw - metrics.FRAME_W, f"dashboard fits {sw}x{sh}"
        assert h <= sh - metrics.FRAME_H
        assert 1.59 <= w / h <= 1.79, "16:10..16:9 ratio band held"


def test_wizard_is_far_under_half_the_screen_everywhere():
    for sw, sh in PANELS:
        w, h = _with_screen(sw, sh, metrics.wizard_size)
        assert w * 2 < sw, f"wizard is under half the width of {sw}x{sh}"
        assert h <= sh - metrics.FRAME_H
        assert w >= 640, "reading column floor kept"


def test_chooser_is_a_picker_not_a_page():
    for sw, sh in PANELS:
        w, h = _with_screen(sw, sh, metrics.chooser_size)
        assert w * 2 < sw
        assert h <= sh - 100


def test_sizing_survives_a_displayless_lane():
    saved = metrics.screen_size
    metrics.screen_size = lambda: (0, 0)
    try:
        assert metrics.window_size() == (1140, 640), \
            "16:9 of the floor width when no monitor answers"
        assert metrics.wizard_size() == (640, 540), "task window at floor"
        assert metrics.chooser_size() == (600, 460)
    finally:
        metrics.screen_size = saved


def test_chooser_reopens_fresh_after_a_pick():
    """GW-171 (visual lane): after a pick, the dashboard held the unmapped
    chooser and Setup re-presented a body-destroyed shell - a blank hub
    with no cards. The reopen must build a fresh, populated hub."""
    from gi.repository import GLib as gl
    from ui.window import MainWindow

    win = MainWindow(on_status_change=None, tray_available=False)
    # The 5s periodic and 1s scan timers do full data-dir refreshes, and
    # under box load they ate the pump (load-livelock fix 11-07). The
    # chooser assertions never read timer output - silence them, never
    # mask the assertion (tab_shell precedent).
    for tid in list(getattr(win, "_glib_ids", []) or []):
        try:
            gl.source_remove(tid)
        except RuntimeError:
            pass                    # already fired
    win._glib_ids = []
    ctx = gl.main_context_default()
    try:
        win.present()
        _pump(ctx, 600)
        win._open_wizard()
        _pump(ctx, 600)
        first = win._chooser
        first._picked(None, "baseline")
        _pump(ctx, 900)
        win._open_wizard()
        _pump(ctx, 900)
        second = win._chooser
        assert second is not first, "reopen must build a fresh hub"
        body = list(second.get_content_area().observe_children())
        assert body, "the reopened chooser must have its cards"
        assert second.get_modal() is False
    finally:
        win.destroy()


def _pump(ctx, ms):
    end = gl_monotonic() + ms * 1000
    while gl_monotonic() < end:
        for _ in range(500):         # bounded: a pending storm
            # must never pin the harness (load-livelock fix 11-07)
            if not ctx.pending():
                break
            ctx.iteration(False)
            if gl_monotonic() > end:
                return               # one dispatch may itself run long

        ctx.iteration(True)


def gl_monotonic():
    from gi.repository import GLib as gl
    return gl.get_monotonic_time()



def test_no_modal_grabs_anywhere_in_the_ui():
    root = pathlib.Path(os.path.dirname(__file__)).parent
    paths = list(root.glob("ui/*.py")) + list(root.glob("wizard/*.py"))
    for path in sorted(paths):
        if path.name == "metrics.py":
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        assert "set_modal(True)" not in src, \
            f"{path.name} grabs the screen modally (GW-170/171)"
        assert "modal=True)" not in src, \
            f"{path.name} still passes modal=True (GW-170/171)"
