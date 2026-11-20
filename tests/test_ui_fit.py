"""The fluid fit: the page fills the window at every width.

The old fit beat pinned every page to a fixed measure and centred it,
which at 4K left a narrow column off centre and body lines running too
long. These pins hold the new law: the page takes the width it is given,
the Security cards reflow to three columns at 2400 and above, and prose
keeps a readable measure.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


def _app() -> Gtk.Application:
    return Gtk.Application(application_id="org.greywatch.test")


def test_grid_uses_three_columns_at_4k():
    from ui import security
    assert security._grid_columns(1280) == 2
    assert security._grid_columns(2399) == 2
    assert security._grid_columns(2400) == 3


def test_prose_labels_cap_their_measure():
    from ui import widgets
    sub = widgets.sub("x" * 200)
    meta = widgets.meta("x" * 200)
    assert sub.get_max_width_chars() == 90
    assert meta.get_max_width_chars() == 90
    # the natural cap is only real when the allocation stops at it: a
    # FILL label in a card is handed the whole card width
    assert sub.get_halign() != Gtk.Align.FILL
    assert meta.get_halign() != Gtk.Align.FILL


def test_relayout_fills_the_grid_at_three_columns():
    from ui import security

    class _Shell:
        def has_page(self, label):
            return False

        def note(self, text):
            pass

    scroll = security.build(_Shell())
    body = scroll._gw_body
    security._relayout(body, 3840)
    grid = body._gw_grid
    assert body._gw_columns == 3
    # the first row holds three cards and the last row starts at column
    # zero; the updates card spans the two cells beside integrity
    assert grid.get_child_at(0, 0) is not None
    assert grid.get_child_at(1, 1) is not None
    assert grid.get_child_at(1, 1) is grid.get_child_at(2, 1)
    assert grid.get_child_at(0, 2) is None


def test_install_result_reaches_the_rebuilt_card(monkeypatch):
    import threading
    import time

    from gi.repository import GLib

    from ui import security

    started = threading.Event()
    release = threading.Event()

    def fake_call(*_args, **_kwargs):
        started.set()
        release.wait(5)
        return 0, "done: all updates installed", ""

    monkeypatch.setattr(security.cliapi, "call", fake_call)
    page = Gtk.Box()
    security.updates_card(None, page)
    first = page._gw_slots["updates"]
    security._patch_run(page, first["button"], first["status"],
                        ["--affected"], "Patch affected packages",
                        "Patching...")
    assert started.wait(5), "the patch worker never started"
    assert page._gw_patching is True
    assert first["button"].get_label() == "Patching..."

    # a reflow or rebuild while the worker runs makes fresh widgets,
    # stuck in flight until the completion reaches them
    security.updates_card(None, page)
    live = page._gw_slots["updates"]
    assert live["button"] is not first["button"]
    assert live["button"].get_label() == "Patching..."
    assert not live["button"].get_sensitive()

    release.set()
    ctx = GLib.main_context_default()
    deadline = time.time() + 5
    while not live["button"].get_sensitive() and time.time() < deadline:
        ctx.iteration(False)
        time.sleep(0.01)

    assert page._gw_patching is False
    assert live["button"].get_sensitive()
    assert live["button"].get_label() == "Patch affected packages"
    assert live["status"].get_text() == "done: all updates installed"


def test_table_marks_its_last_column_expand():
    from ui import kit
    scroll, _store = kit.table(columns=(("Tool", 120), ("State", 80),
                                        ("Note", 120)))
    tree = scroll.get_child()
    columns = tree.get_columns()
    assert columns[-1].get_expand()
    assert not columns[0].get_expand()


def test_fit_beat_does_not_pin_a_page_width():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    # a built page is what the law is about: an empty window holds none
    win.show_page("Security Center")
    win._fit_beat()
    assert win._page_widgets, "the Security Center page must be built"
    for page in win._page_widgets.values():
        assert page.get_size_request()[0] == -1
        assert page.get_halign() != Gtk.Align.CENTER
