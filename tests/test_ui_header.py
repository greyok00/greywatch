"""Pins for the header status as a navigator (task 18).

The header used to be a passive label, so a "scanning" message could not
take the owner to the controls that own the job. It is a button now: it
names the job and the percent while one runs, and opens the owning
surface on a click. Idle is insensitive so it can never look clickable
with nowhere to go. The same pass makes a disabled control unmistakable
and gives Appearance two checked voices.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


def _app() -> Gtk.Application:
    return Gtk.Application(application_id="org.greywatch.test")


def test_header_status_is_a_button_that_opens_the_scan_surface():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win._update_header_status({
        "state": "running", "key": "clamav-frequent",
        "scanners": {"clamav": {"state": "running", "percent": 0.42}}})
    assert isinstance(win._header_status, Gtk.Button)
    assert "42" in win._header_status.get_label()
    win._header_status.emit("clicked")
    assert win._stack.get_visible_child() is win._pages["Security Center"]


def test_idle_header_is_insensitive_and_does_not_say_scanning():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win._update_header_status({})
    assert not win._header_status.get_sensitive()
    assert "SCANNING" not in win._header_status.get_label().upper()


def test_disabled_buttons_are_visually_distinct():
    from ui import themes
    css = themes.gtk_css(themes.load_themes()["graphite"])
    assert "button:disabled" in css
    assert "opacity: 0.38" in css


def test_header_is_sensitive_only_while_a_job_runs():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win._update_header_status({"state": "running", "key": "lynis",
                               "scanners": {}})
    assert win._header_status.get_sensitive()
    win._update_header_status({})
    assert not win._header_status.get_sensitive()


def test_rkhunter_job_opens_the_rootkit_desk():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win.scan_monitor.live = {"key": "rkhunter"}
    win._update_header_status({"state": "running", "key": "rkhunter",
                               "scanners": {}})
    win._header_status.emit("clicked")
    assert "Rootkit" in win._page_modules
    assert win._stack.get_visible_child() is win._pages["Rootkit"]


def test_header_percent_speaks_for_the_running_row_not_a_done_one():
    # clamav finished at 100 percent and is inserted first; lynis is the
    # job still working. The header must not read 100 percent.
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win._update_header_status({
        "state": "running", "key": "lynis",
        "scanners": {
            "clamav": {"state": "done", "percent": 1.0},
            "lynis": {"state": "running", "percent": 0.2},
        }})
    label = win._header_status.get_label()
    assert "20%" in label
    assert "100%" not in label


def test_running_row_without_a_percent_never_borrows_a_done_rows_100():
    # rkhunter carries no total, so its percent is None for the whole
    # run. The finished clamav row must not stand in for it.
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win._update_header_status({
        "state": "running", "key": "rkhunter",
        "scanners": {
            "clamav": {"state": "done", "percent": 1.0},
            "rkhunter": {"state": "running", "percent": None},
        }})
    label = win._header_status.get_label()
    assert label.upper().startswith("SCANNING")
    assert "100" not in label


def test_a_done_row_never_outbids_the_running_rows_percent():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win._update_header_status({
        "state": "running", "key": "clamav",
        "scanners": {
            "clamav": {"state": "running", "percent": 0.42},
            "rkhunter": {"state": "done", "percent": 1.0},
        }})
    assert "42" in win._header_status.get_label()


def test_disabled_hover_and_header_status_rules_are_in_the_sheet():
    from ui import themes
    css = themes.gtk_css(themes.load_themes()["graphite"])
    assert "button:disabled:hover" in css
    assert "button.gw-quiet:disabled:hover" in css
    assert "button.gw-secondary:disabled:hover" in css
    assert ".gw-header-status:disabled" in css
    assert "opacity: 0.85" in css
