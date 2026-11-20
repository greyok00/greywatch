"""Pins for the shared job panel: one chart, one status line, and the
three controls on the same surface. A cancelled job keeps the fraction
it reached; it never paints a full bar."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import charts
from ui.jobpanel import JobPanel


def _panel():
    calls = []
    return JobPanel("Antivirus", lambda: calls.append("pause"),
                    lambda: calls.append("resume"),
                    lambda: calls.append("cancel")), calls


def test_panel_has_a_chart_and_a_status_area():
    panel, _ = _panel()
    assert isinstance(panel.chart, Gtk.DrawingArea)
    assert isinstance(panel.status, Gtk.Label)
    assert panel.status.get_wrap()


def test_running_state_enables_pause_and_cancel_only():
    panel, _ = _panel()
    panel.update("running", 0.42, 90, "Scanning /home/grey/a.bin")
    assert "42" in panel.status.get_text()
    assert panel.pause.get_sensitive()
    assert not panel.resume.get_sensitive()
    assert panel.cancel.get_sensitive()


def test_paused_state_enables_resume():
    panel, _ = _panel()
    panel.update("paused", 0.42, 90, "Paused at 42 percent")
    assert panel.resume.get_sensitive()
    assert not panel.pause.get_sensitive()


def test_cancelled_state_keeps_the_fraction_and_does_not_read_full():
    panel, _ = _panel()
    panel.update("cancelled", 0.06, 120, "Cancelled by you")
    assert "6" in panel.status.get_text()
    assert not panel.pause.get_sensitive()
    assert not panel.cancel.get_sensitive()


def test_indeterminate_job_says_it_is_working():
    panel, _ = _panel()
    panel.update("running", None, 30, "Working")
    assert "working" in panel.status.get_text().lower()


def test_indeterminate_chart_reports_unknown_and_keeps_none_points():
    area = charts.progress_chart()
    area.set_history([(0.0, None), (30.0, None)], indeterminate=True)
    assert area._gw_state["indeterminate"] is True
    assert area._gw_state["points"] == [(0.0, None), (30.0, None)]
    assert all(value is None for _elapsed, value in
               area._gw_state["points"])
    # a determinate update clears the flag; the panel forwards both
    area.set_history([(0.0, 0.4)], indeterminate=False)
    assert area._gw_state["indeterminate"] is False
    panel, _ = _panel()
    panel.update("running", None, 30, "Working")
    assert panel.chart._gw_state["indeterminate"] is True
