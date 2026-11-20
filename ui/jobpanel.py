"""The one job panel: a full-width progress chart, the status text
under it, and the three controls on the same surface. Every progress
screen builds this instead of drawing its own bar, so a job looks the
same wherever it runs."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import actions, charts, labels
from ui.widgets import state_pill


class JobPanel(Gtk.Box):
    def __init__(self, title, on_pause, on_resume, on_cancel):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self._title = str(title or "Job")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        name = Gtk.Label(label=title)
        name.add_css_class("gw-eyebrow")
        name.set_xalign(0.0)
        name.set_hexpand(True)
        head.append(name)
        self.pill = state_pill("Idle", "mute")
        head.append(self.pill)
        self.pause = actions.action_button("Pause", on_pause,
                                           cls="gw-quiet")
        self.resume = actions.action_button("Resume", on_resume,
                                            cls="gw-quiet")
        self.cancel = actions.action_button("Cancel", on_cancel,
                                            cls="gw-quiet")
        for button in (self.pause, self.resume, self.cancel):
            head.append(button)
        self.append(head)
        self.chart = charts.progress_chart()
        self.append(self.chart)
        self.status = Gtk.Label(label="No job on file.")
        self.status.add_css_class("gw-job-status")
        self.status.set_xalign(0.0)
        self.status.set_wrap(True)
        self.status.set_max_width_chars(90)
        self.append(self.status)
        self._history = []
        self.set_idle("No job on file.")

    def set_idle(self, text):
        self._history = []
        self.chart.set_history([], indeterminate=False)
        self.status.set_text(text)
        self.pill.set_label("IDLE")
        for name in ("ok", "warn", "fail"):
            self.pill.remove_css_class(f"gw-pill-{name}")
        for button in (self.pause, self.resume, self.cancel):
            button.set_sensitive(False)

    def update(self, state, percent, elapsed_s, text, *, external=False,
               scanner=""):
        state = str(state or "").lower()
        if state in ("", "idle"):
            # An idle document is not a job: no band may hatch and no
            # "working" may be appended (review C3).
            self.set_idle(text or "No job on file.")
            return
        word, level = labels.scan_state(state)
        self.pill.set_label(word.upper())
        for name in ("ok", "warn", "fail"):
            self.pill.remove_css_class(f"gw-pill-{name}")
        if level in ("ok", "warn", "fail"):
            self.pill.add_css_class(f"gw-pill-{level}")
        self._history.append((float(elapsed_s or 0.0), percent))
        self.chart.set_history(self._history, indeterminate=percent is None)
        shown = "working" if percent is None else \
            f"{int(round(float(percent) * 100))} percent"
        # The status area names the job, the scanner, the check or file,
        # and the elapsed time - the one place a job notification lives.
        who = scanner or self._title
        span = labels.span_words(elapsed_s or 0.0)
        self.status.set_text(f"{who}: {text} {shown}. Elapsed {span}.")
        running = state == "running" and not external
        paused = state == "paused" and not external
        self.pause.set_sensitive(running)
        self.resume.set_sensitive(paused)
        # An external scan is not this service's session: Pause and
        # Resume would be a no-op, so only Cancel is offered.
        self.cancel.set_sensitive(external or state in ("running", "paused"))
