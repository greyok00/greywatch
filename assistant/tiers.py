# assistant/tiers.py
"""The owner-held switch between the assistant's two tiers.

Tier law (owner-HARD, rebuild round 2 task 13): no model load may ever
happen except from the toggle handler. This object IS that guard — it is
the only thing that knows how to start the loader, so window open, page
actions and timers have no road to the model at all. The heuristic tier is
always on; this switch only decides whether the local GPU model is
resident. It stays resident until the owner clicks it off (never unloaded
by idleness), and its disabling step is the only unload in the app.
"""
from __future__ import annotations


class GpuModelToggle:
    """Load once per enable, resident until disabled — nothing else."""

    OFF = "off"
    LOADING = "loading"
    ON = "on"

    def __init__(self, loader=None, unloader=None, on_change=None):
        self._loader = loader
        self._unloader = unloader
        self.on_change = on_change
        self.state = self.OFF
        self.stages = []               # (honest stage name, fraction)
        self.fraction = 0.0
        self.stage_note = ""
        self.note = ""                 # residency note on success
        self.error = ""                # the failure sentence, quoted as given
        self.loads = 0                 # instrumentation: loads through here
        self.unloads = 0

    # -- the handler road ---------------------------------------------------
    def enable(self) -> bool:
        """The toggle's forward click: the only path that may load."""
        if self.state != self.OFF:
            return False
        if self._loader is None:
            self.error = ("the GPU model lane is not wired in this build - "
                          "the assistant answers from its heuristics")
            self._fire()
            return False
        self.state = self.LOADING
        self.fraction = 0.05
        self.loads += 1
        self._fire()
        self._loader(self._stage, self._ready)
        return True

    def disable(self) -> bool:
        """The toggle's off click: the only unload, straight to heuristics."""
        if self.state != self.ON:
            return False
        if self._unloader is not None:
            self._unloader()
        self.unloads += 1
        self.state = self.OFF
        self.fraction = 0.0
        self.stage_note = ""
        self.note = ""
        self._fire()
        return True

    # -- loader callbacks (called on the loader's worker thread) ------------
    def _stage(self, name: str, fraction: float) -> None:
        """One stage COMPLETED. The name and the fraction are honest facts
        about real work, nothing interpolated."""
        if self.state != self.LOADING:
            return
        self.stages.append((str(name), float(fraction)))
        self.stage_note = str(name)
        self.fraction = min(1.0, max(0.0, float(fraction)))
        self._fire()

    def _ready(self, ok: bool, err: str) -> None:
        if self.state != self.LOADING:
            return
        if ok:
            self.state = self.ON
            self.fraction = 1.0
            self.note = str(err or "").strip()
            self.stage_note = ""
        else:
            self.state = self.OFF
            self.fraction = 0.0
            self.stage_note = ""
            self.error = str(err or "").strip() or "the model did not load"
        self._fire()

    # -- the paint the panel reads ------------------------------------------
    def label(self) -> str:
        """The toggle button's label per state. Off loads, on unloads;
        the click is reversible, in the words the button already carries."""
        return {self.OFF: "Enable GPU model",
                self.LOADING: "Loading GPU model…",
                self.ON: "Disable GPU model"}[self.state]

    def line_text(self) -> str:
        """The one muted line beside the toggle: the stage just completed
        while loading, the residency note while on, the error after a
        failed attempt, blank when idle."""
        if self.state == self.LOADING:
            return ("Loaded: " if self.stages else "") + self.stage_note
        if self.state == self.ON:
            return self.note or "The local GPU model is resident."
        return self.error

    def state_line(self) -> tuple:
        """The seam tuple the Settings row and the Help About row read."""
        parts = ["heuristics on - GPU model " + self.state]
        if self.state == self.ON and self.note:
            parts.append(self.note)
        elif self.state == self.OFF and self.error:
            parts.append(self.error)
        return tuple(parts)

    def _fire(self) -> None:
        if self.on_change is not None:
            self.on_change()
