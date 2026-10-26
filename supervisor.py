"""supervisor.py — supervised components + circuit breakers (P0-e).

Every background component (the appfw engine, each collector tailer) is a
supervised unit: liveness checked every daemon cycle (0.5 s ⇒ ≤10 s detect,
per the master prompt), dead components restarted autonomously, a breaker
trips after 3 failures inside 60 s (component parked, surfaced honestly in
status.json — never fake-green), and the breaker resets after a quiet
period. No subprocess per component: the master prompt allows "isolated
subprocesses OR supervised threads with circuit breakers"; threads keep the
inotify fd semantics intact.
"""
from __future__ import annotations

import threading
import time


class Supervised:
    """One supervised component.

    latched_target=True  (default): target() is a long-lived loop running in
    the supervisor's thread; death of that thread = component down.

    latched_target=False: target() is a launcher that returns quickly (it
    spawns the real worker itself); liveness is decided by health() alone
    and restart re-runs the launcher inline.
    """

    def __init__(self, name, target, health=None, breaker_max=3,
                 breaker_window=60.0, quiet_reset=300.0,
                 latched_target: bool = True):
        self.name = name
        self.target = target
        self._health = health or (lambda: True)
        self.breaker_max = breaker_max
        self.breaker_window = breaker_window
        self.quiet_reset = quiet_reset
        self.latched_target = latched_target
        self.thread = None
        self.failures: list[float] = []
        self.tripped = False
        self.last_start = time.monotonic()   # registered = started now
        self.restarts = 0
        self._lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────
    def start(self) -> None:
        self.thread = threading.Thread(target=self._wrapped, daemon=True,
                                       name=f"sup-{self.name}")
        self.thread.start()
        self.last_start = time.monotonic()

    def _wrapped(self) -> None:
        try:
            self.target()
        except BaseException:
            pass                      # the supervisor sees death via health
        finally:
            self._mark_failure()

    def _mark_failure(self) -> None:
        with self._lock:
            now = time.monotonic()
            self.failures.append(now)
            self.failures = [t for t in self.failures
                             if now - t < self.breaker_window]
            if len(self.failures) >= self.breaker_max:
                self.tripped = True

    # ── supervision (called every daemon cycle) ──────────────────────────
    def supervise(self) -> str:
        """Returns the state string; restarts when dead; parks when tripped.
        Never raises — a supervisor must survive its own components. An
        untrip FALLS THROUGH to the live/restart logic in the same call
        (healing restarts happen on the cycle the quiet period ends)."""
        try:
            with self._lock:
                if self.tripped:
                    now = time.monotonic()
                    if self.failures and now - self.failures[-1] \
                            > self.quiet_reset:
                        self.tripped = False      # quiet long enough: retry
                        self.failures = []
                    else:
                        return "tripped"
            if self.latched_target:
                alive = self.thread is not None and self.thread.is_alive() \
                    and bool(self._health())
                if not alive and time.monotonic() - self.last_start > 2.0:
                    # allow 2 s of startup before declaring death
                    self.start()
                    self.restarts += 1
                    return "restarted"
                return "running" if alive else "starting"
            # delegated launcher: the real worker runs its own thread
            if not bool(self._health()) \
                    and time.monotonic() - self.last_start > 2.0:
                try:
                    self.target()                 # the launcher itself
                except Exception:
                    self._mark_failure()
                self.restarts += 1
                self.last_start = time.monotonic()
                return "restarted"
            return "running"
        except Exception:
            return "supervisor-error"


class Supervisor:
    """All components, one check (called each daemon cycle — ≤10 s detect
    given the 0.5 s loop)."""

    def __init__(self):
        self.units: dict[str, Supervised] = {}
        self._lock = threading.Lock()

    def register(self, name, target, health=None, **kw) -> Supervised:
        unit = Supervised(name, target, health=health, **kw)
        with self._lock:
            self.units[name] = unit
        return unit

    def start_all(self) -> None:
        with self._lock:
            units = list(self.units.values())
        for unit in units:
            unit.start()

    def check_all(self) -> dict:
        with self._lock:
            units = list(self.units.items())
        states = {}
        for name, unit in units:
            states[name] = unit.supervise()
        return states

    def snapshot(self) -> dict:
        with self._lock:
            units = dict(self.units)
        out = {}
        for name, unit in units.items():
            out[name] = {"state": (unit.supervise() if not unit.tripped
                                   else "tripped"),
                         "restarts": unit.restarts}
        return out