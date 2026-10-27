from __future__ import annotations

import threading
import time


class Supervised:

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

    def supervise(self) -> str:
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
                    self.start()
                    self.restarts += 1
                    return "restarted"
                return "running" if alive else "starting"
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
