"""Burst gate for the events funnel (owner 2026-11-12).

A two-minute port-scan storm wrote 19,845 deny lines to events.jsonl
(14,044 in one minute), ground the daemon at 40-50% CPU and grew
malformed.log by the megabyte. The gate keeps the FIRST deny lines per
(tool, host) per window — the human still learns the fact — and counts
the rest; when the window closes it emits ONE honest collapse line
naming the suppressed count. No silent caps: the story is told, at human
scale (the 2026-11-10 no-flood law).

The per-(tool, host) key ALONE is not a cap, which is the same
multiplication hole the desktop bubble cap had: a port scan touches a
DIFFERENT host for every connection, so N hosts x 3 admitted = the storm
still lands. Measured on the live 11-12 ledger, the per-key rule admitted
4,826 of 11,483 rows. There is therefore a GLOBAL window budget beside the
per-key one: the window is the unit the human reads, so it is what gets
bounded, and the per-key share keeps one noisy destination from eating it.
"""
from __future__ import annotations

import datetime as _dt
import json
import re

_DENY_PREFIXES = ("deny ", "blocked ", "headless: deny", "unattributable →")
_HOST_RE = re.compile(r"→\s*([^\s:]+)")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


class BurstGate:
    """Admit the first `max_admit` deny-class events per (tool, host) per
    `window` seconds; count and later collapse the rest. Allow-class and
    HIGH/CRITICAL events are never suppressed."""

    def __init__(self, clock=None, host=None, window: float = 60.0,
                 max_admit: int = 3, suppression: str = "deny",
                 global_admit: int = 60):
        self.clock = clock or _dt.datetime.now().timestamp
        self._host = host or (lambda ev: "unknown")
        self.window = float(window)
        self.max_admit = int(max_admit)
        # The window's total budget across every key. 60/min is ~1 line per
        # second sustained: readable at human scale while still telling the
        # story, and it is what stops a many-destination scan from
        # multiplying the per-key share.
        self.global_admit = int(global_admit)
        self.suppression = suppression   # "deny" class-lane | "all" (malformed)
        self._state: dict[tuple, dict] = {}
        self._global = {"start": None, "admitted": 0, "suppressed": 0,
                        "rolled_at": None}
        self._collapse: list[str] = []

    def _suppressible(self, ev: dict) -> bool:
        if self.suppression == "all":
            return True
        if str(ev.get("severity") or "").upper() in ("HIGH", "CRITICAL"):
            return False
        text = str(ev.get("text") or "").lower()
        return text.startswith(_DENY_PREFIXES)

    def admit(self, ev: dict) -> bool:
        """True = the event proceeds to the queue; False = folded into
        the running suppressed count for its key."""
        if not self._suppressible(ev):
            return True
        key = (str(ev.get("from_tool") or "unknown"), self._host(ev))
        now = self.clock()
        self._roll_global(now)
        st = self._state.get(key)
        if st is not None and now - st["start"] > self.window:
            self._roll(key, st)
            st = None
        if st is None:
            st = self._state[key] = {"start": now, "admitted": 0,
                                     "suppressed": 0}
        if (st["admitted"] < self.max_admit
                and self._global["admitted"] < self.global_admit):
            st["admitted"] += 1
            self._global["admitted"] += 1
            return True
        st["suppressed"] += 1
        self._global["suppressed"] += 1
        return False

    def _roll_global(self, now: float) -> None:
        """Close the window's budget when the window turns over."""
        g = self._global
        if g["start"] is None:
            g["start"] = now
            return
        if now - g["start"] <= self.window:
            return
        if g["suppressed"]:
            # ONE line for the whole window, naming the scale rather than
            # one per destination: the human needs the size, not a row each.
            ev = {"from_tool": "appfw", "severity": "MEDIUM",
                  "text": (f"{g['suppressed']} further deny lines "
                           f"suppressed across the window (burst cap)"),
                  "ts": _now_iso(), "nist_func": "PROTECT",
                  "nist_control": ["AC-3"], "cves": [],
                  "interaction": None}
            self._collapse.append(json.dumps(ev, separators=(",", ":")))
        self._global = {"start": now, "admitted": 0, "suppressed": 0,
                        "rolled_at": now}

    def _roll(self, key, st) -> None:
        # One window, one story. If the global budget ALSO rolled on this
        # same pile, its single line already names the count across the
        # whole window, and a per-key line would count the same rows a
        # second time. A per-key line speaks only when its pile is not
        # already covered by the window line.
        if st["suppressed"] and self._global.get("rolled_at") is None:
            tool, host = key
            ev = {"from_tool": tool, "severity": "MEDIUM",
                  "text": (f"{st['suppressed']} further deny lines "
                           f"suppressed for {host} (burst cap)"),
                  "ts": _now_iso(), "nist_func": "PROTECT",
                  "nist_control": ["AC-3"], "cves": [], "interaction": None}
            self._collapse.append(json.dumps(ev, separators=(",", ":")))
        self._state[key] = {"start": self.clock(), "admitted": 0,
                            "suppressed": 0}

    def drain_collapses(self) -> list[str]:
        """Drain accumulated collapse lines (oldest first)."""
        out, self._collapse = self._collapse, []
        return out

    # tests read the same drain under this historical name
    collapse_lines = drain_collapses


def host_from_text(ev: dict) -> str:
    """Default host extractor: the destination after the arrow glyph."""
    m = _HOST_RE.search(str(ev.get("text") or ""))
    return m.group(1) if m else "unknown"
