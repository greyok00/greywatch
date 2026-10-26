"""netwatch.py — the in-daemon light IDS (master prompt Pass 3, D6).

The suite's OWN analyzer over events it ALREADY has — no new packet mirror,
no redundancy with ufw (owner rule). Lanes:

1. PORT-SCAN: ufw BLOCK lines — one source IP touching ≥8 DISTINCT ports
   inside 60 s ⇒ HIGH event, then a 5-minute cooldown per source.
2. CONNECTION BURST: appfw metadata — a program hitting ≥30 distinct
   remote destinations inside 60 s ⇒ MEDIUM event (beacon/scan-like).
3. BLOCKED-CLUSTER: ≥5 appfw denials against one host inside 300 s ⇒
   MEDIUM event (concentrated target behavior).

State is bounded per key; emission goes through the daemon's mirror
callback (never blocks the loop, never raises).
"""
from __future__ import annotations

import collections
import re
import time

SCAN_WINDOW = 60.0
SCAN_PORTS = 8
SCAN_COOLDOWN = 300.0

BURST_WINDOW = 60.0
BURST_CONNS = 30
BURST_COOLDOWN = 300.0

CLUSTER_WINDOW = 300.0
CLUSTER_DENIES = 5
CLUSTER_COOLDOWN = 600.0

_UFW_SRC = re.compile(r"SRC=([\d.]+)")
_UFW_DPT = re.compile(r"DPT=(\d+)")
_APPFW_LINE = re.compile(r"appfw (\S+) → ([^\s:]+):\d+ (allow|deny)\b")

MAX_KEYS = 500               # bounded: newest keys win, evicted beyond


class NetWatch:
    def __init__(self, emit):
        self._emit = emit
        self._scans: dict[str, tuple[set, float]] = {}
        self._bursts: dict[str, tuple[set, float]] = {}
        self._deny_hits: dict[str, collections.deque] = collections.defaultdict(
            collections.deque)
        self._last_scan: dict[str, float] = {}
        self._last_burst: dict[str, float] = {}
        self._last_cluster: dict[str, float] = {}

    # ── entry point ──────────────────────────────────────────────────────
    def ingest(self, ev) -> None:
        try:
            tool = getattr(ev, "from_tool", None)
            text = getattr(ev, "text", None)
            if tool == "ufw" and "BLOCK" in text:
                self._ufw_block(text)
            elif tool == "appfw":
                self._appfw(text)
        except Exception:
            pass                    # an analyzer must never break a tool

    def _bound(self, table, now) -> None:
        """Bounded keys: oldest evicted beyond MAX_KEYS."""
        if len(table) > MAX_KEYS:
            oldest = sorted(table, key=lambda k: table[k][1] if
                            isinstance(table[k], tuple) else 0)[:100]
            for k in oldest:
                table.pop(k, None)

    # ── lane 1: port scan ────────────────────────────────────────────────
    def _ufw_block(self, text: str) -> None:
        s = _UFW_SRC.search(text)
        d = _UFW_DPT.search(text)
        if not s or not d:
            return
        src, dpt = s.group(1), d.group(1)
        now = time.monotonic()
        entry = self._scans.get(src)
        if entry is None or now - entry[1] > SCAN_WINDOW:
            entry = (set(), now)
            self._scans[src] = entry
        entry[0].add(dpt)
        self._bound(self._scans, now)
        if len(entry[0]) >= SCAN_PORTS:
            if now - self._last_scan.get(src, -1e12) > SCAN_COOLDOWN:
                self._last_scan[src] = now
                self._emit("HIGH", f"netwatch: port scan from {src} "
                           f"({len(entry[0])} distinct ports in "
                           f"{SCAN_WINDOW:.0f} s)")

    # ── lane 2: connection burst ─────────────────────────────────────────
    def _appfw(self, text: str) -> None:
        m = _APPFW_LINE.search(text)
        now = time.monotonic()
        if m:
            app, dst = m.group(1), m.group(2)
            entry = self._bursts.get(app)
            if entry is None or now - entry[1] > BURST_WINDOW:
                entry = ({dst}, now)
                self._bursts[app] = entry
            entry[0].add(dst)
            self._bound(self._bursts, now)
            if len(entry[0]) >= BURST_CONNS:
                if now - self._last_burst.get(app, -1e12) > BURST_COOLDOWN:
                    self._last_burst[app] = now
                    self._emit("MEDIUM", f"netwatch: connection burst by "
                               f"{app} ({len(entry[0])} distinct "
                               f"destinations in {BURST_WINDOW:.0f} s)")
        # ── lane 3: denial cluster vs one host ───────────────────────────
        m2 = re.search(r"deny \[.*?blocked by the downloaded list: (\S+)\]",
                       text)
        if not m2:
            m2 = re.search(r"deny \[.*?: (\S+)\]", text)
        if not m2:
            return
        host = m2.group(1)
        hits = self._deny_hits[host]
        hits.append(now)
        while hits and now - hits[0] > CLUSTER_WINDOW:
            hits.popleft()
        if len(hits) >= CLUSTER_DENIES:
            if now - self._last_cluster.get(host, -1e12) > CLUSTER_COOLDOWN:
                self._last_cluster[host] = now
                self._emit("MEDIUM", f"netwatch: {len(hits)} denied attempts "
                           f"against {host} in {CLUSTER_WINDOW:.0f} s")
