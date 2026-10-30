"""Reverse-DNS names with a small on-disk cache.

Lookups run on demand and are cached for a week, so the sites list can show
a real domain name instead of a bare address without asking the network on
every repaint. A failed lookup records an empty name; the caller then shows
the address and says plainly that there is no public name for it.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import subprocess
import threading


def _getent(address: str) -> str:
    try:
        out = subprocess.run(["getent", "hosts", address],
                             capture_output=True, text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    parts = out.split()
    return parts[1].rstrip(".") if len(parts) > 1 else ""


class NameResolver:
    def __init__(self, path, lookup=None, ttl_days=7):
        self.path = pathlib.Path(path)
        self.lookup = lookup or _getent
        self.ttl_days = ttl_days
        self.cache = {}
        self._lock = threading.Lock()
        self.load()

    def load(self):
        try:
            loaded = json.loads(self.path.read_text())
        except (OSError, ValueError):
            loaded = {}
        self.cache = loaded if isinstance(loaded, dict) else {}
        return self

    def save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".new")
            tmp.write_text(json.dumps(self.cache, indent=0))
            tmp.replace(self.path)
        except (OSError, ValueError):
            pass

    def _fresh(self, at: str) -> bool:
        try:
            when = _dt.datetime.fromisoformat(at)
        except (TypeError, ValueError):
            return False
        now = _dt.datetime.now(_dt.timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        return (now - when).days < self.ttl_days

    def name_for(self, address: str) -> str:
        entry = self.cache.get(address)
        if entry and self._fresh(entry.get("at", "")):
            return entry.get("name") or address
        name = self.lookup(address) or ""
        self.remember(address, name)
        return name or address

    def remember(self, address: str, name: str):
        with self._lock:
            self.cache[address] = {
                "name": name,
                "at": _dt.datetime.now(_dt.timezone.utc).isoformat(
                    timespec="seconds")}
            self.save()
