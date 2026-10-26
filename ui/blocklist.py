"""A real, downloadable tracker/malware domain list (owner 2026-10-23:
"it should detect this, download lists and updates, etc. just by clicks").

Source: the widely used StevenBlack hosts list (MIT-style community data).
The raw file is stored in data/blocklist.txt and the domains are matched by
suffix, so subdomains are covered. An explicit TRUST decision in the app
still wins; an explicit BLOCK decision always wins.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re
import urllib.request
from urllib.error import URLError

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "data" / "blocklist.txt"
META = ROOT / "data" / "blocklist-meta.json"
URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

_SKIP = {"localhost", "localhost.localdomain", "broadcast",
         "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters"}
_DOMAIN = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
                     r"[a-z]{2,63}$")


def parse_hosts(text: str) -> set:
    """hosts-file text → the set of real blocked domains."""
    out = set()
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        addr = fields[0]
        if addr not in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            continue
        name = fields[1].lower().rstrip(".")
        if name in _SKIP or not _DOMAIN.match(name):
            continue
        out.add(name)
    return out


class BlockList:
    def __init__(self, path=PATH, meta=META):
        self.path = pathlib.Path(path)
        self.meta_path = pathlib.Path(meta)
        self._mtime = None
        self._set = set()

    def load(self):
        try:
            m = self.path.stat().st_mtime
        except OSError:
            self._mtime, self._set = 0.0, set()
            return self
        if m != self._mtime:
            try:
                self._set = parse_hosts(self.path.read_text(errors="replace"))
            except OSError:
                self._set = set()
            self._mtime = m
        return self

    def count(self) -> int:
        self.load()
        return len(self._set)

    def match(self, host: str) -> bool:
        host = str(host or "").lower().rstrip(".")
        if not host:
            return False
        self.load()
        if host in self._set:
            return True
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in self._set:
                return True
        return False

    def meta(self) -> dict:
        try:
            return json.loads(self.meta_path.read_text())
        except (OSError, ValueError):
            return {}


def download(timeout=90) -> tuple:
    """Fetch the list now. Returns (ok, count, message). Never raises."""
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "greywatch"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(30_000_000)
        text = raw.decode("utf-8", "replace")
        domains = parse_hosts(text)
        if not domains:
            return False, 0, "the download contained no usable entries"
        PATH.parent.mkdir(parents=True, exist_ok=True)
        PATH.write_text(text if text.endswith("\n") else text + "\n")
        info = {"fetched_utc": _dt.datetime.now(
                    _dt.timezone.utc).isoformat(timespec="seconds"),
                "count": len(domains), "source": URL}
        META.write_text(json.dumps(info, indent=1))
        return True, len(domains), "downloaded"
    except (OSError, ValueError, URLError) as e:
        return False, 0, str(e)
