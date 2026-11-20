"""Named site trust entries meet the address-only verdict path.

The packet verdict sees an address (conn.host carries dst_host only when
something resolved a name, which the kernel packet path never has), while
trust-list entries are names picked in the wizard - "Trust
example.net" compiled a rule that could never match an address, so the
pick did nothing (round-1 audit HIGH,. This lane closes that
gap honestly: the named entries are DNS-resolved on the engine's SLOW
lane (a thread, never the packet path), the resolved addresses ride in
the cache file, and the policy consults the cache so a name pick also
matches the address it pointed at. A failed refresh keeps the previous
cache: stale coverage beats none, and the next pass retries.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import socket
import threading

import status

CACHE_NAME = "site-ips.json"
REFRESH_SECONDS = 300                    # engine's slow lane cadence

# The packet verdict consults this file on every connection; a full
# read+parse per packet is the packet path's cost driver, so the parsed
# doc is cached keyed on the file's mtime_ns (one tiny stat per packet,
# a re-read only after the slow lane rewrites the file).
_IP_DOC_LOCK = threading.Lock()
_IP_DOC_CACHE: dict = {"path": None, "ns": -1, "entries": {}}


def _ip_entries_cached(data_dir) -> dict:
    path = cache_path(data_dir)
    key = str(path)
    try:
        ns = path.stat().st_mtime_ns
    except OSError:
        return {}
    with _IP_DOC_LOCK:
        if _IP_DOC_CACHE.get("path") != key or \
                _IP_DOC_CACHE.get("ns") != ns:
            try:
                doc = json.loads(path.read_text())
            except (OSError, ValueError):
                doc = {}
            entries = doc.get("entries") if isinstance(doc, dict) else None
            _IP_DOC_CACHE.update(path=key, ns=ns,
                                 entries=entries if isinstance(entries,
                                                                dict) else {})
        return dict(_IP_DOC_CACHE["entries"])


def cache_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "appfw" / CACHE_NAME


def load(data_dir) -> dict:
    """The cached {"entries": {entry: [addresses]}} doc, or {}."""
    try:
        doc = json.loads(cache_path(data_dir).read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def store(data_dir, entries: dict) -> None:
    doc = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(
               timespec="seconds"),
           "entries": entries}
    try:
        cache_path(data_dir).parent.mkdir(parents=True, exist_ok=True)
        status.atomic_replace(str(cache_path(data_dir)),
                              json.dumps(doc, separators=(",", ":")))
    except (OSError, ValueError):
        pass


def resolve_entry(entry: str) -> list[str]:
    """One entry's live addresses. A wildcard entry ("*.example.net")
    resolves its base name; a pure address carries itself so a re-saved
    entry keeps matching; a failed lookup answers no addresses rather
    than pretending."""
    value = str(entry or "").strip().lower()
    if not value:
        return []
    if value.startswith("*."):
        value = value[2:]
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, value)
            return [value]
        except (OSError, ValueError):
            pass
    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    ips = []
    for info in infos:
        address = str(info[4][0])
        if address and address not in ips:
            ips.append(address)
    return ips[:16]


def resolve_entries(entries) -> dict[str, list[str]]:
    return {entry: resolve_entry(entry)
            for entry in sorted({str(e) for e in entries or []})}


def ip_verdict(data_dir, host: str, allow, block) -> str | None:
    """The verdict an ADDRESS inherits from the named entries that
    resolved to it: 'allow' / 'deny', or None when no cached entry
    claims the address. Names still belong to the trust list's own
    matcher; this only bridges the two languages."""
    host = str(host or "")
    if not host:
        return None
    entries = _ip_entries_cached(data_dir)
    allow_set, block_set = set(allow or ()), set(block or ())
    hits = {entry for entry, ips in entries.items()
            if isinstance(ips, list) and host in ips}
    # Deny is examined across ALL claiming entries before allow (the
    # trust list's own matcher denies first too): the cache's file order
    # - or one stale entry - must not convert a user-set block into a
    # pass (tie goes to deny, symbolic audit R3).
    if hits & block_set:
        return "deny"
    if hits & allow_set:
        return "allow"
    return None