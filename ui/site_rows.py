"""Rows for the sites list: one source of truth for what the UI shows.

Pure functions; no GTK, no network. Names come in from NameResolver.
One row per site, merged from four places: the trust/block lists, what the
application firewall saw, what is connected right now, and recently seen
history. The row keeps the raw entry (the exact string the trust list
stores) so actions can act on it without re-deriving anything.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ui.site_class import classify

_APPFW = re.compile(
    r"^(?P<act>allow|deny)\s+(?P<prog>\S+)\s+→\s+(?P<host>\S+?):(?P<port>\d+)\b")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class SiteRow:
    entry: str
    name: str
    address: str
    description: str
    program: str
    port: int | None
    last_seen: str
    count: int
    verdict: str


def parse_appfw(event) -> tuple[str, int, str] | None:
    m = _APPFW.match(str((event or {}).get("text", "")))
    if not m:
        return None
    return m.group("host"), int(m.group("port")), m.group("prog")


def _empty_row(entry, verdict=""):
    is_ip = bool(_IPV4.match(entry))
    return SiteRow(entry=entry, name=entry,
                   address=entry if is_ip else "",
                   description=classify(entry, None), program="",
                   port=None, last_seen="", count=0, verdict=verdict)


def build_rows(trust, appfw_events=(), connected=(), history=(),
               names=None) -> list[SiteRow]:
    names = names or {}
    rows: dict[str, SiteRow] = {}

    def get(entry):
        if entry not in rows:
            rows[entry] = _empty_row(entry)
        return rows[entry]

    # A place in either list is a decision the owner already made, so it
    # survives even when nothing has been seen recently.
    for entry in sorted(getattr(trust, "allow", ()) or ()):
        get(entry).verdict = "allow"
    for entry in sorted(getattr(trust, "block", ()) or ()):
        get(entry).verdict = "block"

    for event in appfw_events or ():
        got = parse_appfw(event)
        if not got:
            continue
        host, port, prog = got
        row = get(host)
        row.program = row.program or prog
        row.port = port
        stamp = str((event or {}).get("ts", ""))
        row.last_seen = max(row.last_seen, stamp)
        row.count += 1
        row.description = classify(host, port)

    for host in connected or ():
        row = get(host)
        if row.port is None:
            row.port = 443                      # live connections are TLS
        row.description = classify(host, row.port)

    for host in history or ():
        get(host)

    for entry, row in rows.items():
        got = names.get(row.address or entry)
        if got:
            row.name = got
        if row.port is None:
            row.description = classify(entry, None)

    ordered = sorted(rows.values(),
                     key=lambda r: (r.last_seen == "", r.name.lower(),
                                    r.entry))
    # Stable: rows seen most recently float to the top; rows with no
    # sighting at all keep their alphabetical order underneath.
    return sorted(ordered, key=lambda r: r.last_seen, reverse=True)


def filter_rows(rows, query: str) -> list[SiteRow]:
    q = (query or "").strip().lower()
    if not q:
        return list(rows)
    return [r for r in rows
            if q in r.name.lower() or q in r.address.lower()
            or q in r.entry.lower() or q in r.description.lower()
            or q in r.program.lower()]


def short_name(row: SiteRow) -> str:
    """Just the identity: the domain name when known, else the entry."""
    if row.name and row.name != row.entry and row.address:
        return f"{row.name} ({row.address})"
    return row.entry


def display_line(row: SiteRow) -> str:
    return f"{short_name(row)} — {row.description}"
