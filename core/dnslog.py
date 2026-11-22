"""The DNS monitor store (architecture v4, build order item c).

This machine's own domain lookups, derived from the resolver's query
log — dnsmasq's journal here — PLUS the blocklist the feeds render for
dnsmasq, so a blocked hit is named against the very list the wall
serves. Per-domain first/last seen, per-client counts, and every row's
provenance.

The standing law holds: NO DNS NEAR THE PUMP. Nothing here touches the
daemon's status beat; the store rebuilds inside the daemon's slow lane
(root) and every other reader reads the file. If the resolver does not
log its queries yet, the store says so plainly instead of inventing a
silent zero.

Whole-network DNS joins through the same store when the router hands
this machine the DNS role - one setting the owner flips in the router,
then every device's lookups land here with the same flagging.
"""

from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re

STORE_NAME = "dnslog.json"
_BLOCKLIST_PATHS = (
    pathlib.Path("/etc/dnsmasq.d/00-blocklist-merged.conf"),
    pathlib.Path("/usr/lib/greywatch/data/webguard-blocklist.conf"),
)
_DOMAIN_CAP = 4000          # the store rolls: oldest last_seen drops first
_JOURNAL_ROWS = 20000       # the journal slice the pass reads
_SOURCES = "dnsmasq.service"

_QUERY_RE = re.compile(
    r"query\[[A-Z0-9]+\]\s+(\S+)\s+from\s+(\S+)")


def _now_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _journal_lines(rows=_JOURNAL_ROWS) -> str:
    """The resolver's query log slice, one journal read per pass."""
    import subprocess
    try:
        r = subprocess.run(
            ["journalctl", "-u", _SOURCES, "--no-pager",
             "-n", str(rows), "-o", "short-iso"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout if r.returncode == 0 else ""


def _log_queries_state() -> tuple[bool, str]:
    """Whether dnsmasq is being asked to log queries at all. The truth
    sits in one word in /etc/dnsmasq.conf; a commented-out directive
    means the journal stays quiet and the store must say so."""
    try:
        text = pathlib.Path("/etc/dnsmasq.conf").read_text(
            errors="replace")
    except OSError:
        return False, "resolver config unreadable in this context"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#") and "log-queries" in stripped:
            return True, "log-queries is on"
    if "log-queries" in text:
        return False, ("log-queries is commented out - the resolver is "
                       "not keeping a query log")
    return False, ("no log-queries directive - the resolver is not "
                   "keeping a query log")


def _blocked_domains(data_dir) -> tuple[set, str]:
    """The wildcard rows the wall actually serves, as a set of domains.
    The merged conf dnsmasq reads is the truth; the rendered webguard
    file is the fallback the machine keeps in the app tree."""
    for path in _BLOCKLIST_PATHS:
        try:
            body = path.read_text(errors="replace")
        except OSError:
            continue
        out = set()
        for line in body.splitlines():
            if line.startswith("address=/"):
                dom = line[len("address=/"):].split("/")[0]
                if dom:
                    out.add(dom)
        if out:
            return out, str(path)
    try:
        rendered = pathlib.Path(data_dir) / "webguard-blocklist.conf"
        body = rendered.read_text(errors="replace")
    except Exception:                    # noqa: BLE001
        return set(), "no blocklist on file"
    out = set()
    for line in body.splitlines():
        if line.startswith("address=/"):
            dom = line[len("address=/"):].split("/")[0]
            if dom:
                out.add(dom)
    return out, str(rendered) if out else "no blocklist on file"


def build(data_dir=None, journal=None, blocklist=None) -> dict:
    """One build pass: read the slice, flag against the wall, roll the
    per-domain rows. `journal` and `blocklist` are test seams."""
    try:
        import gwpaths
        data_dir = data_dir or gwpaths.data_dir()
    except Exception:                    # noqa: BLE001
        data_dir = pathlib.Path("/var/lib/greywatch")
    data_dir = pathlib.Path(data_dir)

    if journal is None:
        journal = _journal_lines()
    log_on, log_how = _log_queries_state()
    if blocklist is None:
        blocked, block_how = _blocked_domains(data_dir)
    else:
        # a passed-in (set, provenance) pair, the test and lane seam
        blocked, block_how = blocklist

    domains: dict = {}
    clients_total = 0
    queries_total = 0

    for line in journal.splitlines():
        m = _QUERY_RE.search(line)
        if not m:
            continue
        name, client = m.group(1).rstrip("."), m.group(2)
        stamp = ""
        head = line.split(" ", 1)
        if head and "T" in head[0]:
            stamp = head[0]
        row = domains.setdefault(name, {"first": stamp or _now_stamp(),
                                        "last": stamp or _now_stamp(),
                                        "queries": 0, "clients": set(),
                                        "blocked": False})
        row["queries"] += 1
        queries_total += 1
        row["clients"].add(client)
        clients_total = max(clients_total, len(row["clients"]))
        if name in blocked or _matches_parent(blocked, name):
            row["blocked"] = True

    # roll: the cap keeps the store honest and bounded
    if len(domains) > _DOMAIN_CAP:
        ordered = sorted(domains.items(),
                         key=lambda kv: kv[1]["last"], reverse=True)
        domains = dict(ordered[:_DOMAIN_CAP])
        overflow = True
    else:
        overflow = False

    for row in domains.values():
        row["clients"] = sorted(row["clients"])

    blocked_hits = [d for d, row in domains.items() if row["blocked"]]
    report = {
        "version": 1,
        "built_at": _now_stamp(),
        "source": f"journal:{_SOURCES}",
        "log_queries_enabled": log_on,
        "log_how": log_how,
        "blocklist": block_how,
        "domains": domains,
        "counts": {"domains": len(domains), "queries": queries_total,
                   "blocked_hits": len(blocked_hits),
                   "clients_seen": len({c for row in domains.values()
                                        for c in row["clients"]})},
        "note": ("" if (log_on and journal.strip()) else
                 "the resolver keeps no query log yet; turn on "
                 "log-queries and the store fills on the next slow-lane "
                 "pass"),
        "capped": overflow,
    }
    return report


def _matches_parent(blocked: set, name: str) -> bool:
    """`address=/example.com/` also swallows img.example.com: any parent
    domain of the query name counts as blocked."""
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        if ".".join(parts[-i:]) in blocked:
            return True
    return False


def persist(report: dict, data_dir=None) -> pathlib.Path:
    try:
        import gwpaths
        data_dir = data_dir or gwpaths.data_dir()
    except Exception:                    # noqa: BLE001
        data_dir = pathlib.Path("/var/lib/greywatch")
    out = pathlib.Path(data_dir) / STORE_NAME
    body = json.dumps(report, indent=1, sort_keys=True) + "\n"
    from status import atomic_replace, ui_gid
    # 0640 root:ui so the GUI lane can read it (GW-02: a bare
    # tmp-write + replace left dnslog.json 0600 root:root and the DNS
    # card could never fill).
    atomic_replace(str(out), body, gid=ui_gid())
    return out


def human(report: dict) -> str:
    counts = report.get("counts") or {}
    lines = []
    if not report.get("log_queries_enabled"):
        lines.append("dnslog: the resolver keeps no query log yet "
                     f"({report.get('log_how', '')})")
    else:
        lines.append(
            f"dnslog: {counts.get('queries', 0)} queries over "
            f"{counts.get('domains', 0)} domain(s), "
            f"{counts.get('blocked_hits', 0)} landed on the blocklist"
            f" ({report.get('blocklist', '')})")
    rows = sorted((report.get("domains") or {}).items(),
                  key=lambda kv: kv[1].get("last", ""), reverse=True)[:8]
    for name, row in rows:
        mark = " BLOCKED" if row.get("blocked") else ""
        lines.append(f"  {name}  x{row.get('queries', 0)}  "
                     f"last {row.get('last', '')}{mark}")
    if report.get("capped"):
        lines.append("  (the store rolled: only the newest domains "
                     "stay)")
    return "\n".join(lines)
