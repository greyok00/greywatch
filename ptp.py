"""The Patch the Planet map becomes a watchlist (owner 2026-11-06).

OpenAI's Patch the Planet program (Trail of Bits engineering, part of
the Daybreak effort) reviews critical open source code with AI-assisted
discovery and publishes every finding on a public dashboard. That
dashboard is the program's vulnerability map: per project, one row per
finding with a severity and a disclosure status. This module brings the
map in as a snapshot, refreshes it from the dashboard when it is up,
matches the covered projects against what is installed on this machine,
and turns the matches into one-time announcements in the monitors'
voice.

Nothing here patches anything, and no severity here is a measurement of
this machine: a P2P row means "the world's AI-assisted reviewers are
already inside this codebase", so an installed component on the list is
a priority watch, not a detected attack. Every announcement defers to
the keeper: updates move when the keeper moves them.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re
import urllib.request

DASHBOARD_URL = "https://trailofbits.com/patch-the-planet/dashboard/"
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/141.0 Safari/537.36")

# One dashboard row = one public finding. Severity words as the page
# writes them; unknown values pass through without invention.
KNOWN_SEVERITIES = ("high", "medium", "low", "info", "undetermined")

# A P2P project name is rarely the exact Debian or pip package name;
# these aliases map the covered projects this watcher can actually see.
# A project not listed still matches its own name on both channels.
DEB_ALIASES = {
    "sqlite": ["sqlite3", "libsqlite3-0"],
    "zlib": ["zlib1g"],
    "nginx": ["nginx", "nginx-core"],
    "freenginx": ["freenginx-core", "freenginx"],
    "nss": ["libnss3"],
    "rust": ["rustc", "cargo"],
    "cryptography": ["python3-cryptography"],
    "urllib3": ["python3-urllib3"],
    "aiohttp": ["python3-aiohttp"],
    "scapy": ["python3-scapy"],
    "python": ["python3-minimal"],
    "kubernetes-client": ["kubectl"],
}
# pip freeze finds the pure-Python members the deb set cannot confirm;
# a pip name differing from the project name goes here.
PIP_ALIASES = {
    "vllm": ["vllm"],
    "cryptography": ["cryptography"],
    "urllib3": ["urllib3"],
    "aiohttp": ["aiohttp"],
    "scapy": ["scapy"],
    "cachecontrol": ["cachecontrol", "CacheControl"],
    "crypto-bigint": ["crypto-bigint"],
    "noble-curves": ["@noble/curves"],
    "sequelize": ["sequelize"],
    "liteLLM": ["litellm"],
}

_ROW_RE = re.compile(
    r'<tr[^>]*data-project="([^"]+)"[^>]*>(.*?)</tr>', re.S)
_CELL_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.S)
_TAG_RE = re.compile(r"<[^>]+>")

DASH_PROSE = "Patch the Planet"


def map_path(data_dir) -> pathlib.Path:
    """The refreshed runtime copy of the dashboard map."""
    return pathlib.Path(data_dir) / "ptp-map.json"


def snapshot_path() -> pathlib.Path:
    """The map snapshot shipped with the app (repo data/), used when a
    refresh never arrived so the watchlist still has yesterday's map."""
    return pathlib.Path(__file__).resolve().parent / "data" \
        / "ptp-dashboard.json"


def parse_dashboard(html: str) -> list:
    """Every dashboard finding row as a plain dict. The page embeds the
    whole table as <tr data-project> rows; anything the parser cannot
    read stays unread and is dropped, never guessed."""
    rows = []
    for m in _ROW_RE.finditer(html or ""):
        project, body = m.group(1), m.group(2)
        cells = []
        for cm in _CELL_RE.finditer(body):
            txt = _TAG_RE.sub(" ", cm.group(1))
            cells.append(" ".join(txt.split()))
        if len(cells) < 3:
            continue
        rows.append({"project": project.strip().lower(),
                     "severity": cells[1].strip().lower(),
                     "finding": cells[2],
                     "status": cells[3].strip() if len(cells) > 3 else ""})
    return rows


def summarize(rows) -> dict:
    """Per-project finding pressure: totals plus the count of HIGH rows,
    which is what earns a project its place on the watchlist."""
    if not isinstance(rows, list):
        return {}
    out: dict = {}
    for r in rows:
        if not isinstance(r, dict) or not r.get("project"):
            continue
        rec = out.setdefault(
            r["project"], {"project": r["project"], "findings": 0,
                           "high": 0, "medium": 0, "low": 0})
        rec["findings"] += 1
        sev = str(r.get("severity", "")).lower()
        if sev in ("high", "medium", "low"):
            rec[sev] += 1
    return out


def fetch_dashboard(base_url: str = DASHBOARD_URL, timeout: float = 20.0):
    """The dashboard HTML, fetched politely with a browser-facing agent;
    returns None on any failure so callers fall back to the snapshot."""
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def write_map(rows, path) -> int:
    rows = list(rows or [])
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ts": _dt.datetime.now(_dt.timezone.utc)
                      .isoformat(timespec="seconds"),
               "dashboard": DASHBOARD_URL,
               "rows": rows}
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")),
                   encoding="utf-8")
    tmp.replace(path)
    return len(rows)


def refresh(data_dir, base_url: str = DASHBOARD_URL,
            timeout: float = 20.0) -> int:
    """Pull the dashboard and rewrite the runtime map. Returns the row
    count; returns 0 and leaves the previous map (or the shipped
    snapshot) intact when the dashboard is unreachable."""
    html = fetch_dashboard(base_url, timeout)
    if not html:
        return 0
    rows = parse_dashboard(html)
    if not rows:
        return 0
    return write_map(rows, map_path(data_dir))


def load_map(data_dir) -> list:
    """The freshest map available: the runtime refresh when it exists,
    else the shipped snapshot, else nothing (and the caller says so)."""
    for path in (map_path(data_dir), snapshot_path()):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows = data.get("rows") if isinstance(data, dict) else data
        if isinstance(rows, list) and rows:
            return rows
    return []


class Specs(list):
    """One announce pass's specs, with the ledger stall attached.

    A plain list on purpose: `== []`, indexing and iteration behave as
    they always did, so legacy code never notices. What is new is
    `stalled`: an OSError when the announce ledger could not be written,
    None otherwise. The specs STAY when the write fails (retry until
    persisted - news is told again while the ledger is unwritable, and
    flows once it is not); duplication is visible and bounded, loss is
    silent and permanent."""

    def __init__(self, items=()):
        super().__init__(items)
        self.stalled: OSError | None = None


class Coverage(list):
    """The machine's covered projects, with the package-probe honesty
    attached: `probe_failed` names the channels that could not be read
    (never a guess - the empty list with a failed probe is UNKNOWN,
    not 'nothing is covered')."""

    def __init__(self, items=()):
        super().__init__(items)
        self.probe_failed: list | None = None


def installed_names(runner) -> tuple:
    """(deb_names, pip_names, failed_channels) reported by this
    machine's own package channels; a channel that fails yields nothing
    AND its name rides in failed, so downstream 'empty' can be told
    apart from 'unanswered' instead of reading as safe."""
    deb, pip, failed = set(), set(), []
    try:
        rc, out = runner("dpkg-query -W -f='${Package}\\n'")
        if rc == 0 and out:
            deb = {l.strip().lower() for l in out.splitlines() if l.strip()}
        elif rc != 0:
            failed.append("dpkg-query")
    except Exception:
        failed.append("dpkg-query")
    try:
        rc, out = runner("python3 -m pip list --format=freeze")
        if rc == 0 and out:
            for line in out.splitlines():
                name = line.split("=", 1)[0].strip()
                if name:
                    pip.add(name)
        elif rc != 0:
            failed.append("pip")
    except Exception:
        failed.append("pip")
    return deb, pip, failed


def coverage(rows, runner) -> list:
    """The watchlist for THIS machine: every covered project whose
    packages (deb or pip) answer back installed, with its finding
    pressure, sorted so the highest-severity coverage reads first. A
    machine can only be read, never invented: without a package channel
    answer this returns an empty list."""
    if not rows:
        return []
    cov = summarize(rows)
    deb, pip, failed = installed_names(runner)
    out = Coverage()
    for name, rec in cov.items():
        hits = [pkg for pkg in [name, *DEB_ALIASES.get(name, [])]
                if pkg.lower() in deb]
        pip_hits = [pkg for pkg in PIP_ALIASES.get(name, [])
                    if pkg in pip or pkg.lower() in {p.lower() for p in pip}]
        if name in pip or name.lower() in {p.lower() for p in pip}:
            pip_hits.append(name)
        via = []
        if hits:
            via.append("deb")
        if pip_hits:
            via.append("pip")
        if not via:
            continue
        out.append({"project": name, "findings": rec["findings"],
                    "high": rec["high"], "medium": rec["medium"],
                    "low": rec["low"],
                    "via": "+".join(via),
                    "packages": sorted({*hits, *pip_hits})})
    out.sort(key=lambda c: (-c["high"], -c["findings"], c["project"]))
    out.probe_failed = failed or None
    return out


def announced_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "ptp-announced.jsonl"


def _announced(path: pathlib.Path) -> set:
    seen = set()
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("project"):
                    seen.add(rec["project"])
    except OSError:
        return set()
    return seen


def _text(coverage_row: dict) -> str:
    rec = coverage_row
    who = rec["packages"][0] if rec["packages"] else rec["project"]
    head = (f"{DASH_PROSE} watchlist: '{rec['project']}' is installed "
            f"here (as {who}) and {rec['findings']} of its flaws are "
            f"public in the program's map")
    if rec.get("high"):
        return f"{head}, {rec['high']} of them HIGH - verify the " \
               "installed version; the keeper decides any update"
    return f"{head} - verify the installed version; the keeper decides " \
           "any update"


def evaluate(data_dir, runner, rows=None) -> Specs:
    """Announce every covered installed project not yet announced.
    Returns (severity, text, project, packages) specs for the daemon;
    writes one announce line each so a restart never re-announces. When
    the write fails the specs STAY with .stalled set - retry until
    persisted, never silently dropped."""
    data_dir = pathlib.Path(data_dir)
    rows = load_map(data_dir) if rows is None else rows
    cov = coverage(rows, runner)
    path = announced_path(data_dir)
    seen = _announced(path)
    out, lines = Specs(), []
    for rec in cov:
        name = rec["project"]
        if name in seen:
            continue
        sev = "HIGH" if rec.get("high") else "MEDIUM"
        out.append((sev, _text(rec), name, rec["packages"]))
        lines.append(json.dumps(
            {"project": name, "packages": rec["packages"],
             "ts": _dt.datetime.now(_dt.timezone.utc)
             .isoformat(timespec="seconds")},
            separators=(",", ":")))
    if lines:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError as exc:
            # GW-B1: the stall is not silence. The specs STAY (retry
            # until persisted: the same news is told again on the next
            # pass and stops once the ledger takes a write); duplication
            # is visible and bounded, loss is silent and permanent.
            out.stalled = exc
    return out


def delta_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "ptp-delta.jsonl"


def _finding_key(row: dict) -> str:
    return "|".join((str(row.get("project") or ""),
                     str(row.get("severity") or ""),
                     str(row.get("finding") or "")))


def _seen_keys(path: pathlib.Path) -> set:
    seen = set()
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("key"):
                    seen.add(rec["key"])
    except OSError:
        return set()
    return seen


def map_delta(rows_old, rows_new) -> dict:
    """What tonight's map carries that yesterday's did not, per project.
    A finding keeps its identity from project + severity + wording, so
    edits in place read as new and removals simply vanish."""
    seen = {_finding_key(r) for r in rows_old or [] if isinstance(r, dict)}
    out: dict = {}
    for r in rows_new or []:
        if not isinstance(r, dict) or not r.get("project"):
            continue
        key = _finding_key(r)
        if key not in seen:
            out.setdefault(r["project"], []).append(r)
    return out


def evaluate_delta(data_dir, rows_old, rows_new) -> Specs:
    """The nightly delta in the monitors' voice: one announcement per
    newly arriving finding, keyed so a restart never re-reads old news.
    Returns (severity, text, key) specs; nothing is announced that the
    ledger already holds, and when the ledger cannot persist the specs
    STAY with .stalled set (retry until persisted - the news is told
    again on the next pass and stops once the ledger takes a write)."""
    data_dir = pathlib.Path(data_dir)
    delta = map_delta(rows_old, rows_new)
    path = delta_path(data_dir)
    seen = _seen_keys(path)
    out, lines = Specs(), []
    now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    for project in sorted(delta):
        for r in delta[project]:
            key = _finding_key(r)
            if key in seen:
                continue
            sev = "HIGH" if r.get("severity") == "high" else "MEDIUM"
            text = (f"{DASH_PROSE} map update: '{project}' adds a "
                    f"{r.get('severity')} finding - {r.get('finding')} "
                    f"first read at {now}")
            out.append((sev, text, key))
            lines.append(json.dumps(
                {"key": key, "ts": now}, separators=(",", ":")))
    if lines:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError as exc:
            # GW-B1: same stall contract as evaluate - the specs stay
            # and .stalled carries the OSError; retry until persisted,
            # duplication visible and bounded, loss never silent.
            out.stalled = exc
    return out


def cross_join(data_dir, name) -> dict | None:
    """The watch row whose project or installed packages match `name`
    (a machine tool the CVE lane named), or None: the two lanes meet
    only where the program actually covers what the flaw touches. A
    read joins on real coverage, never on word resemblance."""
    if not name:
        return None
    low = str(name).strip().lower()
    for rec in (watch_rows(pathlib.Path(data_dir)) or {}).get("projects") \
            or []:
        if not isinstance(rec, dict):
            continue
        pkgs = {str(p).lower() for p in rec.get("packages") or []}
        if low == str(rec.get("project") or "").lower() or low in pkgs:
            return rec
    return None


def watch_rows(data_dir) -> dict | None:
    """What the dashboard watch can claim for this machine's pages, or
    None when no map has ever arrived (the page says so, never guesses).
    Coverage matching happens in the daemon lane; the pages read the
    result file so the UI thread never runs a package listing."""
    path = pathlib.Path(data_dir) / "ptp-watch.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _watch_file_write(data_dir, runner=None) -> int:
    """The watch file the pages read, written by whichever lane is doing
    the matching (the daemon on its daily cycle, the user-side refresh
    between cycles). Same shape, one writer at a time, atomic."""
    try:
        if runner is None:
            from hardening.detector import prod_runner as runner
        cov = coverage(load_map(data_dir), runner)
        path = pathlib.Path(data_dir) / "ptp-watch.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(
            {"ts": _dt.datetime.now(_dt.timezone.utc)
                  .isoformat(timespec="seconds"), "projects": cov},
            separators=(",", ":")), encoding="utf-8")
        tmp.replace(path)
        return len(cov)
    except Exception:
        return -1


if __name__ == "__main__":
    # The user-side refresh channel (mirrors cve-refresh.py): same state
    # directory, same files, one writer at a time with the daemon.
    from gwpaths import data_dir as _data

    _dd = _data()
    _n = refresh(_dd)
    _out = ("map unchanged (dashboard unreachable)" if not _n
            else f"map refreshed: {_n} findings")
    _m = _watch_file_write(_dd)
    _out += ("; coverage left for the daemon" if _m < 0
             else f"; {_m} projects covered")
    print(_out)
