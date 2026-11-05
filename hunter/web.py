"""Web and download attack patterns — the hunter's browser-side rules.

Hunting goes past CVE feeds: web
activity, browsers, downloads, and the tricks malware actually uses to
reach a machine. This module implements that as bounded, deterministic
rules over three unprivileged evidence sources:

  * HAR files dropped into the hunter inbox — request/response
    captures browsers already make (DevTools → "Save all as HAR").
  * the Downloads folder — file names, archives' inner names, and the
    shell's verdict on file types.
  * Chromium-family browser download history (read from a copy of the
    History database, never the live one).

Everything here is untrusted data: parsed, truncated, and never executed.
A HAR or a history row can say anything it likes; it becomes a finding
only because a rule pattern matched, and the rule names its evidence.

Firefox's download history is read, as is each Chromium family browser's
(from the history databases both keep, not the Downloads folder).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import pathlib
import re
import shutil
import sqlite3
import subprocess
import tempfile
import urllib.parse
import zipfile

HAR_MAX_BYTES = 25 * 1024 * 1024
HAR_MAX_ENTRIES = 6000
DOWNLOADS_MAX_FILES = 400
DOWNLOADS_WINDOW_DAYS = 14

# .pdf.exe and friends — the single most-used delivery trick.
DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|jpe?g|png|xls[xm]?|rtf|txt)"
    r"\.(exe|msi|scr|bat|cmd|ps1|vbs|js|lnk|hta|jar|apk|iso)$", re.I)
EXEC_EXTS = (".exe", ".msi", ".scr", ".hta", ".ps1", ".vbs", ".lnk",
             ".bat", ".cmd", ".jar", ".apk")
ARCHIVE_EXTS = (".zip", ".iso", ".img", ".7z", ".rar")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=\s]{512,}")

# Suffixes where the last two labels are not the registered domain. Not a
# full public-suffix list — enough that the redirect-chain and third-party
# rules do not flag a site's own CDN as a different organisation. The
# limit is recorded here, not hidden.
_SECOND_LEVEL = {"co.uk", "com.au", "co.jp", "com.br", "co.nz", "co.za",
                 "com.mx", "co.in", "org.uk", "gov.uk", "com.tr", "com.cn"}


def _now_iso() -> str:
    # Microseconds, like every note stamp: the reader's pointer and a
    # note created in the same wall second must still order correctly.
    return _dt.datetime.now(_dt.timezone.utc).isoformat(
        timespec="microseconds")


def _clip(text, n=200) -> str:
    return str(text or "")[:n]


def registrable(host: str) -> str:
    """Approximate eTLD+1; a raw IP is its own authority."""
    host = (host or "").strip().lower().rstrip(".")
    if is_raw_ip(host):
        return host
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_raw_ip(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def finding(rule, title, what, next_step, severity, evidence,
            confidence="medium", status="lead", asset="web", facts=None):
    """One structured hunter finding. ``status`` is lead or confirmed —
    confirmed only when the rule is strong on its own (a name pattern plus
    the shell's verdict, for instance)."""
    return {
        "rule": rule, "title": title, "what": what, "next": next_step,
        "severity": severity, "confidence": confidence, "status": status,
        "asset": asset, "evidence": list(evidence)[:8],
        "facts": [str(f)[:300] for f in (facts or [])][:8],
        "ts": _now_iso(), "hunter": "1",
    }


def _download_finding(rule, title, what, severity, status, path, name,
                      basis, extra="", confidence="medium"):
    return finding(
        rule, title, what, "Do not open it until you know what it is; the "
        "assistant can help review it, and it can be quarantined from the "
        "Files row in the Hunter card.", severity,
        [{"source": "fs", "path": path, "basis": basis, "ts": _now_iso()}],
        confidence=confidence, status=status, asset="host",
        facts=[f"path={path}", f"basis={basis}"]
        + ([f"detail={extra}"] if extra else []))


# ------------------------------------------------------------------- HAR

def parse_har(path) -> dict | None:
    """A whole parsed HAR log, or None. Caps keep an untrusted capture from
    becoming a memory event."""
    p = pathlib.Path(path)
    try:
        if p.stat().st_size > HAR_MAX_BYTES:
            return None
        doc = json.loads(p.read_text(errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    log = doc.get("log")
    if not isinstance(log, dict):
        return None
    entries = log.get("entries")
    if not isinstance(entries, list):
        return None
    out = []
    for e in entries[:HAR_MAX_ENTRIES]:
        if not isinstance(e, dict):
            continue
        req = e.get("request") or {}
        resp = e.get("response") or {}
        headers = {}
        for h in (resp.get("headers") or []):
            if isinstance(h, dict) and h.get("name"):
                headers[str(h["name"]).lower()] = str(h.get("value") or "")
        content = resp.get("content") or {}
        post = req.get("postData") or {}
        url = str(req.get("url") or "")
        try:
            host = urllib.parse.urlparse(url).netloc.rpartition("@")[2]
            if host.startswith("["):
                # IPv6 literal: the authority ends at the closing bracket
                # (an address like 2001:db8::5), not at the first colon -
                # a raw-IP websocket on v6 must stay joinable to intel.
                host = host.partition("]")[0].strip("[]")
            else:
                host = host.partition(":")[0]
        except ValueError:        # e.g. "http://[" - skip, never raise on
            continue              # an untrusted capture's odd url
        out.append({
            "url": url, "host": host, "method": str(req.get("method") or ""),
            "status": resp.get("status"),
            "mime": str(content.get("mimeType") or ""),
            "redirect": headers.get("location", "")
            or str(resp.get("redirectURL") or ""),
            "cd": headers.get("content-disposition", ""),
            "post": str(post.get("text") or "")[:4096],
            "frames": len(e.get("_webSocketMessages")
                          or e.get("webSocketMessages") or []),
            "pageref": str(e.get("pageref") or ""),
            "rtype": str(e.get("_resourceType") or ""),
        })
    return {"path": str(p), "entries": out,
            "creator": log.get("creator") or {},
            "pages": [str(pg.get("id") or pg.get("title") or "")
                      for pg in log.get("pages", []) if isinstance(pg, dict)]}


def _filename_from(entry) -> str:
    """The download name a response names, from Content-Disposition or URL."""
    m = re.search(r'filename="?([^";]+)?"?', entry["cd"], re.I)
    if m and m.group(1):
        name = m.group(1).strip()
    else:
        name = urllib.parse.urlparse(entry["url"]).path.rsplit("/", 1)[-1]
    return urllib.parse.unquote(name)


def _is_attachment(entry) -> bool:
    if "attachment" in entry["cd"].lower():
        return True
    mime = entry["mime"].lower()
    return any(t in mime for t in ("octet-stream", "x-msdownload",
                                   "x-msdos-program", "x-iso9660-image",
                                   "zip", "x-7z", "x-rar", "x-tar"))


def har_findings(doc: dict) -> list[dict]:
    """Rules over one parsed HAR. Facts name the matched entry and URL;
    nothing from the capture is executed or trusted beyond the match."""
    entries = doc["entries"]
    if not entries:
        return []
    path = doc["path"]
    out: list[dict] = []

    def ev(idx: int, e: dict) -> dict:
        return {"source": "har", "import": _clip(path, 120), "entry": idx,
                "url": _clip(e["url"]), "host": _clip(e["host"], 120),
                "ts": _now_iso()}

    # R1 — a download carrying a double extension or a program-file name.
    for idx, e in enumerate(entries):
        if not _is_attachment(e):
            continue
        name = _filename_from(e)
        low = name.lower()
        if DOUBLE_EXT_RE.search(name):
            out.append(finding(
                "har-double-extension",
                "A download carried a double extension in the HAR capture",
                f"“{_clip(name, 120)}” arrived as a download while its name "
                "pretends to be a document - the classic malicious-"
                "attachment disguise.",
                "Do not open it; find it in Downloads before anything runs.",
                "HIGH", [ev(idx, e)], confidence="high", status="confirmed",
                facts=[f"name={_clip(name, 120)}"]))
        elif low.endswith(EXEC_EXTS):
            out.append(finding(
                "har-executable-download",
                "A program file arrived through the browser in the captured "
                "session", f"“{_clip(name, 120)}” was downloaded. Program "
                "files from the web are how most host compromises start.",
                "Run a scan over Downloads and review the file before "
                "opening it.", "HIGH", [ev(idx, e)],
                facts=[f"name={_clip(name, 120)}"]))
        elif low.endswith(ARCHIVE_EXTS):
            out.append(finding(
                "har-archive-download",
                "An archive arrived through the browser in the captured "
                "session",
                f"“{_clip(name, 120)}” downloaded. Archives are usually a "
                "staging step in a delivery chain, not the payload itself.",
                "Inspect the archive before extracting.", "MEDIUM",
                [ev(idx, e)], confidence="low",
                facts=[f"name={_clip(name, 120)}"]))

    # R2 — a download whose body is actually a web page: the wrap trick.
    for idx, e in enumerate(entries):
        if _is_attachment(e) and "text/html" in e["mime"].lower():
            out.append(finding(
                "har-mime-wrap",
                "A download answered as an HTML page in the HAR capture",
                "The response marked itself a download but its body is a "
                "web page - a wrap used to smuggle script past content "
                "filters.", "Treat the file as untrusted and check what "
                "produced it.", "MEDIUM", [ev(idx, e)],
                facts=[f"mime={_clip(e['mime'], 80)}",
                       f"url={_clip(e['url'])}"]))

    # R3 — a redirect chain crossing registrable domains that ends in a
    # download. Structural, never proof by itself: always a lead. Each
    # chain answers for itself, so a harmless chain's domains are never
    # woven into an attack chain that merely shares the capture.
    for domains, end_download, start in _walk_chains(entries):
        if end_download and len(domains) >= 2:
            out.append(finding(
                "har-redirect-to-download",
                "A redirect hop crossed several domains and ended in a "
                "download",
                "The captured chain moved through "
                + ", ".join(sorted(domains))
                + " before delivering a file - the "
                "delivery shape phishing kits use to break trajectory "
                "analysis.",
                "Review the download that ended the chain and the last "
                "domain it passed through.", "HIGH",
                [ev(start, entries[start])],
                facts=["domains=" + _clip(", ".join(sorted(domains)),
                                          200)]))

    # R4 — scripts loaded from more than one third-party domain while a
    # download happened on the same page.
    for page_idx, third, download in _page_third_parties(entries):
        if download and len(third) >= 2:
            out.append(finding(
                "har-third-party-kit",
                "A page pulled scripts from several third-party domains and "
                "delivered a download",
                "The captured page loaded scripts from "
                + ", ".join(sorted(third))
                + " and a download happened on the same page - the staging "
                "shape of a drive-by kit.", "Check the download first; the "
                "page's scripts came from domains outside its own.",
                "MEDIUM", [ev(page_idx, entries[page_idx])],
                facts=["third-party="
                       + _clip(", ".join(sorted(third)), 200)]))

    # R5 — a large base64 POST body: the shape of staged command traffic.
    for idx, e in enumerate(entries):
        if e["method"] == "POST" and _BASE64_RE.fullmatch(e["post"]):
            out.append(finding(
                "har-base64-post",
                "Base64-encoded content was posted to a server mid-session",
                f"{_clip(e['host'], 120)} received a large encoded body - "
                "an upload shape used by staged commands and for stolen "
                "data leaving a machine.", "Decide whether you did this in "
                "the session; otherwise review what the page was.",
                "MEDIUM", [ev(idx, e)],
                facts=[f"host={_clip(e['host'], 120)}",
                       "body>=512 chars"]))

    # R6 — a chatty websocket to a bare address: machine channels do not
    # normally need a name.
    for idx, e in enumerate(entries):
        if e["frames"] >= 3 and is_raw_ip(e["host"]):
            out.append(finding(
                "har-raw-ip-websocket",
                "A websocket channel ran to a raw address",
                f"{_clip(e['host'], 120)} held open a websocket with "
                f"{e['frames']} frames - a direct machine channel rather "
                "than a normal web origin.", "Note the address and decide "
                "whether that connection belongs to something you run.",
                "HIGH", [ev(idx, e)],
                facts=[f"host={_clip(e['host'], 120)}",
                       f"frames={e['frames']}"]))
    return out


def _hops(entries) -> dict[int, int]:
    """start-index → next-entry-index, matched by redirect URL → the next
    request. One pass, loop-safe: the walk caps depth separately."""
    pending: dict[str, int] = {}
    links: dict[int, int] = {}
    for idx, e in enumerate(entries):
        src = pending.pop(e["url"], None)
        if src is not None:
            links[src] = idx
        if e["redirect"]:
            pending[e["redirect"]] = idx
    return links


def _walk_chains(entries) -> list[tuple[set[str], bool, int]]:
    """Per redirect chain: the domains THAT chain crossed, whether that
    chain ended in a download, and where it started (the finding's
    evidence anchor). One chain's report never borrows another chain's
    domains."""
    links = _hops(entries)
    chains: list[tuple[set[str], bool, int]] = []
    for start in links:
        cur, depth, seen = start, 0, set()
        domains: set[str] = set()
        end_download = False
        while cur is not None and cur not in seen and depth < 8:
            seen.add(cur)
            depth += 1
            e = entries[cur]
            if e["host"]:
                domains.add(registrable(e["host"]))
            nxt = links.get(cur)
            if nxt is None:
                # Last entry of this chain on the record. It is the
                # download when it carries the file itself, or when its
                # redirect Location names a file outside the capture.
                if _is_attachment(e):
                    end_download = True
                else:
                    try:
                        name = urllib.parse.unquote(urllib.parse.urlparse(
                            e["redirect"] or "").path.rsplit("/", 1)[-1])
                    except ValueError:
                        name = ""
                    if DOUBLE_EXT_RE.search(name) or name.lower() \
                            .endswith(EXEC_EXTS):
                        end_download = True
                break
            cur = nxt
        chains.append((domains, end_download, start))
    return chains


def _page_third_parties(entries) -> list[tuple[int, set[str], bool]]:
    """Per page: index of its Document entry, third-party script origins,
    whether a download happened on that page."""
    pagemap: dict[str, int] = {}
    for idx, e in enumerate(entries):
        if e["rtype"] == "Document" and e["host"] \
                and e["pageref"] not in pagemap:
            pagemap[e["pageref"]] = idx
    out = []
    for ref, page_idx in pagemap.items():
        page_dom = registrable(entries[page_idx]["host"])
        third: set[str] = set()
        download = False
        for e in entries:
            if e["pageref"] != ref:
                continue
            if e["host"] and e["rtype"] in ("Script", "Stylesheet") \
                    and registrable(e["host"]) != page_dom:
                third.add(registrable(e["host"]))
            if _is_attachment(e):
                download = True
        if third:
            out.append((page_idx, third, download))
    return out


# -------------------------------------------------------------- downloads

def downloads_findings(home, limit=DOWNLOADS_MAX_FILES) -> list[dict]:
    """New files in the Downloads folder that look like delivery payloads.

    Name rules first (cheap, deterministic), then the shell's own verdict
    on the handful that look like programs. Archive inspection reads only
    the list of names inside — no extraction ever happens here."""
    root = pathlib.Path(home) / "Downloads"
    try:
        files = [p for p in root.iterdir() if p.is_file()]
    except OSError:
        return []
    files.sort(key=_mtime_of, reverse=True)
    out: list[dict] = []
    now = _now_epoch()
    for p in files:
        if len(out) >= limit:
            break
        try:
            age_days = (max(0.0, now - p.stat().st_mtime)) // 86400
        except OSError:
            continue
        if age_days > DOWNLOADS_WINDOW_DAYS:
            break
        out.extend(_one_download(p))
    return out


def _mtime_of(p: pathlib.Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def _one_download(p: pathlib.Path) -> list[dict]:
    name = p.name
    path = str(p)
    if DOUBLE_EXT_RE.search(name):
        return [_download_finding(
            "download-double-extension",
            "A hazard-named file is in the Downloads folder",
            f"“{_clip(name, 120)}” carries a doubled ending - a document "
            "name with a program ending after it, the most common "
            "disguise for a malicious attachment.",
            "HIGH", "confirmed", path, name,
            "name pattern (double extension)", confidence="high")]
    low = name.lower()
    if low.endswith(EXEC_EXTS):
        verified = _looks_executable(p)
        return [_download_finding(
            "download-executable",
            "A program file is in the Downloads folder",
            f"“{_clip(name, 120)}” is a program file in Downloads"
            + (" and its contents verify it is one" if verified
               else " - flagged by name alone"),
            "HIGH" if verified else "MEDIUM",
            "confirmed" if verified else "lead", path, name,
            "file type" if verified else "name pattern (program file)",
            confidence="high" if verified else "medium")]
    if low.endswith(ARCHIVE_EXTS):
        inner = _zip_hazards(p)
        if inner:
            return [_download_finding(
                "download-archive-hazard",
                "An archive in Downloads contains a disguised program",
                f"“{_clip(name, 120)}” holds"
                f" {_clip(', '.join(inner), 160)} inside - a program hiding "
                "behind a document name, packed to slip past scanners.",
                "HIGH", "confirmed", path, name,
                "archive holds a renamed program", confidence="high")]
    return []


def _now_epoch() -> float:
    return _dt.datetime.now().timestamp()


def _looks_executable(path) -> bool:
    """Ask the shell what the file really is — the honest check behind the
    name. An unavailable tool simply means the name alone is the evidence."""
    probe = shutil.which("file")
    if not probe:
        return False
    try:
        out = subprocess.run([probe, "-b", "--", str(path)],
                             capture_output=True, text=True,
                             timeout=8).stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False
    return any(t in out for t in ("executable", "ms windows shortcut",
                                  "pe32", "elf ", "batch file", "ms-dos"))


def _zip_hazards(path, max_bytes=100 * 1024 * 1024,
                 max_entries=200) -> list[str]:
    hazards: list[str] = []
    try:
        if path.stat().st_size > max_bytes:
            return hazards
        with zipfile.ZipFile(path) as z:
            for info in z.namelist()[:max_entries]:
                base = info.rsplit("/", 1)[-1]
                if DOUBLE_EXT_RE.search(base):
                    hazards.append(base)
                    if len(hazards) >= 4:
                        break
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError,
            NotImplementedError):
        return hazards
    return hazards


# -------------------------------------------------------------- browser

_CHROMIUM_ROOTS = ("google-chrome", "chromium", "BraveSoftware",
                   "microsoft-edge", "vivaldi", "opera")


def history_downloads(home, limit=200) -> list[dict]:
    """Recorded browser downloads from Chromium-family history databases.

    The database is opened strictly through a copy, so the live browser is
    never touched and a locked database never blocks the hunt. Firefox's
    own history is read separately, in hunter/firefox.py.
    Returns [{path, host, ts}] rows, newest first."""
    out = []
    cfg = pathlib.Path(home) / ".config"
    for root in _CHROMIUM_ROOTS:
        base = cfg / root
        if not base.is_dir():
            continue
        for hist in sorted(base.glob("*/History")):
            out.extend(_chrome_history(hist, limit - len(out)))
            if len(out) >= limit:
                return out
    return out


def _chrome_history(path, limit) -> list[dict]:
    if limit <= 0:
        return []
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite",
                                         delete=False) as fh:
            tmp = pathlib.Path(fh.name)
        shutil.copyfile(path, tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            cur = conn.execute(
                "SELECT target_path, tab_url, start_time FROM downloads "
                "ORDER BY start_time DESC LIMIT ?", (limit,))
            rows = []
            for target, tab_url, start in cur.fetchall():
                # Chromium epochs are microseconds since 1601; anything
                # unreadable simply carries an empty timestamp.
                try:
                    ts = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc) \
                        + _dt.timedelta(microseconds=int(start))
                except (TypeError, OverflowError, ValueError):
                    ts = None
                rows.append({"path": str(target or ""),
                             "host": _clip(tab_url, 200),
                             "ts": ts.isoformat() if ts else ""})
            return rows
        finally:
            conn.close()
    except (OSError, sqlite3.Error, ValueError):
        return []
    finally:
        if tmp is not None:
            pathlib.Path(tmp).unlink(missing_ok=True)


# ------------------------------------------------------- persistence hunt

_PERSIST_RE = re.compile(
    r"(/tmp/|/dev/shm|/Downloads/|curl\s|wget\s|python\d?\s+-c\s)", re.I)

_OTHER_PERSIST_RE = re.compile(
    r"(/Downloads/|curl\s|wget\s|python\d?\s+-c\s)", re.I)

# The scratch-space path tokens a line touches, so a vetting pass can
# tell a user's flock -n /tmp/name.lock cron hygiene apart from a
# payload path.
_SCRATCH_PATH_RE = re.compile(r"(?:/tmp/|/dev/shm/?)\S*")
_TOKEN_JUNK_RE = re.compile(r"[\"';,)\]]+$")


def _dropper_line(line: str) -> bool:
    """Whether a startup-automation line still reads as a dropper.

    A flock lock file is bookkeeping, not payload: the only scratch
    space a healthy job touches is its own *<something>.lock. Downloads,
    fetchers, inline code, and any /tmp or /dev/shm token that is not a
    .lock file stay findings."""
    if not _PERSIST_RE.search(line):
        return False
    if _OTHER_PERSIST_RE.search(line):
        return True
    for token in _SCRATCH_PATH_RE.findall(line):
        if not _TOKEN_JUNK_RE.sub("", token).endswith(".lock"):
            return True
    return False


def persistence_findings(home, max_files=60) -> list[dict]:
    """User startup automation pointing at scratch folders or fetchers.

    A crontab line, autostart entry, or systemd --user unit that touches
    /tmp, /dev/shm, or Downloads, or pulls from the network with curl or
    wget, is the cheapest common persistence. Everything is read-only."""
    surfaces = (
        ("user crontab", _crontab_lines()),
        ("autostart entries", _startup_files(home, ".config/autostart",
                                             "*.desktop", ("exec",),
                                             max_files)),
        ("user service units", _startup_files(home, ".config/systemd/user",
                                              "*.service", ("execstart",),
                                              max_files)),
    )
    out: list[dict] = []
    for label, rows in surfaces:
        if rows:
            # The subject carries a digest of the current lines, not the
            # bare surface name: a freshly planted entry is a genuinely
            # new subject and fires within its window, instead of hiding
            # behind "user crontab" for the suppression hours. The
            # evidence keeps the label (the real spool or autostart
            # location is not always knowable without reading deeper).
            digest = hashlib.sha1(
                "\n".join(rows).encode("utf-8", "replace")).hexdigest()[:12]
            subject = f"{label} #{len(rows)} lines #{digest}"
            if len(rows) == 1:
                verbs = "runs from a scratch folder or pulls from the network"
            else:
                verbs = "run from a scratch folder or pull from the network"
            what = (
                f"The {label} has {len(rows)} entr"
                f"{'y' if len(rows) == 1 else 'ies'} that {verbs} with "
                "curl or wget. Startup entries run again at every boot "
                "or login, so this is where an infection makes itself "
                "survive a reboot. The matching lines are in the facts.")
            out.append(finding(
                "persistence-scratch-path",
                "Startup automation points at a scratch or fetch location",
                what,
                "Check the entry: startup commands in scratch folders are "
                "how infections survive a reboot.", "HIGH",
                [{"source": "fs", "path": label, "ts": _now_iso()}],
                asset="host",
                facts=[f"path={subject}"]
                      + [f"{label}: {r[:180]}" for r in rows[:4]]))
    return out


def _crontab_lines() -> list[str]:
    probe = shutil.which("crontab")
    if not probe:
        return []
    try:
        res = subprocess.run([probe, "-l"], capture_output=True, text=True,
                             timeout=8)
    except (OSError, subprocess.SubprocessError):
        return []
    return [line.strip() for line in res.stdout.splitlines()
            if not line.strip().startswith("#") and _dropper_line(line)]


def _startup_files(home, rel, pattern, prefixes, max_files) -> list[str]:
    rows: list[str] = []
    try:
        files = sorted((pathlib.Path(home) / rel).glob(pattern))
    except OSError:
        return []
    for f in files[:max_files]:
        try:
            text = f.read_text(errors="replace")[:20000]
        except OSError:
            continue
        for line in text.splitlines():
            if not line.strip().lower().startswith(prefixes):
                continue
            if _dropper_line(line):
                rows.append(f"{f.name}: {line.strip()}")
    return rows


# ---------------------------------------------------- event correlation

_EXEC_EVENT_RE = re.compile(r"(exec|execve|started|spawned?)", re.I)


def exec_in_downloads(events, max_rows=800) -> list[dict]:
    """Programs run out of the Downloads folder, from event telemetry.

    The rule that joins host telemetry with web delivery: a program that
    arrived as a download and then ran."""
    out = []
    for e in events[-max_rows:]:
        if e.get("from_tool") not in ("tetragon", "auditd"):
            continue
        text = str(e.get("text") or "")
        m = re.search(r"(/home/[^/\s]+/Downloads/\S+)", text)
        if not m or not _EXEC_EVENT_RE.search(text):
            continue
        out.append(finding(
            "download-executed",
            "A program from the Downloads folder was executed",
            f"{_clip(m.group(1), 200)} ran, per {e.get('from_tool')} "
            f"telemetry at {_clip(e.get('ts'), 32)}. Executed downloads are "
            "how web delivery turns into an infection.",
            "Quarantine the file and check what it belongs to before "
            "running anything else.", "HIGH",
            [{"source": "events", "tool": e.get("from_tool", ""),
              "ts": e.get("ts", ""), "text": _clip(text, 240)}],
            asset="host", facts=[f"path={_clip(m.group(1), 200)}"]))
    return out