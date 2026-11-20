"""Firefox lanes for the hunter: download history and pref hijacks.

Firefox records its downloads as ``moz_annos`` rows inside
``places.sqlite`` and its search/homepage defaults as ``user_pref`` lines
in ``prefs.js``. Both are read strictly through copies, the same way the
Chromium reader copies ``History``: the live browser is never touched and
a locked profile never blocks the hunt. This closes the Firefox gap the
web module's report used to state.

Everything parsed here is untrusted data; only rule matches become
findings, and each finding names the evidence it matched.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re
import shutil
import sqlite3
import tempfile
import urllib.parse

from hunter import web

PROFILE_ROOT = ".mozilla/firefox"
HISTORY_LIMIT = 200
PREFS_MAX_BYTES = 200 * 1024

_PREF_LINE_RE = re.compile(
    r'user_pref\("([^"]+)",\s*"?([^"\\]*(?:\\.[^"\\]*)*)"?\s*\)')

# Engine names a Firefox profile normally carries. A default engine whose
# name matches none of these is a lead, not proof - bundled OEM engines
# exist, so the finding says what was found and lets the user decide.
_KNOWN_ENGINE_TOKENS = ("google", "bing", "duckduckgo", "duck", "startpage",
                        "brave", "ecosia", "qwant", "yahoo", "wikipedia",
                        "mojeek", "searx", "kagi", "ecosia", "yep", "presearch")
_SAFE_HOME_HOSTS = ("mozilla.org", "firefox.com", "about:", "startpage.com",
                    "duckduckgo.com", "google.com", "bing.com", "brave.com",
                    "mojeek.com", "qwant.com", "kagi.com", "perplexity.ai",
                    "search.brave.com")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _now_us() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp() * 1_000_000)


def _profiles(home) -> list[pathlib.Path]:
    base = pathlib.Path(home) / PROFILE_ROOT
    try:
        return sorted(p for p in base.iterdir()
                      if p.is_dir() and not p.name.endswith(".tmp"))
    except OSError:
        return []


# ------------------------------------------------------- download history

def history_findings(home, limit=HISTORY_LIMIT) -> list[dict]:
    """Hazard names in Firefox's recorded downloads.

    Reads a copy of each profile's ``places.sqlite``; downloads live as
    ``moz_annos`` rows whose attribute name starts with ``downloads/``.
    The window is the same ``DOWNLOADS_WINDOW_DAYS`` the Downloads and
    Chromium lanes use: older records stay history, not alerts."""
    out: list[dict] = []
    seen_urls: set[str] = set()
    for prof in _profiles(home):
        db = prof / "places.sqlite"
        if not db.is_file():
            continue
        for row in _download_rows(db, limit):
            url = str(row.get("url") or "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            f = _history_finding(row)
            if f is not None:
                out.append(f)
            if len(out) >= limit:
                break
    return out


def history_docs(home, limit=HISTORY_LIMIT) -> list[dict]:
    """Recent browsing as plain docs for the pattern and intel lanes:
    url, host, and the page title the browser remembers. Read-only, and
    only through a copy, like every other places read."""
    out: list[dict] = []
    for prof in _profiles(home):
        db = prof / "places.sqlite"
        if not db.is_file():
            continue
        tmp = None                      # a temp file that never got made
        try:                            # (a full /tmp) must not hit an
            with tempfile.NamedTemporaryFile(suffix=".sqlite",  # unbound
                                             delete=False) as fh:   # name
                tmp = pathlib.Path(fh.name)
            shutil.copyfile(db, tmp)
            conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            try:
                cur = conn.execute(
                    "SELECT url, title FROM moz_places"
                    " WHERE url LIKE 'http%' ORDER BY last_visit_date"
                    " DESC LIMIT ?", (limit,))
                for url, title in cur.fetchall():
                    url = str(url or "")
                    host = (urllib.parse.urlparse(url).hostname
                            or "").strip().lower()
                    out.append({"url": url[:200], "host": host,
                                "title": str(title or "")[:160],
                                "source": "history"})
            finally:
                conn.close()
        except (OSError, shutil.SameFileError, sqlite3.Error, ValueError):
            continue
        finally:
            pathlib.Path(tmp).unlink(missing_ok=True)
        if len(out) >= limit:
            break
    return out[:limit]


def _download_rows(db, limit) -> list[dict]:
    rows: list[dict] = []
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite",
                                         delete=False) as fh:
            tmp = pathlib.Path(fh.name)
        shutil.copyfile(db, tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            cur = conn.execute(
                "SELECT p.url, a.content, a.dateAdded"
                " FROM moz_anno_attributes n"
                " JOIN moz_annos a ON a.anno_attribute_id = n.id"
                " JOIN moz_places p ON p.id = a.place_id"
                " WHERE n.name LIKE 'downloads%' AND p.url IS NOT NULL"
                " ORDER BY a.dateAdded DESC LIMIT ?", (limit,))
            for url, content, added in cur.fetchall():
                rows.append({"url": str(url),
                             "content": str(content or ""),
                             "added_us": added})
        finally:
            conn.close()
    except (OSError, shutil.SameFileError, sqlite3.Error, ValueError):
        return rows
    finally:
        if tmp is not None:
            pathlib.Path(tmp).unlink(missing_ok=True)
    return rows


def _target_name(url: str, content: str) -> str:
    """The download's file name: the annos' targetPath when present, else
    the last URL path segment."""
    try:
        data = json.loads(content)
    except ValueError:
        data = None
    if isinstance(data, dict):
        target = str(data.get("targetPath") or "")
        if target:
            return pathlib.PureWindowsPath(target).name or target
    return urllib.parse.unquote(urllib.parse.urlparse(url).path
                                .rsplit("/", 1)[-1])


def _row_age_ok(added_us, window_days=web.DOWNLOADS_WINDOW_DAYS) -> bool:
    try:
        _dt.datetime.fromtimestamp(int(added_us) / 1_000_000,
                                   tz=_dt.timezone.utc)
    except (TypeError, OverflowError, OSError, ValueError):
        return False
    age_days = (int(_now_us()) - int(added_us)) / 86_400_000_000
    return age_days <= max(0, window_days)


def _history_finding(row) -> dict | None:
    url = row["url"]
    added = row.get("added_us")
    if not _row_age_ok(added):
        return None
    name = _target_name(url, row["content"])
    if not name:
        return None
    ev = [{"source": "firefox-history", "url": web._clip(url, 200),
           "ts": _now_iso()}]
    if web.DOUBLE_EXT_RE.search(name):
        return web.finding(
            "ff-history-double-extension",
            "The browser's history records a hazard download",
            f"“{web._clip(name, 120)}” was downloaded in Firefox - a "
            "document name with a program ending after it, the most "
            "common malicious-attachment disguise.",
            "If the file still exists, treat it as untrusted; if not, ask "
            "whether it was ever opened.", "HIGH", ev,
            confidence="high", status="confirmed",
            facts=[f"path={url[:200]}"])
    if name.lower().endswith(web.EXEC_EXTS):
        return web.finding(
            "ff-history-executable",
            "The browser's history records a program download",
            f"“{web._clip(name, 120)}” arrived as a download in Firefox. "
            "Program files from the web are how most host compromises "
            "start.", "Treat it as untrusted before opening it.", "MEDIUM",
            ev, facts=[f"path={url[:200]}"])
    return None


# ----------------------------------------------------------- hijack lane

def hijack_findings(home) -> list[dict]:
    """Search-engine and homepage defaults that point somewhere unexpected.

    Firefox keeps them as plain ``user_pref`` lines. A value whose site is
    not one of the usual suspects is a lead; the finding shows the value,
    never follows it."""
    out: list[dict] = []
    for prof in _profiles(home):
        prefs = _read_prefs(prof / "prefs.js")
        if not prefs:
            continue
        home_page = prefs.get("browser.startup.homepage")
        override = prefs.get("browser.startup.homepage_override")
        engine = prefs.get("browser.search.defaultenginename")
        for label, value in (("homepage", home_page),
                             ("startup override", override)):
            if value and _home_suspect(value):
                out.append(_hijack_finding(label, value))
        if engine and _engine_suspect(engine):
            out.append(_hijack_finding("default search engine", engine))
    return out


def _read_prefs(path) -> dict:
    try:
        text = path.read_text(errors="replace")[:PREFS_MAX_BYTES]
    except OSError:
        return {}
    prefs: dict[str, str] = {}
    for m in _PREF_LINE_RE.finditer(text):
        key, val = m.group(1), m.group(2)
        if key in ("browser.startup.homepage",
                   "browser.startup.homepage_override",
                   "browser.search.defaultenginename"):
            prefs[key] = val
    return prefs


def _home_suspect(value: str) -> bool:
    if value.startswith("about:") or value.startswith("file://"):
        return False
    host = urllib.parse.urlparse(value).netloc.rpartition("@")[2] \
        .partition(":")[0]
    if not host:
        return bool(value.strip())
    reg = web.registrable(host)
    # Dot boundaries both ways: "evil-google.com" is not google's domain
    # and "google.com.evil.example" is not on the safe list either.
    return not any(reg == s or reg.endswith("." + s)
                   for s in _SAFE_HOME_HOSTS)


def _engine_suspect(name: str) -> bool:
    low = name.lower()
    return not any(tok in low for tok in _KNOWN_ENGINE_TOKENS)


def _hijack_finding(which: str, value: str) -> dict:
    return web.finding(
        "ff-hijack",
        "Firefox's own defaults point somewhere unexpected",
        f"The {which} is set to “{web._clip(value, 160)}” - not a default "
        "a normal install chooses. Homepage and engine hijacks are how "
        "browser infections cash in.",
        "If you did not set it, reset the default in Firefox's settings "
        "and review the extensions list.",
        "HIGH", [{"source": "firefox-prefs", "which": which,
                  "value": web._clip(value, 200), "ts": _now_iso()}],
        facts=[f"{which}={web._clip(value, 200)}"])