"""Browser-config attack checks for the hunter.

A takeover rarely needs malware: an extension nobody installed, a "new"
default search provider, or a notification grant handed to a trick page
is the whole compromise. This module reads those preferences as untrusted
data (copies where a database has to be opened) and turns the shapes a
normal install does not produce into leads the user decides on.

Firefox's own search/homepage hijack lane lives in ``hunter/firefox.py``;
this module covers Chromium-family profiles plus Firefox's notification
permissions database, and the extensions inventory for both.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import shutil
import sqlite3
import tempfile

from hunter import firefox, web

_PREFERENCES_CAP = 4 * 1024 * 1024  # Preferences / Secure Preferences:
                                    # a 1 MB slice cut real mid-size
                                    # profiles into unreadable JSON
_EXTENSIONS_CAP = 200               # extension entries per profile
EXTENSION_GRANT_DAYS = 30           # fresh notification grants = suspect

# Chromium timestamps are microseconds since 1601, like the History DB.
_CHROMIUM_EPOCH_OFFSET_US = 11_644_473_600_000_000

# Engine names a normal Chromium install chooses; anything else is a lead.
_KNOWN_ENGINE_TOKENS = ("google", "bing", "duckduckgo", "duck", "startpage",
                        "brave", "ecosia", "qwant", "yahoo", "wikipedia",
                        "mojeek", "searx", "kagi", "yep", "presearch")
_SAFE_HOME_HOSTS = ("google.com", "bing.com", "brave.com", "duckduckgo.com",
                    "startpage.com")

_CHROMIUM_ROOTS = ("google-chrome", "chromium", "BraveSoftware",
                   "microsoft-edge", "vivaldi", "opera")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _now_us() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp() * 1_000_000)


# ------------------------------------------------------- the chromium lane

def config_findings(home, kept=()) -> list[dict]:
    out: list[dict] = []
    for prof in _chromium_profiles(home):
        out.extend(_chromium_profile_findings(prof, kept=kept))
    for prof in firefox._profiles(home):
        db = prof / "permissions.sqlite"
        if db.is_file():
            out.extend(_notification_rows(db, family="firefox"))
    return out


def history_docs(home, limit=300) -> list[dict]:
    """Recent browsing in each Chromium profile as plain docs for the
    pattern and intel lanes. Read-only through copies, like the config
    reads; a profile without a History file is silent."""
    out: list[dict] = []
    for prof in _chromium_profiles(home):
        db = prof / "History"
        if not db.is_file():
            continue
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".sqlite",
                                             delete=False) as fh:
                tmp = pathlib.Path(fh.name)
            shutil.copyfile(db, tmp)
            conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            try:
                cur = conn.execute(
                    "SELECT url, title FROM urls ORDER BY"
                    " last_visit_time DESC LIMIT ?", (limit,))
                for url, title in cur.fetchall():
                    url = str(url or "")
                    out.append({"url": url[:200],
                                "host": web.registrable(
                                    _host(url)),
                                "title": str(title or "")[:160],
                                "source": "history"})
            finally:
                conn.close()
        except (OSError, shutil.SameFileError, sqlite3.Error, ValueError):
            continue
        finally:
            if tmp is not None:
                pathlib.Path(tmp).unlink(missing_ok=True)
        if len(out) >= limit:
            break
    return out[:limit]


def _host(url: str) -> str:
    import urllib.parse
    return (urllib.parse.urlparse(url).hostname or "").strip().lower()


def _chromium_profiles(home) -> list[pathlib.Path]:
    base = pathlib.Path(home) / ".config"
    profs: list[pathlib.Path] = []
    for root in _CHROMIUM_ROOTS:
        tree = base / root
        try:
            if tree.is_dir():
                profs.extend(p for p in tree.iterdir() if p.is_dir())
        except OSError:
            continue
    return profs


def _chromium_profile_findings(prof, kept=()) -> list[dict]:
    out = _extensions(prof, kept=kept)
    prefs = _merged_json(prof)
    if prefs is None:
        return out
    out.extend(_search_hijack(prefs))
    out.extend(_notification_grants(prefs))
    return out


def _merged_json(prof) -> dict | None:
    """Preferences, then Secure Preferences layered on top: the two files
    share a schema, and Chromium salts the protected half in the second.
    Values read here are advisory; the finding never follows them."""
    merged: dict = {}
    for name in ("Preferences", "Secure Preferences"):
        p = prof / name
        try:
            if p.is_file():
                doc = json.loads(
                    p.read_text(errors="replace")[:_PREFERENCES_CAP])
                merged.update(doc if isinstance(doc, dict) else {})
        except (OSError, ValueError):
            continue
    return merged or None


def _search_hijack(prefs) -> list[dict]:
    out: list[dict] = []
    dsp = prefs.get("default_search_provider_data")
    if isinstance(dsp, dict):
        data = dsp.get("template_url_data")
        if isinstance(data, dict):
            name = str(data.get("short_name") or "")
            if name and _engine_suspect(name):
                out.append(_hijack("default search engine", name, "HIGH"))
    session = prefs.get("session")
    if isinstance(session, dict) and session.get("restore_on_startup") == 4:
        urls = session.get("startup_urls")
        if isinstance(urls, list):
            bad = [str(u) for u in urls[:8] if _home_suspect(str(u))]
            if bad:
                out.append(_hijack("startup pages", ", ".join(bad),
                                   "MEDIUM"))
    # A user-set plain homepage is ordinary; the shapes a hijacker
    # needs are the engine name and the "open these pages" startup mode.
    return out


def _notification_grants(prefs) -> list[dict]:
    out: list[dict] = []
    profile = prefs.get("profile")
    if not isinstance(profile, dict):
        return out
    cs = profile.get("content_settings")
    if not isinstance(cs, dict):
        return out
    exceptions = cs.get("exceptions")
    if not isinstance(exceptions, dict):
        return out
    notifs = exceptions.get("notifications")
    if not isinstance(notifs, dict):
        return out
    for origin, entry in list(notifs.items())[:_EXTENSIONS_CAP]:
        if not isinstance(entry, dict) or entry.get("setting") != 1:
            continue
        when = _chromium_epoch_to_us(entry.get("last_modified"))
        if when is None:
            continue
        age_days = (int(_now_us()) - when) / 86_400_000_000
        if age_days > EXTENSION_GRANT_DAYS:
            continue
        site = str(origin).split(",")[0]
        out.append(_grant_finding("chromium", site,
                                  f"{int(max(0.0, age_days)) + 1} days old"))
    return out


def _chromium_epoch_to_us(value) -> int | None:
    """Chromium epochs are microseconds since 1601; the offset is the
    same constant the History reader's datetime math walks around."""
    try:
        return int(value) - _CHROMIUM_EPOCH_OFFSET_US
    except (TypeError, OverflowError, ValueError):
        return None


def _extensions(prof, kept=()) -> list[dict]:
    out: list[dict] = []
    folder = prof / "Extensions"
    if not folder.is_dir():
        return out
    try:
        ext_ids = [d for d in folder.iterdir() if d.is_dir()]
    except OSError:
        return out
    for ext in sorted(ext_ids, key=lambda d: d.name)[:_EXTENSIONS_CAP]:
        # The profile's Extensions/<name>/ directory IS the extension id
        # (versions nest inside), so a keep entry on file suppresses the
        # same extension across its own updates.
        if ext.name in kept:
            continue
        manifest = _newest_manifest(ext)
        if manifest is None:
            continue
        name = str(manifest.get("name") or ext.name)[:120]
        out.append(web.finding(
            "cfg-new-extension",
            "A browser extension is installed on this computer",
            f"“{name or web._clip(ext.name, 60)}” is present in the "
            "browser's extension list. Extensions can read every page "
            "they act on - every entry here is worth knowing, and any "
            "one you did not choose yourself is a lead.",
            "Review it in the browser's extensions page; remove anything "
            "you do not recognise.", "HIGH",
            [{"source": "chromium-extensions", "ext_id": ext.name[:60],
              "ts": _now_iso()}],
            facts=[f"ext={ext.name[:120]}", f"name={name}"]))
    return out


def _newest_manifest(ext_dir) -> dict | None:
    try:
        versions = sorted(ext_dir.iterdir(), key=lambda d: d.name)[-1:]
    except OSError:
        return None
    for ver in versions:
        mpath = ver / "manifest.json"
        try:
            doc = json.loads(mpath.read_text(errors="replace")[:65536])
            return doc if isinstance(doc, dict) else None
        except (OSError, ValueError):
            continue
    return None


# ------------------------------------------------------- the firefox lane

def _notification_rows(db, family="firefox") -> list[dict]:
    """A permission grant handed to a site is a takeover primitive: fresh
    ``desktop-notification`` grants (< 30 days) are the suspect shape."""
    out: list[dict] = []
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite",
                                         delete=False) as fh:
            tmp = pathlib.Path(fh.name)
        shutil.copyfile(db, tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            cur = conn.execute(
                "SELECT origin, modificationTime FROM moz_perms"
                " WHERE type = 'desktop-notification' AND permission = 1"
                " LIMIT ?", (_EXTENSIONS_CAP,))
            for origin, mod in cur.fetchall():
                mod_us = int(mod or 0)
                if mod_us and abs(mod_us) < 10**14:
                    # Firefox keeps modificationTime in MILLISECONDS - a
                    # value that small cannot be microseconds since the
                    # epoch (which sit around 1.8e15), so scale it up.
                    # The ms assumption turned every real Firefox grant
                    # into an age of ~20,700 days: the lane answered
                    # nothing, on any profile, ever.
                    mod_us *= 1000
                age_days = (int(_now_us()) - mod_us) / 86_400_000_000
                if age_days > EXTENSION_GRANT_DAYS:
                    continue
                out.append(_grant_finding(
                    "firefox", str(origin or ""),
                    f"{int(max(0.0, age_days)) + 1} days old"))
        finally:
            conn.close()
    except (OSError, shutil.SameFileError, sqlite3.Error, ValueError):
        return out
    finally:
        if tmp is not None:
            pathlib.Path(tmp).unlink(missing_ok=True)
    return out


# ------------------------------------------------------------ shared bits

def _engine_suspect(name) -> bool:
    low = name.lower()
    return not any(tok in low for tok in _KNOWN_ENGINE_TOKENS)


def _home_suspect(url) -> bool:
    host = url.rpartition("//")[2].split("/")[0].rpartition("@")[2] \
        .partition(":")[0] if "//" in url else url.split("/")[0]
    if not host or host.startswith("about:"):
        return False
    reg = web.registrable(host)
    # Dot boundaries: "evilgoogle.com" is not google's domain.
    return not any(reg == s or reg.endswith("." + s)
                   for s in _SAFE_HOME_HOSTS)


def _hijack(which, value, severity) -> dict:
    return web.finding(
        "cfg-search-hijack",
        "The browser's own defaults point somewhere unexpected",
        f"The {which} is set to “{web._clip(value, 160)}” - not a "
        "default a normal install chooses. Hijacked search and start "
        "pages are how browser infections cash in.",
        "If you did not set it, reset the default in the browser's "
        "settings and review the extensions list.",
        severity, [{"source": "browser-prefs", "which": which,
                    "value": web._clip(value, 200), "ts": _now_iso()}],
        facts=[f"{which}={web._clip(value, 200)}"])


def _grant_finding(family, origin, age_text) -> dict:
    return web.finding(
        "cfg-notification-grant",
        "A fresh notification permission was granted to a site",
        f"“{web._clip(origin, 160)}” was granted desktop notifications "
        f"in {family} ({age_text}). Notification scams ask for exactly "
        "this, then push fake warnings long after the tab is closed.",
        "Revoke it in the browser's site-permission settings unless you "
        "chose it on purpose.", "MEDIUM",
        [{"source": f"{family}-permissions", "origin": web._clip(origin, 200),
          "ts": _now_iso()}],
        facts=[f"origin={web._clip(origin, 200)}", f"age={age_text}",
               f"family={family}"])