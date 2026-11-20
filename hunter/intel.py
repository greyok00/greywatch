"""The intel updater - pull-only, keyless threat feeds joined to the
machine's own web evidence.

Two keyless sources: openphish (a plain list of live phishing URLs) and
phishing-army (a plain domain blocklist aggregated from several phishing
intelligence sources). abuse.ch's urlhaus and threatfox used to be the
CSV pulls here, but abuse.ch retired their keyless downloads - the paths
answer HTTP 410 and ask references to be removed - so they were dropped
on. Each feed is fetched on a slow interval, held under a
hard size cap, parsed strictly, and cached under the hunter data dir
with a sha256 and a last-ok stamp in ``status.json``. Nothing is ever
pushed anywhere; the join step only reads what was cached and what the
machine already touched, and its findings cite the feed and the feed's
age so a stale cache never masquerades as fresh truth.
"""
from __future__ import annotations

import csv
import hashlib
import json
import pathlib
import time
import urllib.parse
import urllib.request

import status
from hunter import web

FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "phishing-army":
        "https://phishing.army/download/phishing_army_blocklist.txt",
}
FEED_MAX_BYTES = 5 * 1024 * 1024       # one feed, hard cap
INTERVAL_S = 12 * 3600                 # feeds at most twice a day
FETCH_TIMEOUT_S = 20.0
ROWS_MAX = 300_000                     # per feed in the parsed cache -
                                       # a bound ABOVE what a 5 MB feed
                                       # can hold, not a positional slice:
                                       # the old 3000 kept only the head
                                       # of phishing-army's ~100k hosts,
                                       # so hosts deeper in the file were
                                       # never joinable
RULE = "intel-feed-match"


def intel_dir(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "hunter" / "intel"


# ------------------------------------------------------------------ clock

def _now_epoch() -> float:
    return time.time()


def _now() -> float:
    return _now_epoch()


def _iso(ts=None) -> str:
    import datetime as _dt
    return _dt.datetime.fromtimestamp(
        float(ts if ts is not None else _now_epoch()),
        _dt.timezone.utc).isoformat(timespec="seconds")


def _age_h(iso: str) -> int:
    try:
        import datetime as _dt
        ts = _dt.datetime.fromisoformat(str(iso))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_dt.timezone.utc)
        return max(0, int((_now_epoch() - ts.timestamp()) / 3600))
    except (ValueError, TypeError, OverflowError):
        return -1


# ------------------------------------------------------------------ fetch

def fetch_body(url, cap, timeout=FETCH_TIMEOUT_S) -> str | None:
    """The feed body as text, or None when the network failed. Reads at
    most ``cap + 1`` bytes - the one extra byte is the oversize signal,
    and refresh rejects it; nothing oversized is ever decoded in full."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = r.read(cap + 1)
    except (OSError, ValueError):
        return None
    return body.decode("utf-8", "replace")


# ----------------------------------------------------------------- parsing

def _rows_openphish(text: str) -> list[dict]:
    out = [{"value": line.strip(), "kind": "url"}
           for line in text.splitlines() if line.strip().startswith("http")]
    return _dedupe(out)


def _rows_phishing_army(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "://" in line:
            continue
        out.append({"value": line, "kind": "host"})
    return _dedupe(out)


_PARSERS = {"openphish": _rows_openphish, "phishing-army":
            _rows_phishing_army}


def _dedupe(rows: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for r in rows:
        value = str(r.get("value") or "").strip().lower()
        if not value:
            continue
        seen.setdefault(f'{r.get("kind")}|{value}', {"value": value,
                                                     "kind": r.get("kind")})
    return list(seen.values())[:ROWS_MAX]


# ---------------------------------------------------------------- refresh

def read_status(data_dir) -> dict:
    try:
        doc = json.loads((intel_dir(data_dir) / "status.json").read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def status_path(data_dir) -> pathlib.Path:
    return intel_dir(data_dir) / "status.json"


def _load_cache(data_dir, feed) -> dict | None:
    try:
        doc = json.loads((intel_dir(data_dir) / f"{feed}.json").read_text())
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and isinstance(doc.get("rows"), list) \
        else None


def refresh(data_dir, cfg, now=None) -> dict:
    """Fetch what is due, cache what parsed, and stamp the status. A feed
    that fails keeps its previous cache; only a clean parse replaces it."""
    data_dir = pathlib.Path(data_dir)
    if isinstance(cfg, dict) and cfg.get("intel_enabled") is False:
        return read_status(data_dir)
    now_ts = _now_epoch() if now is None else float(now)
    stamp = read_status(data_dir)
    last_ok = 0.0
    try:
        import datetime as _dt
        last_ok = _dt.datetime.fromisoformat(
            str(stamp.get("last_ok") or "")).timestamp()
    except (ValueError, TypeError, OverflowError):
        last_ok = 0.0
    if now_ts - last_ok < INTERVAL_S:
        return stamp

    intel_dir(data_dir).mkdir(parents=True, exist_ok=True)
    ages: dict[str, str] = dict(stamp.get("ages") or {})
    kept: dict[str, str] = dict(stamp.get("rows") or {})
    errors: dict[str, str] = {}
    ok_at = 0.0
    for feed, url in FEEDS.items():
        try:
            body = fetch_body(url, FEED_MAX_BYTES)
        except Exception:                     # noqa: BLE001 - feed failure
            body = None                        # is never a hunt stopper
        if body is None:
            errors[feed] = "fetch"
            continue
        if len(body) > FEED_MAX_BYTES:
            errors[feed] = "oversize"
            continue
        try:
            rows = _PARSERS[feed](body)
        except (KeyError, ValueError, csv.Error):
            rows = []
        if not rows:
            errors[feed] = "parse"
            continue
        doc = {"feed": feed, "fetched": _iso(now_ts),
               "sha256": hashlib.sha256(
                   body.encode("utf-8", "replace")).hexdigest(),
               "rows": rows}
        out = intel_dir(data_dir) / f"{feed}.json"
        try:
            status.atomic_replace(str(out), json.dumps(doc,
                                                       separators=(",", ":")))
        except (OSError, ValueError):
            errors[feed] = "write"
            continue
        ages[feed] = doc["fetched"]
        kept[feed] = f"{len(rows)} rows"
        ok_at = now_ts
    next_state = {"ages": ages, "rows": kept}
    if ok_at:
        next_state["last_ok"] = _iso(now_ts)
    else:
        next_state["last_ok"] = str(stamp.get("last_ok") or "")
    if errors:
        next_state["errors"] = errors
    try:
        status.atomic_replace(str(status_path(data_dir)),
                              json.dumps(next_state, separators=(",", ":")))
    except (OSError, ValueError):
        pass
    return next_state


# ------------------------------------------------------------------- join

def _host_of(value: str) -> str:
    try:
        parsed = urllib.parse.urlparse(str(value or ""))
        host = (parsed.hostname or "").strip().lower()
    except ValueError:
        host = ""
    return host.removeprefix("www.") if host else ""


def _candidates(docs) -> list[dict]:
    """Docs trimmed to what a join can use: host and url, deduped."""
    out: list[dict] = []
    seen: set[str] = set()
    for d in docs or []:
        if not isinstance(d, dict):
            continue
        host = str(d.get("host") or "").strip().lower().removeprefix("www.")
        url = str(d.get("url") or "").strip()
        if not host and url:
            host = _host_of(url)
        if not host:
            continue
        key = f"{host}|{url}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"host": host, "url": url})
    return out


def join_findings(data_dir, docs) -> list[dict]:
    """One finding per unique host the cached feeds also list. The
    finding cites the feed by name and the feed's age in hours, so a
    reader can see exactly how fresh the intelligence was."""
    hosts_index: dict[str, dict] = {}     # host -> {feed: fetched}
    for feed in FEEDS:
        cache = _load_cache(data_dir, feed)
        if not cache:
            continue
        fetched = str(cache.get("fetched") or "")
        for row in cache.get("rows", []):
            if not isinstance(row, dict):
                continue
            value = str(row.get("value") or "")
            host = value if row.get("kind") == "host" else _host_of(value)
            if host:
                hosts_index.setdefault(host, {})[feed] = fetched
    out: list[dict] = []
    seen_hosts: set[str] = set()
    for cand in _candidates(docs):
        feeds = hosts_index.get(cand["host"])
        if not feeds or cand["host"] in seen_hosts:
            continue
        seen_hosts.add(cand["host"])
        named = sorted(feeds)
        names = " and ".join(named)
        ages = [_age_h(feeds[n]) for n in named]
        if any(a < 0 for a in ages):
            # An unparsable cache stamp must not masquerade as fresh
            # intel ("just now" would lie); it reads as unknowable age.
            age = -1
            age_text = "an unknown time"
        else:
            age = max(ages)
            age_text = "just now" if age == 0 else f"{age}h ago"
        evidence = [{"source": "intel", "feed": n,
                     "host": web._clip(cand["host"], 120),
                     "url": web._clip(cand["url"], 200),
                     "ts": web._now_iso()} for n in named]
        out.append(web.finding(
            RULE, "Attack intel matched this machine's web activity",
            f"{cand['host']} appears in the {names} feed, which listed it "
            f"as live attack infrastructure; the feed was pulled "
            f"{age_text} and the address was seen here too.",
            "Nothing on this machine acted on its own. Check what reached "
            "this address - a page, a download, or a link - and do not "
            "re-open it; the assistant can help review the trail.",
            "HIGH", evidence, confidence="medium",
            facts=[f"host={web._clip(cand['host'], 120)}",
                   f"feeds={'+'.join(named)}",
                   f"feed-age={'unknown' if age < 0 else str(age) + 'h'}"]))
    return out