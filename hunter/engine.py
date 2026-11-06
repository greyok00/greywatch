"""The hunter's hypothesis engine.

Each cycle runs a fixed list of hypotheses — small, deterministic rules
over evidence the app already holds: the event store, the Downloads
folder, browser download history, startup automation, scan summaries, and
any HAR capture the user dropped in the inbox.

Facts are rule business: a rule that fires writes its own plain-language
finding with evidence. The explain layer only rewords findings the user
has not read yet; it never invents facts.

Dedupe and suppression keep this an *active* hunter without being a noisy
one: the same rule on the same subject does not repeat inside its
suppression window, but a genuinely new subject always fires.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib

from hunter import browsers, firefox, intel, patterns, store, web

EVENTS_WINDOW_LINES = 2000
SEEN_CAP = 2000

# Per-rule silence after the same subject fires once. Downloads stay quiet
# for a week (the file will still be sitting there); web leads re-raise
# after a day. ``0`` means never suppress — a signature hit only re-fires
# when the antivirus says so again. ``scan-positive`` gets a long window
# precisely because its subject file persists: the newest-6 summary sweep
# would otherwise re-announce the same finished scan every cycle.
SUPPRESS_HOURS = {
    "download-double-extension": 168,
    "download-executable": 168,
    "download-archive-hazard": 168,
    "browser-history-hazard": 168,
    "persistence-scratch-path": 72,
    "rootkit-warning": 72,
    "download-executed": 72,
    "har-double-extension": 24,
    "har-executable-download": 24,
    "har-archive-download": 24,
    "har-mime-wrap": 24,
    "har-redirect-to-download": 24,
    "har-third-party-kit": 24,
    "har-base64-post": 24,
    "har-raw-ip-websocket": 24,
    "malware-detected": 0,
    "scan-positive": 720,

    # The web wave's lanes. History-family rules keep the same quiet week
    # their Downloads twins have; hijacks and config drift get a week;
    # pattern-corpus leads re-raise after a day, like the other web leads.
    "ff-history-double-extension": 168,
    "ff-history-executable": 168,
    "ff-hijack": 168,
    "cfg-search-hijack": 168,
    "cfg-notification-grant": 168,
    "pat-fake-captcha": 24,
    "pat-tech-support-scam": 24,
    "pat-fake-update": 24,
    "intel-feed-match": 24,
    # A newly seen browser extension must not announce itself every
    # cycle for the rest of its life: the window is effectively never,
    # which is distinct from 0 (0 above means never suppress).
    "cfg-new-extension": 87600,
}
_DEFAULT_SUPPRESS_HOURS = 24


def _now() -> float:
    return _dt.datetime.now(_dt.timezone.utc).timestamp()


def _iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _mtime_of(p: pathlib.Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


# Facts that name a finding's subject, in the order emitters write them;
# facts whose value drifts between cycles (ages, counts) never are one.
_SUBJECT_FACT_KEYS = ("path", "scan_id", "ext", "origin", "host")
_SUBJECT_VOLATILE_KEYS = ("age", "family", "feed-age", "mime", "basis",
                          "real_findings", "frames", "body")


def subject_of(f: dict) -> str:
    """What this finding is about — the identity dedupe collapses on.

    A fact that names the subject (a path, a scan id, an extension id,
    an origin, a host) wins, so two different extensions or hijacks are
    two different subjects; then the evidence's own url or fs path;
    then the first stable fact; then the rule itself."""
    for fact in f.get("facts") or []:
        key, _, value = str(fact).partition("=")
        if key.strip().lower() in _SUBJECT_FACT_KEYS and _:
            return value
    for row in f.get("evidence") or []:
        if row.get("url"):
            return str(row["url"])
        if row.get("source") == "fs" and row.get("path"):
            return str(row["path"])
    stable = [str(fact) for fact in f.get("facts") or []
              if "=" in str(fact) and str(fact).partition("=")[0].strip()
              .lower() not in _SUBJECT_VOLATILE_KEYS]
    if stable:
        return stable[0]
    return f.get("rule", "?") + ":" + f.get("title", "")


# ------------------------------------------------------------- event tail

def read_events(path, saved: dict) -> tuple[list[dict], dict]:
    """Forward-only read of the daemon's events.jsonl.

    ``saved`` is the persisted ``events`` state entry: ``{"inode": int,
    "offset": int}``. Returns (new rows, new position). The first run and
    any rotation start at the end of the file — history is never replayed
    as new, because re-alerting on the past is exactly the noise the
    hunter must not make.
    """
    p = pathlib.Path(path)
    try:
        st = p.stat()
    except OSError:
        return [], saved if isinstance(saved, dict) else {}
    inode, size = st.st_ino, st.st_size
    saved_inode = int(saved.get("inode") or 0)
    start = int(saved.get("offset") or 0)
    if not saved_inode or start > size or inode != saved_inode:
        start = size  # first look, or the file was replaced: skip history
    if start == size:
        return [], {"inode": inode, "offset": size}
    try:
        with open(p, "rb") as fh:
            fh.seek(start)
            buf = fh.read(size - start + 1)
    except OSError:
        return [], {"inode": inode, "offset": start}
    # A torn last line (the daemon was mid-append) waits for its rest:
    # the offset stops at the last complete line so the row is re-read
    # whole on the next cycle instead of vanishing. `cut < 0` means the
    # buffer holds ONLY a partial head - keeping the old offset is what
    # honours that promise (advancing to size would strand the tail).
    cut = buf.rfind(b"\n")
    if cut < 0:
        return [], {"inode": inode, "offset": start}
    rows = []
    for line in buf[:cut + 1].decode("utf-8", "replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    # The window is a memory guard, not a fact: everything past it is
    # SKIPPED, never hunted over, and that count rides along as a
    # declared watermark (recovery audit A6) - before this a 2000-row
    # burst simply lost its older rows in silence.
    skipped = max(0, len(rows) - EVENTS_WINDOW_LINES)
    return rows[-EVENTS_WINDOW_LINES:], {"inode": inode,
                                         "offset": start + cut + 1,
                                         "skipped": skipped}


# ------------------------------------------------------------ hypotheses

def h_malware_hit(events, _home, _data_dir) -> list[dict]:
    """Scanner detections, already high-severity, translated verbatim."""
    out = []
    for e in events:
        tool = e.get("from_tool")
        text = str(e.get("text") or "")
        if tool == "clamav" and text.startswith("FOUND"):
            path = text[6:].strip()[:200] or "<unknown>"
            out.append(web.finding(
                "malware-detected", "The antivirus matched a real signature",
                f"ClamAV matched malicious code at “{path}” - a signature "
                "hit, the strongest single piece of evidence this stack "
                "produces.", "Quarantine the file now (the Hunter card "
                "can do it), then run a full scan to catch anything it "
                "dropped.", "HIGH",
                [{"source": "events", "tool": tool, "ts": e.get("ts", ""),
                  "text": text[:240]}], confidence="high",
                status="confirmed", asset="host",
                facts=[f"path={path}"]))
        elif tool == "rkhunter" and text.startswith(("Warning", "Susp")):
            out.append(web.finding(
                "rootkit-warning", "The rootkit checker raised a warning",
                f"rkhunter: {text[:160]}. Checker warnings are often "
                "benign - a changed config or updated binary - but real "
                "rootkits raise the same warnings, so every one deserves "
                "a look.", "Review what the warning names; if you changed "
                "that file yourself, update its baseline and clear it.",
                "HIGH", [{"source": "events", "tool": tool,
                          "ts": e.get("ts", ""), "text": text[:240]}],
                confidence="medium", asset="host",
                facts=[f"detail={text[:200]}"]))
    return out


def h_scan_positive(_events, _home, data_dir) -> list[dict]:
    """A finished scan whose non-routine findings count is above zero."""
    scans = pathlib.Path(data_dir) / "scans"
    try:
        docs = sorted(scans.glob("*.json"), key=_mtime_of, reverse=True)[:6]
    except OSError:
        return []
    out = []
    for doc in docs:
        try:
            data = json.loads(doc.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        if data.get("state") == "done" and data.get("real_findings", 0) > 0:
            sid = str(data.get("scan_id") or doc.stem)
            out.append(web.finding(
                "scan-positive", "A scan finished with findings that matter",
                f"Scan {sid} finished with {data.get('real_findings')} "
                "non-routine finding(s). Routine items (updates, config "
                "drift) already live in Reports; these need eyes.",
                "Open the run from Recent scans and read the non-routine "
                "findings first.", "MEDIUM",
                [{"source": "scan", "scan_id": sid}], asset="host",
                facts=[f"scan_id={sid}",
                       f"real_findings={data.get('real_findings')}"]))
    return out


def h_browser_history(_events, home, _data_dir) -> list[dict]:
    """Hazard names in recorded browser downloads — even after deletion."""
    out = []
    for row in web.history_downloads(home):
        path = row.get("path") or ""
        if not path:
            continue
        name = pathlib.Path(path).name
        if web.DOUBLE_EXT_RE.search(name):
            sev, basis = "HIGH", "double extension"
        elif name.lower().endswith(web.EXEC_EXTS):
            sev, basis = "MEDIUM", "program file"
        else:
            continue
        out.append(web.finding(
            "browser-history-hazard",
            "The browser's own history records a hazard download",
            f"“{name[:120]}” ({basis}) was downloaded via "
            f"{row.get('host') or 'an unknown page'} - even if the file "
            "has since been deleted, the record shows it happened.",
            "If the file still exists, treat it as untrusted; if not, ask "
            "whether it was ever opened.", sev,
            [{"source": "browser-history", "path": path,
              "host": row.get("host", ""), "ts": row.get("ts", "")}],
            asset="web", facts=[f"path={path[:200]}"]))
    out.extend(firefox.history_findings(home))
    return out


def h_browser_config(_events, home, data_dir) -> list[dict]:
    """What the browsers are set to do: hijacked homepages or search
    engines, a fresh extension, a fresh notification grant — all read
    from the browsers' own configuration files, nothing launched. The
    the keep ledger is read here, once per cycle, so a
    kept extension never reaches the rules again."""
    out = firefox.hijack_findings(home)
    out.extend(browsers.config_findings(
        home, kept=store.kept_extension_ids(data_dir)))
    return out


# ---------------------------------------------------------- web documents

HAR_DOCS_MAX = 4       # processed captures read into pattern/intel lanes
HISTORY_DOCS_MAX = 300


def _history_docs(home) -> list[dict]:
    """Recent browsing as plain docs: url, host, and (where the browsers
    keep it) the page title — the source the pattern corpus's title
    rules read. Both families take the same explicit bound."""
    docs = firefox.history_docs(home, limit=HISTORY_DOCS_MAX)
    docs.extend(browsers.history_docs(home, limit=HISTORY_DOCS_MAX))
    return docs


def _page_docs_from(parsed, source) -> list[dict]:
    """One parsed HAR as docs: every entry as itself, plus one aggregate
    doc per page so live-only rules can count frames and downloads. The
    aggregate's ``cdp`` flag is honest provenance: only documents the
    live watcher wrote (it names itself the creator) earn it, never an
    imported capture."""
    entries = parsed.get("entries") or []
    live = str(((parsed.get("creator") or {}).get("name") or "")) \
        == "greywatch-hunter"
    docs: list[dict] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        docs.append({"url": e.get("url"), "host": e.get("host"),
                     "mime": e.get("mime"), "source": source})
    pages: dict[str, dict] = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        page = str(e.get("pageref") or "")
        if not page:
            continue
        agg = pages.setdefault(
            page, {"url": e.get("url"), "host": e.get("host"),
                   "mime": e.get("mime"), "source": source,
                   "iframes": 0, "downloads": 0, "cdp": live})
        try:
            if e.get("rtype") == "Document" and agg.get("url") != \
                    e.get("url"):
                agg["iframes"] = int(agg.get("iframes") or 0) + 1
            if e.get("cd") and web._is_attachment(e):
                agg["downloads"] = int(agg.get("downloads") or 0) + 1
        except (TypeError, ValueError):
            continue
    docs.extend(pages.values())
    return docs


def _web_docs(data_dir, home) -> list[dict]:
    """Everything the web-patterns and intel lanes read, bounded: a few
    processed captures and a slice of recent browsing."""
    docs: list[dict] = []
    processed = store.processed_dir(data_dir)
    try:
        # Recency, not name order: a name-sorted tail drops any capture
        # whose name sorts below the live watchers' names ("Browser-Cap"
        # under "cdp-live-…") no matter how fresh it is.
        paths = sorted((p for p in processed.glob("*.har")
                        if p.is_file()),
                       key=lambda p: p.stat().st_mtime,
                       reverse=True)[:HAR_DOCS_MAX]
    except OSError:
        paths = []
    for p in paths:
        parsed = web.parse_har(p)
        if not parsed:
            continue
        docs.extend(_page_docs_from(parsed, "capture"))
    docs.extend(_history_docs(home))
    return docs


def h_web_patterns(_events, home, data_dir) -> list[dict]:
    """The delivery-pattern corpus over the machine's own web activity."""
    return patterns.apply_rules(_web_docs(data_dir, home))


def h_intel_join(_events, home, data_dir) -> list[dict]:
    """Cached intel feeds joined to the same docs the patterns read."""
    return intel.join_findings(data_dir, _web_docs(data_dir, home))


def h_cve_watch(events, _home, data_dir) -> list[dict]:
    """Wave C: events that name a flaw the active-rule engine tracks.

    The CVE cache is not just metadata - every HIGH+ flaw for a managed
    tool is an active rule, so an event mentioning the same CVE id gets
    the rule's severity, subject and next step joined onto it, instead of
    surfacing as an unlabeled string."""
    import re as _re
    try:
        from cverules import active_rules
        rules = {r["cve"]: r for r in
                 active_rules(pathlib.Path(data_dir) / "cve-cache.json")}
    except Exception:
        return []
    if not rules:
        return []
    out = []
    for e in events:
        text = str(e.get("text") or "")
        for cid in sorted(set(_re.findall(
                r"CVE-\d{4}-\d{4,7}(?!\d)", text))):
            rule = rules.get(cid)
            if not rule:
                continue
            out.append(web.finding(
                "known-cve-mention", rule["cve"] + " showed up in an event",
                f"An event on this machine mentions {cid}, and the active "
                f"rule list tracks it (score {rule.get('score', '?')} "
                f"{rule.get('severity', '')}): "
                f"{str(rule.get('summary') or '')[:180]}",
                "Check which program carries the flaw and whether the "
                "installed version includes the fix; the assistant can "
                "walk you through it.",
                rule.get("severity") or "HIGH",
                [{"source": "events", "tool": e.get("from_tool", ""),
                  "ts": e.get("ts", ""), "text": text[:240]}],
                confidence="medium", status="confirmed", asset="host",
                facts=[f"cve={cid}", f"matches={rule.get('tool', '')}"]))
    return out


def h_host_scan(events, home, _data_dir) -> list[dict]:
    """The host side: the Downloads folder, startup automation, and any
    program that arrived as a download and then ran."""
    out = web.downloads_findings(home)
    out.extend(web.persistence_findings(home))
    out.extend(web.exec_in_downloads(events))
    return out


HYPOTHESES = (
    ("events-detections", h_malware_hit, True),      # only on new events
    ("scan-summaries", h_scan_positive, False),      # every cycle
    ("downloads-and-persistence", h_host_scan, True),# only on new events
    ("browser-history", h_browser_history, False),   # every cycle, capped
    ("browser-config", h_browser_config, False),     # every cycle, bounded
    ("web-patterns", h_web_patterns, False),         # every cycle, bounded
    ("intel-join", h_intel_join, False),             # every cycle, cached
    ("cve-watch", h_cve_watch, True),                # only on new events
)


# ------------------------------------------------------------ dedupe/supp

def _suppress_window(f: dict) -> int:
    """Hours this rule stays quiet after firing. A pattern rule's own
    ``window_hours`` (validated with the rule) is the primary source -
    the rules file is one place to edit - and the engine's table only
    keeps the rules that predate it."""
    rule = f.get("rule", "")
    if rule.startswith("pat-"):
        declared = patterns.window_hours().get(rule)
        if declared is not None:
            return declared
    return SUPPRESS_HOURS.get(rule, _DEFAULT_SUPPRESS_HOURS)


def apply_dedupe(seen: dict, new_findings: list[dict]) -> tuple[list[dict],
                                                                dict]:
    """Drop repeats against the seen map and each rule's suppression
    window. ``seen`` maps dedupe key → ISO last-fired; returned trimmed."""
    now = _now()
    iso = _iso()
    kept = []
    for f in new_findings:
        key = store.dedup_key(f.get("rule", ""), subject_of(f))
        last = seen.get(key)
        if last:
            # Both sides in hours — _age_hours returns hours, so the
            # window must not be rescaled to seconds here.
            window_h = _suppress_window(f)
            if window_h and _age_hours(last, now) < window_h:
                continue
        seen[key] = iso
        kept.append(f)
    trimmed = dict(sorted(seen.items(), key=_fire_time)[:SEEN_CAP])
    return kept, trimmed


def _fire_time(item) -> float:
    try:
        return _dt.datetime.fromisoformat(item[1]).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _age_hours(iso: str, now: float) -> float:
    try:
        then = _dt.datetime.fromisoformat(iso).timestamp()
    except (ValueError, TypeError):
        return 1e9
    return max(0.0, now - then) / 3600.0