"""The hunter process: a loop, an inbox, and bookkeeping - nothing else.

Run for one cycle (``--once``, used by tests and by ``gw hunter --hunt``,
which drives the same in-process tick) or as the resident loop behind
shares nothing with the daemon but files: it reads shared state read-only
and writes only under ``<data_dir>/hunter/``, so a hunter crash leaves the
protected side untouched.

HAR inbox contract: a user drops one or more HAR files into
``<data_dir>/hunter/inbox/``; the hunter answers them into findings and
moves each to ``processed/``. That is the whole protocol — no listening
port, no privileged channel.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import sys
import time

# The unit runs this file BY PATH, so sys.path starts at this directory,
# not at the program root the `hunter` package lives in (: the
# deb-installed hunter looped "No module named 'hunter'"). Point the
# search back one level before anything else imports.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hunter import engine, explain, intel, store, web, watch

HAR_INBOX_CYCLE = 3        # inbox files handled per cycle
INBOX_STABLE_S = 2.0       # hold a capture for a full cycle until its
                           # producer has stopped writing it
INTERVAL_S = 300.0         # resident default
AI_PER_TICK = 1            # at most one model note per cycle: quiet
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_WATCHER_OFF = {"state": "off", "port": 0, "events": 0, "docs": 0,
                "queued": 0}
_WATCHERS: dict[str, watch.Watcher] = {}   # per data dir, across ticks


def _session_watcher(data_dir) -> watch.Watcher:
    """One watcher kept across this process's cycles: rotation timing
    lives on the object, so a fresh Watcher per tick could never rotate
    a document between 1000-event bursts and every drain was lost."""
    key = str(data_dir)
    if key not in _WATCHERS:
        _WATCHERS[key] = watch.Watcher(store.inbox_dir(key))
    return _WATCHERS[key]


def _close_watcher(data_dir) -> None:
    """Retire this data dir's watcher (its socket included) and forget
    the slot, so a later re-enable starts one cleanly."""
    key = str(data_dir)
    w = _WATCHERS.pop(key, None)
    if w is not None:
        try:
            w.close()
        except Exception:  # noqa: BLE001 — closing must not stop a hunt
            pass
    return None


def tick(data_dir, home, *, ai_enabled: bool = True,
         watcher_port=None, intel_enabled=None,
         watcher: watch.Watcher | None = None) -> dict:
    """One complete hunt over every source; returns the live doc.

    The web-wave keys come from the hunter's config.json: ``cdp_port``
    names the browser debug port the OWNER chose (the hunter never pins
    one, and 0 never opens anything), ``intel_enabled`` turns the
    pull-only feed updater on. Callers may override either; a plain
    call decides from the config, and absent keys stay off — an
    explicit call (as run makes) may default intel on."""
    data_dir = pathlib.Path(data_dir)
    state = store.read_state(data_dir)
    state.setdefault("events", {})
    budget = state.setdefault("ai", {})
    cfg = _runtime_cfg(data_dir)
    if watcher_port is None:
        try:
            watcher_port = int(cfg.get("cdp_port") or 0)
        except (TypeError, ValueError):
            watcher_port = 0
    if intel_enabled is None:
        intel_enabled = bool(cfg.get("intel_enabled") or False)

    # A "Hunt now" request is only its presence — consume it and go.
    if store.take_request(data_dir):
        state["last_hunt_requested"] = _iso()

    # 0 — the live CDP watcher: poll between cycles when the config names
    # a port; its rotated documents re-enter through the inbox below.
    if watcher is None and watcher_port:
        watcher = _session_watcher(data_dir)
    elif watcher is None and not watcher_port:
        # The port was demoted or removed: keeping our held object means
        # the open debug connection to the browser never gets a reader
        # again, so close it here instead of inside poll. A caller
        # handed their own watcher keeps it — ours are the only ones the
        # demotion retires.
        _close_watcher(data_dir)
    watcher_status = (watcher.poll(watcher_port, 0.2)
                      if (watcher is not None and watcher_port)
                      else dict(_WATCHER_OFF))

    # 0.5 — intel: pull-only, self-throttled to its own interval.
    if intel_enabled:
        try:
            intel.refresh(data_dir, {}, now=time.time())
        except Exception:  # noqa: BLE001 — feed trouble never stops a hunt
            pass

    # 1 — the untrusted inbox first: it is where a user points at
    # evidence with their own hands.
    har_docs = 0
    har_rejected = 0
    har_findings: list = []
    for path in _har_inbox(data_dir):
        try:
            doc = web.parse_har(path)
        except Exception:  # noqa: BLE001 - one bad capture answers and
            doc = None     # retires; it never stops the hunt behind it
        _retire_har(data_dir, path)
        if doc is None:
            har_rejected += 1
            continue
        har_docs += 1
        har_findings.extend(_har_only(web.har_findings(doc)))

    # 2 — the standing hunt over telemetry, downloads, persistence,
    # browser history, and scan summaries.
    saved = state["events"] if isinstance(state["events"], dict) else {}
    fresh, position = engine.read_events(data_dir / "events.jsonl", saved)
    overflow = int(position.get("skipped") or 0)   # window watermark (A6)
    findings = []
    for _name, fn, needs_events in engine.HYPOTHESES:
        if needs_events and not fresh:
            continue
        try:
            findings.extend(fn(fresh, home, str(data_dir)) or [])
        except Exception:  # noqa: BLE001 — one hypothesis failing stops
            pass           # nothing else

    # 3 — dedupe against the seen map; only new subjects survive.
    seen: dict = {}
    for entry in state.get("seen") or []:
        if isinstance(entry, list) and len(entry) == 2:
            seen[str(entry[0])] = str(entry[1])
    kept, seen = engine.apply_dedupe(seen, findings + har_findings)

    # 4 — record survivors and say something about each one, always in
    # plain language, even when the model is unavailable. A finding the
    # a finding the user dismissed never returns: the id is the dedup key,
    # so an unchanged subject lands on the same id and the ledger drops
    # it before it reaches the feed, while a changed subject is a new id
    # and still alerts.
    quiet_ids = store.quieted_ids(data_dir)
    for f in kept:
        f["id"] = store.dedup_key(f.get("rule", ""), engine.subject_of(f))
        if f["id"] in quiet_ids:
            continue
        store.append_finding(data_dir, f)
        store.append_defender(data_dir, explain.rule_note(f))

    # 5 — the bounded AI layer: at most one model note per cycle. An
    # explainer bug must not strand the state write behind it: findings
    # are already on the disk, and skipping the offset write would re-hunt
    # the same events with an empty seen map next cycle (duplicates
    # climbing the feed until the endpoint recovered).
    if ai_enabled and kept:
        try:
            _ai_one(data_dir, kept, budget)
        except Exception:  # noqa: BLE001 — the note is optional, the
            pass           # offset and dedupe map are not

    # 6 — answered-capture totals accumulate across cycles: the desk's
    # tile is an inventory (every capture ever answered), not the last
    # cycle's numbers, which fall back to zero the moment no capture
    # arrived.
    totals = state.get("har_total")
    if not isinstance(totals, dict):
        totals = {}
    state["har_total"] = {
        "processed": int(totals.get("processed") or 0) + har_docs,
        "rejected": int(totals.get("rejected") or 0) + har_rejected,
    }

    state["events"] = position
    state["seen"] = [[k, v] for k, v in seen.items()]
    state["ai"] = budget
    store.write_state(data_dir, state)
    store.trim(data_dir)

    doc = _live_doc(data_dir, len(kept), har_docs, har_rejected, budget,
                    watcher_status=watcher_status, intel_enabled=intel_enabled,
                    har_totals=state["har_total"],
                    events_overflow=overflow)
    store.write_live(data_dir, doc)
    return doc


def _har_only(pairs) -> list:
    return [f for f in pairs if str(f.get("rule", "")).startswith("har-")]


def _har_inbox(data_dir) -> list[pathlib.Path]:
    """The inbox, oldest first, with a freshness hold: a capture a
    producer is still writing (an external exporter does not rename
    atomically the way ours do) is skipped this cycle and answered on
    the next one, instead of being retired as unreadable junk.

    The hold applies per name, not to the head slots: a capture whose
    mtime never settles (a clock jumped backwards, a producer touching
    the same file) must not hold the lane hostage, so the walk looks
    past it to the next stable capture. The watcher's own documents are
    exempt from the hold - they land by atomic rename, so a young
    mtime is always complete, not mid-write."""
    try:
        names = sorted(store.inbox_dir(data_dir).glob("*"))
    except OSError:
        return []
    now = time.time()
    stable: list[pathlib.Path] = []
    for p in names:
        if len(stable) >= HAR_INBOX_CYCLE:
            break
        try:
            if p.name.startswith("cdp-live-"):
                stable.append(p)            # ours: atomic, never partial
                continue
            if now - p.stat().st_mtime >= INBOX_STABLE_S:
                stable.append(p)
        except OSError:
            continue
    return stable


def _retire_har(data_dir, path) -> None:
    """Answered: the capture moves to processed/ with its name intact, and
    only collides with itself after retries add a suffix. The suffix walk
    runs until a free name appears — a capture in hand is evidence, and
    nothing here deletes it; if every suffix up to 999 somehow exists, the
    capture simply stays in the inbox for the next cycle."""
    target = store.processed_dir(data_dir)
    stem = pathlib.Path(path).name
    out = target / stem
    step = -1
    while step < 999:
        try:
            if not out.exists():
                pathlib.Path(path).rename(out)
                return
        except OSError:
            pass
        step += 1
        out = target / f"{stem}.{step}"


def _ai_one(data_dir, kept, budget: dict) -> None:
    """Explain the single most severe finding this cycle. The budget dict
    is the tick's own — mutated in place, persisted with the state write."""
    best = min(kept, key=lambda f: SEVERITY_ORDER.get(
        str(f.get("severity")).upper(), 3))
    cfg = explain.load_config(data_dir)
    if not cfg.get("enabled"):
        return
    note = explain.explain(best, cfg, budget)
    if note is not None:
        store.append_defender(data_dir, note)


def _live_doc(data_dir, new_findings: int, har_docs: int, har_rejected: int,
              budget: dict, watcher_status=None, intel_enabled=False,
              har_totals=None, events_overflow=0) -> dict:
    """The window reads this file to keep the Hunter card current."""
    findings = store.read_findings(data_dir, limit=store.FINDINGS_KEEP)
    notes = store.read_defender(data_dir, limit=store.DEFENDER_KEEP)
    cfg = explain.load_config(data_dir)
    read_until = explain.read_pointer(data_dir)
    unread = sum(1 for n in notes
                 if explain.note_is_unread(n, read_until))
    stamp = intel.read_status(data_dir)
    return {
        "hunter": 1,
        "ts": _iso(),
        "interval_s": INTERVAL_S,
        "findings_total": len(findings),
        "new_this_cycle": new_findings,
        "events_overflow": int(events_overflow or 0),
        "unread": unread,
        "latest": [f["id"] for f in findings[-3:]],
        "har": {"processed": har_docs, "rejected": har_rejected},
        "har_total": dict(har_totals or {}),
        "watcher": watcher_status or dict(_WATCHER_OFF),
        "intel": {
            "enabled": bool(intel_enabled),
            "last_ok": str(stamp.get("last_ok") or ""),
            "ages": stamp.get("ages") or {},
            "errors": stamp.get("errors") or {},
        },
        "ai": {
            "enabled": bool(cfg.get("enabled")),
            "model": str(cfg.get("model", "")),
            "per_hour": int(cfg.get("per_hour", 0)),
            "used_hour": int((budget or {}).get("used", 0)),
            "cooling": bool((budget or {}).get("cooling")),
        },
    }


def _iso() -> str:
    # Microseconds: two writers in one wall second (the resident loop and
    # a hand-run cycle) must not present the desk two identical ts fields,
    # or the second paint reads as "nothing new"; note pointers get the
    # same precision so a note born mid-second is never unread-proof.
    return _dt.datetime.now(_dt.timezone.utc).isoformat(
        timespec="microseconds")


def _runtime_cfg(data_dir) -> dict:
    """The two web-wave keys live in the hunter's config.json,
    beside the AI explainer's keys."""
    try:
        cfg = json.loads(store.config_path(data_dir).read_text())
    except (OSError, ValueError):
        return {}
    return cfg if isinstance(cfg, dict) else {}


def run(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="gw-hunter",
        description="Watch's threat hunter - a separate unprivileged "
                    "process over events, downloads, browser history, "
                    "startup automation, and HAR imports.")
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--once", action="store_true",
                    help="run one cycle and exit")
    ap.add_argument("--interval", type=float, default=INTERVAL_S)
    ap.add_argument("--no-ai", action="store_true",
                    help="rules only; no cloud explainer calls")
    args = ap.parse_args(argv)
    home = str(pathlib.Path.home())
    # The operator surface opts intel in by default; the library surface
    # (tick's own default) keeps it off so tests and one-shot calls stay
    # offline unless the config says otherwise.
    intel_on = bool(_runtime_cfg(args.data_dir).get("intel_enabled", True))
    if args.once:
        # One-shot surface: a failed cycle is a failed run - a script
        # checking the hunter must be able to see the failure.
        try:
            tick(args.data_dir, home, ai_enabled=not args.no_ai,
                 intel_enabled=intel_on)
        except Exception:  # noqa: BLE001 — the exit code is the report
            return 1
        return 0
    while True:
        try:
            tick(args.data_dir, home, ai_enabled=not args.no_ai,
                 intel_enabled=intel_on)
        except Exception:  # noqa: BLE001 — a bad cycle must not kill the
            pass           # resident loop; the next one repairs state
        _sleep_or_wake(args.data_dir, float(args.interval))


def _sleep_or_wake(data_dir, seconds: float) -> None:
    """Sleep in slices, and cut one short when the user asks for a hunt —
    a "Hunt now" request answers in seconds, not at the interval."""
    deadline = time.monotonic() + max(5.0, seconds)
    while time.monotonic() < deadline:
        time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))
        if store.request_path(data_dir).exists():
            return


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())