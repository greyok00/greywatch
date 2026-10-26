"""UI MODELS — pure logic of the GTK skin (Task 6b). No GTK imports here:
pytest runs headless; the GTK layer (app/window/tray) is a thin wrapper that
ONLY renders these models and forwards actions through `cli.py` (same process
path as the CLI control plane — the GUI is provably a skin; G3.3).

- EventRow: one row for the GtkTreeView (tool label, mark, severity, ts,
  NIST, CVEs, text) — transformed from a raw events.jsonl dict.
- DecisionView: one pending decision → dialog question + option rows.
- PendingBadge: unanswered count fed to tray + status bar.
"""
from __future__ import annotations

MARK_BY_SEVERITY = {"HIGH": "🔴", "CRITICAL": "🔴", "MEDIUM": "🟡", "INFO": "🟢"}
MAX_ROWS = 2_000            # UI rows cap (plan Global Constraints)
MAX_LOG_LINES = 1_000


class EventRow:
    __slots__ = ("tool", "severity", "mark", "ts", "nist", "cves", "text")

    def __init__(self, raw: dict):
        self.tool = raw.get("from_tool", "?")
        self.severity = raw.get("severity", "INFO")
        self.mark = MARK_BY_SEVERITY.get(self.severity, "⚪")
        self.ts = raw.get("ts", "")
        ctl = ",".join(raw.get("nist_control", [])) or "–"
        self.nist = f"{raw.get('nist_func', '–')}/{ctl}"
        cves = raw.get("cves") or []
        self.cves = ",".join(cves) if cves else ""
        self.text = raw.get("text", "")

    def as_list(self):
        return [self.mark, self.ts, self.tool, self.severity,
                self.nist, self.cves, self.text[:200]]


def rows_from(events: list, limit: int = MAX_ROWS) -> list:
    """Raw event dicts → newest-first EventRows, capped."""
    out = [EventRow(e) for e in events if isinstance(e, dict)]
    out.reverse()               # newest first
    return out[:limit]


class DecisionView:
    __slots__ = ("spec_id", "question", "options")

    def __init__(self, spec: dict):
        sanitized = spec if isinstance(spec, dict) else {}
        self.spec_id = sanitized.get("id", "")
        self.question = sanitized.get("question", "")
        self.options = [o for o in sanitized.get("options", [])
                        if isinstance(o, dict) and o.get("id")]

    def unanswered(self, answered: set) -> bool:
        return self.spec_id not in answered


def pending_badge(specs: list, answered: set) -> int:
    """Count PENDING decisions for the tray badge + status bar."""
    return sum(1 for s in specs
               if isinstance(s, dict) and s.get("id") not in answered)


def filter_events(events: list, tool=None, severity=None, text_needle=None,
                  limit: int = MAX_LOG_LINES) -> list:
    """Per-tool log-page rows (tool/severity/text filters, lazy cap)."""
    out = []
    for e in events:
        if tool and e.get("from_tool") != tool:
            continue
        if severity and e.get("severity") != severity:
            continue
        if text_needle and text_needle.lower() not in e.get("text", "").lower():
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


def state_mark(state: str) -> str:
    return {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴",
            "UNKNOWN": "⚪", "OFF": "⚫"}.get(state, "⚫")


def status_mark(state: str, paused: bool = False) -> str:
    """A deliberate pause is a choice, not a fault: show amber, never red."""
    return "🟡" if paused else state_mark(state)


def status_words(state: str, installed=None, paused: bool = False) -> str:
    """The one phrase a row shows. It must never claim more than we know:
    `installed=False` is the ONLY reason to say "not installed"; a failed
    probe is "could not check", and a deliberate stop is "paused by you"."""
    if paused:
        return "paused by you"
    if state == "GREEN":
        return "running"
    if state == "RED":
        return "not running"
    if state == "YELLOW":
        return "not installed" if installed is False else "needs attention"
    if state == "UNKNOWN":
        return "could not check"
    return "unknown"


def recent_rows(events: list, limit: int = 6) -> list:
    """The short feed: only feed-worthy events, duplicates collapsed, and
    always newest first (the old code prepended while iterating newest-first,
    which showed the OLDEST row at the top)."""
    picked = dedupe([e for e in reversed(events) if feed_worthy(e)])
    picked.sort(key=lambda e: str(e.get("ts", "")), reverse=True)
    return picked[:limit]


def local_clock(ts) -> str:
    """Times on screen are the user's own clock, never raw UTC: a UTC stamp
    read as local looks hours in the future (Pass 2 defect, 2026-10-23)."""
    import datetime as _dt
    try:
        when = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        return when.astimezone().strftime("%H:%M:%S")
    except (ValueError, TypeError):
        s = str(ts or "")
        return s[11:19] if len(s) >= 19 else ""


def age_words(ts: str, now=None) -> str:
    """Human age for the status log. Never raises on a bad timestamp.
    Empty means no EVENT was ever recorded — not that the tool never ran
    (scheduled scans write nothing when they find nothing)."""
    if not ts:
        return "no events recorded"
    import datetime as _dt
    try:
        when = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        ref = now or _dt.datetime.now(_dt.timezone.utc)
        secs = max(0, (ref - when).total_seconds())
    except (ValueError, TypeError):
        return "unknown time"
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400:
        return f"{int(secs // 3600)} h ago"
    return f"{int(secs // 86400)} d ago"

def feed_worthy(ev: dict) -> bool:
    """The VISIBLE feed rule (owner 2026-10-23): routine log noise HIDES;
    only genuinely bad/potentially-bad events and finished scans show."""
    sev = ev.get("severity", "INFO")
    # A check-in is liveness, not activity. Its severity now follows the
    # tool's state (so the Logs dot is honest), which would otherwise push
    # a dead tool's heartbeat into every activity feed once per cycle.
    if str(ev.get("text", "")).startswith("check-in:"):
        return False
    if sev in ("MEDIUM", "HIGH", "CRITICAL"):
        return True
    t = ev.get("text", "").lower()
    tool = ev.get("from_tool", "")
    # meaningful INFO: a scan finished (or a device joined the wifi)
    if tool in ("clamav", "aide", "rkhunter", "lynis"):
        return any(k in t for k in ("scan summary", "no differences", "clean",
                                    "audit finished", "report"))
    if tool == "arpwatch":
        return "new station" in t
    return False


def dedupe(events: list, key_fields=("from_tool",)) -> list:
    """Collapse identical consecutive events (same tool + same sentence):
    the flood showed 10 same-second duplicates of one row."""
    out, seen = [], set()
    for e in events:
        k = (e.get("from_tool"), sentence_text(e))
        if k in seen:
            continue
        seen.add(k)
        out.append(e)
    return out


def sentence_text(ev: dict) -> str:
    from ui.plain import sentence
    return sentence(ev)
