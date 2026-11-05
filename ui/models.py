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
    return sum(1 for s in specs
               if isinstance(s, dict) and s.get("id") not in answered)


def filter_events(events: list, tool=None, severity=None, text_needle=None,
                  limit: int = MAX_LOG_LINES) -> list:
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


def recent_alerts(events: list, hours: int = 24, now=None) -> int:
    """HIGH/CRITICAL events from the last `hours` that raise no question.

    Events carrying an interaction are already represented by the pending
    decision they create, so they are not counted twice.
    """
    import datetime as _dt
    now = now or _dt.datetime.now(_dt.timezone.utc)
    cutoff = now - _dt.timedelta(hours=hours)
    n = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        if e.get("severity") not in ("HIGH", "CRITICAL"):
            continue
        if e.get("interaction"):
            continue
        try:
            when = _dt.datetime.fromisoformat(
                str(e.get("ts") or "").replace("Z", "+00:00"))
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        if when >= cutoff:
            n += 1
    return n


def verdict_words(attention: int, paused: int, pending: int = 0,
                  alerts: int = 0) -> tuple[str, str, str]:
    """Headline, pill and tone for the dashboard verdict.

    Tool health alone said "All clear · 0 need attention" while 18 decisions
    waited unanswered; the decision backlog and recent severe events are as
    much a part of "does anything need me" as a red tool.
    """
    if not (attention or paused or pending or alerts):
        return "All clear", "All clear", "ok"
    parts = []
    if pending:
        parts.append(f"{pending} decision{'s' if pending != 1 else ''} waiting")
    if attention:
        parts.append(f"{attention} {'needs' if attention == 1 else 'need'}"
                     " attention")
    if paused:
        parts.append(f"{paused} paused")
    if alerts:
        parts.append(f"{alerts} recent alert{'s' if alerts != 1 else ''}")
    lead = "Needs a look - " + " · ".join(parts)
    if pending:
        pill = f"{pending} decision{'s' if pending != 1 else ''} waiting"
    elif alerts:
        pill = f"{alerts} recent alert{'s' if alerts != 1 else ''}"
    elif attention:
        pill = f"{attention} {'needs' if attention == 1 else 'need'} attention"
    else:
        pill = f"{paused} paused"
    return lead, pill, "fail" if (attention or alerts) else "warn"


def status_mark(state: str, paused: bool = False) -> str:
    return "🟡" if paused else state_mark(state)


def status_words(state: str, installed=None, paused: bool = False) -> str:
    if paused:
        return "paused"
    if state == "GREEN":
        return "running"
    if state == "RED":
        return "not running"
    if state == "YELLOW":
        return "not installed" if installed is False else "needs attention"
    if state == "UNKNOWN":
        return "could not check"
    return "unknown"


def service_words(state: str, installed=None, paused: bool = False) -> str:
    """The pill on a Security Tools row names the SERVICE it describes.

    That row also carries the scan's own sentence and log, so a bare
    "running" sitting beside "Last scan failed" read as a contradiction:
    one word was about the unit, the other about the scan. Naming the service keeps the two apart.
    """
    word = status_words(state, installed, paused)
    if word in ("not installed", "could not check", "unknown"):
        return word
    return "service " + word


def recent_rows(events: list, limit: int = 6) -> list:
    picked = dedupe([e for e in reversed(events) if feed_worthy(e)])
    picked.sort(key=lambda e: str(e.get("ts", "")), reverse=True)
    return picked[:limit]


def local_clock(ts) -> str:
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
    if not ts:
        return "-"
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
    sev = ev.get("severity", "INFO")
    if str(ev.get("text", "")).startswith("check-in:"):
        return False
    if sev in ("MEDIUM", "HIGH", "CRITICAL"):
        return True
    t = ev.get("text", "").lower()
    tool = ev.get("from_tool", "")
    if tool in ("clamav", "aide", "rkhunter", "lynis"):
        return any(k in t for k in ("scan summary", "no differences", "clean",
                                    "audit finished", "report"))
    if tool == "arpwatch":
        return "new station" in t
    return False


def dedupe(events: list, key_fields=("from_tool",)) -> list:
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
