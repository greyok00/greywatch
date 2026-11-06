from __future__ import annotations
"""The event record shared by every collector and parser in the suite.

Event instances carry the tool name, severity, human-readable text,
timestamp and any enrichment or interaction data."""


import dataclasses
from typing import Optional

SEVERITIES = ("INFO", "MEDIUM", "HIGH", "CRITICAL")

_FIELDS = ("from_tool", "severity", "text", "ts", "nist_func", "nist_control", "cves", "interaction")


@dataclasses.dataclass
class Event:
    """Event."""
    from_tool: str
    severity: str                  # one of SEVERITIES
    text: str                      # human-readable, tool-labeled
    ts: str                        # ISO-8601 UTC
    nist_func: str = "DETECT"      # NIST CSF 2.0 function
    nist_control: list[str] = dataclasses.field(default_factory=list)  # SP 800-53r5 controls
    cves: list[str] = dataclasses.field(default_factory=list)
    interaction: Optional[dict] = None  # decision spec, see decisions.py

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        unknown = set(d) - set(_FIELDS)
        if unknown:
            raise KeyError(f"foreign keys in event payload: {sorted(unknown)}")
        missing = {"from_tool", "severity", "text", "ts"} - set(d)
        if missing:
            raise KeyError(f"missing required keys: {sorted(missing)}")
        return cls(**d)


def normalize_event(tool: str, line: str) -> Optional[Event]:
    from parsers import PARSERS  # late import: parsers import events

    parser = PARSERS.get(tool)
    if parser is None or not line.strip():
        return None
    return parser(line)


# 2026-11-06, owner directive: greywatch is two systems - threats and
# tools - each with its own voice and controls. Every event sorts into a
# lane at read time so the whole stored history classifies without any
# daemon change. Tool state is enumerated; anything else that carries
# HIGH weight defaults to a threat, never to silence.
TOOL_MARKERS = ("NOT RUNNING", "needs attention", "not installed", "paused",
                "exited", "timed out", "updated", "updater", "healer")
THREAT_TOOLS = frozenset({"responderd", "appfw", "netwatch", "tetragon"})
THREAT_MARKERS = ("quarantine", "deny", "ban", "drop", "alert", "credential")


def lane_for(event: dict) -> str:
    if not isinstance(event, dict):
        return "tool"
    tool = str(event.get("from_tool", ""))
    text = str(event.get("text", ""))
    if text.startswith("check-in:") or any(m in text for m in TOOL_MARKERS):
        return "tool"
    if isinstance(event.get("interaction"), dict):
        return "threat"
    if tool in THREAT_TOOLS and any(m in text for m in THREAT_MARKERS):
        return "threat"
    return "threat" if event.get("severity") in ("HIGH",
                                                 "CRITICAL") else "tool"
