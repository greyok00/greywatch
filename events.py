from __future__ import annotations

import dataclasses
from typing import Optional

SEVERITIES = ("INFO", "MEDIUM", "HIGH", "CRITICAL")

_FIELDS = ("from_tool", "severity", "text", "ts", "nist_func", "nist_control", "cves", "interaction")


@dataclasses.dataclass
class Event:
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
