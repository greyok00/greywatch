"""The Action Gate drawer: every pending decision, one list, one count.

The header pill counts ONE list (status.json's pending_list, published by
the daemon whole-store); this drawer renders that same list, so the
number on the pill can never disagree with what a click reveals again
(the 12-vs-0 mismatch class). Every source renders: blocker reviewer
asks, quarantine questions, scanner-ban prompts, service-healer
suggestions - source-filtering happens only for page placement, never
for this list.

It reuses the decision window's answer pipeline (card_widget, one helper
per option, one recorded answer per id) by subclassing it; what changes
data source is the one overridden row reader, which reads the published
list and falls back to the whole-file scan only when an older daemon has
not published yet.
"""
from __future__ import annotations

import json
import pathlib

from ui.decisionlist import DecisionsWindow, _resolve_data_dir  # noqa: F401


class ActionGateWindow(DecisionsWindow):
    """"Action Gate" face on the shared decision pipeline."""

    _window_title = "greywatch: action gate"
    _eyebrow = "action gate"

    def _rows(self):
        status = _status_path_rows(self._data_dir)
        if status is not None:
            return status
        return super()._rows()

    def _headline_copy(self, n):
        if n:
            return (f"{n} decision{'s' if n != 1 else ''} waiting",
                    "every ask the suite is holding, from every source · "
                    "answering here records it in data/decisions.jsonl")
        return ("No decisions waiting",
                "the gate is clear. decisions appear here the moment a "
                "component has something for your answer")


def _status_path_rows(data_dir):
    """[(spec, ts)] straight from status.json's published list, or None
    when the daemon has not published one yet (older deployment)."""
    if not isinstance(data_dir, pathlib.Path):
        data_dir = _resolve_data_dir()
    try:
        snap = json.loads((data_dir / "status.json").read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(snap, dict) or "pending_list" not in snap:
        return None
    rows = []
    for item in snap.get("pending_list") or []:
        if not isinstance(item, dict):
            continue
        spec = item.get("spec")
        if isinstance(spec, dict) and spec.get("id"):
            rows.append((spec, str(item.get("ts", ""))))
    return rows
