"""Reusable log-row and threat-card helpers (wave D split: one home
for the pieces the Full-log rows, the decisions surface and the shell all
read)."""
from __future__ import annotations

import pathlib

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk    # noqa: E402

from events import lane_for
from ui.plain import severity_word as pc_severity_word
from ui.toolicons import icon_name as tool_icon

QUARANTINE_HELPERS = ("keep-quarantine", "restore-quarantine")


def _fixed(col, width):
    """A TreeView column pinned to a fixed width (column geometry shared
    by the log view and the desk views)."""
    col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
    col.set_fixed_width(width)
    return col


def log_row_values(ev, time_tool, event_text, severity_ink):
    """The Full logs row's display values plus the raw event and its lane
    (GW-197): the row carries what happened, so a click can fix it right
    there instead of sending the reader hunting for the lever."""
    return ([tool_icon(str(ev.get("from_tool", ""))),
             pc_severity_word(str(ev.get("severity", ""))),
             severity_ink, time_tool, event_text],
            ev, lane_for(ev))


def _threat_target(ev) -> str:
    """The file a threat event is about, from its decision's first or its
    quarantine line (GW-197). Only absolute-looking paths count."""
    spec = ev.get("interaction") or {}
    opts = [o for o in (spec.get("options") or []) if o.get("helper")]
    if opts:
        args = opts[0].get("args") or []
        if args and str(args[0]).startswith("/"):
            return str(args[0])
    text = str(ev.get("text", ""))
    if text.startswith("quarantine:"):
        tail = text.split(":", 1)[1].strip()
        first = tail.split(" ", 1)[0] if " " in tail else tail
        if first.startswith("/"):
            return first
    return ""


def threat_card_options(ev) -> list:
    """The threat row's real controls (GW-197): the stored decision's own
    options first, then Delete permanently when this lane holds a copy
    (quarantine helpers present) or the file still sits at its path.
    Tool controls never appear here, and a quarantine ask gains delete
    instead of staying locked to keep-or-restore forever."""
    spec = ev.get("interaction") or {}
    opts = [dict(o) for o in (spec.get("options") or []) if o.get("helper")]
    target = _threat_target(ev)
    if any(o.get("helper") in QUARANTINE_HELPERS for o in opts) and target:
        opts.append({"id": "delete", "label": "Delete permanently",
                     "tone": "danger", "helper": "delete-quarantine",
                     "args": [target]})
    elif target and not any(o.get("helper") == "file-action"
                            for o in opts) \
            and pathlib.Path(target).exists():
        opts.append({"id": "delete", "label": "Delete permanently",
                     "tone": "danger", "helper": "file-action",
                     "args": ["delete", target]})
    return opts
