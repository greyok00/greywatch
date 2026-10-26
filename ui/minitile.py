"""Mini status tile — a small always-visible strip answering one owner
question: "what is supposed to be running right now, and is it?"

Sections, all read from the daemon's own snapshot (data/status.json,
root-written but 0644 so the desktop session can read it):
- Watchers: the daemon's inotify/journal follower components with their
  state and restart count — the machinery that never stops.
- AppFW engine: one row, running or off.
- Protections: every tool in the snapshot with its honest state; a row
  stays quiet when GREEN+active and names its problem when not.

Optional by design: nothing opens unless the tile's own checkbox says so
(persisted in data/greywatch-ui-settings.json under "mini_tile", default
off — opt-in like every other noisy surface). Closing the tile is a REAL
close; the checkbox only decides whether the next launch brings it back."""
from __future__ import annotations

import html
import json
import os
import pathlib
import sys
import time
from datetime import datetime

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gdk, GLib, Gtk, Pango

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SETTINGS_PATH = ROOT / "data" / "greywatch-ui-settings.json"
STATUS_PATH = ROOT / "data" / "status.json"
STALE_AFTER = 90  # seconds; the daemon rewrites the snapshot every few s

_GREEN, _AMBER, _RED, _GREY = "#3fb950", "#d29922", "#f85149", "#8b949e"


def _dot(state: str) -> str:
    return {"GREEN": _GREEN, "AMBER": _AMBER, "RED": _RED}.get(state, _GREY)


def _comp_dot(state: str) -> str:
    s = (state or "").lower()
    if s == "running":
        return _GREEN
    if s in ("failed", "stopped", "dead"):
        return _RED
    return _AMBER


def load_status(path=None):
    """The snapshot dict, or None when unreadable/missing — never a fake
    empty. Missing file and unreadable file look the same to the caller
    and render as one grey row."""
    p = pathlib.Path(path or STATUS_PATH)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def is_stale(status, now=None) -> bool:
    """True when there is no usable timestamp or it is older than
    STALE_AFTER seconds — a paused daemon must look paused, not absent."""
    if not status or not status.get("updated"):
        return True
    try:
        stamp = datetime.fromisoformat(status["updated"]).timestamp()
    except (ValueError, TypeError, OSError):
        return True
    ref = now if now is not None else time.time()
    return ref - stamp > STALE_AFTER


def _age_words(status, now=None) -> str:
    if not status or not status.get("updated"):
        return ""
    try:
        stamp = datetime.fromisoformat(status["updated"]).timestamp()
    except (ValueError, TypeError, OSError):
        return ""
    age = int(max(0, (now if now is not None else time.time()) - stamp))
    return f"updated {age}s ago"


def tile_wanted(path=None) -> bool:
    """Whether the tile opens with the app. Default: never (opt-in)."""
    p = pathlib.Path(path or SETTINGS_PATH)
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool(cfg.get("mini_tile"))


def set_tile_wanted(on: bool, path=None) -> None:
    """Merge the mini_tile key, keeping every other setting intact."""
    p = pathlib.Path(path or SETTINGS_PATH)
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cfg = {}
    cfg["mini_tile"] = bool(on)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(cfg), encoding="utf-8")
    os.replace(tmp, p)


def build_rows(status) -> list:
    """The tile's content lines (pango markup), minus the timestamp
    header. Pure function so the battery can verify every row shape
    without a display."""
    if status is None:
        return [f'<span color="{_GREY}">●</span> status not readable']

    rows = []
    pending = status.get("pending_decisions") or 0
    if pending:
        rows.append(f'<span color="{_AMBER}">●</span> {pending} '
                    f'decision(s) waiting')

    rows.append(f'<span color="{_GREY}">· watching (daemon)</span>')
    for name in sorted(status.get("components", {})):
        comp = status["components"][name]
        state = (comp.get("state") or "?").lower()
        suffix = ""
        if state != "running":
            suffix = f' {html.escape(state)}'
        if comp.get("restarts"):
            suffix += f' · {comp["restarts"]} restarts'
        rows.append(f'<span color="{_comp_dot(state)}">●</span> '
                    f'{html.escape(str(name))}{suffix}')

    engine = status.get("appfw_engine") or ""
    if engine:
        word = str(engine)
        color = _GREEN if word == "running" else _GREY
        suffix = "" if word == "running" else f" {html.escape(word)}"
        rows.append(f'<span color="{color}">●</span> appfw-engine{suffix}')

    rows.append(f'<span color="{_GREY}">· protections</span>')
    tools = status.get("tools", {})
    for name in sorted(tools):
        tool = tools[name]
        state = tool.get("state") or "?"
        suffix = ""
        if state != "GREEN" and state:
            suffix = f" {html.escape(state.lower())}"
        elif tool.get("unit_state") and tool.get("unit_state") != "active":
            suffix = f" {html.escape(str(tool['unit_state']))}"
        elif tool.get("installed") is False:
            suffix = " not installed"
        rows.append(f'<span color="{_dot(state)}">●</span> '
                    f'{html.escape(str(name))}{suffix}')
    return rows


_TILE_CSS = "".join(
    ".gwtile label { font-size: 10px; padding: 0px; }\n"
    ".gwtile headerbar { padding: 0px; min-height: 26px; }\n"
    ".gwtile checkbutton label { font-size: 10px; }\n"
    ".gwtile checkbutton { min-height: 20px; padding: 1px 0px; }\n"
    ".gwtile headerbar button { min-height: 18px; min-width: 18px; "
    "padding: 0px 4px; font-size: 10px; }\n")


class MiniTileWindow(Gtk.Window):
    """150px-wide opt-in strip. Refreshes from the snapshot every few
    seconds; a stale snapshot turns the header amber, an unreadable one
    names itself. Nothing here fakes a healthy state."""

    def __init__(self, status_path=None, refresh_seconds=5):
        super().__init__()
        self._status_path = status_path
        self._refresh_seconds = refresh_seconds

        self.set_title("greywatch — always on")
        self.set_default_size(150, 150)
        self.set_resizable(False)
        self.set_icon_name("greywatch")
        self.add_css_class("gwtile")

        provider = Gtk.CssProvider.new()
        provider.load_from_string(_TILE_CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider,
            Gtk.STYLE_PROVIDER_PRIORITY_USER)

        bar = Gtk.HeaderBar()
        bar.set_show_title_buttons(True)
        self._stamp = Gtk.Label(xalign=0)
        self._stamp.set_ellipsize(Pango.EllipsizeMode.END)
        bar.set_title_widget(self._stamp)
        self._check = Gtk.CheckButton()
        self._check.set_child(Gtk.Label(xalign=0))
        self._check.get_child().set_markup(
            '<span size="7680">start with app</span>')
        self._check.set_active(tile_wanted())
        self._check.connect("toggled", self._on_toggle)
        self.set_titlebar(bar)

        self._rows = Gtk.Label(xalign=0)
        self._rows.set_wrap(True)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_propagate_natural_width(False)
        scroll.set_propagate_natural_height(False)
        scroll.set_vexpand(True)
        scroll.set_child(self._rows)
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=2,
            margin_top=4, margin_bottom=6, margin_start=8, margin_end=8)
        outer.append(self._check)
        outer.append(scroll)
        self.set_child(outer)

        self.refresh()
        GLib.timeout_add_seconds(self._refresh_seconds, self._tick)

    def _tick(self) -> bool:
        self.refresh()
        return GLib.SOURCE_CONTINUE

    def _on_toggle(self, btn) -> None:
        set_tile_wanted(btn.get_active())

    def refresh(self) -> bool:
        status = load_status(self._status_path)
        body = "\n".join(build_rows(status))
        self._rows.set_markup(f'<span size="7680">{body}</span>')
        if status is None:
            self._stamp.set_markup(
                f'<span size="7680" color="{_RED}">status unreadable</span>')
        elif is_stale(status):
            self._stamp.set_markup(
                f'<span size="7680" color="{_AMBER}">'
                f'stale · {_age_words(status)}</span>')
        else:
            self._stamp.set_markup(
                f'<span size="7680">{_age_words(status)}</span>')
        return True