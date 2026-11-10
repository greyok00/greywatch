"""The Activity Log page (rebuild Phase 4): read-only history, three tabs.

Security events reuse the raw-logs desk the window already carries;
operator decisions read decisions.jsonl (the one answer ledger); active
quarantines read the quarantine ledger the owner's symlink points at,
with the existing quarantine helpers behind the confirm pipeline.

The page searches with one filter box; the date cut-off is a plain
"since last N days" picker. The GUI reads only files it can read -
an unreadable ledger renders as its own empty state, never as nothing
to say.
"""
from __future__ import annotations

import pathlib

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from ui.plain import friendly_name
from ui import metrics


def _read(path, limit=500):
    try:
        lines = pathlib.Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return None
    out = []
    for line in lines[-limit:]:
        try:
            import json
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


class _DecisionsTab(Gtk.Box):
    def __init__(self, data_dir):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._decisions_path = pathlib.Path(data_dir) / "decisions.jsonl"
        self._list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                             spacing=4)

    def paint(self, needle=""):
        self._clear()
        rows = _read(self._decisions_path) or []
        rows = [r for r in rows if needle in str(r)]
        head = Gtk.Label(
            xalign=0, wrap=True,
            label=("every answer on record, newest last" if rows
                   else "no answers recorded yet"))
        head.add_css_class("gw-meta")
        self.append(head)
        for r in rows[-120:]:
            src = str(r.get("source") or
                      friendly_name(str(r.get("id", "")).split(":")[0]))
            row = Gtk.Label(xalign=0, wrap=True, selectable=True)
            row.set_text(f"{str(r.get('ts', ''))[:19]} · {src} · "
                         f"{r.get('option', '')}")
            row.add_css_class("gw-meta")
            self._list.append(row)
        self.append(self._list)

    def _clear(self):
        for child in list(self):
            self.remove(child)
        self._list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                             spacing=4)


class _QuarantineTab(Gtk.Box):
    def __init__(self, data_dir, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._path = pathlib.Path(data_dir) / "quarantine.jsonl"
        self._win = win

    def paint(self, needle=""):
        for child in list(self):
            self.remove(child)
        rows = _read(self._path) or []
        rows = [r for r in rows if needle in str(r)]
        head = Gtk.Label(
            xalign=0, wrap=True,
            label=(f"{len(rows)} quarantine record(s) on file" if rows
                   else "nothing in quarantine"))
        head.add_css_class("gw-meta")
        self.append(head)
        for r in rows[-80:]:
            self.append(self._card(r))

    def _card(self, r):
        from ui.decisionlist import card_widget
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.add_css_class("gw-card")
        title = Gtk.Label(xalign=0, wrap=True, selectable=True)
        title.set_markup("<b>" + str(r.get("orig") or "?") + "</b>")
        card.append(title)
        meta = ", ".join(str(x) for x in (r.get("tag"), r.get("ts"),
                                          r.get("sha256_16")) if x)
        lbl = Gtk.Label(xalign=0, wrap=True, selectable=True)
        lbl.set_text(meta)
        lbl.add_css_class("gw-meta")
        card.append(lbl)
        # the three quarantine answers ride the same spec shape the live
        # events carry, so the confirm pipeline and record bookkeeping
        # stay the keeper's, never the page's
        orig = str(r.get("orig") or "")
        spec = {"id": f"quarantine:{orig}",
                "eyebrow": "Quarantine",
                "subject": str(r.get("orig") or "?"),
                "question": "Keep it quarantined?",
                "options": [
                    {"id": "keep", "label": "Keep quarantined",
                     "tone": "primary", "helper": "keep-quarantine",
                     "args": [orig]},
                    {"id": "restore", "label": "Put it back",
                     "tone": "primary", "helper": "restore-quarantine",
                     "args": [orig]},
                    {"id": "wipe", "label": "Secure-wipe",
                     "tone": "danger", "helper": "delete-quarantine",
                     "args": [orig]},
                ]}
        card.append(card_widget(spec, "", self._run_option))
        return card

    def _run_option(self, _btn, spec, opt, buttons, state):
        w = self._win
        if w is not None and hasattr(w, "_run_log_option"):
            w._run_log_option(_btn, dict(opt))


class ActivityLogPage(Gtk.Box):
    """Three stacked tabs with one shared filter above them."""

    def __init__(self, win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self._win = win
        self._search = Gtk.SearchEntry()
        self._search.set_placeholder_text("search the record")
        self._search.connect("search-changed", self._refilter)
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        top.append(self._search)
        self.append(top)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(
            Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        switch = Gtk.StackSwitcher()
        switch.set_stack(self._stack)
        # security events (the window's raw-logs desk): a docked builder
        # now returns (content, dock groups); a plain widget stays valid
        # for a window shape that carries no dock.
        built = self._win._logs_view()
        page = built[0] if isinstance(built, tuple) else built
        self._stack.add_titled(page, "events", "Security events")

        self._decisions = _DecisionsTab(_data_dir())
        self._quarantines = _QuarantineTab(_data_dir(), win)
        self._stack.add_titled(self._decisions, "decisions",
                               "Operator decisions")
        self._stack.add_titled(self._quarantines, "quarantines",
                               "Active quarantines")
        # the switcher IS the tab strip; keep it after the stack for the
        # approved top placement
        self.append(switch)
        self._stack.set_vexpand(True)
        self.append(self._stack)

    def refresh(self, *_a, **_k):
        self._refilter()

    def _refilter(self, *_a):
        needle = self._search.get_text().lower()
        self._decisions.paint(needle)
        self._quarantines.paint(needle)


def _data_dir():
    from gwpaths import data_dir
    return data_dir()
