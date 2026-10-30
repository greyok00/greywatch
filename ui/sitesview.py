"""The sites list: one row per site, click to select, then act.

Rows merge the trust lists, recent application-firewall events, live
connections and browser history. Names resolve in a background thread, one
row per site, so the list never blocks the window and a slow or missing
lookup just leaves the address showing.
"""
from __future__ import annotations

import concurrent.futures
import pathlib
import threading

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk, Pango  # noqa: E402

from assistant import audit  # noqa: E402
from ui import discover  # noqa: E402
from ui.site_names import NameResolver  # noqa: E402
from ui.site_rows import (SiteRow, build_rows, display_line,  # noqa: E402
                          filter_rows, short_name)

VERDICT_WORDS = {"allow": "Trusted", "block": "Blocked", "": "Not on list"}
VERDICT_INK = {"allow": "#4dd07a", "block": "#ff5a52", "": "#8b9bb0"}
MUTED = "#8b9bb0"


class SitesView(Gtk.Box):
    def __init__(self, get_store, data_dir, audit=audit.record):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.get_store = get_store
        self.data_dir = pathlib.Path(data_dir)
        self.audit = audit
        self.resolver = NameResolver(self.data_dir / "site-names.json")
        self.rows: list[SiteRow] = []
        self.selected: SiteRow | None = None
        self._gen = 0

        self.filter_entry = Gtk.Entry()
        self.filter_entry.set_placeholder_text(
            "Filter sites by name, description or program")
        self.filter_entry.connect("changed", lambda *_a: self._repaint())
        self.append(self.filter_entry)

        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.listbox.connect("row-selected", self._on_selected)
        self.empty = Gtk.Label(xalign=0)
        self.empty.set_xalign(0)
        self.empty.set_wrap(True)
        self.empty.set_margin_top(12)
        self.empty.set_margin_bottom(12)
        self.empty.set_markup(
            f"<span color='{MUTED}'>Nothing discovered yet — sites appear "
            f"here as programs connect and as you browse.</span>")
        self.listbox.set_placeholder(self.empty)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_size_request(-1, 220)
        scroll.set_child(self.listbox)
        self.append(scroll)

        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.trust_btn = Gtk.Button(label="Trust")
        self.block_btn = Gtk.Button(label="Block")
        self.remove_btn = Gtk.Button(label="Remove")
        self.trust_btn.connect("clicked", lambda *_a: self._act_note("allow"))
        self.block_btn.connect("clicked", lambda *_a: self._act_note("block"))
        self.remove_btn.connect("clicked",
                                lambda *_a: self._act_note("remove"))
        for b in (self.trust_btn, self.block_btn, self.remove_btn):
            bar.append(b)
        self.note = Gtk.Label(xalign=0)
        self.note.set_xalign(0)
        self.note.set_wrap(True)
        self.note.set_hexpand(True)
        self.note.set_markup(
            f"<span color='{MUTED}'>Select a row, then choose what to do."
            f"</span>")
        bar.append(self.note)
        self.append(bar)
        self._set_buttons(False)

    # ---- data -------------------------------------------------------
    def reload(self):
        """Gather in the background; paint on the main loop when ready."""
        self._gen += 1
        gen = self._gen
        threading.Thread(target=self._gather, args=(gen,), daemon=True,
                         name="sites-reload").start()

    def _gather(self, gen):
        store = self.get_store()
        connected, history, events = [], [], []
        try:
            connected = discover.connected_sites()
        except (OSError, ValueError):
            pass
        try:
            history = discover.browser_sites(limit=30)
        except (OSError, ValueError):
            pass
        try:
            from greywatch_daemon import read_events
            events = [e for e in read_events(self.data_dir / "events.jsonl",
                                             2000)
                      if (e or {}).get("from_tool") == "appfw"]
        except (OSError, ValueError, ImportError):
            events = []
        rows = build_rows(store, events, connected, history)
        wanted = sorted({r.address or r.entry for r in rows
                         if r.address or not r.description.startswith(
                             "unrecognized")})
        names = {}
        if wanted:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for addr, name in zip(wanted, pool.map(self.resolver.name_for,
                                                       wanted)):
                    names[addr] = name
        rows = build_rows(store, events, connected, history, names=names)
        GLib.idle_add(self._deliver, rows, gen)

    def _deliver(self, rows, gen):
        if gen == self._gen:
            self.paint(rows)
        return False

    # ---- rendering --------------------------------------------------
    def paint(self, rows):
        self.rows = list(rows)
        self._repaint()

    def _repaint(self):
        keep = self.selected.entry if self.selected else None
        self._render()
        self._restore(keep)

    def _render(self):
        while (c := self.listbox.get_first_child()) is not None:
            self.listbox.remove(c)
        shown = filter_rows(self.rows, self.filter_entry.get_text())
        for row in shown:
            item = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            label = Gtk.Label(label=display_line(row), xalign=0)
            label.set_xalign(0)
            label.set_hexpand(True)
            label.set_ellipsize(Pango.EllipsizeMode.END)
            label.set_tooltip_text(self._tooltip(row))
            chip = Gtk.Label()
            chip.set_markup(
                f"<span size='11000' color='"
                f"{VERDICT_INK.get(row.verdict, MUTED)}'>"
                f"{VERDICT_WORDS.get(row.verdict, row.verdict)}</span>")
            box.append(label)
            box.append(chip)
            item.set_child(box)
            item._row = row
            self.listbox.append(item)

    @staticmethod
    def _tooltip(row):
        bits = [display_line(row)]
        if row.program:
            bits.append(f"last seen from {row.program}")
        if row.count:
            bits.append(f"{row.count} sighting{'s' if row.count != 1 else ''}")
        return " · ".join(bits)

    def row_text(self, index: int) -> str:
        child = self.listbox.get_row_at_index(index)
        if child is None:
            return ""
        box = child.get_child()
        label = box.get_first_child() if box else None
        return label.get_text() if label else ""

    def visible_count(self) -> int:
        return sum(1 for i in range(2000)
                   if self.listbox.get_row_at_index(i) is not None)

    def _restore(self, entry):
        self.selected = None
        if entry:
            self.selected = next((r for r in self.rows if r.entry == entry),
                                 None)
        self._set_buttons(self.selected is not None)

    def select(self, index: int):
        row = self.listbox.get_row_at_index(index)
        if row is not None:
            self.listbox.select_row(row)
        else:
            self.selected = None
            self._set_buttons(False)

    def _on_selected(self, _listbox, row):
        self.selected = getattr(row, "_row", None) if row else None
        self._set_buttons(self.selected is not None)
        if self.selected is not None:
            self.note.set_markup(
                f"<span color='{MUTED}'>{self.selected.entry} selected."
                f"</span>")

    def _set_buttons(self, have):
        self.trust_btn.set_sensitive(have)
        self.block_btn.set_sensitive(have)
        self.remove_btn.set_sensitive(have)

    # ---- actions ----------------------------------------------------
    def act(self, verdict: str) -> str:
        row = self.selected
        if row is None:
            text = "Select a site in the list first."
            self.note.set_markup(f"<span color='{MUTED}'>{text}</span>")
            return text
        store = self.get_store()
        if verdict == "remove":
            ok = store.remove(row.entry)
            text = (f"Removed {row.entry} from the lists." if ok
                    else f"Could not remove {row.entry}.")
        else:
            ok = store.add(row.entry, verdict)
            shown = short_name(row)
            text = (f"Trusted {shown}." if verdict == "allow"
                    else f"Blocked {shown}.")
            if not ok:
                text = f"That address was not accepted: {row.entry}"
        self.audit("trust", f"{verdict}:{row.entry}", ok)
        self.note.set_text(text)
        self.reload()
        return text

    def _act_note(self, verdict):
        self.act(verdict)
        return False
