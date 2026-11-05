"""The pinned hunter digest on Home.

Unread defender notes pin here until they are read; once the read pointer
moves, each note travels into the conversation as one report bubble. The
digest only renders files the hunter wrote — findings are data, and the
buttons on a row open the same ask path the finding rows on the Threat
Hunter tab use, or switch to that tab. Nothing here executes anything.
"""
from __future__ import annotations

import json
import pathlib

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from hunter import explain, store  # noqa: E402
from ui.plain import muted as theme_muted  # noqa: E402
from ui.plain import severity_colour  # noqa: E402

MAX_DIGEST = 4

# A status word that means "this protection wants a hand". The
# suite verdict counts these; UNKNOWN is not one — a tool that has never
# reported in is shown as green-but-starting, not as a problem.
BAD_STATES = frozenset({"YELLOW", "RED", "ORANGE", "FAIL"})


def suite_summary(data_dir) -> tuple[str, str]:
    """The suite-first Home lead: one verdict sentence over
    status.json plus a one-line context strip. The verdict counts only
    protections that want attention, so 'All N are green' is a checked
    count, not an optimistic one. With no snapshot yet the card says so
    rather than promising green."""
    try:
        raw = json.loads(
            (pathlib.Path(data_dir) / "status.json").read_text(
                encoding="utf-8"))
    except (OSError, ValueError):
        return ("The suite is starting",
                "The protections report in a moment.")
    tools = raw.get("tools")
    rows = list(tools.values()) if isinstance(tools, dict) else []
    checked = [r for r in rows
               if str(r.get("state") or "").upper() != "UNKNOWN"]
    bad = [r for r in checked
           if str(r.get("state") or "").upper() in BAD_STATES]
    if bad:
        verdict = (f"{len(bad)} protection{'s' if len(bad) != 1 else ''} "
                   "need attention" if len(bad) != 1
                   else "1 protection needs attention")
    else:
        verdict = (f"All {len(checked)} protections are green"
                   if checked else "The suite is starting")
    waiting = int(raw.get("pending_decisions") or 0)
    updated = str(raw.get("updated") or "")
    # Name what wants attention: "1 protection needs attention"
    # is a riddle without the name — the same sentence carries the
    # snapshot's own labels for each protection in a bad state, so the
    # Home lead answers "which one?" before the desk is opened.
    bad_names = sorted({str(r.get("label") or "").strip() or
                        "one that has not named itself" for r in bad})
    # The snapshot clock inside an ISO stamp: 'T00:16:43+00:00'
    # reads as 00:16 — the suite's own last check-in, not a fake 'now'.
    words = ([", ".join(bad_names)] if bad_names else [])
    words.append(f"{waiting} decision{'s' if waiting != 1 else ''} waiting"
                 if waiting else "no decisions waiting")
    if len(updated) >= 16:
        words.append(f"snapshot {updated[11:16]}")
    return verdict, " · ".join(words)


def unread_notes(data_dir) -> list[dict]:
    """Unread defender notes, newest first by each note's own time (the
    other half of ): a cycle can write an older-evidence note after
    a newer one, so line order is not reading order. The read pointer is
    a user-owned value in config.json (see
    hunter.explain.read_pointer)."""
    notes = store.read_defender(data_dir, limit=store.DEFENDER_KEEP)
    since = explain.read_pointer(data_dir)
    unread = [n for n in notes if str(n.get("ts") or "") > since]
    unread.sort(key=lambda n: str(n.get("ts") or ""), reverse=True)
    return unread


def report_text(note: dict, finding: dict | None) -> str:
    """The plain text of one read note for a report bubble: the finding
    names the subject, the note's rule-written language says what it is
    and what to do next."""
    title = str((finding or {}).get("title") or "")
    text = str(note.get("text") or (finding or {}).get("what") or "")
    hint = str(note.get("hint") or (finding or {}).get("next") or "")
    head = (f"Threat Hunter report - {title}" if title
            else "Threat Hunter report")
    body = " ".join(part for part in (text, hint) if part)
    return f"{head}:\n{body}" if body else head


class SuiteCard(Gtk.Box):
    """The Home lead (suite first: one card that says,
    in plain words, how the security suite is doing right now.
    status.json is the only source; there is no second copy of any state.
    """

    def __init__(self, data_dir, on_open=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add_css_class("gw-card")
        self.add_css_class("gw-suite")
        self.data_dir = data_dir
        self.on_open = on_open
        eyebrow = Gtk.Label(xalign=0)
        eyebrow.set_text("Security suite")
        eyebrow.add_css_class("gw-eyebrow")
        self.append(eyebrow)
        self.verdict = Gtk.Label(xalign=0)
        self.verdict.add_css_class("gw-suite-verdict")
        self.verdict.set_selectable(False)
        self.append(self.verdict)
        self.subline = Gtk.Label(xalign=0)
        self.subline.add_css_class("gw-meta")
        self.append(self.subline)
        # The verdict card opens the Protections desk: the count
        # reads, and the click walks you to the desk that names answers.
        click = Gtk.GestureClick()
        click.connect("released", self._on_click)
        self.add_controller(click)
        self.refresh()

    def _on_click(self, _gesture, _n, _x, _y) -> None:
        if self.on_open is not None:
            self.on_open()

    def refresh(self) -> None:
        verdict, subline = suite_summary(self.data_dir)
        self.verdict.set_text(verdict)
        self.subline.set_text(subline)


class HomeDigest(Gtk.Box):
    """One pinned card with up to four newest unread notes. It hides
    itself when everything is read — the conversation below carries the
    story from there."""

    def __init__(self, data_dir, on_explain=None, on_open=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add_css_class("gw-card")
        self.add_css_class("gw-digest")
        self.data_dir = data_dir
        self.on_explain = on_explain
        self.on_open = on_open
        # The note ids this window has pinned at the top (newest first).
        # The home hand-over watches this ledger: when a pinned id drops
        # out (the note was read), it becomes one report bubble.
        self.last_ids: list[str] = []
        self._head = Gtk.Label(xalign=0)
        self._head.set_xalign(0)
        self._head.add_css_class("gw-eyebrow")
        self.append(self._head)
        self._rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.append(self._rows)

    def refresh(self) -> int:
        """Render the newest unread notes; return the unread count."""
        unread = unread_notes(self.data_dir)
        count = len(unread)
        self.last_ids = [str(n.get("ts") or "") for n in unread[:MAX_DIGEST]]
        if not count:
            self.set_visible(False)
            return 0
        self.set_visible(True)
        self._head.set_markup(
            f"<span size='10500' font_family='IBM Plex Mono' "
            f"font-weight='600' color='{theme_muted()}'>"
            f"THREAT HUNTER · "
            f"{count} NEW FINDING{'S' if count != 1 else ''}"
            "</span>")
        for child in list(self._rows.observe_children()):
            self._rows.remove(child)
        ids = {n.get("finding_id") for n in unread[:MAX_DIGEST]}
        findings = {f.get("id"): f
                    for f in store.read_findings(self.data_dir, 60)
                    if f.get("id") in ids}
        for note in unread[:MAX_DIGEST]:
            self._rows.append(
                self._row(note, findings.get(note.get("finding_id"))))
        return count

    def _row(self, note: dict, finding: dict | None) -> Gtk.Box:
        sev = str((finding or {}).get("severity")
                  or note.get("severity") or "?")
        color = severity_colour(sev)
        row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        dot = Gtk.Label(xalign=0)
        dot.set_markup(
            f"<span size='11500' font_family='Inter' weight='600' "
            f"color='{color}'>●</span>")
        head.append(dot)
        title = Gtk.Label(xalign=0)
        title.set_xalign(0)
        title.set_wrap(True)
        title.set_hexpand(True)
        title.set_markup(
            f"<span size='12000' font_family='Inter' weight='600' "
            f"color='{color}'>{_esc((finding or {}).get('title')
                                    or note.get('finding_id') or 'a finding')}"
            "</span>")
        head.append(title)
        row.append(head)
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        text = str(note.get("text") or (finding or {}).get("what") or "")
        hint = str(note.get("hint") or (finding or {}).get("next") or "")
        tail = f" <i>{_esc(hint)}</i>" if hint else ""
        body.set_markup(
            f"<span size='11500' font_family='Inter' "
            f"color='{theme_muted()}'>{_esc(text)}{tail}</span>")
        row.append(body)
        acts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        if self.on_explain is not None:
            ask = Gtk.Button(label="Ask about this")
            ask.add_css_class("gw-mini")
            ask.connect("clicked", self._ask_of(note, finding))
            acts.append(ask)
        if self.on_open is not None:
            open_b = Gtk.Button(label="Open the hunter")
            open_b.add_css_class("gw-mini")
            open_b.set_tooltip_text(
                "See every finding on the Threat Hunter tab")
            open_b.connect("clicked", self._open_of())
            acts.append(open_b)
        row.append(acts)
        return row

    def _ask_of(self, note: dict, finding: dict | None):
        # Same wording the finding rows on the Threat Hunter tab use, so
        # the answer reads identically from either surface.
        f = finding or {}
        def handler(_btn):
            self.on_explain(
                f"Explain this hunter finding: {f.get('title', '')}. "
                f"What it found: {f.get('what', '')}"
                " - what should I do about it?", finding)
        return handler

    def _open_of(self):
        def handler(_btn):
            self.on_open()
        return handler


def _esc(text) -> str:
    text = str(text or "")
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))