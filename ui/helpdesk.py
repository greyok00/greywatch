"""The Help page (architecture v4 app tail).

Every tool's digest, in plain words, and the tour: the six surfaces
and what each one is for, in the order a person meets them. A digest
opens inside this page with a Back control; nothing here writes
anything.
"""

from __future__ import annotations

import pathlib

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import pageutil
from ui.widgets import card, eyebrow, headline, meta, state_pill, sub

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_DIGEST_DIR = _ROOT / "tool-digests"

# the tour: rail surface -> what it is for, one plain sentence each
TOUR = (
    ("Security Center", "The score, the defenses and the actions. Its "
                        "three tabs carry the overview, the findings and "
                        "the baseline detail."),
    ("Network", "The devices this machine sees and the DNS it asked."),
    ("Tools", "Every lane's status on the daemon's cycle."),
    ("Timeline", "Everything that happened, each row with its "
                 "evidence."),
    ("Assistant", "The chat answers from the machine's own facts and "
                  "points you at the screen that acts."),
    ("Help", "This page: every tool's digest, opened in place, and the "
             "tour."),
)


def build(window) -> Gtk.Widget:
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page.set_hexpand(True)
    scroll.set_child(page)
    scroll._gw_body = page
    page._gw_scroll = scroll
    _refresh_into(page)
    page._gw_sig = _digest_sig()
    return scroll


def _digest_sig() -> str:
    try:
        return "|".join(
            f"{path.name}:{path.stat().st_mtime_ns}:{path.stat().st_size}"
            for path in sorted(_DIGEST_DIR.glob("*.md")))
    except OSError:
        return ""


def refresh(page: Gtk.Widget) -> None:
    """Help is static. A return visit keeps the open digest and the
    reader's place; it rebuilds only when the digest files changed."""
    body = getattr(page, "_gw_body", None) or page
    sig = _digest_sig()
    if sig == getattr(body, "_gw_sig", None):
        scroll = getattr(body, "_gw_scroll", None) or page
        if hasattr(scroll, "get_vadjustment"):
            pageutil.restore_scroll(scroll)
        return
    _refresh_into(body)
    body._gw_sig = sig


def _refresh_into(page: Gtk.Box) -> None:
    _clear(page)
    window = page._gw_window
    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    head.append(headline("Help"))
    head.append(state_pill("Tour and digests", "ok"))
    head.set_halign(Gtk.Align.START)
    page.append(head)
    page.append(meta("Read-only: nothing on this screen writes "
                     "anything."))

    stack = Gtk.Stack()
    stack.set_transition_type(Gtk.StackTransitionType.NONE)
    stack.set_vexpand(True)
    tour_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    digest_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    stack.add_named(tour_box, "tour")
    stack.add_named(digest_box, "digest")
    stack.set_visible_child_name("tour")
    page._gw_stack = stack
    page._gw_digest_box = digest_box
    page.append(stack)

    _tour_into(window, tour_box)
    _digests_into(page, tour_box)


def _tour_into(window, box: Gtk.Box) -> None:
    """Each description is one expanding label that wraps inside the
    card instead of being squeezed into a narrow column."""
    tour = []
    for name, words in TOUR:
        if not window.has_page(name):
            continue
        b = Gtk.Button(label=name)
        b.add_css_class("gw-quiet")
        b.set_valign(Gtk.Align.START)
        b.connect("clicked", lambda _b, n=name: window.show_page(n))
        words_label = Gtk.Label(label=words, xalign=0.0)
        words_label.add_css_class("gw-meta")
        words_label.set_wrap(True)
        words_label.set_hexpand(True)
        words_label.set_halign(Gtk.Align.FILL)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.append(b)
        row.append(words_label)
        tour.append(row)
    box.append(card(eyebrow("The tour"),
                    *tour, cls="gw-card gw-card-quiet"))


def _digests_into(page: Gtk.Box, box: Gtk.Box) -> None:
    rows = []
    for path in sorted(_DIGEST_DIR.glob("*.md")):
        b = Gtk.Button(label=_digest_title(path))
        b.add_css_class("gw-quiet")
        b.set_halign(Gtk.Align.START)
        b.connect("clicked", lambda _b, p=path: _open_digest(page, p))
        rows.append(b)
    if rows:
        box.append(card(eyebrow("Tool digests"), *rows))
    else:
        box.append(card(eyebrow("Tool digests"),
                        sub("No digest"),
                        meta("No digest files on this tree. The install "
                             "carries them in tool-digests.")))


def _digest_title(path: pathlib.Path) -> str:
    return path.stem.replace("-", " ")


def _open_digest(page: Gtk.Box, path: pathlib.Path) -> None:
    """Swap the Help stack to the digest page: a Back control and the
    digest text, read-only, in place. No window is opened."""
    box = getattr(page, "_gw_digest_box", None)
    stack = getattr(page, "_gw_stack", None)
    if box is None or stack is None:
        return
    _clear(box)

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
    back = Gtk.Button(label="Back")
    back.add_css_class("gw-quiet")
    back.connect("clicked", lambda _b: stack.set_visible_child_name("tour"))
    head.append(back)
    head.append(sub("Tool digest"))
    head.append(meta(_digest_title(path)))
    box.append(head)

    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        body = "the digest could not be read"
    text = Gtk.TextView()
    text.set_wrap_mode(Gtk.WrapMode.WORD)
    text.set_editable(False)
    text.set_cursor_visible(False)
    text.get_buffer().set_text(body[:8000])
    frame = Gtk.ScrolledWindow()
    frame.set_child(text)
    frame.set_min_content_height(260)
    frame.set_vexpand(True)
    box.append(frame)

    stack.set_visible_child_name("digest")


def _clear(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt
