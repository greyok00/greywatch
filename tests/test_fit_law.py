"""The fit law (owner amendment 2026-11-10): NO page scrolls whole-page.

Pages LAY OUT TO FIT the window; only INNER containers scroll (the event
table, the console, a card's config editor, the chat transcript, the
rail-side lists). This file pins that law three ways:

1. STRUCTURE - every `_builders` page, walked from its stack child: a
   ScrolledWindow reached by a single-child chain from the page root is a
   whole-page scroll (the exact shape this law deletes), and every other
   ScrolledWindow in the page tree must be a DECLARED inner container -
   an allow-list per page of its legitimate scrolling lists (by widget
   name or by the shared desk widget that owns the scroll).
2. HEIGHT - the page's natural height at a 1080p window budget (1920 wide
   with the rail's five-percent law and the dock's quarter law applied)
   must fit under the window minus the header chrome, measured with GTK's
   own size machinery on the built page. A page that would clip at the
   owner's 1080p window fails here - that is the other wrong direction
   (Firewall had no scroller and clipped).
3. WIZARD - the same law for the wizard windows (the hub, the setup
   assistant, every RuleWizard page) and the decisions drawer window.

Runs on the GUI-test display only (the private Xvfb conftest starts, or
GREYWATCH_TEST_DISPLAY=1 on purpose); measuring needs GTK, never data.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import shutil
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402


def _gtk_ready() -> bool:
    try:
        if not Gtk.init_check():
            return False
        from gi.repository import Gdk
        return Gdk.Display.get_default() is not None
    except Exception:
        return False


if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display, never the owner's desktop.", allow_module_level=True)
if not _gtk_ready():
    pytest.skip("no display available", allow_module_level=True)


def pump(n=30):
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


# ------------------------------------------------------------------ budgets
FIT_W = 1920                      # the owner's 1080p panel
FIT_H = 1080


def _budgets():
    """The 1080p window budget, from the pure laws, never measured against
    the test display's own geometry: rail five percent, dock a quarter,
    the window's own chrome allowance (ui.metrics.FRAME_H), and the
    header the app draws for itself."""
    from ui import metrics, shell
    from ui.window import dock_width
    rail = shell.rail_size(FIT_W, None)
    dock = dock_width(FIT_W, None)
    return rail, dock, FIT_H - metrics.FRAME_H


def _page_width():
    rail, dock, _h = _budgets()
    return FIT_W - rail - dock


def _header_height(win) -> int:
    _mn, nat = win._header_bar.measure(
        Gtk.Orientation.VERTICAL, _page_width())[:2]
    return max(nat, _mn)


def _page_budget(win) -> int:
    _rail, _dock, win_h = _budgets()
    return win_h - _header_height(win)


def _nat_h(widget, width=None) -> int:
    """The widget's natural height at a width, GTK's own size machinery
    (never the test display's geometry): the floor is the widget's own
    minimum width, since measuring below it warns and lies."""
    wmin = widget.measure(Gtk.Orientation.HORIZONTAL, -1)[0]
    for_size = wmin if not width else max(width, wmin)
    mn, nat = widget.measure(Gtk.Orientation.VERTICAL, for_size)[:2]
    return max(mn, nat)


def _pages_for(win) -> list:
    """Every stack page the window's builders can make - the sweep never
    guesses the key list, it reads the one dict."""
    return sorted(win._builders.keys())


# ------------------------------------------------------------ structural walk
class _Scroller:
    """A ScrolledWindow found in a page tree, with its identity: an
    explicit widget name when the page named it (its declared inner
    container), else the shared shell widget that owns the scroll."""

    def __init__(self, widget, root):
        self.widget = widget
        # GTK4 hands a widget its GType name when no name is set, so an
        # unset name reads exactly like the class name - unnamed then.
        self.name = widget.get_name() or ""
        if self.name == type(widget).__gtype__.name:
            self.name = ""
        self.owner = ""
        node = widget.get_parent()
        while node is not None and node is not root:
            own = type(node).__name__
            if own.startswith(("Desk", "ToolsDesk", "Assistant",
                               "ScanConsole", "Hunter", "ToolConfig")) \
                    and own not in ("DeskStrip",):
                self.owner = own
                break
            node = node.get_parent()
        self.identity = self.name or self.owner or "<unnamed>"

    def declared(self, allowed: set) -> bool:
        return bool(allowed & {self.name, self.owner, "*"})


def _children(w) -> list:
    out = []
    ch = w.get_first_child()
    while ch is not None:
        out.append(ch)
        ch = ch.get_next_sibling()
    return out


def _whole_page_scroller(root):
    """The whole-page scroll shape: from the page root down, a chain of
    containers that hold exactly one child reaches a ScrolledWindow."""
    node = root
    while True:
        kids = _children(node)
        if len(kids) != 1:
            return None
        node = kids[0]
        if isinstance(node, Gtk.ScrolledWindow):
            return node


# Widgets whose OWN internal ScrolledWindow is GTK machinery, not page
# content: a combobox's or dropdown's popup rows live under the page
# tree but are its popup, never a list on the page (the dropdown's
# popup list reads differently per GTK minor version, so the walk ends
# at the widget instead of guessing at its internals). The walk does
# not descend into these.
_GTK_INTERNAL = (Gtk.ComboBox, Gtk.DropDown)


def _scrollers(root) -> list:
    found = [root] if isinstance(root, Gtk.ScrolledWindow) else []
    todo = [root]
    while todo:
        node = todo.pop()
        for kid in _children(node):
            if isinstance(kid, Gtk.ScrolledWindow):
                found.append(_Scroller(kid, root))
                continue            # the page never scrolls inside a scroller
            if not isinstance(kid, _GTK_INTERNAL):
                todo.append(kid)
    return found


# The declared inner containers per page: widget names set beside the
# scroller its page owns, plus the shared desk widgets' scrolls. "*" here
# would mean "anything goes"; no page is given it - the law has no such
# page. DeskFeed/DeskDossier/AssistantPanel/ScanConsole own their inner
# scroll by design (feed rows, dossier body, chat transcript, console).
PAGE_INNER = {
    "auditlog": {"audit-table"},
    "services": {"DeskFeed", "DeskDossier"},
    "help": set(),
    "logs": {"logs-table"},
    "overview": {"AssistantPanel", "overview-needs",
                 "overview-trend-table"},
    "protect": {"protect-wall", "DeskFeed", "DeskDossier"},
    "scans": {"scan-findings", "ScanConsole", "DeskFeed", "DeskDossier"},
    "defense": {"defense-asks", "defense-blocked", "defense-watch"},
    "harden": {"harden-rows", "DeskFeed", "DeskDossier"},
    "thunter": {"hunter-feed", "hunter-dossier", "HunterPanel",
                "DeskFeed", "DeskDossier"},
    "tools": {"tool-config", "tools-list", "DeskFeed", "DeskDossier"},
    "settings": {"sites-table", "learn-table", "programs-table"},
}


# ------------------------------------------------------------------- data
def _seed(data_dir: pathlib.Path) -> None:
    """A populated snapshot, so the fit height is measured against real
    paint (an empty state fits almost anything; the law is not about the
    empty state). One digest, 22 tools in every state, blocked rows,
    pending asks, and an events chronology the Activity Log reads."""
    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    events = []
    tools = {}
    for i in range(22):
        name = f"t{i:02d}-tool"
        state = ("GREEN", "YELLOW", "RED", "UNKNOWN")[i % 4]
        tools[name] = {"state": state, "installed": True}
        for s in range(3):
            events.append({"ts": (now - dt.timedelta(minutes=40 + s * 3))
                           .isoformat(), "from_tool": name,
                           "severity": ["info", "high", "critical"][s],
                           "text": f"check-in: event {s} from {name}"})
    blocked = [{"ip": f"10.66.{i}.7", "ts": stamp, "reason": "auto block",
                "why": "psad level 5", "forever": False}
               for i in range(24)]
    asks = [{"spec": {"id": f"ask-{k}", "eyebrow": "network",
                      "subject": f"allow guest host {k}?",
                      "detail": "the ask the page answers here",
                      "options": [{"id": "allow", "label": "Allow",
                                   "tone": "primary", "helper": "tool",
                                   "args": ["noop"]}]},
             "ts": stamp} for k in range(6)]
    snap = {
        "updated": stamp,
        "tools": tools,
        "recent": events[:80],
        "defense": {"blocked": blocked},
        "pending_list": asks,
        "browser_watch": {"projects": [], "rows": []},
        "components": {f"comp-{i}": {"state": "failed", "restarts": 1}
                       for i in range(6)},
        "failures": {},
    }
    (data_dir / "status.json").write_text(json.dumps(snap))
    lines = [json.dumps(e) for e in events]
    (data_dir / "events.jsonl").write_text("\n".join(lines))


@pytest.fixture(scope="module")
def fit_win():
    """The real dashboard on a private data dir with the seeded digest."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gw-fitlaw-"))
    _seed(tmp)
    old_env = os.environ.get("GREYWATCH_DATA_DIR")
    os.environ["GREYWATCH_DATA_DIR"] = str(tmp)
    import ui.window as W
    old_data = W.DATA_DIR
    W.DATA_DIR = tmp
    try:
        win = W.MainWindow()
        win.present()
        pump(40)
        yield win
    finally:
        win.destroy()
        W.DATA_DIR = old_data
        if old_env is None:
            os.environ.pop("GREYWATCH_DATA_DIR", None)
        else:
            os.environ["GREYWATCH_DATA_DIR"] = old_env
        shutil.rmtree(tmp, ignore_errors=True)


def _painted(win, key):
    """Mount + paint one page the way a click does, and return the
    widget the stack actually shows (the builder key, never the legacy
    fold-in: the sweep walks the page each builder returns)."""
    if key not in win._views:
        win._mount(key)
    win.stack.set_visible_child_name(key)
    win.refresh()
    pump(10)
    return win._views[key]


# ------------------------------------------------------------------ 1. shape
@pytest.mark.parametrize("key", sorted(list(PAGE_INNER.keys())))
def test_page_has_no_whole_page_scroller(key, fit_win):
    page = _painted(fit_win, key)
    outer = _whole_page_scroller(page)
    assert outer is None, (
        f"page '{key}' lays out under a whole-page ScrolledWindow (the "
        f"shape the fit law deletes) - wrap inner container(s) instead")


@pytest.mark.parametrize("key", sorted(list(PAGE_INNER.keys())))
def test_page_scrollers_are_declared_inner_containers(key, fit_win):
    page = _painted(fit_win, key)
    undeclared = [s for s in _scrollers(page)
                  if not s.declared(PAGE_INNER[key])]

    def _path(scroller):
        """The page ancestry of one undeclared scroll, so a foreign or
        version-dependent container names itself instead of hiding
        behind '<unnamed>'."""
        chain = [scroller.widget]
        node = chain[0].get_parent()
        while node is not None and node is not page:
            chain.append(node)
            node = node.get_parent()
        return "/".join(type(w).__name__ for w in reversed(chain))

    detail = [f"{s.identity} ({_path(s)})" for s in undeclared]
    assert not detail, (
        f"page '{key}' scrolls in a container it never declared as its "
        f"inner list: {detail} - declare the legitimate inner "
        f"containers in PAGE_INNER, or stop scrolling the page")


# ------------------------------------------------------------------ 2. fit
@pytest.mark.parametrize("key", sorted(list(PAGE_INNER.keys())))
def test_page_fits_the_1080p_window(key, fit_win):
    page = _painted(fit_win, key)
    budget = _page_budget(fit_win)
    nat = _nat_h(page, _page_width())
    assert nat <= budget, (
        f"page '{key}' lays out {nat}px tall; the 1080p window budget "
        f"after header chrome is {budget}px - the page clips at the "
        f"owner's window instead of laying out to fit")


def test_rail_and_dock_are_budgeted_in_the_law(fit_win):
    """The height law is only honest once the shell chrome is in the
    budget: the rail and dock hold fixed widths at 1080p and the header
    holds a row of the window."""
    rail, dock, win_h = _budgets()
    assert (rail, dock) == (150, 320), (
        "the 1080p budget must be net of the rail's five percent and the "
        "dock's quarter law")
    assert win_h == FIT_H - 60, "the window chrome allowance is real"


def test_every_builder_key_is_covered_by_the_law(fit_win):
    """The sweep reads the law's own key list, so the crosscheck holds it
    to the window's real `_builders` dict: a page added without a
    PAGE_INNER entry (or retired without removing one) fails here, never
    silently escapes the fit law."""
    assert _pages_for(fit_win) == sorted(PAGE_INNER.keys()), (
        "the window's _builders and the fit law's PAGE_INNER have "
        "drifted apart - a page the law does not name, or a page named "
        "that the window cannot build")


# ------------------------------------------------------------------ 3. wizard
WIZARD_KEYS = ("site", "ufw", "appfw", "fail2ban", "tetragon", "yara",
               "arpwatch")


def test_rule_wizard_pages_fit_the_1080p_window():
    """Every Gtk.Assistant page is measured like the shell's pages: the
    page and its own chrome fit the window the law allows at 1080p."""
    from ui.wizard import RuleWizard
    for tool in WIZARD_KEYS:
        wz = RuleWizard(tool, parent=None)
        pump(5)                     # the sidebar labels settle first
        nat = _nat_h(wz, 700)
        wz.destroy()
        assert nat <= FIT_H - 60, (
            f"RuleWizard '{tool}' lays out {nat}px tall - over the "
            f"1080p window budget")


def test_wizard_hub_fits_and_scrolls_inner_only():
    from ui.wizard import ToolChooser
    chooser = ToolChooser(on_pick=lambda _k: None, parent=None)
    pump(5)
    outer = _whole_page_scroller(chooser)
    assert outer is None, "the hub must not scroll whole-page"
    nat = _nat_h(chooser, 600)
    chooser.destroy()
    assert nat <= FIT_H - 60, (
        f"the wizard hub lays out {nat}px tall - over the 1080p budget")


def test_setup_wizard_fits_and_scrolls_inner_only():
    from wizard.ui_pages import SetupWizardWindow
    w = SetupWizardWindow(parent=None, open_dashboard=lambda: None,
                          open_chooser=lambda: None)
    w.present()
    pump(20)
    outer = _whole_page_scroller(w.get_child())
    assert outer is None, "the setup wizard must not scroll whole-page"
    nat = _nat_h(w, 700)
    w.destroy()
    assert nat <= FIT_H - 60, (
        f"the setup wizard lays out {nat}px tall - over the 1080p budget")


def test_decisions_drawer_fits_and_scrolls_inner_only():
    from ui.actiongate import ActionGateWindow
    w = ActionGateWindow(parent=None, on_change=lambda: None)
    w.present()
    pump(20)
    outer = _whole_page_scroller(w)
    assert outer is None, "the decisions drawer must not scroll whole-page"
    nat = _nat_h(w, 700)
    w.destroy()
    assert nat <= FIT_H - 60, (
        f"the decisions drawer lays out {nat}px tall - over the 1080p budget")
