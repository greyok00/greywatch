"""Scans = s2 (owner pick, rebuild round 2 task 10): mode cards + console.

The page answers "what can I run": three mode cards (Quick sweep / Full
suite / Deep audit) with big Run buttons through the EXISTING validated-key
scan-request seam, the existing ScanConsole below them (its inner scroll
stays; the page itself never scrolls as a whole), and the dock's Schedule /
Throttle groups - honest where a lane exists, honest where one does not.
No CVE rows and no threat controls ever land here.
"""
import inspect
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi_required = pytest.importorskip("gi")
gi_required.require_version("Gtk", "4.0")

from gi.repository import Gtk  # noqa: E402


def _walk(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def _buttons(root):
    return [w for w in _walk(root) if isinstance(w, Gtk.Button)
            and w.get_sensitive()]


def _labels(root):
    return [str(b.get_label() or "") for b in _buttons(root)]


def _texts(root):
    out = []
    for w in _walk(root):
        if isinstance(w, Gtk.Label):
            out.append(str(w.get_text() or ""))
    return out


class _FakeWin:
    def __init__(self, data_dir):
        self.data_dir = pathlib.Path(data_dir)
        self.registry = [
            {"name": "yara-tmp-scan", "unit": "yara-tmp-scan.timer"},
            {"name": "aide", "unit": "aide-check.timer"},
            {"name": "clamav", "unit": "clamav-daemon.service"},
            {"name": "cve-updater", "unit": "greywatch-cve.timer"}]
        self.scanned = []
        self.asked = []
        self.rescans = []

    def _hunter_scan(self, key):
        self.scanned.append(key)

    def _ask_assistant(self, *_a, **_k):
        pass

    def _rescan_tool(self, key, *_a, **_k):
        self.rescans.append(key)

    def _show_folder(self, *_a, **_k):
        pass

    def _show(self, *_a, **_k):
        pass

    def _get_status(self):
        return {}


@pytest.fixture
def page(tmp_path):
    from ui.scanview import ScansPage
    win = _FakeWin(tmp_path)
    return ScansPage(win=win), win


# ---- the three mode cards route the existing machinery -------------------
def test_three_mode_cards_lead_the_page(page):
    p, _win = page
    labels = [t.lower() for t in _texts(p)]
    assert any("quick sweep" in t for t in labels)
    assert any("full suite" in t for t in labels)
    assert any("deep audit" in t for t in labels)


def test_run_buttons_use_the_validated_key_seam(page):
    p, win = page
    run = [b for b in _walk(p) if isinstance(b, Gtk.Button)
           and b.get_sensitive() and b.get_label().startswith("Run ")]
    assert len(run) == 3
    run[0].emit("clicked")
    run[1].emit("clicked")
    run[2].emit("clicked")
    # The machinery's own fixed keys, one request each - never command text
    assert win.scanned == ["yara-tmp-scan", "full", "lynis"]


def test_cards_carry_run_notes_from_the_modes(page):
    """Each card says what it runs in the machinery's own words (throttle
    word on the everyday runs), never a promise the machinery lacks."""
    p, _win = page
    joined = " ".join(_texts(p)).lower()
    assert "throttled" in joined or "seconds" in joined


# ---- the console below the cards ------------------------------------------
def test_console_lives_below_the_cards(page):
    p, _win = page
    from ui.scanview import ScanConsole
    assert isinstance(p.scanconsole, ScanConsole)
    # window-fit law: the page box itself never scrolls - no direct child
    # of the page is a whole-page ScrolledWindow (the console keeps its
    # own inner ones for findings and output)
    direct = [c for c in p]
    assert not any(isinstance(c, Gtk.ScrolledWindow) for c in direct)
    # the cards row precedes the console in the page's child order
    children = list(p)
    assert children.index(p.cards_row) < children.index(p.scanconsole)


# ---- the dock: Schedule and Throttle --------------------------------------
def test_dock_groups_are_schedule_then_throttle(page):
    p, _win = page
    groups = p.dock_groups()
    assert [g[0] for g in groups] == ["Schedule", "Throttle"]


def test_schedule_group_shown_and_honestly_disabled(page):
    """status.json publishes no boot-sweep schedule: the edit says so and
    names the REAL timer units, the stagger fact stays on the page."""
    p, _win = page
    group = [w for _t, ws in p.dock_groups() if _t == "Schedule"
             for w in ws]
    edit = [w for w in group if isinstance(w, Gtk.Button)]
    disabled = [b for b in edit if not b.get_sensitive()]
    assert disabled, "the schedule edit must not pretend to work"
    tips = [str(b.get_tooltip_text() or "") for b in disabled]
    joined = " ".join(tips)
    assert "yara-tmp-scan.timer" in joined
    assert "aide-check.timer" in joined
    texts = " ".join(str(w.get_text() or "") for w in group
                     if isinstance(w, Gtk.Label))
    assert "one per slot" in texts or "one per slot" in joined


def test_throttle_group_reads_the_daemons_own_caps(page):
    p, _win = page
    group = [w for _t, ws in p.dock_groups() if _t == "Throttle"
             for w in ws]
    texts = " ".join(str(w.get_text() or "") for w in group
                     if isinstance(w, Gtk.Label))
    texts = (texts + " " + " ".join(str(w.get_tooltip_text() or "")
                                    for w in group)).lower()

    from scan_session import THROTTLE
    caps = THROTTLE["clamav"]
    assert f"nice {caps['nice']}" in texts
    assert f"cpu {caps['cpu_quota']}" in texts
    # read-only: any edit control is disabled with an honest reason
    edit = [b for b in group if isinstance(b, Gtk.Button)
            and not b.get_sensitive()]
    assert edit, "the throttle knobs have no lane: they must not fake edit"


def test_one_subject_per_page(page):
    """The scans page runs the suite, it does not patch and it does not
    grow the protections wall or the tool grid."""
    p, _win = page
    from ui.toolsdesk import ToolsDesk
    assert not any(isinstance(w, ToolsDesk) for w in _walk(p))
    text = " ".join(_texts(p)).lower() + " ".join(_labels(p)).lower()
    assert "patch advisories" not in text
    assert "advisory" not in text


# ---- the route pins --------------------------------------------------------
def test_guided_entry_is_schedule():
    from ui.guided import PAGE_ENTRY
    assert PAGE_ENTRY.get("scans") == "Schedule"


def test_page_is_its_own_page_again():
    from ui.window import _LEGACY_PAGE
    assert "scans" not in _LEGACY_PAGE
    assert "protect" not in _LEGACY_PAGE      # own page again (task 10)
    assert _LEGACY_PAGE.get("security") == "protect"
    assert _LEGACY_PAGE.get("deep") == "protect"
    assert _LEGACY_PAGE.get("harden") == "services"


def test_builder_returns_the_page_no_whole_page_scroller():
    from ui import window
    src = inspect.getsource(window.MainWindow._scans_view)
    assert "ScrolledWindow" not in src     # window-fit law: no page scroller
    assert "ScansPage" in src


def test_window_refresh_feeds_the_scans_page():
    from ui import window
    src = inspect.getsource(window.MainWindow.refresh)
    assert 'shown == "scans"' in src
    assert "scan_page.refresh" in src


def test_scan_tick_lands_on_the_scans_console():
    from ui import window
    src = inspect.getsource(window.MainWindow._scan_tick)
    assert "scan_page" in src or 'shown == "scans"' in src
