"""Harden = h1 (owner, rebuild round 2 task 11): score bar + flat checklist.

The page's own design contract, owner-verified:
  1. ONE hardening-score progress band at the page top (percent computed
     from the checklist's applied/open counts; ok >= 80, warn 40-79,
     fail < 40) with the number.
  2. ONE flat checklist where every row applies ITSELF in place through
     the existing harden changeset lane and states what happened
     ("applied changeset ..."); resolved rows collapse to one line.
  3. A Profile dock group (recommended / strict / paranoid) - honest
     where the machinery has no profile lane: disabled radios with the
     "no profile lane yet" reason, never a fake filter.
  4. A Recheck dock group (the real recheck-after-apply the apply lane
     already runs, toggled off only by choice).
  5. Window-fit law: the checklist is the page's ONE inner-scrolled
     container - the chrome fits and never scrolls as a whole.
  6. Route: "harden" is its own page again (the Services fold is gone).
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib    # noqa: E402

from hardening import detector    # noqa: E402
from hardening.controls import Control    # noqa: E402
from ui.harden import HardenPage, hardening_score    # noqa: E402


if not os.environ.get("GREYWATCH_TEST_DISPLAY"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (GREYWATCH_TEST_DISPLAY=1), never the owner's desktop.",
        allow_module_level=True)


import time as _time


def pump(n=400, ms=900):
    """Drain the main context for up to `ms` wall milliseconds: when a
    source storm is pending, iteration(False) dispatches one event per
    call and sleeps only when the context is quiet, so the scan/apply
    worker threads still get their idle callbacks landed before the
    helper returns."""
    ctx = GLib.main_context_default()
    end = GLib.get_monotonic_time() + int(ms * 1000)
    for _ in range(n):
        if GLib.get_monotonic_time() > end:
            return
        if not ctx.iteration(False):
            _time.sleep(0.005)



def F(cid, state, current="", note=""):
    return detector.Finding(control_id=cid, state=state, current=current,
                            note=note)


GOOD = Control("good-control", "kernel", "A control already at baseline",
               probe="true", severity="HIGH", nist=["CM-7"])
GAPFIX = Control("gap-control", "kernel", "A gap the helper can fix",
                 probe="false", severity="HIGH",
                 fix=[["sysctl-set", "kernel.knob", "0"]], nist=["SC-2"])
ADVISORY = Control("advisory-gap", "docs", "Advisory: update when you choose",
                   probe="false", severity="INFO", advisory=True)
MANUAL = Control("manual-control", "systemd-unit",
                 "Needs a change the helper cannot make",
                 probe="false", severity="CRITICAL",
                 fix=[["unit-install", "{{unit}}", "TRANCHE"]])

CONTROLS = [GOOD, GAPFIX, ADVISORY, MANUAL]


def fake_runner(line):
    _ = line                     # every probe here: false -> gap
    return (1, "")


def make_page(state):
    """state: mutable dict shared with the runner, so a recheck can flip
    a probe (the way a real fixed setting would)."""

    def runner(line):
        return (0 if state.get("pass") else 1), "stubbed"

    return HardenPage(controls=CONTROLS, runner=runner,
                      journal_path=pathlib.Path("/tmp/h1-unused-journal"))


# ------------------------------------------------------- 1. the score bar

def test_score_bands_follow_the_owner_law():
    # >= 80 ok, 40-79 warn, < 40 fail. Non-advisory checks only; a
    # could-not-check control counts as not earned.
    by_state = {"PASS": detector.PASS, "GAP": detector.GAP}
    def found(seq):
        return [F(cid, by_state.get(st, st))
                for cid, st in seq]
    ctrls = [Control(f"c{i}", "g", f"c{i}", probe="true", severity="HIGH")
             for i in range(10)]
    fnd = found([(f"c{i}", "PASS") for i in range(8)]
                + [(f"c{i}", "GAP") for i in (8, 9)])
    assert hardening_score(fnd, ctrls) == (80, "ok")
    fnd = found([(f"c{i}", "PASS") for i in range(4)]
                + [(f"c{i}", "GAP") for i in range(4, 10)])
    assert hardening_score(fnd, ctrls) == (40, "warn")
    fnd = found([(f"c{i}", "GAP") for i in range(10)])
    assert hardening_score(fnd, ctrls) == (0, "fail")
    fnd = found([(f"c{i}", "PASS") for i in range(9)]
                + [("cx", "GAP")])            # cx is not one of ours
    assert hardening_score(fnd, ctrls) == (90, "ok")
    # CANT never lies its way into the numerator
    fnd = found([(f"c{i}", "PASS") for i in range(4)]
                + [(f"c{i}", "CANT-CHECK") for i in range(4, 10)])
    assert hardening_score(fnd, ctrls) == (40, "warn")
    # advisory rows never score
    adv = Control("adv", "docs", "adv", probe="true", severity="INFO",
                  advisory=True)
    assert hardening_score([F("adv", detector.GAP)], [adv]) == (0, "idle")


def test_score_bar_renders_at_page_top_with_the_number():
    state = {"pass": False}
    page = make_page(state)
    # the bar is page-top chrome: h1, intro, then the score band
    first = page.get_first_child()
    page._scan_done([F("good-control", detector.PASS),
                     F("gap-control", detector.GAP),
                     F("manual-control", detector.GAP),
                     F("advisory-gap", detector.GAP)],
                    list(CONTROLS))
    pump()
    pct = page.score_bar.get_fraction()
    assert abs(pct - 1 / 3) < 0.01            # 1 of 3 non-advisory changeables
    classes = page.score_bar.get_css_classes()
    assert any(str(c) == "fail" for c in classes), classes
    assert "33%" in page.score_label.get_text()
    # after the machinery applies and the checks re-run, the score moves
    state["pass"] = True
    page._scan_done([F("good-control", detector.PASS),
                     F("gap-control", detector.PASS),
                     F("manual-control", detector.PASS),
                     F("advisory-gap", detector.GAP)],
                    list(CONTROLS))
    pump()
    assert abs(page.score_bar.get_fraction() - 1.0) < 0.001
    classes = page.score_bar.get_css_classes()
    assert any(str(c) == "ok" for c in classes), classes
    # before any scan the band says so instead of painting a fake 0%
    fresh = HardenPage(controls=CONTROLS, runner=fake_runner)
    assert "not scored yet" in fresh.score_label.get_text()


# ------------------------------------------- 2. the flat self-applying rows

def test_open_rows_carry_their_real_action_button():
    page = make_page({"pass": False})
    page._on_scan(None)
    pump()
    joined = "\n".join(_row_texts(page))
    # flat: one row per check, in checklist order
    assert "A gap the helper can fix" in joined
    labels = [str(b.get_label() or "") for b in _walk(page)
              if isinstance(b, Gtk.Button) and b.get_sensitive()]
    assert any("Tighten the setting" in x for x in labels), labels
    assert any("Apply all open" in x for x in labels)     # the batch lane
    assert any("Run baseline checks" in x for x in labels)


def _deep(w):
    """BFS stack traversal (used everywhere in this file for buttons:
    a plain recursive sibling walk proved flaky against this GTK's
    sibling chain, so the pins never hand it a page again)."""
    out = []
    stack = [w]
    while stack:
        cur = stack.pop(0)
        out.append(cur)
        c = cur.get_first_child()
        while c is not None:
            stack.append(c)
            c = c.get_next_sibling()
    return out


def _deep_button(page, label):
    """The page's first SENSITIVE button carrying the label (a row's own
    fix button, not the dock or the batch controls)."""
    for b in _deep(page.rows):
        if isinstance(b, Gtk.Button) and b.get_sensitive()                 and b.get_label() == label:
            return b
    return None


def _row_texts(page):
    out = []
    frame = page.rows.get_first_child()
    while frame is not None:
        stack = [frame.get_child()]
        while stack:
            w = stack.pop(0)
            if isinstance(w, Gtk.Label):
                out.append(str(w.get_text() or w.get_label() or ""))
            c = w.get_first_child() if not isinstance(w, Gtk.Label) else None
            while c is not None:
                stack.append(c)
                c = c.get_next_sibling()
        frame = frame.get_next_sibling()
    return out


def test_row_apply_states_the_changeset_result():
    state = {"pass": False}
    page = make_page(state)
    plans = []

    def helper(args):
        plans.append(json.loads(pathlib.Path(args[1]).read_text()))
        return 0, "APPLY gap-control 0\nVERBIFY gap-control 0\n", ""

    page._helper = helper
    page._on_scan(None)
    pump()
    btn = _deep_button(page, "Tighten the setting")
    assert btn is not None, "the gap row ships its own fix button"
    btn.emit("clicked")
    for _ in range(60):
        pump(4)
        if plans:
            break
    assert plans and plans[0]["entries"][0]["verb"] == "sysctl-set"
    assert plans[0]["entries"][0]["id"] == "gap-control"
    result = "\n".join(_row_texts(page))
    assert "applied changeset gap-control" in result
    assert "fixed and verified" in result
    assert "gap-control GREEN" in page.verify_label.get_text()


def test_failed_row_apply_says_so_in_place():
    state = {"pass": False}
    page = make_page(state)
    page._helper = lambda args: (4, "APPLY gap-control 0\n"
                                     "VERBIFY gap-control 1\n",
                                 "ROLLBACK-SKIP gap-control\n")
    page._on_scan(None)
    pump()
    btn = _deep_button(page, "Tighten the setting")
    btn.emit("clicked")
    for _ in range(60):
        pump(4)
        if "did not hold" in "\n".join(_row_texts(page)):
            break
    result = "\n".join(_row_texts(page))
    assert "did not hold" in result
    assert "gap-control RED" in page.verify_label.get_text()


def test_resolved_rows_collapse_to_one_line():
    state = {"pass": False}
    page = make_page(state)
    page._scan_done(
        [F("good-control", detector.PASS),
         F("gap-control", detector.GAP),
         F("manual-control", detector.GAP),
         F("advisory-gap", detector.GAP)],
        list(CONTROLS))
    pump()
    frames = []
    f = page.rows.get_first_child()
    while f is not None:
        frames.append(f)
        f = f.get_next_sibling()
    assert len(frames) == 4, "one flat row per check"
    # the resolved (PASS) row is ONE line: a single label, no buttons
    first = frames[0].get_child()
    labels = [w for w in _walk(first) if isinstance(w, Gtk.Label)]
    buttons = [w for w in _walk(first) if isinstance(w, Gtk.Button)]
    assert len(labels) == 1, labels
    assert not buttons, buttons
    oneline = labels[0].get_text()
    assert "already at baseline" in oneline
    assert "A control already at baseline" in oneline
    # the open rows stay full
    assert "NEEDS A MANUAL CHANGE" in "\n".join(_row_texts(page))


def _walk(w):
    """The widget and its whole subtree (a bare _walk over a dock widget
    must see the widget itself, not only its children)."""
    out = [w]
    c = w.get_first_child()
    while c is not None:
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def test_manual_gap_holds_no_fake_button():
    page = make_page({"pass": False})
    page._scan_done(
        [F("good-control", detector.PASS),
         F("gap-control", detector.GAP),
         F("manual-control", detector.GAP),
         F("advisory-gap", detector.GAP)],
        list(CONTROLS))
    pump()
    texts = "\n".join(_row_texts(page))
    assert "NEEDS A MANUAL CHANGE" in texts
    frames = []
    f = page.rows.get_first_child()
    while f is not None:
        frames.append(f)
        f = f.get_next_sibling()
    manual = [fr for fr in frames
              if any("NEEDS A MANUAL CHANGE" in (w.get_text() or "")
                     for w in _walk(fr.get_child())
                     if isinstance(w, Gtk.Label))]
    assert len(manual) == 1
    assert not [w for w in _walk(manual[0].get_child())
                if isinstance(w, Gtk.Button)]


# ------------------------------------------------------------ 3. the dock

def test_profile_group_is_honest_where_no_lane_exists():
    page = make_page({"pass": False})
    groups = page.dock_groups()
    assert [g[0] for g in groups][0] == "Profile"
    radios = [w for w in _walk(groups[0][1][0])
              if isinstance(w, Gtk.CheckButton)]
    words = sorted(r.get_label() for r in radios)
    assert words == ["paranoid", "recommended", "strict"], words
    for r in radios:
        assert not r.get_sensitive()
        assert "no profile lane yet" in r.get_tooltip_text()


def test_recheck_toggle_gates_the_rescan():
    state = {"pass": False}
    page = make_page(state)
    groups = page.dock_groups()
    assert [g[0] for g in groups][1] == "Recheck"
    toggle = [w for w in _walk(groups[1][1][0])
              if isinstance(w, Gtk.CheckButton)][0]
    assert toggle.get_active()          # the apply lane rechecks by default

    scans: list = []
    page._helper = lambda args: (0, "APPLY gap-control 0\n"
                                     "VERBIFY gap-control 0\n", "")
    page._on_scan(None)
    pump()
    scans.clear()

    def runner(line):                   # the recheck flips the probe
        scans.append(line)
        state["pass"] = True
        return (0 if state["pass"] else 1), "stubbed"

    page._runner = runner
    btn = _deep_button(page, "Tighten the setting")
    assert btn is not None
    toggle.set_active(True)
    scans.clear()
    btn.emit("clicked")
    for _ in range(60):
        pump(4)
        if scans:
            break
    assert scans, "recheck on: the checks ran again after the apply"
    # recheck off: the same apply keeps the row results in place instead
    state["pass"] = False
    page2 = make_page(state)
    page2._helper = lambda args: (0, "APPLY gap-control 0\n"
                                     "VERBIFY gap-control 0\n", "")
    page2._recheck.set_active(False)
    page2._on_scan(None)
    pump()
    btn2 = _deep_button(page2, "Tighten the setting")
    btn2.emit("clicked")
    for _ in range(60):
        pump(4)
        if "applied changeset gap-control" in "\n".join(_row_texts(page2)):
            break
    assert "applied changeset gap-control" in "\n".join(_row_texts(page2))


# ------------------------------------------------------ 4. greeting + route

@pytest.fixture(scope="module")
def win():
    from ui.window import MainWindow
    w = MainWindow()
    w.present()
    # the he1 walkthrough's autorun may still be a pending timeout: it
    # re-shows pages and would race a route pin mid-pump.
    w._tour_autorun = lambda: False
    pump(30)
    if getattr(w, "_glib_ids", None):
        GLib.source_remove(w._glib_ids[0])
        w._glib_ids.remove(w._glib_ids[0])
    yield w
    w.destroy()


def test_page_entry_and_route_reshaping(win):
    from ui import guided
    from ui.window import _LEGACY_PAGE
    assert guided.PAGE_ENTRY.get("harden") == "Profile"
    # harden is its own page again: the Services fold is gone
    assert "harden" not in _LEGACY_PAGE
    assert "harden" in win._builders
    win._show("harden")
    pump(6)
    assert win.stack.get_visible_child_name() == "harden"
    # the arrival greeting pulses the Profile group the page declared
    assert [g[0] for g in getattr(win, "harden_page").dock_groups()][0] == \
        "Profile"


# ---------------------------------------------------------- 5. the fit law

def test_checklist_is_the_one_inner_scroll():
    page = make_page({"pass": False})
    direct = []
    c = page.get_first_child()
    while c is not None:
        direct.append(c)
        c = c.get_next_sibling()
    scrollers = [w for w in direct if isinstance(w, Gtk.ScrolledWindow)]
    assert len(scrollers) == 1, "window-fit law: ONE inner-scrolled container"
    # GTK parks a plain box in an internal viewport: unwrap one level.
    inner = scrollers[0].get_child()
    held = inner.get_child() if isinstance(inner, Gtk.Viewport) else inner
    assert held is page.rows
    with open(pathlib.Path(ROOT / "ui" / "window.py")) as fh:
        src = fh.read()

    def _harden_view_src():
        start = src.index("def _harden_view")
        return src[start:src.index("def ", start + 1)]

    # the builder returns the page and its dock groups, no extra scroller
    assert "_harden_view" in src and "ScrolledWindow" not in _harden_view_src()
