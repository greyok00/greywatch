"""Rebuild round 2, task 9: the Tools page returns as owner-verified t2.

One full-width, self-contained card per registered tool: header (glyph,
name, status dot, one-line status), a lifecycle row wired ONLY through the
apply/polkit lanes that exist (a lane that does not exist ships disabled
with an honest reason, never a dead click), a schedule row that is honest
about where the schedule really lives (the systemd unit - there is no
editable schedule value in this build), quick lanes that exist, and
"Open config": the tool's RAW config file expanding INSIDE the card, an
editable view only where a write lane exists, with line-level validation
(unknown key -> honest inline error, no write), an Apply through the
config-write polkit lane, and then the baseline permafix offer (rkhunter
--propupd / aide --update) with Yes/Later.

Fitted laws pinned here: the cards live in ONE inner-scrolled list (the
page chrome does not whole-scroll) and an expanded editor scrolls INSIDE
its card.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import json  # noqa: E402

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui import guided  # noqa: E402
from ui.toolcontrol import (ToolControlPage,  # noqa: E402
                            ToolCard, ToolConfigEditor, schedule_words, validate_config)


# --------------------------------------------------------------- helpers
def _walk(host):
    out = []
    try:
        kids = list(host)
    except TypeError:
        return out
    for k in kids:
        out.append(k)
        out.extend(_walk(k))
    return out


def _buttons(host):
    return [b for b in _walk(host) if isinstance(b, Gtk.Button)]


def _button_by_label(host, label):
    for b in _buttons(host):
        if b.get_label() == label:
            return b
    return None


def _texts(host):
    out = []
    for w in _walk(host):
        if isinstance(w, Gtk.Label):
            out.append(str(w.get_text() or ""))
    return out


def pump(ms=0):
    while GLib.main_context_default().iteration(False):
        pass


def _registry():
    doc = json.loads((ROOT / "registry.json").read_text())
    return doc["tools"]


_REG = _registry()


class _Paused:
    def is_paused(self, name):
        return False


class _FakeWin:
    """The seams the page routes through: state probing, the toggle lane,
    the validated scan-request seam, the show router, the data dir."""

    def __init__(self, tmp_path, reg=None):
        reg = reg if reg is not None else _REG
        self.data_dir = tmp_path
        self.registry = reg
        self.by_name = {t["name"]: t for t in reg}
        self.paused = _Paused()
        self.toggled = []
        self.scanned = []
        self.shows = []
        self.refreshed = 0

    def _display_state(self, name, info, updated):
        return (info or {}).get("state", "UNKNOWN")

    def _toggle_tool(self, name, pause):
        self.toggled.append((name, bool(pause)))

    def _hunter_scan(self, key):
        self.scanned.append(key)

    def _show(self, key):
        self.shows.append(key)

    def refresh(self):
        self.refreshed += 1


def _page(tmp_path, monkeypatch, reg=None) -> ToolControlPage:
    win = _FakeWin(tmp_path, reg)
    return ToolControlPage(win=win)


# ---------------------------------------------------------------- cards
def test_one_full_width_card_per_registry_tool(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    assert set(page.cards) == {t["name"] for t in _REG}
    # the fit law: the page carries ONE inner scroller for the whole
    # card list; the page chrome above it never scrolls
    scroller = page._scroll
    assert isinstance(scroller, Gtk.ScrolledWindow)
    assert scroller.get_policy() == (Gtk.PolicyType.NEVER,
                                     Gtk.PolicyType.AUTOMATIC)
    inner = scroller.get_child()
    assert inner.get_child() is page.cards_box   # the viewport's body
    # full width: every card fills the list, the list runs top to bottom
    assert page.cards_box.get_orientation() == Gtk.Orientation.VERTICAL
    card = page.cards["fail2ban"]
    assert "gw-card" in card.get_css_classes()
    assert card.get_hexpand()


def test_card_anatomy(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    card = page.cards["fail2ban"]
    words = _texts(card)
    assert "Intrusion blocker · fail2ban" in words
    assert "could not check" in words   # the honest state before a snapshot
    # one line of status, a result line that exists from birth
    assert isinstance(card.status, Gtk.Label)
    assert isinstance(card.result, Gtk.Label)
    assert card.glyph is not None
    # the schedule row exists and never pretends the UI owns the timer
    sched = str(card.schedule.get_text())
    assert isinstance(card.schedule, Gtk.Label) and sched


def test_lifecycle_lane_wiring(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    # fail2ban: the tool-control lane covers its unit -> wired opts
    opts = {o["op"]: o for o in page.cards["fail2ban"].opts}
    assert opts["restart"]["helper"] == "tool-control"
    assert opts["restart"]["args"] == ["restart", "fail2ban.service"]
    assert opts["start"].get("sensitive", True)
    # psad: the tool-control allowlist does NOT list psad.service
    opts = {o["op"]: o for o in page.cards["psad"].opts}
    assert opts["stop"].get("sensitive") is False
    assert "no lane" in str(opts["stop"]["disabled"]).lower()
    # unit-less scanners: honest, the scan lane runs them
    opts = {o["op"]: o for o in page.cards["rkhunter"].opts}
    assert opts["start"].get("sensitive") is False
    assert opts["run"]["scan"] == "rkhunter"
    # user-scope units ride the app's own user lane, never a new power
    opts = {o["op"]: o for o in page.cards["yara-tmp-scan"].opts}
    assert opts["start"].get("kind") == "toggle"


def test_lane_click_runs_the_helper_lane_on_the_card(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    calls = []

    def fake_exec(helper, args):
        calls.append((helper, args))
        return 0, ""

    monkeypatch.setattr("ui.decisionlist._helper_exec", fake_exec)
    card = page.cards["fail2ban"]
    opt = next(o for o in card.opts if o["op"] == "restart")
    card._run_opt_now(opt)
    pump()
    assert calls == [("tool-control", ["restart", "fail2ban.service"])]
    assert "restart" in str(card.result.get_text()).lower()
    # a busy card refuses a second lane while the first is in flight
    card.set_busy(True)
    card._run_opt_now(opt)
    assert calls == [("tool-control", ["restart", "fail2ban.service"])]
    for b in _buttons(card.lane_box):
        assert not b.get_sensitive()


def test_run_now_uses_the_validated_scan_request(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    card = page.cards["aide"]
    btn = _button_by_label(card.lane_box, "Run now")
    assert btn is not None and btn.get_sensitive()
    btn.emit("clicked")
    assert page._win.scanned == ["aide"]
    # freshclam's "run" is an update lane, not a scan request
    card = page.cards["freshclam"]
    opt = next(o for o in card.opts if o["op"] == "run")
    assert opt["helper"] == "tool-control"


def test_schedule_row_honesty(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    # a timer tool words the schedule FROM its unit file...
    unit = tmp_path / "yara-tmp-scan.timer"
    unit.write_text("[Timer]\nOnUnitActiveSec=15min\n")
    words = schedule_words({"unit": "yara-tmp-scan.timer",
                            "name": "yara-tmp-scan"},
                           roots=[tmp_path])
    assert "15" in words and "min" in words
    # ...and every timer card says where it lives: the systemd unit
    for name in ("yara-tmp-scan", "aide", "cve-updater"):
        words = str(page.cards[name].schedule.get_text())
        assert "read-only" in words, name
    # unit-less scanners have no schedule to name, honestly
    for name in ("rkhunter", "lynis"):
        words = str(page.cards[name].schedule.get_text())
        assert "no schedule" in words.lower(), name


def test_schedule_entry_never_claims_an_edit_seam(tmp_path, monkeypatch):
    # The contract: no editable schedule value exists in this build; the
    # row names read-only honesty everywhere, including for timers.
    page = _page(tmp_path, monkeypatch)
    for name in ("aide", "yara-tmp-scan", "cve-updater"):
        text = str(page.cards[name].schedule.get_text()).lower()
        assert "read-only" in text, name
        assert "editable" not in text, name


# ------------------------------------------------------- config editor
def test_tool_configs_real_path_map(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    entries = page.cards["rkhunter"].configs
    paths = {e["key"]: e["path"] for e in entries}
    assert paths["rkhunter-default"] == "/etc/default/rkhunter"
    assert paths["rkhunter-conf"] == "/etc/rkhunter.conf"
    psad = page.cards["psad"].configs[0]["path"]
    assert psad == "/etc/psad/psad.conf"
    aide = page.cards["aide"].configs[0]["path"]
    assert pathlib.Path(aide) == pathlib.Path("/etc/aide/aide.conf")


def test_open_config_expands_inside_the_card(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    conf = {"key": "t", "path": str(tmp_path / "x.conf"),
            "mode": "kv", "writable": True}
    (tmp_path / "x.conf").write_text("Answer yes\nLogTime true\n")
    card = ToolCard(page, page._win.by_name["fail2ban"], page._win,
                    configs=[conf])
    card.load_configs()
    assert not card._reveal.get_reveal_child()
    inner = [w for w in _walk(card._reveal)
             if isinstance(w, Gtk.ScrolledWindow)]
    assert inner, "the editor must scroll INSIDE its card container"
    btn = card.open_btn
    btn.emit("clicked")
    pump()
    assert card._reveal.get_reveal_child()
    body = "\n".join(_texts(card))
    # the REAL file content is in the editor's buffer, not rewritten
    ed = card.editors[0]
    shown = ed.buffer.get_text(ed.buffer.get_start_iter(),
                               ed.buffer.get_end_iter(), False)
    assert "Answer yes" in shown
    assert "no write lane" not in body.lower()


def test_config_editor_loads_the_real_file(tmp_path, monkeypatch):
    conf = {"key": "t", "path": str(tmp_path / "r.conf"),
            "mode": "keyval", "writable": True}
    (tmp_path / "r.conf").write_text("DatabaseMirror db.local.clamav.net\n")
    ed = ToolConfigEditor(None, conf, data_dir=tmp_path)
    ed.load()
    text = str(ed.buffer.get_text(
        ed.buffer.get_start_iter(), ed.buffer.get_end_iter(), False))
    assert "DatabaseMirror" in text


def test_validation_rejects_unknown_key_without_writing(
        tmp_path, monkeypatch):
    conf = {"key": "t", "path": str(tmp_path / "r.conf"),
            "mode": "keyval", "writable": True}
    (tmp_path / "r.conf").write_text("Checks 24\n")
    ed = ToolConfigEditor(None, conf, data_dir=tmp_path)
    ed.load()
    ed.buffer.set_text("Checks 24\nNonsense 1\n")
    calls = []

    def fake_exec(helper, args):
        calls.append((helper, args))
        return 0, ""

    monkeypatch.setattr("ui.decisionlist._helper_exec", fake_exec)
    errs = validate_config(conf, "Checks 24\nNonsense 1\n", "Checks 24\n")
    assert any("Nonsense" in e and "line 2" in e for e in errs)
    ed._apply_now()
    pump()
    assert calls == []                  # nothing was written
    assert "Nonsense" in str(ed.result.get_text())


def test_apply_writes_through_the_lane_then_offers_the_baseline(
        tmp_path, monkeypatch):
    calls = []

    def fake_exec(helper, args):
        calls.append((helper, args))
        return 0, ""

    monkeypatch.setattr("ui.decisionlist._helper_exec", fake_exec)
    win = _FakeWin(tmp_path)
    page = ToolControlPage(win=win, reg=[t for t in _REG
                                         if t["name"] == "rkhunter"])
    card = page.cards["rkhunter"]
    card.configs[0]["path"] = str(tmp_path / "rkh.conf")
    (tmp_path / "rkh.conf").write_text("REPORT_EMAIL=\"root\"\n")
    card.load_configs()
    ed = card.editors[0]
    ed.buffer.set_text("REPORT_EMAIL=\"grey\"\n")
    ed._apply_now()
    pump()
    assert calls[0][0] == "config-write"
    assert "applied" in str(card.result.get_text()).lower()
    # the permafix offer: the baseline question with Yes / Later, Yes runs
    q = "\n".join(_texts(card._permafix))
    assert "--propupd" in q
    yes = _button_by_label(card._permafix, "Yes, refresh it")
    assert yes is not None and _button_by_label(card._permafix, "Later")
    yes.emit("clicked")
    pump()
    assert ("baseline-update", ["rkhunter"]) in calls
    assert "baseline" in str(card.result.get_text()).lower()
    # Later leaves the baseline alone, and says so
    card.offer_permafix()
    later = _button_by_label(card._permafix, "Later")
    later.emit("clicked")
    pump()
    assert "later" in str(card.result.get_text()).lower()


def test_permafix_baselines_are_rkhunter_and_aide_only(tmp_path,
                                                       monkeypatch):
    page = _page(tmp_path, monkeypatch)
    assert page.cards["rkhunter"]._permafix_tool() == "rkhunter"
    assert page.cards["aide"]._permafix_tool() == "aide"
    for name in ("fail2ban", "psad", "clamav"):
        assert page.cards[name]._permafix_tool() is None


# -------------------------------------------------- read-only honesty
def test_no_write_lane_opens_read_only(tmp_path, monkeypatch):
    conf = {"key": "jail.conf", "path": str(tmp_path / "jail.conf"),
            "mode": "shell", "writable": False}
    (tmp_path / "jail.conf").write_text("[DEFAULT]\n")
    ed = ToolConfigEditor(None, conf, data_dir=tmp_path)
    ed.load()
    ed.open_for()
    assert "read-only" in str(ed.banner.get_text()).lower()
    assert not ed.apply_btn.get_sensitive()


def test_missing_config_file_is_honest(tmp_path, monkeypatch):
    conf = {"key": "t", "path": str(tmp_path / "absent.conf"),
            "mode": "kv", "writable": True}
    ed = ToolConfigEditor(None, conf, data_dir=tmp_path)
    ed.load()
    assert "not on this machine" in str(ed.banner.get_text()).lower()
    assert not ed.apply_btn.get_sensitive()


# --------------------------------------------------------- dock + entry
def test_page_entry_is_show():
    assert guided.PAGE_ENTRY.get("tools") == "Show"


def test_dock_groups_are_show_and_schedule(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    groups = page.dock_groups()
    titles = [t for t, _w in groups]
    assert titles[0] == "Show"
    assert "Schedule" in titles
    show_btns = [w for w in groups[0][1] if isinstance(w, Gtk.Switch)]
    assert show_btns, "the live-only filter rides the Show group"
    # no schedule stagger is surfaced by the status digest: the dock's
    # toggle says so instead of pretending
    sched = [w for w in groups[1][1] if isinstance(w, Gtk.Button)]
    assert sched and not sched[0].get_sensitive()
    assert "stagger" in str(sched[0].get_tooltip_text()).lower()


def test_live_only_filter_hides_a_stopped_tool(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)
    page.refresh({"tools": {"fail2ban": {"state": "RED"},
                            "responderd": {"state": "GREEN"}},
                  "updated": "2026-11-10T12:00:00+00:00"})
    card = page.cards["fail2ban"]
    assert card.results_running() is False
    page.show_switch.set_active(False)      # live-only
    assert not card.get_visible()
    assert page.cards["responderd"].get_visible()
    page.show_switch.set_active(True)
    assert card.get_visible()


# ------------------------------------------------------- wiring in window
def test_tools_page_returns_not_a_legacy_alias():
    # task 9 gives the Tools page back the way task 8 un-retired the
    # Threat Hunter: the alias is gone from the fold-in map.
    from ui.window import _LEGACY_PAGE
    assert "tools" not in _LEGACY_PAGE


def test_builder_named_tools_view():
    import inspect
    from ui import window as W
    src = inspect.getsource(W.MainWindow._build_all)
    assert '"tools": self._tools_view' in src
