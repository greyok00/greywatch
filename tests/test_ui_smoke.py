import os
import sys
import json
import pathlib
import shutil
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Gdk  # noqa: E402


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
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)
if not _gtk_ready():
    pytest.skip("no display available", allow_module_level=True)


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def observe(widget):
    return list(widget.observe_children())


@pytest.fixture(scope="module")
def win():
    from ui.window import MainWindow
    w = MainWindow()
    w.present()
    pump(30)
    yield w
    w.destroy()


def test_launch_shows_exactly_one_screen(win):
    assert win.stack.get_visible_child_name() == "tools"


def test_unknown_view_key_cannot_grey_the_app(win):
    win._show("status")          # the old fatal key
    pump()
    assert win.stack.get_visible_child_name() == "tools"
    assert win._views["tools"].get_visible()


def test_every_rail_button_switches(win):
    for key in ("tools", "deep", "harden", "settings", "logs", "help"):
        win._rail_pick(None, key)
        pump(5)
        assert win.stack.get_visible_child_name() == key


def test_file_watchers_are_wired(win):
    assert len(getattr(win, "_monitors", [])) >= 2


def test_scan_buttons_write_a_request_the_daemon_picks_up(win):
    # The GUI asks, the root daemon runs. Nothing is spawned here and no
    # password is ever requested; one JSON file names one of six keys.
    from ui.cards import SCAN_MODES
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gw-scan-test-"))
    old = win.data_dir
    win.data_dir = tmp
    try:
        for mode in SCAN_MODES:
            ok, key = win._request_scan(mode)
            assert ok, key
            doc = json.loads((tmp / "scan-request.json").read_text())
            assert doc["key"] == mode["key"]
            assert doc["id"][:8].isdigit() and len(doc["id"]) == 20
    finally:
        win.data_dir = old
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_scan_button_opens_the_protections_page(win):
    # One page now: the progress rows and the findings live together
    # (owner 2026-10-30 — two pages showed the same scan twice).
    from ui.cards import SCAN_MODES
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gw-scan-test-"))
    old = win.data_dir
    win.data_dir = tmp
    try:
        mode = next(m for m in SCAN_MODES if m["key"] == "yara-tmp-scan")
        win._start_scan(None, mode)
        pump(10)
        assert win.stack.get_visible_child_name() == "deep"
        assert "Security Tools" in win.scan_status.get_text() or \
            "asked" in win.scan_status.get_text()
    finally:
        win.data_dir = old
        shutil.rmtree(tmp, ignore_errors=True)


def test_card_scan_maps_yara_watch_to_the_quick_scan(win):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gw-scan-test-"))
    old = win.data_dir
    win.data_dir = tmp
    try:
        win._open_scan_for(None, "yara-watch")
        doc = json.loads((tmp / "scan-request.json").read_text())
        assert doc["key"] == "yara-tmp-scan"
    finally:
        win.data_dir = old
        shutil.rmtree(tmp, ignore_errors=True)


def test_wizard_chooser_has_working_cancel(win):
    win._open_wizard()
    pump(20)
    chooser = win._chooser
    assert chooser is not None and chooser.get_visible()

    def button_labels(widget):
        out = []
        if isinstance(widget, Gtk.Button):
            out.append(widget.get_label() or "")
        for c in observe(widget):
            out.extend(button_labels(c))
        return out

    labels = button_labels(chooser)
    assert any("Cancel" in lab for lab in labels), labels

    mons = Gdk.Display.get_default().get_monitors()
    screen_h = mons.get_item(0).get_geometry().height if mons.get_n_items() \
        else 1000
    _w, h = chooser.get_default_size()
    assert h <= screen_h, (h, screen_h)

    chooser.emit("response", Gtk.ResponseType.CANCEL)
    pump(10)
    assert not chooser.get_visible()


def test_row_selection_carries_the_registry_key(win):
    # Rows are ordered by what needs attention, so find the tool by name
    # instead of assuming it sits first.
    path = next((i for i, r in enumerate(win.list_store)
                 if "responderd" in (r[2] or "")), None)
    assert path is not None, [r[2] for r in win.list_store]
    win.list_view.get_selection().select_path(path)
    pump(5)
    assert win._selected_tool == "responderd"


def test_selection_survives_a_live_refresh(win):
    win.list_view.get_selection().select_path(3)
    pump(5)
    chosen = win._selected_tool
    assert chosen
    win.refresh()
    pump(5)
    assert win._selected_tool == chosen
    assert win.sel_note.get_text().startswith("Selected:")


def test_pause_button_uses_the_selected_tool(win):
    calls = []
    win._pause_tool = lambda name: calls.append(name)
    win.list_view.get_selection().select_path(3)
    pump(5)
    win._pause_selected()
    assert calls == [win._selected_tool]


def test_every_tool_icon_file_exists():
    import pathlib
    from ui.toolicons import ICONS
    root = (pathlib.Path(__file__).resolve().parents[1]
            / "assets" / "icons" / "tools")
    for tool, icon in ICONS.items():
        assert (root / f"{icon}.svg").is_file(), tool


def test_every_tool_has_a_friendly_name_plain_name_and_icon():
    from registry import load_registry
    from ui.plain import friendly_name
    from ui.toolicons import ICONS, icon_name
    for tool in load_registry():
        name = tool["name"]
        # plain-language label for people, and the real service name beside it
        assert friendly_name(name) != name, name
        # one drawn icon per tool, installed as a themed symbolic
        assert name in ICONS, name
        assert icon_name(name) == f"gw-tool-{name}-symbolic"


def test_recent_rows_are_newest_first_and_deduped():
    from ui.models import recent_rows
    events = [
        {"ts": "2026-10-23T11:00:00+00:00", "from_tool": "ufw",
         "severity": "HIGH", "text": "BLOCK 1.1.1.1"},
        {"ts": "2026-10-23T12:00:00+00:00", "from_tool": "ufw",
         "severity": "HIGH", "text": "BLOCK 1.1.1.1"},
        {"ts": "2026-10-23T12:30:00+00:00", "from_tool": "fail2ban",
         "severity": "MEDIUM", "text": "Ban 2.2.2.2"},
    ]
    rows = recent_rows(events, limit=6)
    stamps = [r["ts"] for r in rows]
    assert stamps == sorted(stamps, reverse=True)
    assert len(rows) == 2                      # the duplicate is collapsed


def test_action_state_wins_until_status_catches_up(win):
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    win._state_override = {"yara-tmp-scan": ("GREEN", now)}
    info = {"state": "RED"}
    assert win._effective_state(
        "yara-tmp-scan", info, "2026-01-01T00:00:00+00:00") == "GREEN"
    later = (now + dt.timedelta(seconds=5)).isoformat()
    assert win._effective_state("yara-tmp-scan", info, later) == "RED"
    assert "yara-tmp-scan" not in win._state_override


def test_wizard_chooser_does_not_preselect_a_card():
    from ui.wizard import ToolChooser
    c = ToolChooser(on_pick=lambda k: None)
    c.present()
    pump(10)
    fb = []

    def walk(x):
        if isinstance(x, Gtk.FlowBox):
            fb.append(x)
        for ch in observe(x):
            walk(ch)

    walk(c)
    assert fb and fb[0].get_selection_mode() == Gtk.SelectionMode.NONE
    kid = fb[0].get_child_at_index(0)
    assert not (kid.get_state_flags()
                & Gtk.StateFlags.SELECTED), kid.get_state_flags()
    c.destroy()


def test_site_wizard_lists_real_sites_and_needs_no_typing():
    from ui.wizard import RuleWizard
    from ui import discover
    w = RuleWizard("site")
    pump(20)
    ids = _combo_ids(w.w["site"])
    assert ids, "no sites detected at all"
    assert ids == [""] + [c["host"] for c in discover.site_choices()]
    page = w.get_nth_page(1)              # "Which site?"
    assert not w.get_page_complete(page)  # the "Choose a site…" row
    w.w["site"].set_active(1)
    pump(5)
    assert w.get_page_complete(page)
    w.destroy()


def test_no_wizard_flow_contains_a_typing_field():
    from ui.wizard import RuleWizard
    for tool in ("site", "ufw", "fail2ban", "tetragon", "yara", "arpwatch"):
        w = RuleWizard(tool)
        pump(10)
        entries = []

        def walk(x):
            if isinstance(x, Gtk.Entry):
                entries.append(x)
            for c in observe(x):
                walk(c)

        walk(w)
        assert not entries, (tool, len(entries))
        w.destroy()


def test_wizard_close_button_really_closes():
    from ui.wizard import RuleWizard
    w = RuleWizard("site")
    pump(20)
    w.set_current_page(w.get_n_pages() - 1)
    pump(10)
    w.emit("close")
    pump(10)
    assert not w.get_visible()


def test_confirm_text_wraps_instead_of_stretching_the_window():
    from ui.wizard import RuleWizard
    w = RuleWizard("site")
    pump(20)
    assert w.confirm.get_wrap()
    assert w.confirm.get_max_width_chars() > 0
    w.destroy()


def test_wizard_done_page_keeps_the_window_width():
    from ui.wizard import RuleWizard
    w = RuleWizard("site")
    pump(20)
    assert w._done_body.get_max_width_chars() > 0
    page = w.get_nth_page(w.get_n_pages() - 1)
    labels = []

    def walk(x):
        if isinstance(x, Gtk.Label):
            labels.append(x.get_text())
        for c in observe(x):
            walk(c)

    walk(page)
    assert "Done" in labels
    w.destroy()


def test_sites_list_explains_the_selection_rule(win):
    win._show("settings")
    view = win.sites_view
    view.select(-1)
    assert view.act("allow") == "Select a site in the list first."
    assert not view.trust_btn.get_sensitive()
    win.app_entry.set_text("")
    win._on_app_add(None, None)
    assert "pick" in win.app_note.get_text().lower()
    win._app_sel = None
    win._on_app_remove(None)
    assert "select" in win.app_note.get_text().lower()


def test_removing_a_site_says_which_site(win):
    from ui.site_rows import SiteRow

    class FakeTrust:
        def __init__(self):
            self.allow = {"regression-test.example"}
            self.block = set()
            self.apps_allow = {"firefox"}

        def remove(self, name):
            self.allow.discard(name)
            self.block.discard(name)
            return True

        def remove_app(self, name):
            self.apps_allow.discard(name)
            return True

    old = win.trust
    win.trust = FakeTrust()
    win._show("settings")
    try:
        view = win.sites_view
        view.paint([SiteRow(entry="regression-test.example",
                            name="regression-test.example", address="",
                            description="unrecognized service — "
                                        "treat with care",
                            program="", port=None, last_seen="", count=0,
                            verdict="allow")])
        pump(5)
        view.select(0)
        text = view.act("remove")
        assert "regression-test.example" in text
        assert "None" not in text
        assert not win.trust.allow

        win._refresh_apps()
        win._app_sel = "firefox"          # what the cursor handler stores
        win._on_app_remove(None)
        assert "firefox" in win.app_note.get_text()
        assert "None" not in win.app_note.get_text()
        assert not win.trust.apps_allow
    finally:
        win.trust = old
        win._refresh_trust()
        win._refresh_apps()


def test_feed_times_are_the_users_own_clock():
    import datetime as dt
    from ui.models import local_clock
    stamp = "2026-10-23T12:00:51+00:00"
    expect = dt.datetime.fromisoformat(stamp).astimezone().strftime("%H:%M:%S")
    assert local_clock(stamp) == expect
    assert local_clock("") == ""
    assert local_clock("garbage") == ""


def test_status_words_are_honest():
    from ui.models import status_words
    assert status_words("GREEN", True, False) == "running"
    assert status_words("RED", True, False) == "not running"
    assert status_words("YELLOW", False, False) == "not installed"
    assert status_words("YELLOW", True, False) == "needs attention"
    assert status_words("UNKNOWN", None, False) == "could not check"
    assert status_words("RED", True, True) == "paused"


def test_wizard_trust_change_reaches_settings(win):
    from ui.site_rows import build_rows

    class Loader:
        allow, block, apps_allow = {"late.example"}, set(), set()
        loaded = False

        def load(self):
            self.loaded = True

    win._show("settings")       # lazy views: Settings builds on first show
    old = win.trust
    loader = Loader()
    win.trust = loader
    try:
        win._reload_trust()
        assert loader.loaded
        win.sites_view.paint(build_rows(win.trust, [], [], []))
        rows = win.sites_view.rows
        assert any(r.entry == "late.example" and r.verdict == "allow"
                   for r in rows)
    finally:
        win.trust = old
        win._reload_trust()


def test_empty_trust_lists_explain_themselves(win):
    class EmptyTrust:
        allow, block, apps_allow = set(), set(), set()

        def remove(self, name):
            return True

        def remove_app(self, name):
            return True

    old = win.trust
    win.trust = EmptyTrust()
    win._show("settings")
    try:
        win._refresh_trust()
        win._refresh_apps()
        assert "Nothing discovered yet" in win.sites_view.empty.get_text()
        assert len(win.app_store) == 1
        assert "Nothing" in win.app_store[0][0]
        win.app_view.set_cursor(0)
        pump(5)
        assert win._app_sel is None
    finally:
        win.trust = old
        win._refresh_trust()
        win._refresh_apps()


def test_validation_errors_are_plain_english():
    from ui.wiz_forms import _friendly
    msg = _friendly(ValueError("from-ip invalid: 'NOT-AN-IP'"))
    assert "from-ip" not in msg
    assert "the computer address is not valid" in msg


def test_yara_error_text_cannot_break_the_done_page(monkeypatch):
    from ui.wizard import RuleWizard
    import wiz.yara_wizard as Y
    import ui.discover as D
    monkeypatch.setattr(
        Y, "compile_gate",
        lambda src: (False, "line 1: unexpected <b> & </b>"))
    monkeypatch.setattr(
        D, "yara_source",
        lambda key, name: f"rule {name} {{ condition: filesize < 1 }}")
    w = RuleWizard("yara")
    pump(20)
    w._on_apply(None)
    pump(5)
    assert "unexpected <b> & </b>" in w._done_body.get_text()
    w.destroy()


def test_missing_status_snapshot_is_not_reported_as_a_fault(win, monkeypatch):
    import ui.window as W
    monkeypatch.setattr(W.daemon_mod, "load_status",
                        lambda *a, **k: {"updated": None, "tools": {}})
    win.refresh()
    pump(5)
    words = win.status_words.get_text()
    assert "no status yet" in words.lower(), words
    assert "need attention" not in words.lower(), words
    assert win.list_store[1][3] == "could not check"


def test_saved_theme_is_applied_at_startup(win):
    assert win._theme_store._provider is not None


def test_detail_empty_state_is_explained(win, monkeypatch):
    import ui.window as W
    monkeypatch.setattr(W.daemon_mod, "read_events", lambda *a, **k: [])
    win._open_detail("clamav")
    pump(10)
    assert len(win._detail_store) == 1
    assert "Nothing recorded" in win._detail_store[0][0]
    win._detail_dialog.destroy()


def test_details_open_as_a_visible_dialog(win):
    win._open_detail("clamav")
    pump(20)
    assert win._detail_dialog is not None
    assert win._detail_dialog.get_visible()
    win._detail_dialog.destroy()


def test_every_detail_page_packs_its_widgets_once(win):
    problems = []

    def handler(_domain, _level, message, _data):
        if "gtk_widget_get_parent" in message or "gtk_box" in message:
            problems.append(message)

    hid = GLib.log_set_handler(
        "Gtk", GLib.LogLevelFlags.LEVEL_CRITICAL, handler, None)
    try:
        for tool in win.registry:
            win._open_detail(tool["name"])
            pump(10)
            win._detail_dialog.destroy()
            pump(5)
    finally:
        GLib.log_remove_handler("Gtk", hid)
    assert not problems, problems


def test_detail_close_button_actually_closes(win):
    win._open_detail("clamav")
    pump(20)
    dlg = win._detail_dialog

    def buttons(w):
        out = []
        if isinstance(w, Gtk.Button):
            out.append(w)
        for c in observe(w):
            out.extend(buttons(c))
        return out

    close = [b for b in buttons(dlg)
             if "Close" in (b.get_label() or "")][0]
    close.emit("clicked")
    pump(20)
    assert not dlg.get_visible()


def _combo_ids(combo):
    return [row[1] for row in combo.get_model()]


def test_ufw_wizard_offers_real_computers_and_ports():
    from ui.wizard import RuleWizard
    from ui import discover
    w = RuleWizard("ufw")
    pump(20)
    who = _combo_ids(w.w["who"])
    assert "any" in who, who
    for h in discover.lan_hosts():
        assert h["ip"] in who, h
    ports = _combo_ids(w.w["port"])
    assert "any" in ports
    for p in discover.external_ports():
        assert str(p["port"]) in ports, p
    w.destroy()


def test_tetragon_wizard_names_the_policy_itself():
    from ui.wizard import RuleWizard
    w = RuleWizard("tetragon")
    pump(20)
    assert w.w["name"].get_text().startswith("policy name: watch-")
    w.w["kind"].set_active_id("connect")
    pump(5)
    assert w.w["name"].get_text().endswith("watch-connect")
    w.destroy()


def test_yara_wizard_lists_ready_rules_and_names_the_choice():
    from ui.wizard import RuleWizard
    from ui import discover
    w = RuleWizard("yara")
    pump(20)
    keys = _combo_ids(w.w["pick"])
    assert keys == [p["key"] for p in discover.YARA_PRESETS]
    assert w.w["name"].get_text().startswith("rule name: gw_")
    w.w["pick"].set_active_id("webshell")
    pump(5)
    assert "gw_webshell" in w.w["name"].get_text()
    assert w.w["about"].get_text()          # plain-English description
    w.destroy()


def test_every_ready_malware_rule_compiles_with_the_real_scanner():
    from ui import discover
    from wiz.yara_wizard import compile_gate
    for p in discover.YARA_PRESETS:
        ok, err = compile_gate(discover.yara_source(p["key"],
                                                    "gw_test_" + p["key"]))
        assert ok, (p["key"], err)


def test_fail2ban_wizard_defaults_to_a_real_journal_unit():
    from ui.wizard import RuleWizard
    from ui import discover
    w = RuleWizard("fail2ban")
    pump(20)
    assert w.w["src"].get_active_id() == "journal"
    assert w._f2b_source().startswith("journal:")
    unit = w.w["unit"].get_active_id()
    if "ssh.service" in discover.journal_units():
        assert unit == "ssh.service"
    assert w.w["pat"].get_active_id()
    assert len(discover.F2B_PATTERNS) == len(_combo_ids(w.w["pat"]))
    w.destroy()


def test_fail2ban_file_source_needs_a_chosen_file():
    from ui.wizard import RuleWizard
    w = RuleWizard("fail2ban")
    pump(20)
    page = w.get_nth_page(0)              # "What should it watch?"
    assert w.get_page_complete(page)
    w.w["src"].set_active_id("file")
    pump(5)
    assert not w.get_page_complete(page)   # nothing to watch yet
    w._f2b_file = "/var/log/fail2ban.log"
    w.w["src"].set_active_id("journal")
    pump(5)
    w.w["src"].set_active_id("file")      # the handler re-checks the file
    pump(5)
    assert w.get_page_complete(page)
    w.destroy()


def test_arpwatch_wizard_lists_the_real_devices():
    from ui.wizard import RuleWizard
    from ui import discover
    w = RuleWizard("arpwatch")
    pump(20)
    assert _combo_ids(w.w["iface"]) == [i["name"] for i in discover.interfaces()]
    w.destroy()


def test_program_picker_is_a_real_list_not_a_typing_box(win):
    ids = _combo_ids(win.app_combo)
    assert ids, "no programs discovered"
    for path in ids[:10]:
        assert pathlib.Path(path).exists(), path
    assert win.app_entry.get_placeholder_text()


def test_picking_a_program_trusts_its_real_path(win):
    class FakeTrust:
        apps_allow = set()

        def add_app(self, entry):
            self.apps_allow.add(entry)
            return True

        def remove_app(self, entry):
            self.apps_allow.discard(entry)

    old = win.trust
    win.trust = FakeTrust()
    try:
        path = _combo_ids(win.app_combo)[0]
        win.app_combo.set_active(0)
        win._on_app_add(None, None)
        assert path in win.trust.apps_allow
        assert win.app_entry.get_text() == ""
    finally:
        win.trust = old
        win._refresh_apps()


def test_settings_has_a_browse_button(win):
    win._show("settings")      # lazy views: the Settings screen builds here
    pump(5)
    found = []

    def walk(x):
        if isinstance(x, Gtk.Button) and "Browse" in (x.get_label() or ""):
            found.append(x)
        for c in observe(x):
            walk(c)

    walk(win._views["settings"])
    assert found, "the browse button is missing"


def test_progress_ring_only_exists_while_a_scan_runs(win):
    from ui.window import ProgressCircle
    win._ensure_view("deep")     # the ring lives on the Tools page
    # Earlier scan tests in this module leave the ring spinning; stop it so
    # this test measures the widget, not the leftovers.
    win.circle.stop("idle")
    assert not win.circle.get_visible()      # Tools screen starts clean
    c = ProgressCircle()
    assert not c.get_visible()
    c.start("Quick scan")
    assert c.get_visible()
    assert c.elapsed() >= 0
    c.done()
    assert not c.get_visible()


def test_the_ring_has_no_frozen_percentage_state():
    import inspect
    import pathlib
    from ui import window
    from ui.window import ProgressCircle
    try:
        src = inspect.getsource(ProgressCircle)
    except (OSError, TypeError):            # compiled (.so) tree: read the source
        text = (pathlib.Path(window.__file__).parent / "window.py").read_text()
        start = text.index("class ProgressCircle")
        rest = text[start + 1:]
        ends = [i for i in (rest.find("\nclass "), rest.find("\ndef "))
                if i != -1]
        src = text[start:start + 1 + (min(ends) if ends else len(rest))]
    assert "self.frac" not in src          # no frozen fraction state
    assert 'f"{int(' not in src            # no invented percentage text


def test_root_scans_watch_their_real_process():
    from ui.cards import SCAN_MODES
    by_key = {m["key"]: m for m in SCAN_MODES}
    for key, proc in (("clamav", "clamscan"), ("rkhunter", "rkhunter"),
                      ("lynis", "lynis")):
        assert by_key[key].get("proc") == proc, key


def test_updates_panel_shows_real_timestamps(win):
    win._show("settings")        # lazy view: the panel is built on first show
    win._refresh_updates()
    text = win.updates_note.get_text()
    assert "ClamAV virus definitions" in text
    assert "Security list (CVE)" in text
    assert "today" in text or ":" in text
    from ui import updates
    if updates.clamav_definitions() is None:
        pytest.skip("ClamAV definitions are not installed on this machine")
    assert updates.clamav_definitions() is not None
    if updates.cve_cache().exists() and updates.cve_list() is None:
        pytest.skip("cve-cache.json exists but is still root-only; the "
                    "daemon repairs it to 0640 root:grey on next restart")
    assert updates.cve_list() is not None


def test_cve_list_is_displayed_as_up_to_date_not_not_running(win):
    from ui import updates
    if not updates.cve_is_fresh():
        pytest.skip("the cache is genuinely old")
    import greywatch_daemon as dm
    snap = dm.load_status(str(dm.DATA_DIR / "status.json"))
    info = (snap.get("tools") or {}).get("cve-updater") or {"state": "RED"}
    assert win._display_state("cve-updater", info, snap.get("updated")) \
        == "GREEN"
    assert "list fetched" in win._update_detail("cve-updater")


def test_settings_exposes_the_firewall_and_learning_controls(win,
                                                             monkeypatch):
    win._show("settings")       # lazy views: Settings builds on first show
    # The note follows the engine's real state; force "on" so the test does
    # not depend on whether this machine has the firewall armed.
    monkeypatch.setattr(win, "_fw_is_on", lambda: True)
    win._refresh_fw()           # fw_note is filled by the live refresh only
    assert win.fw_btn.get_label() in ("Turn on", "Turn off")
    assert "firewall on," in win.fw_note.get_text().lower()
    # The controls are switches now (macOS), so the words live in the row
    # labels next to them rather than inside the control.
    assert "Learning mode" in win.learn_title.get_text()
    assert win.learn_for.get_active_id() in ("15", "60", "480", "0")
    assert win.update_btn.get_label() == "Update lists"
    assert "unknown" in win.fw_block_title.get_text().lower()


def test_learning_toggle_writes_the_real_flag(win):
    from ui.settings import LearningStore
    tmp = pathlib.Path(win._learn_store.path)
    before = tmp.read_text() if tmp.exists() else ""
    try:
        win.learn_for.set_active_id("15")
        win.learn_check.set_active(True)
        assert LearningStore(tmp).active()
        win.learn_check.set_active(False)
        assert not LearningStore(tmp).active()
    finally:
        if before:
            tmp.write_text(before)
        else:
            tmp.unlink(missing_ok=True)


def test_sites_list_shows_discovered_sites(win):
    from ui.site_rows import build_rows
    win._show("settings")
    rows = build_rows(win.trust, [], ["updates.ubuntu.com"], [])
    win.sites_view.paint(rows)
    pump(5)
    row = next(i for i in range(win.sites_view.visible_count())
               if "updates.ubuntu.com" in win.sites_view.row_text(i))
    assert "software updates" in win.sites_view.row_text(row)


def test_detail_config_pages_are_click_only(win):
    for tool in ("ufw", "fail2ban", "tetragon", "yara-watch",
                 "yara-tmp-scan", "arpwatch"):
        win._open_detail(tool)
        pump(10)
        entries, labels = [], []

        def walk(x):
            if isinstance(x, Gtk.Entry):
                entries.append(x)
            if isinstance(x, Gtk.Button):
                labels.append(x.get_label() or "")
            for c in observe(x):
                walk(c)

        walk(win._detail_dialog)
        assert not entries, (tool, len(entries))
        assert any("guided setup" in lab for lab in labels), (tool, labels)
        win._detail_dialog.destroy()
        pump(5)


def test_firewall_toggle_result_is_reported_where_the_button_is(win):
    win._show("settings")
    pump(10)
    win._after_toggle("appfw", False, 126)     # prompt cancelled
    pump(10)
    text = win.fw_status.get_text()
    assert "not authorised" in text and "password" in text
    assert win.fw_btn.get_sensitive()


def test_no_gtk3_only_api_survives_in_the_ui_sources():
    import re
    ui_dir = pathlib.Path(ROOT) / "ui"
    banned = [
        r"show_all\(", r"set_position\(", r"(?<!loop)\.run\(\)",
        r"Gtk\.MessageDialog", r"pack_start\(", r"pack_end\(",
        r"set_border_width\(", r"set_relief\(", r"get_style_context\(\)",
        r"set_line_wrap\(", r"get_action_area\(", r"set_no_show_all\(",
        r"Gtk\.main\(\)", r"Gtk\.main_quit", r"Gtk\.main_iteration",
        r"delete-event", r"Gtk\.WindowPosition", r"ReliefStyle",
        r"Gdk\.Screen", r"require_version\(\"Gtk\",\s*\"3\.0\"\)",
        r"\.set_focus\(", r"FileChooserDialog\(",
    ]

    def code_only(src: str) -> str:
        src = re.sub(r'""".*?"""', " ", src, flags=re.S)   # docstrings
        src = re.sub(r"'''.*?'''", " ", src, flags=re.S)
        lines = [re.sub(r"\s#.*$", "", ln) for ln in src.splitlines()]
        return "\n".join(lines)

    offenders = []
    for py in sorted(ui_dir.glob("*.py")):
        if py.name == "notify_alert.py":    # gi use is Notify-only there
            continue
        if py.name == "tray_helper.py":     # the tray IS a GTK3 process,
            continue                        # own cycle — by design
        src = code_only(py.read_text())
        src = code_only(py.read_text())
        for pat in banned:
            for m in re.finditer(pat, src):
                line = src[:m.start()].count("\n") + 1
                offenders.append((py.name, line, pat))
    assert not offenders, offenders


def test_window_close_hides_when_a_tray_exists(win):
    quits = []
    old = win._tray_available, win.quit_cb
    win._tray_available, win.quit_cb = True, (lambda: quits.append(1))
    try:
        assert win.emit("close-request") is True    # handler OWNS the close
        assert quits == []                          # the app stays alive in the tray
        assert not win.get_visible()                # hidden but summonable
        win.present()
        pump(5)
        assert win.get_visible()                    # tray Show brings it back
    finally:
        win._tray_available, win.quit_cb = old


def test_window_close_without_any_tray_ends_the_app(win):
    quits = []
    old = win._tray_available, win.quit_cb
    win._tray_available, win.quit_cb = False, (lambda: quits.append(1))
    try:
        assert win.emit("close-request") is True    # handler owns the close either way
        assert quits == [1]
    finally:
        win._tray_available, win.quit_cb = old


def test_wizard_hub_lists_the_baseline_and_every_tool_as_peers():
    """The baseline pass is one task in the hub, not the hub itself.

    Before the split the rail's "Wizard" opened the baseline flow and the
    per-tool wizards were a single link on its first page.
    """
    from ui.wizard import TOOL_CHOICES
    keys = [k for k, _i, _t, _a in TOOL_CHOICES]
    assert keys[0] == "baseline"
    for tool in ("appfw", "site", "ufw", "fail2ban", "tetragon",
                 "yara", "arpwatch"):
        assert tool in keys, tool
    # every card carries a drawn icon name, never an emoji glyph
    for key, icon, _title, _about in TOOL_CHOICES:
        assert icon.endswith("-symbolic"), (key, icon)


def test_appfw_choice_builds_appfw_pages_not_the_ufw_ones():
    from ui.wizard import RuleWizard
    w = RuleWizard("appfw")
    pump(10)
    assert "target" in w.w, "appfw flow has no program picker"
    assert isinstance(w.w["target"], Gtk.ComboBoxText)
    assert "who" not in w.w, "appfw flow leaked the UFW pages"
    w.destroy()


def test_baseline_has_its_own_rail_page(win):
    # Owner 2026-10-30: the baseline pass belongs in the rail, named
    # Endpoint Hardening — not a card at the bottom of the tool list.
    assert "harden" in win._builders
    assert "harden" in win._rail_btns
    assert not hasattr(win, "_baseline_card")
    win._rail_pick(None, "harden")
    pump(5)
    assert win.stack.get_visible_child_name() == "harden"
    assert isinstance(win.harden_view, Gtk.Box)


def test_tool_card_shows_plain_name_and_real_tool_name(win):
    frame = win.card_widgets["responderd"]
    found = []
    todo = [frame]
    while todo:
        x = todo.pop()
        if isinstance(x, Gtk.Label):
            found.append(x.get_label() or "")
        todo.extend(observe(x))
    blob = "\n".join(found)
    assert "Auto-responder" in blob
    assert "responderd" in blob


def test_assistant_chat_answers_are_selectable():
    """The owner asked to copy a log line out of the chat: the answer
    bubbles must be selectable text, not painted-on labels."""
    from ui.assistant import AssistantPanel
    panel = AssistantPanel(registry=[], get_status=lambda: {},
                           get_recent=lambda: [], get_llm=lambda: None,
                           on_intent=lambda *a: None)
    lbl = panel._bubble("copy this line")
    assert lbl.get_selectable() is True



def test_assistant_panel_header_identifies_the_ai_assistant():
    """The owner asked for it to 'look like an AI assistant': a mascot, a
    real title, and a sentence saying what it is."""
    from ui.assistant import AssistantPanel
    panel = AssistantPanel(registry=[], get_status=lambda: {},
                           get_recent=lambda: [], get_llm=lambda: None,
                           on_intent=lambda *a: None)

    def walk(w, out):
        if isinstance(w, Gtk.Label):
            out.append(w.get_label() or "")
        c = w.get_first_child()
        while c is not None:
            walk(c, out)
            c = c.get_next_sibling()

    labels = []
    walk(panel, labels)
    blob = "\n".join(labels)
    assert "GreyWatch Assistant" in blob
    assert "Local AI assistant" in blob
    # The sub-line says what it is *and* that it never changes anything
    # without the confirm box (owner: "more execution", same gate).
    assert "asks before changing anything" in blob
    # The header shows the app's own icon art, not a separate assistant
    # logo (owner: the wolf must be the white one, same as the icon).
    art = ROOT / "assets" / "logo" / "greywatch-icon-128.png"
    assert art.exists() and art.stat().st_size > 1000
    blue = ROOT / "assets" / "logo" / "greywatch-assistant-128.png"
    assert not blue.exists(), "the blue assistant logo should be gone"
