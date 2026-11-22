"""Pins for the final whole-branch review fix wave (2026-11-19).

Every test here fails on the reviewed head: the self-healer re-armed the
daily clam timer, job panels mirrored whichever job was live, labels
carried raw daemon tokens, and the schedule/patch paths were not honest.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk


# ---------------------------------------------------------------- helpers


def _pump(iterations=400):
    ctx = GLib.main_context_default()
    for _ in range(iterations):
        ctx.iteration(False)
        time.sleep(0.002)


def _texts(w) -> str:
    out = []

    def walk(node):
        if isinstance(node, Gtk.Button):
            out.append(node.get_label() or "")
        if isinstance(node, Gtk.Label):
            out.append(node.get_text())
        child = node.get_first_child() if hasattr(node, "get_first_child") \
            else None
        while child is not None:
            walk(child)
            child = child.get_next_sibling()

    walk(w)
    return " ".join(out)


def _tree_texts(w) -> str:
    """Every cell in every table under a widget, plus column titles."""
    out = []

    def walk(node):
        if isinstance(node, Gtk.TreeView):
            for column in node.get_columns():
                out.append(str(column.get_title() or ""))
            model = node.get_model()
            if model is not None:
                for row in model:
                    out.extend(str(value) for value in row)
        child = node.get_first_child() if hasattr(node, "get_first_child") \
            else None
        while child is not None:
            walk(child)
            child = child.get_next_sibling()

    walk(w)
    return " ".join(out)


def _buttons(w) -> list:
    out = []

    def walk(node):
        if isinstance(node, Gtk.Button):
            out.append(node)
        child = node.get_first_child() if hasattr(node, "get_first_child") \
            else None
        while child is not None:
            walk(child)
            child = child.get_next_sibling()

    walk(w)
    return out


def _button(root, label):
    for button in _buttons(root):
        if button.get_label() == label:
            return button
    raise AssertionError(f"button {label!r} missing")


class _Win:
    notes: list = []

    def note(self, text):
        self.notes.append(text)

    def has_page(self, label):
        return True

    def get_width(self):
        return 1280


# ------------------------------------------- on-demand ClamAV (critical 1, 4)


def test_the_healer_never_starts_or_enables_the_on_demand_clam_timer():
    import selfheal
    from types import SimpleNamespace

    calls = []
    tool = {"name": "clamav", "unit": "greywatch-clam-scan.timer",
            "scope": "root", "label": "ClamAV", "on_demand": True}
    healer = selfheal.SelfHealer("/tmp/nope", [tool],
                                 log=lambda *a: None,
                                 clock=lambda: 1000.0)

    def systemctl(_tool, *args):
        calls.append(list(args))
        return SimpleNamespace(stdout="inactive\n", returncode=0)

    healer._systemctl = systemctl
    healer._journal = lambda *_a, **_k: ""
    healer._active = lambda _tool: False
    healer.tick({"clamav": {"state": "ON_DEMAND", "unit_state": "inactive"}})
    healer.repair("clamav")
    bad = [c for c in calls
           if c and c[0] in ("start", "enable", "restart")]
    assert bad == [], bad


def test_ensure_updates_never_starts_a_scan_timer(monkeypatch):
    import greywatch_daemon as daemon

    tools = [
        {"name": "clamav", "unit": "greywatch-clam-scan.timer",
         "on_demand": True},
        {"name": "boot-sweep", "unit": "greywatch-boot-sweep.timer"},
        {"name": "cve-updater", "unit": "greywatch-cve.timer"},
    ]
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-enabled"]:
            return subprocess.CompletedProcess(argv, 0, "enabled\n", "")
        if argv[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(argv, 0, "inactive\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(daemon.subprocess, "run", fake_run)
    stub = type("S", (), {"registry": tools,
                          "data_dir": pathlib.Path("/nonexistent")})()
    daemon.Daemon.ensure_updates(stub)
    bad = [c for c in calls
           if ({"start", "enable"} & set(c))
           and {"greywatch-clam-scan.timer",
                "greywatch-boot-sweep.timer"} & set(c)]
    assert bad == [], bad


def test_status_snapshot_publishes_the_on_demand_lane_healthy():
    import status

    registry = [{"name": "clamav", "label": "ClamAV",
                 "unit": "greywatch-clam-scan.timer", "on_demand": True,
                 "logs": []}]
    snap = status.snapshot(registry, lambda _t: "inactive")
    row = snap["tools"]["clamav"]
    assert row["state"] == "ON_DEMAND", row


def test_the_clam_lane_reads_on_demand_in_the_virus_card_and_tools(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "status.json").write_text(json.dumps({
        "updated": "2026-11-19T12:00:00+00:00",
        "tools": {"clamav": {"label": "ClamAV", "state": "ON_DEMAND"},
                  "freshclam": {"label": "Signatures", "state": "GREEN"}}}))
    from ui import security, tools
    card = security.virus_card(_Win())
    text = _texts(card).lower()
    assert "on demand" in text
    assert "down" not in text
    page = tools.build(_Win())
    page_text = _tree_texts(page).lower()
    assert "on demand" in page_text
    assert "on_demand" not in page_text


# --------------------------------------- job ownership (critical 2, 3, 21)


def _desk(tmp_path, monkeypatch, tool_id="rkhunter"):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import cliapi, tooldesk
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, **k: {"tool": tool_id, "state": "GREEN",
                                         "events": []})
    window = _Win()
    window.scan_monitor = None
    scroll = tooldesk.build(window, "Rootkit", (tool_id,), tool_id)
    _pump()
    return tooldesk, scroll, scroll._gw_body


def test_a_desk_panel_stays_idle_when_another_key_is_running(
        tmp_path, monkeypatch):
    tooldesk, _scroll, body = _desk(tmp_path, monkeypatch)
    tooldesk._apply_job(body, {
        "key": "clamav", "state": "running", "scan_id": "20261119T120000-a1",
        "scanners": {"clamav": {"state": "running", "percent": 0.42}}})
    panel = body._gw_job_panel
    assert panel.status.get_text() == "No job on file."
    assert panel.chart._gw_state["indeterminate"] is False
    assert "working" not in panel.status.get_text().lower()
    for control in (panel.pause, panel.resume, panel.cancel):
        assert not control.get_sensitive()


def test_a_desk_control_passes_its_own_documents_scan_id(
        tmp_path, monkeypatch):
    tooldesk, _scroll, body = _desk(tmp_path, monkeypatch)
    from ui import scanrequests
    calls = []
    monkeypatch.setattr(scanrequests, "control_scan",
                        lambda *a, **k: calls.append(a) or (True, ""))
    # no owned document: nothing may reach the service's current session
    tooldesk._control(body, "pause")
    assert calls == []
    tooldesk._apply_job(body, {
        "key": "rkhunter", "state": "running", "scan_id": "20261119T120000-a2",
        "scanners": {"rkhunter": {"state": "running", "percent": 0.1}}})
    tooldesk._control(body, "pause")
    assert calls and calls[0][-1] == "20261119T120000-a2", calls


def test_an_idle_desk_shows_no_indeterminate_band_and_no_working(
        tmp_path, monkeypatch):
    tooldesk, _scroll, body = _desk(tmp_path, monkeypatch)
    tooldesk._apply_job(body, {})
    panel = body._gw_job_panel
    assert panel.chart._gw_state["indeterminate"] is False
    assert "working" not in panel.status.get_text().lower()


def test_the_antivirus_block_does_not_paint_a_check_job(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "posture.json").write_text(json.dumps({"score": 57,
                                                       "inputs": {}}))
    (tmp_path / "status.json").write_text(json.dumps({"tools": {}}))
    from ui import security
    window = _Win()
    window.scan_monitor = None
    body = Gtk.Box()
    body._gw_window = window
    security._scan_block(window, body)
    security._apply_scan(body, {
        "key": "rkhunter", "state": "running", "scan_id": "20261119T120000-a3",
        "scanners": {"rkhunter": {"state": "running", "percent": 0.3}}})
    panel = body._gw_scan["panel"]
    assert panel.status.get_text() == "No job on file."
    assert panel.chart._gw_state["indeterminate"] is False
    assert body._gw_scan["quick"].get_sensitive()
    assert body._gw_scan["deep"].get_sensitive()


def test_an_external_scan_disables_pause_and_keeps_cancel():
    from ui.jobpanel import JobPanel
    panel = JobPanel("Antivirus", lambda: None, lambda: None, lambda: None)
    panel.update("running", None, 30, "A scan started outside the app",
                 external=True)
    assert not panel.pause.get_sensitive()
    assert not panel.resume.get_sensitive()
    assert panel.cancel.get_sensitive()


# --------------------------------------------------- labels (important 5)


def test_the_security_cards_speak_words_not_daemon_tokens(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "status.json").write_text(json.dumps({
        "updated": "2026-11-19T12:00:00+00:00",
        "tools": {name: {"label": name, "state": "GREEN"}
                  for name in ("clamav", "freshclam", "ufw", "fail2ban",
                               "appfw", "aide", "tetragon", "apparmor",
                               "cve-updater")}}))
    from ui import security
    for builder in (security.virus_card, security.net_card,
                    security.program_card, security.integrity_card,
                    security.updates_card):
        text = _texts(builder(_Win())).lower()
        assert "green" not in text, builder.__name__
        assert "live" in text or "on demand" in text, builder.__name__


def test_the_baseline_table_uses_display_names_and_word_states(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import baseline_detail
    page = Gtk.Box()
    page._gw_window = _Win()
    page._gw_verify = {"tool_baseline": [
        {"tool": "responderd", "check": "unit is running",
         "state": "active=inactive enabled=disabled", "fix": "start it"}]}
    rows = baseline_detail._tools_rows(page)
    text = _texts(rows) + " " + _tree_texts(rows)
    assert "Responderd" in text
    assert "responderd" not in text
    assert "active=" not in text and "enabled=" not in text


# ------------------------------------------------ patch path (important 6, 9)


def test_the_per_package_patch_timeout_outlasts_the_cli_budget(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 10, "suite": "trixie",
        "entries": [{"package": "openssl", "id": "CVE-2026-1",
                     "severity": "HIGH", "installed": "1.0",
                     "fixed": "2.0"}]}))
    from ui import actions, baseline_detail, cliapi
    seen = []
    monkeypatch.setattr(cliapi, "call",
                        lambda *a, **k: seen.append(k.get("timeout"))
                        or (0, "patched", ""))
    monkeypatch.setattr(actions, "ask", lambda *a, **k: True)
    page = baseline_detail.build(_ShellStub())
    _button(page, "Patch openssl").emit("clicked")
    _pump()
    assert seen and seen[0] > 1800, seen


def test_the_patch_helper_refuses_dash_names_and_passes_the_separator(
        tmp_path):
    root = pathlib.Path(__file__).resolve().parents[1]
    script = root / "apply" / "patch-packages.sh"
    calls = tmp_path / "apt.log"
    calls.write_text("")
    apt = tmp_path / "apt-get"
    apt.write_text("#!/bin/sh\n"
                   f'echo "$*" >> "{calls}"\n'
                   "exit 0\n")
    apt.chmod(0o755)
    dpkg = tmp_path / "dpkg-query"
    dpkg.write_text("#!/bin/sh\nexit 0\n")
    dpkg.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin", "APT_GET_BIN": str(apt),
           "DPKG_QUERY_BIN": str(dpkg)}
    smuggled = subprocess.run(
        ["bash", str(script), "openssl", "--all"],
        capture_output=True, text=True, env=env, timeout=30)
    assert smuggled.returncode != 0
    assert "invalid package name: --all" in smuggled.stderr
    log = calls.read_text()
    assert " -y upgrade" not in log
    good = subprocess.run(["bash", str(script), "openssl"],
                          capture_output=True, text=True, env=env,
                          timeout=30)
    assert good.returncode == 0, good.stderr
    assert "install --only-upgrade -- openssl" in calls.read_text()


def _ShellStub():
    from tests.test_ui_v4 import _ShellStub as stub
    return stub()


# --------------------------------------------- quick scan roots (important 10)


def test_quick_scan_skips_missing_roots(tmp_path):
    import scan_session as S
    home = tmp_path
    (home / "Downloads").mkdir()
    svc = S.ScanService(tmp_path / "state", home=str(home),
                        ui_user="grey", spawn=lambda *a, **k: None,
                        count_totals=False, use_systemd=False)
    roots = svc._run_roots("clamav-frequent")
    assert str(home / "Downloads") in roots
    assert str(home / "Desktop") not in roots
    assert str(home / "Documents") not in roots
    assert all(pathlib.Path(root).is_dir() for root in roots)


# -------------------------------------------- header / findings (11, 8, 14)


def test_the_header_click_opens_the_overview_tab():
    from ui import app as app_mod

    class _App(Gtk.Application):
        pass

    win = app_mod.Window(_App(application_id="org.greywatch.fixwave"))
    win.show_page("Security Center")
    body = win._pages["Security Center"]._gw_body
    body._gw_tab_stack.set_visible_child_name("findings")
    win._update_header_status({
        "state": "running", "key": "clamav-frequent",
        "scanners": {"clamav": {"state": "running", "percent": 0.42}}})
    win._header_status.emit("clicked")
    assert body._gw_tab_stack.get_visible_child_name() == "overview"


def test_recent_runs_render_from_the_scan_journal(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "20261119T120000-a1.json").write_text(json.dumps({
        "scan_id": "20261119T120000-a1", "key": "clamav-home",
        "state": "done", "started_at": "2026-11-19T12:00:00+00:00",
        "ended_at": "2026-11-19T12:02:00+00:00",
        "scanners": {"clamav": {"state": "done", "count": 120,
                                "total": 120}}}))
    from ui import findings
    runs = findings._recent_runs()
    assert runs and runs[0]["key"] == "clamav-home"
    assert runs[0]["seconds"] == 120
    card = findings._run_history_card()
    text = _texts(card)
    assert "recent runs" in text.lower()
    assert "2 minutes" in text or "120" in text


def test_the_schedule_has_no_parenthetical_and_names_only_real_timers():
    from ui import findings
    rows_box = Gtk.Box()
    out = ("Mon 2026-11-19 12:00:00 UTC  1h  greywatch-cve.timer\n"
           "n/a  n/a  n/a  n/a  greywatch-clam-scan.timer\n"
           "n/a  n/a  n/a  n/a  greywatch-boot-sweep.timer\n")
    findings._schedule_fill(rows_box, out)
    text = _texts(rows_box)
    assert "greywatch-cve.timer" in text
    assert "clam-scan" not in text and "boot-sweep" not in text
    assert "(" not in text and ")" not in text
    empty = Gtk.Box()
    findings._schedule_fill(empty, "")
    empty_text = _texts(empty).lower()
    assert "scan block" in empty_text


# -------------------------------------------------- caps (important 7)


def test_pending_decisions_state_how_many_are_shown(monkeypatch):
    from ui import findings
    box = Gtk.Box()
    page = Gtk.Box()
    asks = [{"id": f"ask-{i}", "question": f"Q{i}",
             "options": [{"id": "a", "label": "Allow"}]}
            for i in range(11)]
    findings._asks_fill(page, box, asks, "")
    text = _texts(box)
    assert "Showing 8 of 11" in text


def test_the_cve_table_states_how_many_rows_are_shown(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    entries = [{"package": f"pkg{i}", "id": f"CVE-2026-{i}",
                "severity": "HIGH", "installed": "1", "fixed": "2"}
               for i in range(60)]
    (tmp_path / "cve-cache.json").write_text(json.dumps({
        "installed_count": 100, "suite": "trixie", "entries": entries}))
    from ui import baseline_detail
    card = baseline_detail._cve_card(None)
    text = _texts(card)
    assert "Showing 40 of 60" in text


# ------------------------------------------- deep scan copy (important 13)


def test_the_scan_block_shows_the_last_deep_run_count(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "posture.json").write_text(json.dumps({"score": 57,
                                                       "inputs": {}}))
    (tmp_path / "status.json").write_text(json.dumps({"tools": {}}))
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "20261119T110000-a1.json").write_text(json.dumps({
        "key": "clamav-home", "state": "done",
        "started_at": "2026-11-19T11:00:00+00:00",
        "ended_at": "2026-11-19T11:30:00+00:00",
        "scanners": {"clamav": {"count": 4321}}}))
    from ui import security
    window = _Win()
    window.scan_monitor = None
    body = Gtk.Box()
    body._gw_window = window
    card = security._scan_block(window, body)
    text = _texts(card)
    assert "4,321" in text
    assert "30 minutes" in text


# ----------------------------------------------- assistant (12)


def test_a_scan_intent_redirects_before_the_confirm_gate():
    from ui.assistant import AssistantPanel
    from assistant.intents import Intent

    calls = []

    class Stub:
        _turn_seq = 1
        _friendly = {}

        def _confirm(self, intent):
            calls.append(("confirm", intent))

        def _scan_redirect(self, holder):
            calls.append(("redirect", holder))
            holder.set_text("Start scans from the Security Center scan "
                            "block.")
            return False

    texts = []

    class Holder:
        def set_text(self, text):
            texts.append(text)

    AssistantPanel._turn_planned(
        Stub(), 1, Holder(),
        {"kind": "intent", "intent": Intent("scan", "clamav")}, {})
    assert [kind for kind, _ in calls] == ["redirect"]
    assert texts and "Security Center" in texts[0]


# ------------------------------------------- diagnose fix (18)


def test_diagnose_and_fix_runs_the_fix_after_confirmation(monkeypatch):
    from ui import security, cliapi, actions
    page = Gtk.Box()
    page._gw_window = _Win()
    calls = []
    monkeypatch.setattr(cliapi, "call",
                        lambda *a, **k: calls.append(a) or (0, "ok", ""))
    monkeypatch.setattr(actions, "ask", lambda *a, **k: True)
    box = security._actions_box(page._gw_window, page)
    _button(box, "Diagnose + fix").emit("clicked")
    _pump()
    assert any("doctor" in args and "--fix" in args for args in calls), calls


# ------------------------------------------- pending timeout (20)


def test_the_pending_timeout_is_honest_when_the_request_is_gone(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "posture.json").write_text(json.dumps({"score": 57,
                                                       "inputs": {}}))
    (tmp_path / "status.json").write_text(json.dumps({"tools": {}}))
    from ui import security
    window = _Win()
    window.scan_monitor = None
    body = Gtk.Box()
    body._gw_window = window
    security._scan_block(window, body)
    security._start_scan(body, "clamav-frequent")
    (tmp_path / "scan-request.json").unlink()
    security._scan_pending_timeout(body, body._gw_scan["pending_token"])
    text = body._gw_scan["panel"].status.get_text()
    assert "on file" not in text


# ------------------------------------------- GUI never sends the batch key


def test_no_gui_path_sends_full_or_scan_all(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "posture.json").write_text(json.dumps({"score": 57,
                                                       "inputs": {}}))
    (tmp_path / "status.json").write_text(json.dumps({"tools": {}}))
    from ui import actions, cliapi, security, scanrequests, tooldesk
    keys = []
    monkeypatch.setattr(scanrequests, "request_scan",
                        lambda _d, key: keys.append(key) or (True, ""))
    monkeypatch.setattr(actions, "ask", lambda *a, **k: True)
    window = _Win()
    window.scan_monitor = None
    body = Gtk.Box()
    body._gw_window = window
    card = security._scan_block(window, body)
    _button(card, "Quick scan").emit("clicked")
    # The first start owns the slot; clear the pending guard so the Deep
    # button can file its own request in this test.
    body._gw_scan["pending"] = None
    body._gw_scan["quick"].set_sensitive(True)
    body._gw_scan["deep"].set_sensitive(True)
    _button(card, "Deep scan").emit("clicked")
    for tool_id in ("rkhunter", "lynis", "aide", "yara-tmp-scan"):
        monkeypatch.setattr(cliapi, "jcall",
                            lambda *a, _t=tool_id, **k: {"tool": _t,
                                                         "state": "GREEN",
                                                         "events": []})
        scroll = tooldesk.build(window, tool_id, (tool_id,), tool_id)
        _pump()
        _button(scroll, "Run check").emit("clicked")
    assert keys
    assert not ({"full", "scan-all", "max-speed"} & set(keys)), keys


# ------------------------------------------- quiet labels (15, 16)


def test_the_dns_column_header_is_result(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "dnslog.json").write_text(json.dumps({
        "log_queries_enabled": True, "counts": {"queries": 5, "domains": 1},
        "domains": {"example.com": {"queries": 5, "blocked": True,
                                    "last": "2026-11-19T12:00:00+00:00"}}}))
    from ui import network
    card = network._dns_card(None)
    text = _tree_texts(card)
    assert "Result" in text
    assert "Blocked" not in text


def test_the_clam_description_is_on_demand():
    from ui import plain
    _name, sentence = plain.FRIENDLY["clamav"]
    assert "once a day" not in sentence.lower()
    assert "ask" in sentence.lower() or "demand" in sentence.lower()


# ------------------------------------------- page contract (17)


def test_tools_refresh_skips_an_unchanged_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "status.json").write_text(json.dumps({
        "updated": "2026-11-19T12:00:00+00:00",
        "tools": {"psad": {"label": "Port Scan Watch", "state": "GREEN"}}}))
    from ui import tools
    page = tools.build(_Win())
    body = page._gw_body
    first = body.get_first_child()
    tools.refresh(page)
    assert body.get_first_child() is first


def test_read_jsonl_streams_only_the_tail(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "events.jsonl").write_text(
        "".join(json.dumps({"n": i}) + "\n" for i in range(5000)))
    from ui import cliapi
    rows = cliapi.read_jsonl("events.jsonl", last=3)
    assert [r["n"] for r in rows] == [4997, 4998, 4999]


# ------------------------------------------- job panel naming (19)


def test_the_job_panel_names_the_job_and_the_elapsed_time():
    from ui.jobpanel import JobPanel
    panel = JobPanel("Antivirus", lambda: None, lambda: None, lambda: None)
    panel.update("running", 0.4, 120, "Scanning /home/grey/a.bin")
    text = panel.status.get_text()
    assert "Antivirus" in text
    assert "2 minutes" in text


def test_help_refresh_keeps_the_open_digest(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import helpdesk
    page = helpdesk.build(_Win())
    stack = page._gw_body._gw_stack
    stack.set_visible_child_name("digest")
    helpdesk.refresh(page)
    assert stack.get_visible_child_name() == "digest"


def test_timeline_refresh_skips_an_unchanged_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    (tmp_path / "events.jsonl").write_text("")
    (tmp_path / "quarantine.jsonl").write_text("")
    (tmp_path / "status.json").write_text(json.dumps({"tools": {}}))
    from ui import timeline
    page = timeline.build(_Win())
    body = page._gw_body
    first = body.get_first_child()
    timeline.refresh(page)
    assert body.get_first_child() is first


def test_no_config_level_or_registry_entry_arms_a_scan_timer():
    root = pathlib.Path(__file__).resolve().parents[1]
    levels = json.loads((root / "data" / "baseline-configs.json").read_text())
    text = json.dumps(levels)
    assert "greywatch-clam-scan.timer" not in text
    assert "greywatch-boot-sweep.timer" not in text
    registry = json.loads((root / "registry.json").read_text())
    clam = next(tool for tool in registry["tools"]
                if tool["name"] == "clamav")
    assert clam.get("on_demand") is True


def test_the_deb_postinst_disables_both_scan_timers():
    root = pathlib.Path(__file__).resolve().parents[1]
    script = (root / "packaging" / "build-deb.sh").read_text()
    assert "systemctl disable --now greywatch-clam-scan.timer" in script
    assert "systemctl disable --now greywatch-boot-sweep.timer" in script
