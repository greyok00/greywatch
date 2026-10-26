"""tests/test_ui_harden.py — HardenView smoke tests (Task 6).

Injected fakes only: never pkexec, never the shell, never the real
controls file. The planfile-contract test asserts the exact JSON shape
apply/harden.sh (Task 5) decodes.
"""
import json
import sys
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib    # noqa: E402

from hardening.controls import Control    # noqa: E402
from ui.harden import (HardenView, verby_args, planfile_entries,
                       parse_apply_output)    # noqa: E402


def _gtk_ready() -> bool:
    """GTK4 defers real display init — init_check() alone returns True
    headless and widget code then segfaults. A default display existing
    is the honest probe; nothing else makes the module skip cleanly."""
    try:
        if not Gtk.init_check():
            return False
        from gi.repository import Gdk
        return Gdk.Display.get_default() is not None
    except Exception:
        return False


if not _gtk_ready():
    pytest.skip("no display available", allow_module_level=True)


def pump(n=60):
    ctx = GLib.main_context_default()
    for _ in range(n):
        while ctx.iteration(may_block=False):
            pass


# ── GTK window-leak guard (banked requirement) ─────────────────────────
# A MainWindow opened in a test stays MAPPED after the test on GTK4: the
# app's close-request hides to tray, so the ghost window keeps piling up
# on the owner's desktop (owner bug report: 6 accumulated, and closing
# does nothing). Contract: every test closes AND destroys what it made,
# no-tray path so a real close ends the window, and a session finalizer
# enumerates the leftover toplevels as the safety net.
def make_no_tray_window(**kw):
    """The ONLY way to build a MainWindow in this module: no-tray so a
    close/destroy really unmaps. (HardenView itself opens no toplevels;
    this exists for future UI tests kept to the same rule.)"""
    from ui.window import MainWindow
    return MainWindow(tray_available=False, **kw)


@pytest.fixture(autouse=True)
def leak_guard():
    """Per test: record the toplevels at entry; at exit close AND destroy
    every toplevel that appeared during the test (HardenView makes none,
    but any window a future test opens must not survive it)."""
    start = set(Gtk.Window.list_toplevels())
    yield
    for _ in range(10):                    # settle: let thread idle_adds land
        pump(4)
    for w in list(Gtk.Window.list_toplevels()):
        if w in start:
            continue
        try:
            w.close()
        except Exception:
            pass
    for _ in range(10):
        pump(4)
    for w in list(Gtk.Window.list_toplevels()):
        if w in start:
            continue
        try:
            w.destroy()
        except Exception:
            pass


@pytest.fixture(scope="session", autouse=True)
def no_greywatch_ghosts():
    """Safety net: after EVERYTHING in this module ran, enumerate the
    leftover toplevels and destroy every greywatch window left, then
    assert none remain — the pytest battery must leave the owner's
    desktop empty of greywatch windows."""
    yield
    for _ in range(10):
        pump(4)
    for w in list(Gtk.Window.list_toplevels()):
        title = ""
        try:
            title = w.get_title() or ""
        except Exception:
            pass
        if isinstance(w, Gtk.Window) and "greywatch" in title.lower():
            try:
                w.destroy()
            except Exception:
                pass
    # windows of THIS process only: list_toplevels cannot see other apps
    leftover = []
    for w in Gtk.Window.list_toplevels():
        try:
            if "greywatch" in (w.get_title() or "").lower():
                leftover.append(w.get_title())
        except Exception:
            pass
    assert not leftover, f"leaked greywatch windows: {leftover}"


def _find_card_texts(view):
    out = []
    child = view.cards.get_first_child()
    while child is not None:
        frame = child.get_child()
        try:
            box = frame.get_child()
            b = box.get_first_child()          # head label
            texts = []
            while b is not None:
                t = b.get_text() if hasattr(b, "get_text") else ""
                if t:
                    texts.append(t)
                b = b.get_next_sibling()
            out.append(" | ".join(texts))
        except Exception:
            pass
        child = child.get_next_sibling()
    return out


CONTROLS = [
    Control("good-control", "kernel", "Good control, already at baseline",
            probe="true", severity="HIGH", nist=["CM-7"], cis=["1.1"]),
    Control("gap-control", "kernel", "A gap the helper can fix",
            probe="false", severity="HIGH",
            fix=[["sysctl-set", "kernel.knob", "0"]], nist=["SC-2"]),
    Control("unsure-control", "misc", "Probing is impossible here",
            probe="EXPLODE", severity="MEDIUM"),
    Control("advisory-card", "docs", "Advisory: document the ARP policy",
            probe="true", severity="INFO", advisory=True),
]
# runner: unsure-control's probe explodes; detector maps that to
# CANT-CHECK (honesty rule). "true" -> PASS, anything else -> GAP.


def fake_runner(line):
    if line == "EXPLODE":
        raise RuntimeError("no probe here")
    return (0 if line == "true" else 1), "stubbed " + line


def make_view(cant=True):
    controls = CONTROLS if cant else [
        c for c in CONTROLS if c.id != "unsure-control"]
    return HardenView(controls=controls, runner=fake_runner)


def test_scan_renders_one_card_per_finding():
    view = make_view()
    view._on_scan(None)
    pump()
    texts = _find_card_texts(view)
    assert texts, "expected finding cards after scan"
    joined = "\n".join(texts)
    for want in ("Good control", "A gap the helper can fix",
                 "COULD NOT BE CHECKED", "Advisory"):
        assert want in joined, want
    # NIST/CIS tags render on the cards
    assert "NIST CM-7" in joined and "CIS 1.1" in joined


def test_apply_disabled_while_a_cant_check_exists():
    view = make_view(cant=True)
    assert not view.apply_btn.get_sensitive()
    view._on_scan(None)
    pump()
    assert not view.apply_btn.get_sensitive()
    assert view.apply_btn.get_tooltip_text()  # says WHY it is off


def test_apply_enabled_when_all_checks_run(tmp_path):
    view = make_view(cant=False)
    view._on_scan(None)
    pump()
    assert view.apply_btn.get_sensitive()


def test_verby_args_maps_the_helper_contract():
    assert verby_args([["sh", "true"]]) == {"verb": "sh", "cmd": "true"}
    assert verby_args([["sysctl-set", "k.k", "0"]]) == {
        "verb": "sysctl-set", "key": "k.k", "value": "0"}
    assert verby_args([["service-off", "ssh"]]) == {
        "verb": "service-off", "unit": "ssh"}
    assert verby_args([["pkg-upgrade"]]) == {"verb": "pkg-upgrade"}
    # placeholder template: not resolvable in the GUI
    assert verby_args([["unit-install", "{{unit}}", "TRANCHE"]]) == {
        "verb": "unit-install", "unresolvable": True}


def test_planfile_json_matches_helper_contract():
    from hardening.apply import build_plan
    controls = [Control("hard-ssh", "network-services",
                        "SSH service off", probe="systemctl is-active ssh",
                        probe_invert=True,
                        fix=[["service-off", "ssh"]]),
                Control("hard-bpf", "kernel", "BPF locked",
                        probe="sysctl -n kernel.unprivileged_bpf_disabled",
                        fix=[["sysctl-set",
                              "kernel.unprivileged_bpf_disabled", "2"]])]
    plan, _adv = build_plan(
        # GAP findings by hand; detector.scan already maps rc -> state
        [type("F", (), {"control_id": "hard-ssh", "state": "GAP",
                        "current": "active", "note": ""})(),
         type("F", (), {"control_id": "hard-bpf", "state": "GAP",
                        "current": "0", "note": ""})()],
        controls)
    entries, skipped = planfile_entries(plan, controls)
    assert skipped == []
    payload = json.dumps({"entries": entries})
    got = json.loads(payload)          # exact planfile shape -> tmp file
    e = got["entries"][0]
    assert e["id"] == "hard-ssh" and e["verb"] == "service-off"
    assert e["unit"] == "ssh" and e["probe"] == "systemctl is-active ssh"
    assert e["probe_invert"] is True
    e2 = got["entries"][1]
    assert e2["verb"] == "sysctl-set" and e2["key"] == \
        "kernel.unprivileged_bpf_disabled" and e2["value"] == "2"


def test_parse_apply_output_maps_the_verify_strip():
    out = "\n".join([
        "APPLY a 0", "APPLY b 0", "APPLY c 0",
        "VERBIFY a 0", "VERBIFY b 1", "VERBIFY c none",
        "ROLLBACK b"])
    got = parse_apply_output(out)
    assert got == {"a": "GREEN", "b": "RED", "c": "AMBER"}


def test_undo_wired_to_latest_journal_entry(tmp_path):
    journal = tmp_path / "j.jsonl"
    view = HardenView(controls=CONTROLS, runner=fake_runner,
                      journal_path=journal)
    assert not view.undo_btn.get_sensitive()    # no journal yet
    from hardening.journal import write_entry
    write_entry(journal, "hard-ssh", {}, [{"verb": "service-off",
                                           "unit": "ssh",
                                           "id": "hard-ssh",
                                           "probe": "",
                                           "probe_invert": True}])
    view._refresh_undo()
    assert view.undo_btn.get_sensitive()
    calls = []

    def fake_helper(args):
        calls.append(list(args))
        return 0, "VERBIFY hard-ssh 0\n"

    view._helper = fake_helper
    view._on_undo(None)
    pump()
    # contract: run_helper("harden", ["undo", entry_id, journal-path])
    assert calls and calls[0][0] == "undo" and calls[0][1] == "hard-ssh"
    assert "restored" in view.verify_label.get_text()
    calls.clear()


def test_failed_apply_looks_failed_not_green():
    """The reviewer's stderr case: a RED verify whose rollback also failed
    (ROLLBACK-FAILED on STDERR) must still be RED on the strip."""
    view = make_view(cant=False)
    view._helper = lambda args: (4, "APPLY a 0\nVERBIFY a 1\n",
                                 "ROLLBACK-SKIP a\nROLLBACK a\n")
    view._on_scan(None)
    for _ in range(100):
        pump(4)
        if view._scanned:
            break
    view._on_apply(None)
    for _ in range(100):
        pump(4)
        if view.verify_label.get_text() != \
                "Nothing applied in this session yet.":
            break
    text = view.verify_label.get_text()
    assert "a RED" in text


def test_failed_scan_never_reenables_apply():
    """The reviewer's Important #1: a scan that CRASHES must keep Apply
    off and say why — it must not display '0 checks done'."""
    def exploding_runner(_line):
        raise RuntimeError("kernel went away")
    controls = [Control("boom", "misc", "Boom", probe="boom",
                        severity="LOW")]
    view = HardenView(controls=controls, runner=exploding_runner)
    # detector.scan swallows per-control probe errors (-> CANT-CHECK), so
    # the WORKER failure is delivered directly: findings=None is the
    # sentinel a crashed scan sends to the main thread.
    view._scan_done(None, list(controls))
    pump()
    assert not view.apply_btn.get_sensitive()
    assert view.scan_btn.get_sensitive()       # ready for a re-run
    assert "0 checks done" not in view.status.get_text()
    assert not view._scanned


def test_unresolvable_fix_shown_on_the_card_at_review_time():
    """The reviewer's Important #2: a GAP the GUI cannot plan (the
    {{unit}}/TRANCHE template) says so ON THE CARD before any apply."""
    controls = [Control("template-control", "systemd-unit",
                        "Hardened unit template", probe="false",
                        severity="CRITICAL",
                        fix=[["unit-install", "{{unit}}", "TRANCHE"]])]
    view = HardenView(controls=controls, runner=fake_runner)
    view._on_scan(None)
    pump()
    joined = "\n".join(_find_card_texts(view))
    assert "NEEDS A MANUAL CHANGE" in joined
    assert "Apply cannot fix this one" in joined


def test_rollback_failed_on_stderr_is_red():
    out = "APPLY z 0\nVERBIFY z 1\n"
    err = "ROLLBACK-FAILED z\n"
    assert parse_apply_output(out + "\n" + err)["z"] == "RED"


FAKE_CVE_CACHE = {
    "entries": [
        {"id": "CVE-2999-0417", "modified": "2026-01-02T00:00:00.000",
         "nist": ["SC-2"]},
    ],
}


def test_card_shows_the_display_only_cve_note():
    """The reviewer's Important: cve_note was implemented and tested but
    never rendered — the card must show it when the cache yields one,
    and stay quiet when it does not."""
    view = HardenView(controls=CONTROLS, runner=fake_runner,
                      cve_cache=FAKE_CVE_CACHE)
    view._on_scan(None)
    pump()
    joined = "\n".join(_find_card_texts(view))
    assert "Relevant CVEs on record: CVE-2999-0417" in joined
    # and a view with NO cache yields no note
    bare = HardenView(controls=CONTROLS, runner=fake_runner,
                      cve_cache={})
    bare._on_scan(None)
    pump()
    assert "Relevant CVEs" not in "\n".join(_find_card_texts(bare))
