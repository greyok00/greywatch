"""GW-181 (owner 2026-11-05, "picking up my browser extensions... I
want to keep these so I should be able to whitelist them or click
ignore and it remembers"): the browser watch flagged an installed
browser extension (the owner's user-agent switcher), and an owner's
deliberate keep must outlive restarts.

Three layers pin the whole chain: the ledger (hunter/store, config.json
beside the AI keys), the discovery skip (browsers._extensions drops
kept ids so the hunter never raises the rule again), and the desk
(Keep this extension on the dossier, the KEPT strip with Warn again,
and a feed that paints only what the owner asked for). The store itself
stays append-only — a keep hides records from the desk, it never
rewrites the record."""
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"  # noqa: F821
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

from hunter import browsers, engine, store  # noqa: E402
from ui.hunterview import HunterPanel  # noqa: E402
from tests.test_hunter_page import pump  # noqa: E402

EXT_A = "cjpalhdlnbpafiamejdnhcphjbkeiagm"      # the owner-style kept id
NAME_A = "User Agent Switcher"
EXT_B = "mgndgjkgofhjncljhhkkkdagpjjcdame"      # a stranger still raised


def _ext_profile(home: pathlib.Path, ext_id, name) -> None:
    ver = home / ".config/chromium/Default/Extensions" / ext_id / "1.0"
    ver.mkdir(parents=True)
    (ver / "manifest.json").write_text(json.dumps({"name": name}))


# ------------------------------------------------------------- the ledger

def test_keep_roundtrip_and_other_keys(tmp_path):
    # A keep lands in config.json, keeps its label, and is idempotent.
    store.write_config(tmp_path, {"enabled": True, "model": "glm"})
    store.keep_extension(tmp_path, EXT_A, NAME_A)
    store.keep_extension(tmp_path, EXT_A, NAME_A)
    rows = store.kept_extensions(tmp_path)
    assert rows == [{"ext": EXT_A, "name": NAME_A}]
    assert store.kept_extension_ids(tmp_path) == {EXT_A}
    # The AI keys rode through untouched.
    cfg = store.read_config(tmp_path)
    assert cfg["enabled"] is True and cfg["model"] == "glm"
    # Unkeep removes exactly the one row and nothing else on file.
    store.keep_extension(tmp_path, EXT_B, "Other Tool")
    store.unkeep_extension(tmp_path, EXT_A)
    assert store.kept_extension_ids(tmp_path) == {EXT_B}
    # A missing or corrupt config reads as nothing kept, never a crash.
    (tmp_path / "hunter").mkdir(exist_ok=True)
    (tmp_path / "hunter/config.json").write_text("{not json")
    assert store.kept_extensions(tmp_path) == []


def test_browser_discovery_skips_kept_ids(tmp_path):
    _ext_profile(tmp_path, EXT_A, NAME_A)
    _ext_profile(tmp_path, EXT_B, "Stranger Tool")
    assert [f["rule"] for f in
            browsers.config_findings(str(tmp_path))].count(
        "cfg-new-extension") == 2
    kept = {EXT_A}
    rules = [f["rule"] for f in
             browsers.config_findings(str(tmp_path), kept=kept)]
    assert rules == ["cfg-new-extension"], (
        "the kept extension must not raise, the stranger still must")
    # The evidence names the id the way the desk's Keep parses it.
    f = browsers.config_findings(str(tmp_path), kept=())[0]
    assert f["evidence"][0]["ext_id"] == EXT_A


def test_engine_hypothesis_reads_the_ledger(tmp_path):
    _ext_profile(tmp_path, EXT_A, NAME_A)
    _ext_profile(tmp_path, EXT_B, "Stranger Tool")
    store.keep_extension(tmp_path, EXT_A, NAME_A)
    out = engine.h_browser_config([], str(tmp_path), str(tmp_path))
    ids = [f["evidence"][0]["ext_id"] for f in out
           if f["rule"] == "cfg-new-extension"]
    assert ids == [EXT_B], "a kept extension must never reach the rules"


# ---------------------------------------------------------------- the desk

def _ext_finding(data_dir, fid="cfg-1", ext_id=EXT_A, name=NAME_A):
    ts = "2026-11-05T01:00:00+00:00"
    store.append_finding(data_dir, {
        "id": fid, "ts": ts, "rule": "cfg-new-extension",
        "title": "A browser extension is installed on this computer",
        "what": f"“{name}” is present in the extension list.",
        "next": "Review it in the browser's extensions page.",
        "severity": "HIGH", "confidence": "medium", "status": "lead",
        "facts": [f"ext={ext_id}", f"name={name}"],
        "evidence": [{"source": "chromium-extensions", "ext_id": ext_id,
                      "ts": ts}],
        "hunter": "1"})


def _plain_finding(data_dir, fid="plain-1"):
    store.append_finding(data_dir, {
        "id": fid, "ts": "2026-11-05T01:05:00+00:00",
        "rule": "download-double-extension", "title": "Double extension",
        "what": "What happened.", "next": "Next step.", "severity": "HIGH",
        "facts": [], "evidence": [], "hunter": "1"})


def _buttons(widget):
    if hasattr(widget, "observe_children"):
        for child in widget.observe_children():
            if isinstance(child, Gtk.Button):
                yield child
            yield from _buttons(child)


def _click(label, widget):
    for btn in _buttons(widget):
        if btn.get_label() == label:
            btn.emit("clicked")
            pump(10)
            return True
    return False


def test_feed_hides_kept_and_warn_again_restores(tmp_path):
    _ext_finding(tmp_path)
    _plain_finding(tmp_path)
    store.keep_extension(tmp_path, EXT_A, NAME_A)
    panel = HunterPanel(tmp_path)
    pump(20)
    rows = panel._findings
    assert [f["id"] for f in rows] == ["plain-1"], (
        "a kept extension's records must leave the feed, the rest stay")
    assert panel._kept_box.get_visible()
    head = [w for w in panel._kept_box.observe_children()
            if isinstance(w, Gtk.Label)][0]
    assert "1 extension" in head.get_text()
    # Warn again is the way back: the row returns from the same record
    # (latest first — the plain finding is the newer one).
    assert _click("Warn again", panel._kept_box)
    pump(20)
    assert [f["id"] for f in panel._findings] == ["plain-1", "cfg-1"]
    assert not panel._kept_box.get_visible()


def test_keep_button_persists_and_hides(tmp_path):
    _ext_finding(tmp_path)
    _plain_finding(tmp_path)
    panel = HunterPanel(tmp_path)
    pump(20)
    panel._select_finding("cfg-1")
    pump(10)
    # The dossier offers the keep, a plain rule never does.
    keep = [b for b in _buttons(panel._detail)
            if b.get_label() == "Keep this extension"]
    assert len(keep) == 1
    keep[0].emit("clicked")
    pump(20)
    assert store.kept_extension_ids(tmp_path) == {EXT_A}
    assert [f["id"] for f in panel._findings] == ["plain-1"], (
        "keeping must empty the extension's rows at once")
    assert panel._kept_box.get_visible(), "the kept strip mounts at once"
    assert panel._kept_box.observe_children(), "Warn again is reachable"
    # The plain rule's dossier gets no keep button either way.
    panel._select_finding("plain-1")
    pump(10)
    assert not [b for b in _buttons(panel._detail)
                if b.get_label() == "Keep this extension"]
