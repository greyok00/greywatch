import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Gdk    # noqa: E402


def _gtk_ready() -> bool:
    try:
        if not Gtk.init_check():
            return False
        return Gdk.Display.get_default() is not None
    except Exception:
        return False


if not os.environ.get("GREYWATCH_TEST_DISPLAY"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (GREYWATCH_TEST_DISPLAY=1), never the owner's desktop.",
        allow_module_level=True)
if not _gtk_ready():
    pytest.skip("no display available", allow_module_level=True)


def pump(n=40):
    ctx = GLib.main_context_default()
    for _ in range(n):
        while ctx.iteration(may_block=False):
            pass


@pytest.fixture(autouse=True)
def leak_guard():
    start = set(Gtk.Window.list_toplevels())
    yield
    for _ in range(6):
        pump(4)
    for w in list(Gtk.Window.list_toplevels()):
        if w in start:
            continue
        try:
            w.close()
        except Exception:
            pass


def _win(tmp_path, monkeypatch):
    monkeypatch.setattr("ui.window.DATA_DIR", tmp_path)
    from ui.window import MainWindow
    win = MainWindow(tray_available=False)
    win._show("settings")        # lazy views: the firewall card builds here
    pump()
    return win


def test_appfw_never_reads_or_writes_the_pause_store(tmp_path, monkeypatch):
    from ui.settings import PausedStore
    win = _win(tmp_path, monkeypatch)
    win.paused = PausedStore(tmp_path / "paused.json")
    win._after_toggle("appfw", True, 0)
    assert win.paused.paused == set()
    win._after_toggle("appfw", False, 0)
    assert win.paused.paused == set()


def test_stale_appfw_pause_record_is_cleared(tmp_path, monkeypatch):
    from ui.settings import PausedStore
    win = _win(tmp_path, monkeypatch)
    win.paused = PausedStore(tmp_path / "paused.json")
    win.paused.set("appfw", True)
    win._reconcile_pause_markers({"appfw_engine": "running"})
    assert win.paused.paused == set()


def test_firewall_tile_renders_the_engine_sentence(tmp_path, monkeypatch):
    win = _win(tmp_path, monkeypatch)
    win._render_appfw_state({
        "appfw_engine": "off (failed: kernel module unavailable)",
        "appfw_history": [{"ts": "2026-10-30T12:34:00Z", "event": "fail",
                           "reason": "nftables install failed"}],
    })
    text = win.fw_status.get_text()
    assert "kernel module unavailable" in text
    assert "12:34 fail" in text and "nftables install failed" in text


def test_mode_selector_writes_the_three_flags(tmp_path, monkeypatch):
    from appfw import config as acfg
    win = _win(tmp_path, monkeypatch)

    class Combo:
        def get_active_id(self):
            return "whitelist"

    win._on_fw_mode_pick(Combo())
    cfg = acfg.load(tmp_path)
    assert cfg["learning_mode"] is False
    assert cfg["strict_mode"] is True
    assert cfg["fail_open"] is False
    assert acfg.mode_of(cfg) == "whitelist"

    class Learning:
        def get_active_id(self):
            return "learning"

    win._on_fw_mode_pick(Learning())
    cfg = acfg.load(tmp_path)
    assert acfg.mode_of(cfg) == "learning"
