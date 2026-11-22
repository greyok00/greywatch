import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import greywatch_daemon as gd
from collectors import JournalTailer
from greywatch_daemon import Daemon, read_events
from registry import load_registry


def _daemon(tmp_path):
    return Daemon(data_dir=tmp_path / "data", registry=load_registry())


def _line(port, src="203.0.113.7", shape="GW-SCAN"):
    return (f"kernel: {shape}: IN=wlan0 SRC={src} DST=192.168.0.203 "
            f"PROTO=TCP SPT=4000 DPT={port} SYN")


def test_sensor_line_reaches_the_feed_without_malformed_noise(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_NETGUARD_BLOCK", "0")
    d = _daemon(tmp_path)
    monkeypatch.setattr(d, "_notify_scan", lambda *a, **k: None)
    for port in range(4000, 4008):
        assert d.consume("ufw", _line(port)) is None
    d.flush_outbox()
    rows = read_events(d.events_path)
    assert len(rows) == 1
    assert rows[0]["from_tool"] == "net-watch"
    assert "port scan" in rows[0]["text"]
    assert list(d._malformed) == []


def test_psad_fallback_line_is_analyzed_not_parsed_as_ufw(
        tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_NETGUARD_BLOCK", "0")
    d = _daemon(tmp_path)
    monkeypatch.setattr(d, "_notify_scan", lambda *a, **k: None)
    for port in range(6000, 6008):
        d.consume("ufw", f"PSAD-IN: SRC=203.0.113.8 DST=192.168.0.203 "
                         f"PROTO=TCP DPT={port}")
    d.flush_outbox()
    rows = read_events(d.events_path)
    assert len(rows) == 1 and rows[0]["from_tool"] == "net-watch"
    assert list(d._malformed) == []


def test_scan_notification_bypasses_open_gui_but_respects_notifyd(
        tmp_path, monkeypatch):
    d = _daemon(tmp_path)
    calls = []
    monkeypatch.setattr(gd.notifyd, "notify",
                        lambda *a, **k: calls.append(a))
    monkeypatch.setattr(d, "_ui_alive", lambda: True)
    d._netguard_event("HIGH", "net-watch: scan", {
        "kind": "scan", "source": "203.0.113.7", "local": False,
        "block": False})
    # _notice passes the GUI-alive callable; the explicit scan alert must
    # pass None so notifyd actually fires while the GUI is open.
    assert any(call[5] is None for call in calls), calls


def test_autoblock_only_for_external_sources(tmp_path, monkeypatch):
    d = _daemon(tmp_path)
    calls = []

    class P:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return P()

    monkeypatch.setattr(gd.subprocess, "run", fake_run)
    monkeypatch.setattr(d, "_notice", lambda *a, **k: None)
    d._netguard_event("HIGH", "LAN scan", {
        "kind": "scan", "source": "192.168.0.32", "local": True,
        "block": False})
    assert calls == []
    d._netguard_event("HIGH", "WAN scan", {
        "kind": "scan", "source": "203.0.113.7", "local": False,
        "block": True})
    assert len(calls) == 1
    assert calls[0][0].endswith("netguard-block.sh")


def test_deploy_sync_ships_the_modules_the_daemon_now_imports():
    """A sync that copies only hand-listed files strands new modules in
    the checkout and the daemon imports the old installed code at boot.
    Pin the broad top-level copy and the package copies."""
    src = (ROOT / "sync-to-system.sh").read_text()
    assert 'cp "$SRC"/*.py' in src
    for pkg in ("appfw", "assistant", "wiz", "schemas"):
        assert f'"$SRC"/{pkg}/*.py' in src or \
            f'"$SRC"/{pkg}/*.json' in src or \
            f'"$SRC"/{pkg}/*.c' in src, pkg


def test_registry_no_longer_tails_the_net_watch_mirror(tmp_path):
    d = _daemon(tmp_path)
    tailers = d.build_collectors()
    assert not any(getattr(t, "tool", "") == "net-watch" for t in tailers)
    kern = next(t for t in tailers
                if isinstance(t, JournalTailer)
                and t.argline.startswith("-k"))
    assert "GW-SCAN:" in kern.line_filter
    assert "GW-STEALTH:" in kern.line_filter
    assert "PSAD-IN:" in kern.line_filter
