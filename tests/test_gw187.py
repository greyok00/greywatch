# GW-187..GW-190: notification popups carry a picture and a place, name the
# program honestly, group repeats per (app, destination), and can be snoozed
# or silenced per lane (2026-11-05 notification upgrade).
from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import time
import unittest.mock as mock

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui import identity                  # noqa: E402
from ui import notify_alert as na        # noqa: E402
from ui import visuals                   # noqa: E402


# ---------------------------------------------------------------- Task 1

def test_geoip_lookups_strip_the_port():
    ip = "114.111.39.11"
    assert identity._addr_only(ip + ":443") == ip
    assert identity._addr_only("[2606:4700:4700::1111]:443") == "2606:4700:4700::1111"
    assert identity._addr_only("2606:4700:4700::1111") == "2606:4700:4700::1111"
    assert identity._addr_only("::1") == "::1"
    assert identity._addr_only("example.invalid") == "example.invalid"
    assert identity._addr_only("") == ""


class _Recorder:
    """Stands in for the GeoIP table and records what it is asked."""

    def __init__(self, known=None):
        self.v4: list[str] = []
        self.v6: list[str] = []
        self.known = dict(known or {})   # addr → (code, name)

    def country_code_by_addr(self, addr):
        self.v4.append(addr)
        return self.known.get(addr, ("", ""))[0]

    def country_name_by_addr(self, addr):
        return self.known.get(addr, ("", ""))[1]

    def country_code_by_addr_v6(self, addr):
        self.v6.append(addr)
        return ""

    def country_name_by_addr_v6(self, addr):
        return ""


def test_geoip_country_uses_the_v4_table_for_port_bearing_addresses():
    rec = _Recorder({"114.111.39.11": ("JP", "Japan")})
    with mock.patch.object(identity, "_geo", rec, create=True):
        code, name = identity.geoip_country("114.111.39.11:443")
    assert (code, name) == ("JP", "Japan")
    assert rec.v4 == ["114.111.39.11"]      # the port was stripped
    assert rec.v6 == []                     # never routed into the v6 branch


def test_geoip_country_still_routes_real_v6_addresses_to_the_v6_table():
    rec = _Recorder()
    with mock.patch.object(identity, "_geo", rec, create=True):
        code, _name = identity.geoip_country("2606:4700:4700::1111")
    assert code == ""
    assert rec.v6 == ["2606:4700:4700::1111"]
    assert rec.v4 == []


# ---------------------------------------------------------------- Task 2

@pytest.mark.parametrize("addr,want", [
    ("192.168.1.20", True),
    ("10.9.8.7", True),
    ("172.16.4.4", True),
    ("127.0.0.1", True),
    ("169.254.3.3", True),
    ("8.8.8.8", False),
])
def test_private_addresses_are_recognised(addr, want):
    assert na.is_private(addr) is want


def test_place_words_say_the_ladder_out_loud(monkeypatch):
    rec = _Recorder({"114.111.39.11": ("JP", "Japan")})
    monkeypatch.setattr(identity, "_geo", rec, raising=False)
    assert na.place_words("114.111.39.11:443") == "Japan"
    assert na.place_words("192.168.1.20:22") == "local network"
    rec2 = _Recorder()       # table does not know it
    monkeypatch.setattr(identity, "_geo", rec2, raising=False)
    assert na.place_words("8.8.4.4:443") == ""   # no made-up place


def test_tile_ladder_ends_in_a_picture(monkeypatch):
    rec = _Recorder()        # the table knows nothing here
    monkeypatch.setattr(identity, "_geo", rec, raising=False)
    alert = na.NotifyAlert(na.BlockedQueue(pathlib.Path("/tmp")))
    # a named program on an unknown public address → a program tile
    pic = alert._tile("/usr/bin/curl", "8.8.4.4:443")
    assert pic is not None
    # an unnamed program on a private address → the local-network tile
    local = visuals.local_tile(64)
    pic = alert._tile("<unknown>", "192.168.1.20:22")
    assert pic is not None and pic.get_pixels() == local.get_pixels()
    # nothing known at all → still a picture (the shield), never None
    shield = visuals.shield_tile(64)
    pic = alert._tile("<unknown>", "8.8.4.4:443")
    assert pic is not None and pic.get_pixels() == shield.get_pixels()
    # a known country still wins the ladder
    rec3 = _Recorder({"114.111.39.11": ("JP", "Japan")})
    monkeypatch.setattr(identity, "_geo", rec3, raising=False)
    jp = alert._tile("<unknown>", "114.111.39.11:443")
    assert jp is not None


# ---------------------------------------------------------------- Task 3

@pytest.fixture
def bq():
    return na.BlockedQueue(pathlib.Path("/tmp"))


def test_repeats_of_one_pair_are_grouped(bq):
    text, kind, rec = bq.add_deny("chrome", "1.2.3.4:443", now=1000.0)
    assert kind == "fresh" and "chrome → 1.2.3.4:443" in text
    _t, kind, rec = bq.add_deny("chrome", "1.2.3.4:443", now=1050.0)
    assert kind == "repeat-quiet" and rec["count"] == 2
    _t, kind, rec = bq.add_deny("chrome", "1.2.3.4:443", now=1250.0)
    assert kind == "repeat-ok" and rec["count"] == 3
    assert "3 blocked" in _t               # the counter replaces the story


def test_a_new_pair_or_app_pops_fresh_again(bq):
    bq.add_deny("chrome", "1.2.3.4:443", now=1000.0)
    text, kind, _rec = bq.add_deny("chrome", "5.6.7.8:443", now=1005.0)
    assert kind == "fresh"
    text, kind, _rec = bq.add_deny("curl", "1.2.3.4:443", now=1006.0)
    assert kind == "fresh"


def test_the_pair_window_expires(bq):
    bq.add_deny("chrome", "1.2.3.4:443", now=1000.0)
    text, kind, _rec = bq.add_deny("chrome", "1.2.3.4:443", now=1700.0)
    assert kind == "fresh" and "Blocked" in text
    assert bq.pending() == 1               # one live pair, not two


def test_unnamed_programs_are_called_that(bq):
    text, _kind, _rec = bq.add_deny("<unknown>", "5.6.7.8:80", now=1000.0)
    assert "an unidentified program" in text


def test_the_pair_map_stays_bounded(bq):
    for i in range(70):
        bq.add_deny(f"app{i}", f"10.0.0.{i}:80", now=1000.0 + i)
    assert len(bq.pairs) <= 64
    assert ("app0", "10.0.0.0:80") not in bq.pairs      # oldest gone


# ---------------------------------------------------------------- Task 4

@pytest.fixture
def prefs_file(tmp_path):
    return tmp_path / "greywatch-ui-settings.json"


def test_prefs_default_to_open(prefs_file):
    prefs = na.read_alert_prefs(prefs_file)
    assert prefs == {"alerts": True, "deny_popups": True,
                     "critical_popups": True, "alerts_snooze_until": 0.0}
    prefs_file.write_text("{not json")                  # broken file
    assert na.read_alert_prefs(prefs_file)["alerts"] is True


def test_allow_popup_gate_order(prefs_file):
    ok, why = na.allow_popup("deny", now=1000.0, path=prefs_file)
    assert ok and why == ""
    # master off silences every lane
    na.write_alert_prefs(prefs_file, alerts=False)
    ok, why = na.allow_popup("deny", now=1000.0, path=prefs_file)
    assert not ok and why == "notifications are off"
    # snooze rides above the lanes, auto-rearms at the stamp
    na.write_alert_prefs(prefs_file, alerts=True,
                         alerts_snooze_until=1800.0)
    ok, why = na.allow_popup("deny", now=1000.0, path=prefs_file)
    assert not ok and why == "snoozed"
    ok, why = na.allow_popup("deny", now=1800.0, path=prefs_file)
    assert ok
    # per-lane off silences only its lane
    na.write_alert_prefs(prefs_file, alerts_snooze_until=0.0,
                         deny_popups=False)
    ok, why = na.allow_popup("deny", now=1900.0, path=prefs_file)
    assert not ok and why == "deny popups are off"
    ok, why = na.allow_popup("critical", now=1900.0, path=prefs_file)
    assert ok


def test_snooze_helpers_stamp_and_clear(prefs_file):
    stamp = na.snooze_alerts(30, now=1000.0, path=prefs_file)
    assert stamp == 2800.0
    prefs = na.read_alert_prefs(prefs_file)
    assert prefs["alerts_snooze_until"] == 2800.0
    na.clear_snooze(path=prefs_file)
    assert na.read_alert_prefs(prefs_file)["alerts_snooze_until"] == 0.0


def test_writing_one_key_rides_through_the_others(prefs_file):
    prefs_file.write_text('{"alerts": false, "theme": "warm"}')
    na.write_alert_prefs(prefs_file, deny_popups=False)
    prefs = json.loads(prefs_file.read_text())
    assert prefs["alerts"] is False and prefs["theme"] == "warm"
    assert prefs["deny_popups"] is False
    # the reader defaults what the file never said
    assert na.read_alert_prefs(prefs_file)["critical_popups"] is True


# ---------------------------------------------------------------- Task 4b
# the show() lane honours the gates; a user click still pops

class _FakeNote:
    def __init__(self, summary=None, body=None):
        self.summary, self.body = summary, body
        self.shown = 0
    def set_timeout(self, t):
        pass
    def update(self, s, b):
        self.body = b
    def add_action(self, *a):
        pass
    def show(self):
        self.shown += 1


class _FakeNotify:
    Notification = _FakeNote
    initted = True
    @staticmethod
    def is_initted():
        return True
    @staticmethod
    def init(_app):
        pass


def test_show_respects_the_gates(tmp_path, monkeypatch):
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    alert = na.NotifyAlert(na.BlockedQueue(tmp_path), notifier=_FakeNotify)
    note = _FakeNote()
    alert._n = note
    alert.show("hello")                                   # open prefs → shows
    assert note.shown == 1
    na.write_alert_prefs(settings, alerts=False)
    alert.show("quiet")
    assert note.shown == 1                                # master off
    na.write_alert_prefs(settings, alerts=True,
                         alerts_snooze_until=time.time() + 1800)
    alert.show("snoozed")
    assert note.shown == 1                                # snoozed
    na.write_alert_prefs(settings, alerts_snooze_until=0.0,
                         deny_popups=False)
    alert.show("lane off")
    assert note.shown == 1                                # this lane off
    na.write_alert_prefs(settings, deny_popups=True)
    alert.show("back")
    assert note.shown == 2 and alert._n.body == "back"


def test_critical_lane_gates_separately(tmp_path, monkeypatch):
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    square = na.CriticalSquare(na.BlockedQueue(tmp_path),
                               notifier=_FakeNotify)
    note = _FakeNote()
    square._n = note
    na.write_alert_prefs(settings, critical_popups=False)
    square.show("quiet")
    assert note.shown == 0
    na.write_alert_prefs(settings, critical_popups=True)
    square.show("back")
    assert note.shown == 1


def test_a_user_click_pops_even_when_snoozed(tmp_path, monkeypatch):
    settings = tmp_path / "greywatch-ui-settings.json"
    settings.write_text('{"alerts": true}')
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    alert = na.NotifyAlert(na.BlockedQueue(tmp_path), notifier=_FakeNotify)
    note = _FakeNote()
    alert._n = note
    na.snooze_alerts(30, now=time.time(), path=settings)
    alert.show("answer", gate=False)
    assert note.shown == 1


# ---------------------------------------------------------------- Task 5
# the settings card: a group in the index, three switches, a snooze button

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402


def pump(iterations: int = 5):
    from gi.repository import GLib
    for _ in range(iterations):
        GLib.MainContext.default().iteration(may_block=False)


def _walk(widget):
    if widget is None:
        return
    yield widget
    for child in widget.observe_children():
        yield from _walk(child)


@pytest.fixture(scope="module")
def win():
    from ui.window import MainWindow
    old = os.environ.get("GREYWATCH_DATA_DIR")
    os.environ["GREYWATCH_DATA_DIR"] = str(
        pathlib.Path(os.environ.get("GW187_DATA", tempfile.mkdtemp(
            prefix="gw187-"))))
    w = MainWindow()
    w.present()
    pump(30)
    yield w
    w.destroy()
    if old:
        os.environ["GREYWATCH_DATA_DIR"] = old


def test_notifications_group_is_in_the_settings_index(win):
    win._show("settings")
    pump(10)
    row = win._settings_index.get_first_child()
    keys = []
    while row is not None:
        keys.append(row._key)
        row = row.get_next_sibling()
    assert "alerts" in keys


def test_the_alerts_pane_has_master_snooze_and_lanes(win):
    win._settings_open(None, "alerts")
    pump(10)
    pane = win._settings_stack.get_child_by_name("alerts")
    widgets = list(_walk(pane))
    switches = [w for w in widgets if isinstance(w, Gtk.Switch)]
    buttons = [w.get_label() for w in widgets
               if isinstance(w, Gtk.Button) and w.get_label()]
    assert len(switches) == 3
    assert switches[0].get_active()          # prefs default open
    assert "Snooze 30 minutes" in buttons


def test_alerts_handlers_write_their_keys(win, monkeypatch, tmp_path):
    settings = tmp_path / "settings.json"
    monkeypatch.setattr(na, "ALERTS_SETTING_PATH", settings)
    sw = Gtk.Switch()
    sw.set_active(False)
    assert win._on_alerts_master(sw) is True
    assert na.read_alert_prefs(settings)["alerts"] is False
    assert na.read_alert_prefs(settings)["deny_popups"] is True

    lane = Gtk.Switch()
    lane._alerts_key = "critical_popups"
    lane.set_active(False)
    win._on_alerts_lane(lane)
    prefs = na.read_alert_prefs(settings)
    assert prefs["critical_popups"] is False
    assert prefs["deny_popups"] is True               # rode through

    win._on_alerts_snooze(None)
    stamp = na.read_alert_prefs(settings)["alerts_snooze_until"]
    assert abs(stamp - (time.time() + 1800)) < 10
    assert "until" in win._alerts_snooze_status.get_text().lower()


# ---------------------------------------------------------------- Task 6

from appfw.base import Conn            # noqa: E402
from appfw import engine as engine_mod  # noqa: E402
from appfw.resolve import Resolver     # noqa: E402


def _synthetic_proc(tmp_path, port_local=1234, port_remote=80):
    """A fake /proc with one listening socket owned by a fake process."""
    root = tmp_path / "proc"
    netdir = root / "net"
    netdir.mkdir(parents=True)
    uid = os.getuid()
    lp, rp = f"{port_local:04X}", f"{port_remote:04X}"
    row = (f"  0: 04030201:{lp} 09090909:{rp} 01 "
           "00000000:00000000 00:00000000 00000000"
           f"  {uid}        0 42 1 f0000000000000000 100 0 0")
    (netdir / "tcp").write_text(
        "  sl  local_address rem_address   st tx_rx tr tm->when"
        " retrnsmt   uid  timeout inode\n" + row + "\n")
    pdir = root / "10"
    (pdir / "fd").mkdir(parents=True)
    (pdir / "fd" / "3").symlink_to("socket:[42]")
    (pdir / "exe").symlink_to("/usr/bin/curl")
    (pdir / "cmdline").write_bytes(b"/usr/bin/curl\0\0")
    return root


def test_the_resolver_tells_the_engine_why_it_missed(tmp_path):
    root = _synthetic_proc(tmp_path)
    r = Resolver(proc_root=str(root))
    conn = Conn(protocol="tcp", src_ip="1.2.3.4", src_port=1234,
                dst_ip="9.9.9.9", dst_port=80)
    r.resolve(conn)
    assert conn.process_path == "/usr/bin/curl"
    assert conn.attribution == "resolved"
    miss = Conn(protocol="tcp", src_ip="5.5.5.5", src_port=77,
                dst_ip="8.8.8.8", dst_port=443)
    r.resolve(miss)
    assert miss.process_path == "" and miss.attribution == "row-missing"


def test_the_engine_notes_misses_but_not_every_minute(monkeypatch):
    events: list[str] = []
    eng = object.__new__(engine_mod.Engine)
    eng._miss_last = {}
    eng.on_event = events.append
    clock = [100.0]
    monkeypatch.setattr(engine_mod.time, "monotonic",
                        lambda: clock[0])
    conn = Conn(protocol="tcp", src_ip="1.1.1.1", src_port=1,
                dst_ip="8.8.8.8", dst_port=80, process_path="",
                attribution="row-missing")
    eng._miss_note(conn)
    eng._miss_note(conn)
    assert len(events) == 1 and "row-missing" in events[0]
    clock[0] = 200.0                       # past the 60 s rate window
    eng._miss_note(conn)
    assert len(events) == 2
