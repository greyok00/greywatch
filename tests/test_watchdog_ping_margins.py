"""The pet cadence and staleness gate must leave real watchdog margin.

Regression for the SIGABRT loop (2026-11-10, "Watchdog timeout (limit
30s)!", restart counter 53+): the ping loop petted every 10 s against a
30 s watchdog - one jitter away from death - AND refused to pet whenever
the beat was older than 8 s, while legal heavy steps (a batched unit
refresh, one systemctl probe) run up to 10 s. So a healthy-but-slow
service saw an 8-10 s beat, skipped the pet, and skipped pets stacked
toward the kill even as write_status fed the beat per probe.

The cadence is now 5 s and the gate admits beats refreshed within 15 s:
any legal step passes, a genuinely wedged call (no beat refresh beyond
15 s) still goes unpetted - the honest wedge law holds.
"""
import inspect
import pathlib
import re
import threading
import time


import appfw.sd_notify as sd
import greywatch_daemon as gd


def _one_pass(d, stop, monkeypatch, pings):
    """Drive _watchdog_ping_loop for exactly one pass, notifications
    captured, side effects off."""
    monkeypatch.setattr(sd, "notify", lambda w: pings.append(w))
    monkeypatch.setattr(pathlib.Path, "write_text", lambda *a, **k: "")
    monkeypatch.setattr(pathlib.Path, "mkdir", lambda *a, **k: None)
    stop.wait = lambda _s: (stop.set() or 0)
    d._watchdog_ping_loop(stop)


def _daemon(tmp_path, beat_age):
    d = gd.Daemon(data_dir=tmp_path / "data")
    d._beat = time.monotonic() - beat_age
    return d


def test_beat_refreshed_by_a_legal_10s_step_still_pets(tmp_path,
                                                       monkeypatch):
    # the exact gap that got healthy services killed: write_status fed
    # the beat after a full-length probe (10 s), but the 8 s gate then
    # refused the pet. 15 s gate: the pet goes through.
    stop, pings = threading.Event(), []
    _one_pass(_daemon(tmp_path, beat_age=9.0), stop, monkeypatch, pings)
    assert pings == ["WATCHDOG=1"]


def test_a_genuinely_wedged_call_is_never_petted(tmp_path, monkeypatch):
    # honest wedge law unchanged: past the gate, no pet - systemd still
    # sees a petless service and kills it, as it should.
    stop, pings = threading.Event(), []
    _one_pass(_daemon(tmp_path, beat_age=20.0), stop, monkeypatch, pings)
    assert pings == []


def test_cadence_and_gate_values_leave_watchdog_margin():
    """Pin the load-bearing constants by source: cadence <= 5 s against
    the 30 s watchdog, gate >= 10 s (admits one full-length legal step)
    but < half the watchdog."""
    src = inspect.getsource(gd.Daemon._watchdog_ping_loop)
    cadence = re.search(r"stop\.wait\(([\d.]+)\)", src)
    gate = re.search(r"- self\._beat < ([\d.]+)", src)
    assert cadence is not None and gate is not None
    assert float(cadence.group(1)) <= 5.0
    assert float(gate.group(1)) >= 10.0
    # gate + cadence must stay comfortably inside the 30 s watchdog: a
    # stale-beat skip can cost one cadence, so gate alone must be < 30/2.
    assert float(gate.group(1)) <= 15.0


def test_stale_beat_names_the_wedge(monkeypatch, tmp_path):
    """When the beat is stale the loop dumps all thread stacks to the
    journal (rate-limited), so a wedged pass NAMES its line instead of
    dying anonymously (2026-11-11 loop: 52 stale skips, no attribution)."""
    import faulthandler
    stop, pings = threading.Event(), []
    dumps = []

    def fake_dump(file=None, all_threads=True):
        dumps.append(True)

    monkeypatch.setattr(faulthandler, "dump_traceback", fake_dump)
    d = gd.Daemon(data_dir=tmp_path / "data")
    d._beat = time.monotonic() - 40.0      # stale: the pet is refused
    _one_pass(d, stop, monkeypatch, pings)
    assert pings == [] and dumps == [True]
    # a second stale pass within the window does not re-dump (rate limit)
    d._beat = time.monotonic() - 40.0
    _one_pass(d, stop, monkeypatch, pings)
    assert len(dumps) == 1
