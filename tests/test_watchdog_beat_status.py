"""The status pass must never hold a petless window across its probes.

Regression for the watchdog-timeout crash loop (2026-11-10, journal:
"Watchdog timeout (limit 30s)!", restart counter 53): write_status runs
one systemd probe per tool and a batched unit query, each seconds-long
under boot load, as ONE un-fed block. The beat only got refreshed by the
loop AROUND write_status, so one slow status pass crossed the 30 s pet
boundary and systemd SIGABRTed the daemon mid-pass. write_status now
feeds the beat at probe granularity - inside that call, not just around
it.
"""
import time

import greywatch_daemon as gd
from greywatch_daemon import Daemon
from registry import load_registry


class _Checker:
    def invalidate(self):
        self.invalidated = True

    def __call__(self, tool):
        return "inactive"


def _unit_tools(registry, count):
    return [dict(t) for t in registry if t.get("unit")][:count]


def mk_daemon_with_tools(tmp_path, tools):
    return Daemon(data_dir=tmp_path / "data", registry=tools)


def test_write_status_feeds_beat_between_tool_probes(tmp_path):
    tools = _unit_tools(load_registry(), 4)
    d = mk_daemon_with_tools(tmp_path, tools)

    order = []

    def probing(tool):
        order.append("probe")
        return None                      # would be a slow systemctl probe

    def feeding():
        order.append("beat")

    checker = _Checker()
    d.unit_checker = checker
    d.tool_installed = probing
    d._feed_beat = feeding
    d.write_status()

    assert checker.invalidated is True
    assert order.count("probe") == 4
    assert order.count("beat") >= 5
    for i, event in enumerate(order):
        if event == "probe":
            assert order[i - 1] == "beat" and order[i + 1] == "beat", (
                f"probe {i} not bracketed by beats: {order[i - 1:i + 2]}")


def test_slow_probes_never_span_30s_of_beat_age(tmp_path):
    """Every probe is bracketed by a beat refresh, so the age the petting
    thread ever sees stays within a single probe - it can never be the
    whole status pass."""
    tools = _unit_tools(load_registry(), 4)
    d = mk_daemon_with_tools(tmp_path, tools)

    ages = []
    d._beat = time.monotonic()

    def slow_probe(tool):
        ages.append(time.monotonic() - (d._beat or d._beat))
        return None

    d.unit_checker = _Checker()
    d.tool_installed = slow_probe
    d.write_status()
    assert ages
    assert max(ages) < 30.0
