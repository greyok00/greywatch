# GW-187..GW-190: notification popups carry a picture and a place, name the
# program honestly, group repeats per (app, destination), and can be snoozed
# or silenced per lane (2026-11-05 notification upgrade).
from __future__ import annotations

import json
import math
import sys
import time
import types
import unittest.mock as mock

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from ui import identity          # noqa: E402
from ui import notify_alert as na  # noqa: E402


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

    def __init__(self):
        self.v4 = []
        self.v6 = []

    def country_code_by_addr(self, addr):
        self.v4.append(addr)
        return "JP"

    def country_name_by_addr(self, addr):
        return "Japan"

    def country_code_by_addr_v6(self, addr):
        self.v6.append(addr)
        return ""

    def country_name_by_addr_v6(self, addr):
        return ""


def test_geoip_country_uses_the_v4_table_for_port_bearing_addresses():
    rec = _Recorder()
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
