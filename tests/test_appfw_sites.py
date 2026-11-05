# tests/test_appfw_sites.py
"""The named-trust-site lane: wizard names meet the address verdict.

Round-1 audit HIGH (2026-11-03): "Trust example.net" stored a NAME, the
packet verdict sees an ADDRESS, so the pick matched nothing. The lane
resolves entries on the engine's slow thread, caches addresses on disk,
and the policy consults that cache when the name match misses.
"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from appfw import config, sites                     # noqa: E402
from appfw.engine import Engine                     # noqa: E402
from appfw.policy import Policy                     # noqa: E402
from appfw.rules import Rule, RuleStore             # noqa: E402


class _FakeTrust:
    def __init__(self, allow=(), block=()):
        self.allow = set(allow)
        self.block = set(block)

    def load(self):
        pass

    def decide(self, host):
        if host in self.allow:
            return "allow"
        if host in self.block:
            return "deny"
        return None


# ---- resolve ---------------------------------------------------------------

def test_resolve_entry_carries_a_literal_address():
    assert sites.resolve_entry("203.0.113.7") == ["203.0.113.7"]


def test_resolve_entry_wildcard_drops_to_base():
    got = sites.resolve_entry("*.nowhere.invalid")
    assert got == []          # .invalid can never resolve: honest miss


def test_resolve_entry_localhost_lookup():
    got = sites.resolve_entry("localhost")
    assert any(ip in ("127.0.0.1", "::1") for ip in got)


def test_resolve_entries_dedupes_and_sorts():
    out = sites.resolve_entries(["localhost", "203.0.113.7", "localhost"])
    assert list(out) == sorted({"localhost", "203.0.113.7"})
    assert out["203.0.113.7"] == ["203.0.113.7"]


# ---- cache -----------------------------------------------------------------

def test_store_load_roundtrip(tmp_path):
    sites.store(tmp_path, {"example.net": ["203.0.113.7"]})
    doc = sites.load(tmp_path)
    assert doc["entries"]["example.net"] == ["203.0.113.7"]


def test_load_answers_empty_on_corrupt_file(tmp_path):
    p = sites.cache_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ not json")
    assert sites.load(tmp_path) == {}


def test_ip_verdict_bridges_address_to_entry(tmp_path):
    sites.store(tmp_path, {"example.net": ["203.0.113.7"]})
    tl = _FakeTrust(allow={"example.net"})
    assert sites.ip_verdict(tmp_path, "203.0.113.7", tl.allow, tl.block) \
        == "allow"
    tb = _FakeTrust(block={"example.net"})
    assert sites.ip_verdict(tmp_path, "203.0.113.7", tb.allow, tb.block) \
        == "deny"
    assert sites.ip_verdict(tmp_path, "198.51.100.9", [], []) is None


# ---- policy ----------------------------------------------------------------

def test_policy_trust_site_address_hits_the_cache(tmp_path):
    sites.store(tmp_path, {"example.net": ["203.0.113.7"]})
    policy = Policy(tmp_path, trust_list=_FakeTrust(allow={"example.net"}))
    assert policy.trust_site("203.0.113.7") == "allow"   # name ≠ address
    assert policy.site_entries() == ["example.net"]
    policy = Policy(tmp_path, trust_list=None)
    assert policy.site_entries() == []
    assert policy.trust_site("203.0.113.7") is None


# ---- engine slow lane ------------------------------------------------------

def test_engine_sites_lane_starts_and_runs(tmp_path, monkeypatch):
    eng = Engine(tmp_path)
    assert eng._sites_thread is None
    # Age the lane beyond the refresh window relative to THIS clock: a
    # freshly booted runner's monotonic() can be younger than the window.
    eng._sites_at = time.monotonic() - (sites.REFRESH_SECONDS + 1.0)
    calls = []
    monkeypatch.setattr(eng.policy, "site_entries",
                        lambda: calls.append("ask") or ["example.net"])
    monkeypatch.setattr(sites, "resolve_entries",
                        lambda entries: {"example.net": ["203.0.113.7"]})
    monkeypatch.setattr(sites, "store",
                        lambda d, entries: calls.append(("store", entries)))
    eng._sites_step()
    assert eng._sites_thread is not None, \
        "the resolver thread must actually be started"
    eng._sites_thread.join(timeout=5)
    assert calls, "the resolver thread must actually be started"
    assert ("store", {"example.net": ["203.0.113.7"]}) in calls


# ---- cross-process rule refresh -------------------------------------------

def test_rule_store_refresh_if_changed_sees_an_outside_write(tmp_path):
    store = RuleStore(tmp_path)
    store.add(Rule(name="allow-me", action="allow", duration="always",
                   op_kind="dst.ip", op_value="203.0.113.7"))
    # A second process (the popup) writes the file directly.
    outside = RuleStore(tmp_path)
    outside.add(Rule(name="deny-me", action="deny", duration="always",
                     op_kind="process.path", op_value="/usr/bin/curl"))
    assert all(r.name != "deny-me" for r in store.all_rules())
    assert store._loaded_at != store._latest_mtime()      # a write happened
    store.refresh_if_changed()
    assert "deny-me" in [r.name for r in store.all_rules()]


# ---- config sanitize -------------------------------------------------------

def test_build_ruleset_survives_a_garbage_queue_number():
    for bad in ("not-a-number", 99999, None, ["111"]):
        doc = config.build_ruleset({"nfqueue_num": bad})
        assert "num 111" in doc
    doc = config.build_ruleset({"nfqueue_num": "not-a-number",
                                "fail_open": False})
    assert "queue num 111" in doc


def test_build_ruleset_coerces_a_bare_string_exempt():
    doc = config.build_ruleset({"always_exempt": "1.1.1.1"})
    assert "ip daddr 1.1.1.1 counter accept" in doc


def test_build_ruleset_drops_unusable_exempt_entries():
    doc = config.build_ruleset({"always_exempt": [
        "1.1.1.1", "192.168.0.0/16", "::1", "example.net", "",
        "999.999.1.1"]})
    assert "ip daddr 1.1.1.1 counter accept" in doc
    assert "192.168.0.0/16" in doc
    assert "ip daddr ::1" not in doc            # loopback ip6 line is base
    assert "ip daddr example.net" not in doc
    assert "ip daddr 999.999" not in doc