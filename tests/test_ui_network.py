"""Pins for the Network page: devices fingerprinted, IPs flagged, the
DNS monitor under it - one page, its own page in the v4 rail."""

from __future__ import annotations

import json
import pathlib
import time

import gi
import pytest

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from tests.test_ui_v4 import _ShellStub, _all_texts


def _pump(iterations=400):
    """The read worker lands through GLib.idle_add."""
    ctx = GLib.main_context_default()
    for _ in range(iterations):
        ctx.iteration(False)
        time.sleep(0.002)


def _texts(page) -> str:
    return " ".join(_all_texts(getattr(page, "_gw_body", page)))


@pytest.fixture(autouse=True)
def _fresh_cache():
    from ui import network
    cache = getattr(network, "_CACHE", None)
    if cache is not None:
        cache.update({"at": 0.0, "doc": None})
    yield
    if cache is not None:
        cache.update({"at": 0.0, "doc": None})


@pytest.fixture
def stores(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "network-analytics.json").write_text(json.dumps({
        "version": 1, "built_at": "2026-11-15T09:00:00+00:00",
        "devices": {
            "00:11:22:33:44:55": {
                "vendor": "Lan Device Works", "first_seen": "2026-11-15T08:00:00+00:00",
                "last_seen": "2026-11-15T09:00:00+00:00",
                "ips": ["192.168.1.24"],
                "what": [{"when": "2026-11-15T08:00:00+00:00",
                          "what": "new station 00:11:22:33:44:55 "
                                  "(192.168.1.24)"}]},
            "unknown-mac": {
                "vendor": "unknown", "first_seen": "2026-11-15T08:30:00+00:00",
                "last_seen": "2026-11-15T09:00:00+00:00",
                "ips": ["203.0.113.9"],
                "what": [{"when": "2026-11-15T08:30:00+00:00",
                          "what": "psad flagged the ip"}]},
        },
        "ips": {
            "203.0.113.9": {
                "first_seen": "2026-11-15T08:30:00+00:00",
                "last_seen": "2026-11-15T09:00:00+00:00",
                "flagged_by": ["psad", "intel:blocklist"],
                "what": [{"when": "2026-11-15T08:30:00+00:00",
                          "what": "psad flagged the ip"}]},
            "192.168.1.24": {
                "first_seen": "2026-11-15T08:00:00+00:00",
                "last_seen": "2026-11-15T09:00:00+00:00",
                "flagged_by": [],
                "what": []},
        },
        "counts": {"devices": 2, "ips": 2, "flagged": 1},
    }))
    (d / "dnslog.json").write_text(json.dumps({
        "version": 1, "built_at": "2026-11-15T09:00:00+00:00",
        "source": "journal:dnsmasq.service",
        "log_queries_enabled": True,
        "log_how": "log-queries is on",
        "blocklist": "/etc/dnsmasq.d/00-blocklist-merged.conf",
        "domains": {
            "ads.example.com": {
                "first": "2026-11-15T09:00:01+00:00",
                "last": "2026-11-15T09:05:01+00:00", "queries": 7,
                "clients": ["127.0.0.1"], "blocked": True},
            "greywatch.local": {
                "first": "2026-11-15T09:00:01+00:00",
                "last": "2026-11-15T09:05:09+00:00", "queries": 3,
                "clients": ["127.0.0.1"], "blocked": False},
        },
        "counts": {"domains": 2, "queries": 10, "blocked_hits": 1,
                   "clients_seen": 1},
        "note": "", "capped": False,
    }))
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(d))

    import ui.network as network
    from ui import cliapi
    real = cliapi.read_state

    def fake_netmon(name=None):
        return real(real.__name__)

    # the page asks the CLI first; in tests the CLI subprocess is
    # unavailable by isolation, so the store file answers
    monkeypatch.setattr(cliapi, "jcall", lambda *a, **k: None)
    return network, d, cliapi


def _build(network, shell=None):
    shell = shell or _ShellStub()
    page = network.build(shell)
    _pump()
    return page


def _tree_rows(page) -> list:
    out = []

    def walk(w):
        rows = getattr(w, "_gw_rows", None)
        if rows:
            out.extend(rows)
        child = w.get_first_child() if hasattr(w, "get_first_child") else None
        while child is not None:
            walk(child)
            child = child.get_next_sibling()

    walk(getattr(page, "_gw_body", page))
    return out


def test_devices_read_fingerprinted_rows(stores):
    network, d, _cli = stores
    page = _build(network)
    rows = _tree_rows(page)
    assert any("lan device works" in " ".join(r).lower() for r in rows)
    assert any("unresolved" in " ".join(r).lower() for r in rows)
    texts = _all_texts(getattr(page, "_gw_body", page))
    assert any("2 devices seen on the interface" in t.lower() for t in texts)


def test_flagged_address_names_what_flagged_it(stores):
    network, d, _cli = stores
    page = _build(network)
    rows = _tree_rows(page)
    assert any("203.0.113.9" in r[0] and "psad" in r[1]
               and "intel:blocklist" in r[1] for r in rows)
    texts = _all_texts(getattr(page, "_gw_body", page))
    assert any("flagged addresses - 1 address" in t.lower() for t in texts)


def test_dns_section_names_blocked_hits_against_the_wall(stores):
    network, d, _cli = stores
    page = _build(network)
    rows = _tree_rows(page)
    assert any("ads.example.com" in r[0] and r[3] == "blocked"
               for r in rows)
    assert any("greywatch.local" in r[0] and r[3] == "passed"
               for r in rows)
    texts = _all_texts(getattr(page, "_gw_body", page))
    assert any("1 block on the blocklist" in t.lower() for t in texts)


def test_network_does_not_call_the_cli_on_build(monkeypatch):
    import threading
    from ui import network, cliapi
    started = threading.Event()
    release = threading.Event()

    def slow(*a, **k):
        started.set()
        release.wait(2)
        return {"counts": {"devices": 0, "flagged": 0}}

    monkeypatch.setattr(cliapi, "jcall", slow)
    page = network.build(_ShellStub())
    assert page is not None
    assert started.wait(1)
    assert _texts(page).lower().find("reading") >= 0
    release.set()
    page._gw_body._gw_read_thread.join(2)
    _pump()


def test_the_network_store_is_cached(monkeypatch):
    from ui import network, cliapi
    calls = []
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, **k: calls.append(1) or {"counts": {}})
    network._CACHE.update({"at": 0.0, "doc": None})
    network._netmon_store()
    network._netmon_store()
    assert len(calls) == 1


def test_a_stale_cache_is_read_again(monkeypatch):
    from ui import network, cliapi
    calls = []

    def jcall(*a, **k):
        calls.append(1)
        return {"counts": {"n": len(calls)}}

    monkeypatch.setattr(cliapi, "jcall", jcall)
    network._CACHE.update({"at": time.time() - network._CACHE_S - 1,
                           "doc": {"counts": {"n": 0}}})
    doc = network._netmon_store()
    assert len(calls) == 1
    assert doc["counts"]["n"] == 1


def test_the_cache_stamp_is_taken_after_the_read(monkeypatch):
    from ui import network, cliapi
    read_done = []

    def slow(*a, **k):
        time.sleep(0.05)
        read_done.append(time.time())
        return {"counts": {"devices": 1}}

    monkeypatch.setattr(cliapi, "jcall", slow)
    network._CACHE.update({"at": 0.0, "doc": None})
    network._netmon_store()
    assert network._CACHE["at"] >= read_done[0] - 0.001


def test_refresh_with_a_fresh_cache_repaints_without_the_cli(monkeypatch):
    from ui import network, cliapi
    calls = []
    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, **k: calls.append(1) or {"counts": {}})
    doc = {"counts": {"devices": 2, "flagged": 0},
           "built_at": "2026-11-15T09:00:00+00:00"}
    network._CACHE.update({"at": time.time(), "doc": doc})

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    network.refresh(box)

    assert calls == []
    assert "2 devices seen" in _texts(box).lower()


def test_build_then_refresh_runs_one_cli(monkeypatch):
    import threading
    from ui import network, cliapi
    calls = []
    release = threading.Event()

    def gated(*a, **k):
        calls.append(1)
        release.wait(2)
        return {"counts": {"devices": 1, "flagged": 0}}

    monkeypatch.setattr(cliapi, "jcall", gated)
    page = network.build(_ShellStub())
    network.refresh(page)
    release.set()
    page._gw_body._gw_read_thread.join(2)
    _pump()
    assert len(calls) == 1


def test_quiet_lanes_read_honest_states(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "network-analytics.json").write_text(json.dumps({
        "version": 1, "built_at": "2026-11-15T09:00:00+00:00",
        "devices": {}, "ips": {},
        "counts": {"devices": 0, "ips": 0, "flagged": 0}}))
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(d))
    import ui.network as network
    from ui import cliapi
    monkeypatch.setattr(cliapi, "jcall", lambda *a, **k: None)
    page = _build(network)
    texts = _all_texts(getattr(page, "_gw_body", page))
    joined = " ".join(texts).lower()
    assert "no address is flagged by any lane" in joined
    assert "no devices yet" in joined
    assert "watching" in joined


def test_built_scroller_fills_the_page(stores, monkeypatch):
    """A lazily shown page must fill the window. The scroller and the
    body both expand, so the page never collapses to its minimum."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(stores))
    import ui.network as network
    from ui import cliapi
    monkeypatch.setattr(cliapi, "jcall", lambda *a, **k: None)
    page = network.build(_ShellStub())
    assert page.get_vexpand() is True
    assert page.get_hexpand() is True
    assert page._gw_body.get_vexpand() is True
