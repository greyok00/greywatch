"""intelwall: pure rendering + guarded apply of the gw_intel nft table."""
from __future__ import annotations


import intelwall


def test_render_collapses_overlapping_ranges():
    body, summary, count = intelwall.render_elements(
        {"192.0.2.1", "192.0.2.0/24", "203.0.113.5"})
    assert "192.0.2.0/24" in body
    assert "192.0.2.1" not in body.replace("192.0.2.0/24", "")
    assert "203.0.113.5/32" in body
    assert count == 2


def test_render_splits_v4_and_v6_sets():
    body, summary, count = intelwall.render_elements(
        {"192.0.2.1", "2001:db8::/32"})
    assert "type ipv4_addr" in body and "type ipv6_addr" in body
    assert "ip saddr @intel4 drop" in body
    assert "ip6 daddr @intel6 drop" in body
    assert count == 2


def test_render_drops_unparsable_and_never_raises():
    body, summary, count = intelwall.render_elements({"junk", "999.1.2.3"})
    assert count == 0 and "elements" not in body


def test_render_is_idempotent_wholesale_table():
    a, _, _ = intelwall.render_elements({"192.0.2.0/24"})
    b, _, _ = intelwall.render_elements(set())
    assert a.count("table inet gw_intel {") == 1
    assert b.count("table inet gw_intel {") == 1


def test_apply_stores_file_and_runs_nft_only_when_root(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(intelwall, "_nft_path", lambda: "/usr/sbin/nft")
    monkeypatch.setattr(intelwall, "_euid", lambda: 0)

    class Done:
        returncode = 0
        stderr = b""

    run = lambda argv, **k: calls.append(argv) or Done()
    result = intelwall.apply({"192.0.2.0/24"}, tmp_path, run=run)
    assert result["loaded"] is True
    assert result["count"] == 1
    assert (tmp_path / "gw-intel.nft").exists()
    assert calls and calls[0] == ["/usr/sbin/nft", "-f",
                                  str(tmp_path / "gw-intel.nft")]


def test_apply_nonroot_stores_but_never_loads(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(intelwall, "_nft_path", lambda: "/usr/sbin/nft")
    monkeypatch.setattr(intelwall, "_euid", lambda: 1000)
    run = lambda argv, **k: calls.append(argv)
    result = intelwall.apply({"192.0.2.0/24"}, tmp_path, run=run)
    assert result["loaded"] is False
    assert calls == []
    assert (tmp_path / "gw-intel.nft").exists()


def test_apply_without_nft_binary_is_a_no_op(tmp_path, monkeypatch):
    monkeypatch.setattr(intelwall, "_nft_path", lambda: None)
    result = intelwall.apply({"192.0.2.0/24"}, tmp_path, run=lambda *a, **k: None)
    assert result["loaded"] is False and "error" not in result


def test_apply_stored_reloads_last_file(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(intelwall, "_nft_path", lambda: "/usr/sbin/nft")
    monkeypatch.setattr(intelwall, "_euid", lambda: 0)

    class Done:
        returncode = 0
        stderr = b""

    intelwall.apply({"198.51.100.0/24"}, tmp_path, run=lambda *a, **k: Done())
    result = intelwall.apply_stored(tmp_path, run=lambda argv, **k:
                                    calls.append(argv) or Done())
    assert result["loaded"] is True
    assert calls and "gw-intel.nft" in calls[0][-1]


def test_apply_stored_without_file_is_silent_noop(tmp_path):
    result = intelwall.apply_stored(tmp_path, run=lambda *a, **k: None)
    assert result == {"stored": None, "loaded": False}


def test_nft_failure_is_reported_not_raised(tmp_path, monkeypatch):
    monkeypatch.setattr(intelwall, "_nft_path", lambda: "/usr/sbin/nft")
    monkeypatch.setattr(intelwall, "_euid", lambda: 0)

    class Done:
        returncode = 2
        stderr = b"netlink: bad thing"

    result = intelwall.apply({"192.0.2.0/24"}, tmp_path, run=lambda *a, **k: Done())
    assert result["loaded"] is False
    assert "bad thing" in result["error"]
