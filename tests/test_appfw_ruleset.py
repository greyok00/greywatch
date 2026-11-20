"""appfw nftables ruleset renderer (plan Task 4).

Renders the `greywatch2` table: per-app cgroupv2 scope rules, feed IP
sets, catch deny+LOG. Contract: exactly one table; NO jump NFQUEUE in
scope mode (the worker retires from the decision path); feed sets carry
only validated IP rows; catch rule last; idempotent byte-identical
re-render; nft -c validates text before any live swap.
"""
from __future__ import annotations

import pathlib

import pytest

from appfw.ruleset import AppRule, render_ruleset


def _rules():
    return [
        AppRule(scope="/app.slice/app-gnome-firefox@4123.scope",
                basename="app-gnome-firefox@4123.scope",
                verdict="allow", note="baseline allow (browser)"),
        AppRule(scope="/app.slice/app-flatpak-Com.example@8811.scope",
                basename="app-flatpak-Com.example@8811.scope",
                verdict="deny", note="feed hit: malware (urlhaus)"),
    ]


FEED_IPS = {"firehol-l1": {"203.0.113.7", "198.51.100.23"},
            "urlhaus": {"192.0.2.66"}}


def test_one_table_and_no_nfqueue_in_scope_mode():
    text = render_ruleset(_rules(), FEED_IPS, catch=True)
    assert text.count("table inet greywatch2") == 1
    assert "NFQUEUE" not in text.upper()
    assert "queue" not in text.lower()


def test_scope_rules_match_full_path_not_depth2():
    """C1 (review): `socket cgroupv2 level N` counts depth FROM THE ROOT,
    so deep desktop scopes (user.slice/…/app.slice/app-x.scope) never
    matched and the catch rule dropped them. The rule must quote the
    FULL scope path and use no `level` token at all.

    SUPERSEDED (C1 round 2): full path is unexpressible — the grammar
    requires `level N`; N derives from the live path. See
    test_scope_rules_render_live_depth_not_fixed_depth."""
    deep = AppRule(scope="/user.slice/user-1000.slice/user@1000.service"
                         "/app.slice/app-gnome-firefox@4123.scope",
                   basename="app-gnome-firefox@4123.scope",
                   verdict="allow", note="")
    text = render_ruleset([deep], FEED_IPS, catch=True)
    assert "level 2" not in text         # the reviewer's blackhole shape: never


def test_exempt_lanes_accept_before_catch():
    """C1 companion: loopback, RFC1918/LAN and DNS accepts ride the same
    table BEFORE the catch rule — gate 5's exemptions are kernel facts,"""
    text = render_ruleset(_rules(), FEED_IPS, catch=True)
    assert "ip daddr 127.0.0.0/8 accept" in text
    assert "ip daddr 192.168.0.0/16 accept" in text
    assert "udp dport 53 accept" in text


def test_per_app_scope_rules_come_from_our_data():
    text = render_ruleset(_rules(), FEED_IPS, catch=True)
    assert 'socket cgroupv2 level 2 "app-gnome-firefox@4123.scope"' in text
    assert "accept" in text          # the allow app
    assert "drop" in text            # the deny app


def test_catch_rule_last_deny_with_log():
    """Catch overflow pin (re-review 4): the LAST verdict-bearing rule is
    the unlimited trailing drop — the limited log rule only logs; nothing
    after it allows and nothing falls through to policy accept."""
    text = render_ruleset(_rules(), FEED_IPS, catch=True)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    catch_idx = next(i for i, ln in enumerate(lines)
                     if 'log prefix "GW-DENY "' in ln)   # limit-first form
    # the FIRST verdict-bearing rule after the log line is an unlimited
    # drop (overflow denied; never policy accept)
    tail = [ln for ln in lines[catch_idx + 1:]
            if ("accept" in ln or "drop" in ln)]
    assert tail and "drop" in tail[0] and "accept" not in tail[0], tail
    assert "counter drop" in tail[0] and "limit" not in tail[0]
    # and it is genuinely last: no further verdict lines follow
    assert tail[1:] == []
    assert 'log prefix "GW-DENY "' in text


def test_catch_rule_optional_off():
    text = render_ruleset(_rules(), FEED_IPS, catch=False)
    assert "GW-DENY" not in text


def test_feed_sets_hold_only_ips_and_drop_invalid(tmp_path):
    sets = {"firehol-l1": {"203.0.113.7", "not-an-ip", "999.1.1.1"}}
    text = render_ruleset([], sets, catch=True)
    assert "203.0.113.7" in text
    assert "not-an-ip" not in text
    assert "999.1.1.1" not in text


def test_idempotent_render_byte_identical():
    a = render_ruleset(_rules(), FEED_IPS, catch=True)
    b = render_ruleset(_rules(), FEED_IPS, catch=True)
    assert a == b


def test_scope_string_is_nft_quoted_safely():
    evil = AppRule(scope='/app.slice/app-x".scope',
                   basename='app-x".scope', verdict="deny", note="")
    text = render_ruleset([evil], FEED_IPS, catch=True)
    assert 'socket cgroupv2 level 2 "app-x\\".scope"' in text


def test_swap_rejects_text_nft_c_fails(tmp_path, monkeypatch):
    import subprocess
    import appfw.ruleset as rs
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        raise FileNotFoundError("nft unavailable")   # any failure rejects

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert rs.swap_ruleset("table inet greywatch2 {}", nft_bin="nft") is False
    assert len(calls) == 1                      # the check step rejected


def test_swap_runs_exact_two_step_check_then_load(tmp_path, monkeypatch):
    import subprocess
    import appfw.ruleset as rs
    seen = []
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: seen.append(list(cmd)) or
                        type("R", (), {"returncode": 0})())
    ok = rs.swap_ruleset("table inet greywatch2 {}\n", nft_bin="nft")
    assert ok is True
    assert len(seen) == 2
    assert seen[0][0:3] == ["nft", "-c", "-f"]      # validate first
    assert seen[1][0:2] == ["nft", "-f"]            # then load
    assert seen[1][2] == seen[0][3]                 # same file both steps


def test_ruleset_renderer_self_test_via_nft_unavailable_here(monkeypatch):
    """Environment guard: the renderer text stands alone on machines
    without nft; swap_ruleset must fail CLOSED when nft is absent."""
    import subprocess
    import appfw.ruleset as rs

    def missing(cmd, **kw):
        raise FileNotFoundError(2, "nft missing")

    monkeypatch.setattr(subprocess, "run", missing)
    assert rs.swap_ruleset("table inet greywatch2 {}\n",
                           nft_bin="/nonexistent/nft") is False


def test_rendered_file_validates_under_real_nft():
    """Reviewer fix 5: string tests cannot catch semantics; run the REAL
    nft -c check-fd pass on the rendered table when nft + privileges
    exist (skips otherwise). Catches the level-2/full-path class of bug
    at the syntax layer for any future renderer change."""
    import shutil
    import subprocess
    import appfw.ruleset as rs
    nft = shutil.which("nft")
    if nft is None:
        pytest.skip("nft binary not present")
    text = render_ruleset(_rules(), FEED_IPS, catch=True)
    stage = pathlib.Path("/tmp/gw-real-nft-check.nft")
    stage.write_text(text)
    try:
        run = subprocess.run(["nft", "-c", "-f", str(stage)],
                             capture_output=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as exc:
        pytest.skip(f"real nft unavailable here: {exc}")
    if run.returncode != 0 and b"Operation not permitted" in run.stderr:
        pytest.skip("no privilege for netlink check")
    assert run.returncode == 0, run.stderr.decode(errors="replace")


def test_scope_rules_render_live_depth_not_fixed_depth():
    """C1 round 2: `socket cgroupv2 level N` counts from the ROOT (1-
    indexed, N required by grammar). The renderer must derive N from the
    LIVE path: leaf basename at its own depth."""
    deep = AppRule(scope="/user.slice/user-1000.slice/user@1000.service"
                         "/app.slice/app-gnome-firefox@4123.scope",
                   basename="app-gnome-firefox@4123.scope",
                   verdict="allow", note="")
    text = render_ruleset([deep], FEED_IPS, catch=True)
    assert 'socket cgroupv2 level 5 "app-gnome-firefox@4123.scope"' in text
    assert "level 2" not in text
    shallow = AppRule(scope="/app-firefox.scope",
                      basename="app-firefox.scope",
                      verdict="deny", note="")
    text2 = render_ruleset([shallow], FEED_IPS, catch=True)
    assert 'socket cgroupv2 level 1 "app-firefox.scope"' in text2


def test_scope_path_components_feed_the_depth():
    from appfw.ruleset import _depth_of
    assert _depth_of("/user.slice/user@1000.service/app.slice/x.scope") == 4
    assert _depth_of("/x.scope") == 1
    assert _depth_of("") == 0
    assert _depth_of("/a/b/c") == 3


def test_catch_rule_limit_first_overflow_stays_dropped():
    """Re-review 4/P0: limit gates the LOG; the drop is the NEXT rule,
    unlimited and unconditional — overflow is denied, never policy-accept."""
    text = render_ruleset(_rules(), FEED_IPS, catch=True)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    log_idx = next(i for i, ln in enumerate(lines) if 'log prefix "GW-DENY "' in ln)
    catch = lines[log_idx]
    limit_idx = catch.find("limit rate 30/minute")
    assert 0 <= limit_idx < catch.find("log prefix"), catch  # limit precedes log
    assert "drop" not in catch          # the log rule does NOT deny
    # the very next rule is the unlimited unconditional drop
    nxt = lines[log_idx + 1]
    assert "counter drop" in nxt and "limit" not in nxt, nxt
    assert "accept" not in nxt
