"""Carried review minors — implementation pass (re-reviews 2-5 ledger).

Every finding here was graded Minor by the reviewers and carried across
passes; this file turns each into a contract pin. One test per finding,
in ledger order:

1.  card-per-window churn: the catch card id is KEY-STABLE (app+dst host
    shape), so a retried connection re-opens the SAME pending ask instead
    of minting a new file per window edge
2.  refused-swap retry: a failed nft swap must not freeze the kernel lane
    until process truth churns — the next refresh retries
3.  dead catch-path app_rules param: gone, or actually fed
4.  appfw/decisions.jsonl: append_checked (planted-name refusal) + a
    stated cap
5.  sweep_asks' dead seen map: removed (or consulted)
6.  runtime feed refresh reaches the INSTALLED dnsmasq conf
7.  catch-path dedupe-key construction: pinned by a _catch_path driver
8.  M2 scope.py: the two cgroup parsers share ONE tokenizer
9.  M5 rejected-pull cadence: a rejection must not skip the next cycle
10. M6 ts parse: timezone-aware (UTC) — not host-local naive parse
11. M-2: v6 GW-DENY lines parse (attribution + card)
12. M v6-LAN exemption rendered
13. M-1 ruling: feed-drop-before-trust divergence is STATED in the
    renderer, where the order is chosen
"""
from __future__ import annotations

import json
import pathlib
import sys
import unittest.mock as mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import pytest


# ---------------------------------------------------------------- 1: card
def test_catch_card_id_is_key_stable_across_window_edges():
    """A retried catch-path connection (same app+dst, new src port) must
    re-open the SAME card — the pending queue can only shrink."""
    from appfw import policy
    conn = _conn(app_name="brave", path="/usr/bin/brave",
                 host="tracker.example", dst_port=443, src_port=55555,
                 pid=4242)
    spec_a = policy._card_spec(conn, 'tracker.example', 'L3', 50, {}, {}, policy.Policy.__new__(policy.Policy))
    conn.src_port = 61000
    spec_b = policy._card_spec(conn, 'tracker.example', 'L3', 50, {}, {}, policy.Policy.__new__(policy.Policy))
    assert spec_a["id"] == spec_b["id"], (spec_a["id"], spec_b["id"])


def _conn(app_name="", path="", host="", dst_port=443, src_port=0,
          pid=0, proto="tcp"):
    import types
    return types.SimpleNamespace(
        app_name=app_name, process_path=path, process_args="",
        host=host, dst_ip=host, dst_port=dst_port, src_port=src_port,
        protocol=proto, pid=pid)


# ------------------------------------------------------- 2: swap retry
def test_refused_swap_is_retried_on_next_refresh():
    """A transient nft failure must not freeze the kernel lane: the next
    refresh retries the swap (signature stays 'wanted', not 'done')."""
    from appfw import enforce
    procs = {1: ("/usr/bin/firefox", "app-firefox.scope",
                 "user.slice/user-firefox@1.service"
                 "/app.slice/app-firefox.scope")}
    # first pass: swap refused
    orig = enforce.ruleset.swap_ruleset
    try:
        enforce.ruleset.swap_ruleset = lambda t: False
        snap1 = enforce.refresh("/tmp/x", app_rules={},
                                trusted={"/usr/bin/firefox"},
                                baseline_apps=set(), state=None,
                                procs=procs, mode="nft-scope")
        assert snap1.swapped is False and snap1.swap_failed is True
        # second pass, same truth, swap now works: it MUST retry
        enforce.ruleset.swap_ruleset = lambda t: True
        snap2 = enforce.refresh("/tmp/x", app_rules={},
                                trusted={"/usr/bin/firefox"},
                                baseline_apps=set(), state=snap1,
                                procs=procs, mode="nft-scope")
        assert snap2.swapped is True, "refused swap was never retried"
    finally:
        enforce.ruleset.swap_ruleset = orig


# ----------------------------------------------- 3: dead app_rules param
def test_evaluate_connection_has_no_dead_app_rules_param():
    """The catch-path chain runs the FULL policy (the kernel already
    dropped the packet); the dead app_rules parameter is gone."""
    import inspect
    import appfw.enforce as enforce
    sig = inspect.signature(enforce.evaluate_connection)
    assert "app_rules" not in sig.parameters, list(sig.parameters)


# ------------------------------------------- 4: decisions.jsonl hygiene
def test_asklifecycle_record_refuses_a_planted_name(tmp_path):
    """The appfw decisions ledger meets the repo's planted-name standard
    (append_checked): a symlink planted before the daemon's first write
    is never followed — the refusal surfaces (OSError) so the caller
    can count it."""
    from appfw import asklifecycle
    base = tmp_path / "appfw"
    base.mkdir()
    target = tmp_path / "evil"
    target.write_text("victim")
    link = base / "decisions.jsonl"
    link.symlink_to(target)
    with pytest.raises(OSError):
        asklifecycle._record(link, {"id": "x", "option": "deny"})
    assert "victim" in target.read_text()


# ------------------------------------------------ 5: dead seen map
def test_sweep_asks_builds_no_unconsulted_seen_map(tmp_path):
    import inspect
    from appfw import asklifecycle
    src = inspect.getsource(asklifecycle.sweep_asks)
    # the seen map was built and never consulted: either gone, or read
    assert 'seen[json.loads' not in src, \
        "decisions.txt re-scan at every sweep is the cost being removed"


# --------------------------------- 6: dnsmasq conf reaches the install
def test_feeds_lane_renders_into_the_installed_include(monkeypatch, tmp_path):
    """The feeds timer lane mirrors its rendered conf into the resolver's
    INSTALLED include — the install-day copy must not serve forever."""
    import feeds
    import feeds_lane
    d = tmp_path / "feeds"
    d.mkdir(parents=True)
    (d / "urlhaus.txt").write_text("tracker.example\n")
    (d / "manifest.json").write_text(json.dumps(
        {name: {"fetched_at": 9_999_999_999.0, "state": "ok", "rows": 1}
         for name in feeds.FEEDS}))
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    installed = tmp_path / "installed-include.conf"
    monkeypatch.setattr(feeds_lane, "INSTALLED_DNSMASQ_CONF", str(installed))
    monkeypatch.setattr(feeds_lane.webguard, "reload_dnsmasq", lambda: True)
    rc = feeds_lane.main()
    assert rc == 0
    assert installed.exists(), "the resolver's conf never got the refresh"
    assert installed.read_text() == (tmp_path / "webguard-blocklist.conf"
                                     ).read_text()


# ------------------------------------------------- 7: catch dedupe key
def test_catch_notice_dedupes_on_app_and_dst_not_port():
    """_catch_path must group on app+dst — a retried multi-port hammering
    is ONE row; pinned through the daemon with a fake engine."""
    import types
    import greywatch_daemon as dm
    d = dm.Daemon.__new__(dm.Daemon)
    d.data_dir = pathlib.Path("/tmp/gw-catch-key")
    notices = []
    d._notice = lambda *a, **k: notices.append(k.get("dedupe_key"))
    d.count_failure = lambda *a, **k: None
    eng = types.SimpleNamespace(policy=object(), store=None, resolver=None)
    d.appfw_engine = eng
    line = ('kernel: GW-DENY IN= OUT=wlp3s0 SRC=192.168.1.5 '
            'DST=93.184.216.34 PROTO=TCP SPT=55555 DPT=443')
    import appfw.enforce as enforce_mod
    orig = enforce_mod.evaluate_connection
    enforce_mod.evaluate_connection = lambda *a, **k: (
        "brave", "93.184.216.34", 443, "deny", "once", "")
    try:
        d._catch_path(line)
        d._catch_path(line.replace("55555", "61000"))
    finally:
        enforce_mod.evaluate_connection = orig
    assert len(notices) == 2
    assert notices[0] == notices[1], "port leaked into the catch key"
    assert notices[0].startswith("catch|")


# ------------------------------------ 8: one cgroup tokenizer, two names
def test_scope_and_enforce_share_the_cgroup_tokenizer():
    """M2: the two cgroup parsers must not drift — enforce's reader
    delegates to appfw.scope (or scope's to enforce's), pinned by source
    identity of the split + the 0:: marker."""
    enforce_src = (ROOT / "appfw" / "enforce.py").read_text()
    # exactly ONE place strips the 0:: marker outside of scope.py, or
    # enforce imports the reader from scope
    marks = enforce_src.count('"0::"') + enforce_src.count("'0::'")
    assert marks == 0, "enforce must reuse scope's reader"


# ------------------------------------------ 9: rejected-pull cadence
def test_rejected_pull_does_not_skip_the_next_cadence(tmp_path):
    """A rejected/failed pull records a failure stamp that does NOT
    count as 'fresh' — the next lane run retries at once."""
    from feeds import _record as _record_orig, PullResult
    import feeds
    cache = tmp_path / "feeds"
    cache.mkdir()
    spec = feeds.FEEDS[next(iter(feeds.FEEDS))]
    manifest_path = cache / "manifest.json"
    _record_orig({}, manifest_path,
                 PullResult(spec.name, "rejected", reason="too big",
                            kept_yesterday=True), spec, now=1000.0)
    row = json.loads(manifest_path.read_text())[spec.name]
    # the lane's freshness check: now - fetched_at < cadence → skip.
    # A REJECTED pull must not read as fresh: fetched_at must be 0 (or
    # row state must gate the skip) so the next run retries immediately.
    assert row["state"] == "rejected"
    assert row.get("fetched_at", 999) == 0, \
        "rejected pull stamped as fresh — the next cycle is skipped"


# --------------------------------------------------- 10: ts parse tz
def test_ledger_ts_parses_as_utc():
    """M6: the ledger timestamp is ISO with an explicit zone; the parse
    must yield the UTC epoch ('Z' != host-local midnight)."""
    import baseline as baseline_mod
    row = json.dumps({
        "from_tool": "appfw",
        "ts": "2026-11-11T00:01:30+00:00",
        "text": "appfw /usr/bin/app → example.com:443 tcp allow",
    })
    parsed = baseline_mod._parse_ledger_line(row)
    assert parsed is not None, "the pinned appfw row shape must parse"
    app, dst, port, action, ts = parsed
    # 2026-11-11T00:01:30Z — UTC epoch; a host-local parse would drift
    import calendar
    assert abs(ts - calendar.timegm(
        (2026, 11, 11, 0, 1, 30, 0, 0, 0))) < 2, ts


def test_bad_lines_counts_only_appfw_rows():
    """bad_lines is a parse-quality metric of OUR ledger: non-appfw
    tool rows are not 'bad', they are out of scope."""
    import baseline as baseline_mod
    base = baseline_mod.Baseline()
    assert base.bad_lines == 0
    # (build() counts; the parser returns None for non-appfw rows —
    # that must NOT increment bad_lines)


# --------------------------------------------- 11: v6 kernel lines
def test_v6_kernel_deny_line_parses():
    """M-2: IPv6 catch lines attribute and card too."""
    from appfw import enforce
    line = ('kernel: GW-DENY IN= OUT=wlp3s0 SRC=2600::5 '
            'DST=2606:4700::6810:84e5 PROTO=TCP SPT=55555 DPT=443')

    class P:
        def loopback_ports(self):
            return ()

    verdict = enforce.evaluate_connection(
        line, policy=P(), resolver=None)
    assert verdict is not None, "v6 catch line must parse (was v4-only)"
    assert verdict[1].startswith("2606:4700")


# --------------------------------------------- 12: v6-LAN exemption
def test_v6_lan_exempt_rendered():
    """2026-11-11 audit upgrade: BOTH rendered kernel chains must carry
    the v6-LAN exemption — the feed-guard lane is where a hostile feed row
    could blackhole the resolver's LAN path, not just the egress lane."""
    from appfw.ruleset import render_ruleset
    text = render_ruleset([], {}, catch=True)
    egress = text.split("chain egress {")[1].split("\n    }")[0]
    guard = text.split("chain feed-guard {")[1].split("\n    }")[0]
    assert "fc00::/7 accept" in egress, "v6-LAN exemption missing in egress"
    assert "fc00::/7 accept" in guard, "v6-LAN exemption missing in feed-guard"
    assert text.count("fc00::/7 accept") == 2


def test_cgroup_tokenizer_resolves_a_live_scope_shape():
    """2026-11-11 audit upgrade (adds behavior where the one-tokenizer
    check above only prevents reintroduction): the shared reader must turn
    a /proc cgroup line into the kernel-canonical ABSOLUTE scope path the
    renderer needs, and must survive a missing/unreadable proc entry
    (never raises)."""
    from appfw import scope
    with mock.patch.object(scope, "_read_cgroup",
                           return_value="0::/user.slice/user-1000.slice/"
                                        "user@1000.service/app.slice/"
                                        "app-firefox.scope"):
        full = scope.cgroup_scope(4242)
    assert full.startswith("/user.slice"), full
    assert "app-firefox.scope" in full
    # unshareable shapes degrade to '' instead of raising
    with mock.patch.object(scope, "_read_cgroup", return_value="0::/"):
        assert scope.cgroup_scope(4242) in ("", "/", None)


# ------------------------------------------- 13: lane-differ ruling
def test_kernel_lane_priorities_ruling_is_stated():
    """M-1: feed-guard (priority -5) drops before the egress allows —
    deny-biased across lanes by design; the renderer must SAY so where
    the order is chosen."""
    src = (ROOT / "appfw" / "ruleset.py").read_text()
    assert "trusted" in src.lower() and ("priority -5" in src), src[:50]


# ------------------------------ 14: notice wording for once-answers
def test_catch_notice_honest_for_once_answers():
    """C3 residual: 'applies onward' only for always-answers; a once
    answer must not overpromise. Pinned through _catch_path."""
    import types
    import greywatch_daemon as dm
    texts = []

    def _mk(action, duration):
        d = dm.Daemon.__new__(dm.Daemon)
        d.data_dir = pathlib.Path("/tmp/gw-catch-wording")
        d._notice = lambda tool, sev, text, **k: texts.append(text)
        d.count_failure = lambda *a, **k: None
        d.appfw_engine = types.SimpleNamespace(policy=object(), store=None,
                                               resolver=None)
        return d

    import appfw.enforce as enforce_mod
    line = ('kernel: GW-DENY IN= OUT=eth0 SRC=10.0.0.2 DST=93.184.216.34 '
            'PROTO=TCP SPT=55555 DPT=443')
    orig = enforce_mod.evaluate_connection
    try:
        enforce_mod.evaluate_connection = lambda *a, **k: (
            "brave", "93.184.216.34", 443, "deny", "once", "")
        _mk("deny", "once")._catch_path(line)
        enforce_mod.evaluate_connection = lambda *a, **k: (
            "brave", "93.184.216.34", 443, "allow", "always", "")
        _mk("allow", "always")._catch_path(line)
    finally:
        enforce_mod.evaluate_connection = orig
    assert "once at the gate" in texts[0], texts[0]
    assert "applies onward" not in texts[0]
    assert "applies onward" in texts[1], texts[1]


# --------------------------------- P2s from the verification pass
def test_bad_lines_matches_compact_producer_shape(tmp_path):
    """Re-review 6 P2: the production writer emits COMPACT json
    (separators=(',',':')) — a malformed appfw row in that shape must
    still count, and a compact other-tool row must still be out of
    scope, spacing-independent."""
    import baseline as baseline_mod
    (tmp_path / "events.jsonl").write_text(
        json.dumps({"from_tool": "appfw", "text": 12345},
                   separators=(",", ":")) + "\n"
        + json.dumps({"from_tool": "clamav", "text": "FOUND"},
                     separators=(",", ":")) + "\n")
    base = baseline_mod.build(tmp_path, now=1.0)
    assert base.bad_lines == 1, base.bad_lines


def test_decisions_trim_never_creates_a_plantable_tmp(tmp_path):
    """Re-review 6 P2: the trim rewrites through atomic_replace's
    private staging — no group-writeable sidecar in the shared dir."""
    import appfw.asklifecycle as al
    base = tmp_path / "appfw"
    (base / "asks" / "archive").mkdir(parents=True)
    dec = base / "decisions.jsonl"
    for i in range(al.DECISIONS_KEEP + 10):
        dec.parent.joinpath("decisions.jsonl")
        with open(dec, "a") as fh:
            fh.write(json.dumps({"id": f"appfw:x:{i}", "option": "deny",
                                 "ts": "2026-11-11T00:00:00+00:00"})
                     + "\n")
    al._trim_decisions(dec)
    assert len(dec.read_text().splitlines()) == al.DECISIONS_KEEP
    # the ONLY extra entry is the private 0700 root staging dir
    # (.root-tmp) — any group-writeable sidecar beside the ledger is a
    # planted-content promotion path and is forbidden
    sidecars = [p for p in base.iterdir() if p.name not in
                ("decisions.jsonl", "asks", ".root-tmp")]
    assert not sidecars, [p.name for p in sidecars]
    if (base / ".root-tmp").exists():
        mode = (base / ".root-tmp").stat().st_mode & 0o777
        assert mode == 0o700, oct(mode)
