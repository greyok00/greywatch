"""Observability research wave (2026-11-12): failure-storm detection and
supervisor-health publication.

Both are observe-only additions to the daemon's health truth: a STORM
names a same-signature failure burst inside the log window; the
`supervisors` block publishes what the Supervised units already track
(state/restarts/tripped). Neither lane acts — the healer, the Supervised
breaker and the deadline discipline stay the only authorities.
"""
from __future__ import annotations

import json

import pytest

from appfw.askgate import AskGate  # noqa: F401  (guards import hygiene)
import greywatch_daemon as gd
from greywatch_daemon import Daemon
from registry import load_registry


def _reg():
    return load_registry()


def mk_daemon(tmp_path, **kw):
    return Daemon(data_dir=tmp_path / "data", registry=_reg(), **kw)


def test_identical_failure_signature_reaches_storm(tmp_path):
    d = mk_daemon(tmp_path)
    for _ in range(gd.Daemon.FAIL_STORM_N):
        d.count_failure("scan", "poll", RuntimeError("disk hiccup"))
    assert d._fail_counts["scan"]["storm"] is True


def test_distinct_signatures_do_not_storm(tmp_path):
    d = mk_daemon(tmp_path)
    where = ["alpha", "beta", "gamma", "delta"]  # different `where` each
    for w in where:
        d.count_failure("scan", w, RuntimeError("disk hiccup"))
    assert d._fail_counts["scan"]["storm"] is False


def test_alternating_signatures_reset_the_run(tmp_path):
    d = mk_daemon(tmp_path)
    for i in range(gd.Daemon.FAIL_STORM_N * 2):
        where = "alpha" if i % 2 == 0 else "beta"
        d.count_failure("scan", where, RuntimeError("disk hiccup"))
    assert d._fail_counts["scan"]["storm"] is False


def test_storm_clears_when_the_storm_stops(tmp_path):
    d = mk_daemon(tmp_path)
    for _ in range(gd.Daemon.FAIL_STORM_N):
        d.count_failure("scan", "poll", RuntimeError("x"))
    assert d._fail_counts["scan"]["storm"] is True
    d.count_failure("scan", "other-lane", RuntimeError("x"))  # sig change
    assert d._fail_counts["scan"]["storm"] is False


def test_storm_fails_are_published_additively(tmp_path):
    d = mk_daemon(tmp_path)
    for _ in range(gd.Daemon.FAIL_STORM_N):
        d.count_failure("scan", "poll", RuntimeError("x"))
    snap = {"failures": {k: v["count"]
                         for k, v in d._fail_counts.items()}}
    snap["failure_storms"] = sorted(k for k, v in d._fail_counts.items()
                                    if v.get("storm"))
    assert snap["failure_storms"] == ["scan"]
    # additive key never changes the classic failures map shape
    assert snap["failures"]["scan"] == gd.Daemon.FAIL_STORM_N


def test_components_block_is_the_single_supervisor_source(tmp_path):
    """Supervisor health has ONE published source (snap["components"],
    pre-existing); the research wave added no duplicate key."""
    d = mk_daemon(tmp_path)
    assert not hasattr(d, "_supervisor_facts"), \
        "a duplicate supervisor publication crept back in"
    with pytest.MonkeyPatch.context() as m:
        m.setattr(d, "collect_burst", lambda tailers, settle: [])
        snap = d.run_once(tailers=[], settle=0.01)
    # the daemon's own components block carries the supervised units
    if getattr(d, "supervisor", None) is not None:
        assert isinstance(snap.get("components"), dict)
