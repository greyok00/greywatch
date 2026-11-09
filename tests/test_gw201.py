"""GW-201/202 (owner 2026-11-06, wave B): the blocked-IP ledger, the
periodic verification pass, and the reviewer that QUESTIONS blocks that
smell accidental and never auto-fixes anything. psad already auto-blocks
at danger level 5; wave B is the bookkeeping and review layer on top:
the ledger remembers, verification keeps the wall standing, and the
reviewer asks before an own-network or content-network block stays."""
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import blockledger
import greywatch_daemon as gd
import blockreviewer
from decisions_factory import HELPERS, interaction_for, sanitize
from events import Event
from greywatch_daemon import Daemon, read_events
from parsers import parse_psad


def _j(text):
    return f"Nov  6 09:20:34 greyhost psad[1234]: {text}"


def _ev(tool, text, severity="HIGH"):
    ev = Event(from_tool=tool, severity=severity, text=text,
               ts="2026-11-06T09:20:34+00:00")
    return ev


# ---- psad's real auto-block phrases become events ------------------------
def test_psad_auto_block_phrases_are_events():
    added = parse_psad(_j("added iptables auto-block against 203.0.113.9 "
                          "timeout: 3600 sec"))
    assert added and added.severity == "CRITICAL"
    renewed = parse_psad(_j("renewed iptables auto-block against 203.0.113.9 "
                            "timeout: 3600 sec"))
    assert renewed and renewed.severity == "HIGH"
    removed = parse_psad(_j("removed iptables auto-block against 203.0.113.9"))
    assert removed and removed.severity == "MEDIUM"
    assert "203.0.113.9" in removed.text


def test_psad_block_chatter_stays_silent():
    assert parse_psad(_j("block rule for IP: 203.0.113.9 already exists")) \
        is None


# ---- the ledger: append-only, latest entry wins --------------------------
def test_ledger_records_blocks_and_releases(tmp_path):
    blockledger.record_block(tmp_path, "203.0.113.9", "psad", "sweep")
    active = blockledger.active_blocks(tmp_path)
    assert "203.0.113.9" in active and active["203.0.113.9"]["forever"] is False
    blockledger.record_release(tmp_path, "203.0.113.9", "psad", "expired")
    assert blockledger.active_blocks(tmp_path) == {}          # release wins
    assert blockledger.blocked(tmp_path)["203.0.113.9"]["kind"] == "release"


def test_ledger_forever_and_review_tracking(tmp_path):
    blockledger.record_block(tmp_path, "192.168.0.99", "manual",
                             "keeper chose block for good", forever=True)
    assert list(blockledger.forever_blocks(tmp_path)) == ["192.168.0.99"]
    assert blockledger.reviews(tmp_path) == {}    # no verdict yet
    blockledger.record_review(tmp_path, "192.168.0.99", "keep")
    blockledger.record_review(tmp_path, "192.168.0.99", "lift")
    assert blockledger.reviews(tmp_path)["192.168.0.99"] == "lift"
    # review lines never touch the block state
    assert list(blockledger.active_blocks(tmp_path)) == ["192.168.0.99"]


def test_ledger_ingests_psad_and_fail2ban_events(tmp_path):
    for ev, kind in (
        (_ev("psad", "added iptables auto-block against 198.51.100.7"),
         "block"),
        (_ev("psad", "renewed iptables auto-block against 198.51.100.7"),
         "block"),
        (_ev("psad", "removed iptables auto-block against 198.51.100.7"),
         "release"),
    ):
        rec = blockledger.classify_event(ev, tmp_path)
        assert rec and rec["kind"] == kind
    assert blockledger.active_blocks(tmp_path) == {}
    ban = blockledger.classify_event(_ev("fail2ban", "Ban sshd - 203.0.113.5"),
                                     tmp_path)
    assert ban and ban["kind"] == "block" and ban["source"] == "fail2ban"
    blockledger.classify_event(_ev("fail2ban", "Unban sshd - 203.0.113.5"),
                               tmp_path)
    assert blockledger.active_blocks(tmp_path) == {}
    assert blockledger.classify_event(
        _ev("appfw", "deny something"), tmp_path) is None


# ---- the decision card on the auto-block itself --------------------------
def test_auto_block_event_offers_forever_or_lift():
    ev = parse_psad(_j("added iptables auto-block against 203.0.113.9 "
                       "timeout: 3600 sec"))
    card = sanitize(interaction_for(ev))
    assert card and card["question"]
    helpers = [o["helper"] for o in card["options"]]
    assert "block-ip" in helpers and "lift-block" in helpers


def test_wave_b_helpers_are_sanitizer_known():
    for name in ("block-ip", "lift-block", "block-review"):
        assert name in HELPERS


# ---- the reviewer questions, never fixes ---------------------------------
def test_reviewer_baselines_classify_own_cdn_scanner():
    assert blockreviewer.classify("192.168.0.15")["cls"] == "own-infra"
    assert blockreviewer.classify("10.1.2.3")["cls"] == "own-infra"
    assert blockreviewer.classify("104.18.32.7")["cls"] == "cdn"
    assert blockreviewer.classify("151.101.65.140")["cls"] == "cdn"
    far = blockreviewer.classify("203.0.113.9")
    assert far["cls"] == "datacenter"


def test_reviewer_asks_about_house_and_cdn_blocks_only():
    house = blockreviewer.review_block("192.168.0.99", "keeper chose block",
                                  )
    cdn = blockreviewer.review_block("104.18.32.7")
    assert house and cdn and house["options"] and cdn["options"]
    for card in (house, cdn):
        helpers = [o["helper"] for o in card["options"]]
        assert set(helpers) <= {"block-review", "lift-block"}
        assert "block-review" in helpers and "lift-block" in helpers
    # and says nothing about a real scanner
    assert blockreviewer.review_block("203.0.113.9") is None


def test_reviewer_module_never_touches_the_firewall():
    src = (ROOT / "blockreviewer.py").read_text()
    for forbidden in ("subprocess", "nft ", "iptables", "blockledger"):
        assert forbidden not in src, forbidden


# ---- periodic verification: re-arm forever blocks, ask once ---------------
def mk_daemon(tmp_path):
    return Daemon(data_dir=tmp_path / "data",
                  registry=gd.load_registry())


def test_verification_rearms_drifted_forever_blocks(tmp_path):
    d = mk_daemon(tmp_path)
    blockledger.record_block(d.data_dir, "203.0.113.9", "psad",
                             "sustained attack", forever=False)
    blockledger.record_block(d.data_dir, "45.155.0.77", "manual",
                             "keeper chose block for good", forever=True)
    rearm_calls = []
    done = d.verify_blocks(
        probe=lambda ip: False, rearm=rearm_calls.append)
    assert rearm_calls == ["45.155.0.77"]     # only the keeper's own hold
    assert ("rearm", "45.155.0.77") in done
    # the far scanner gets no re-arm and no reviewer question
    assert ("question", "203.0.113.9") not in done


def test_verification_asks_once_about_a_house_block(tmp_path):
    d = mk_daemon(tmp_path)
    blockledger.record_block(d.data_dir, "192.168.0.99", "manual",
                             "house device blocked for good", forever=True)
    for run in range(2):
        d.verify_blocks(probe=lambda ip: True, rearm=lambda ip: None,
                        )
    d.flush_outbox()
    cards = [e for e in read_events(d.events_path)
             if e["from_tool"] == "block-reviewer"]
    assert len(cards) == 1, cards             # ONE question, never a flood
    spec = cards[0]["interaction"]
    assert spec["id"].startswith("block-reviewer:")
    assert [o["helper"] for o in spec["options"]] == \
        ["block-review", "lift-block"]


def test_answered_house_block_never_asks_again(tmp_path):
    d = mk_daemon(tmp_path)
    blockledger.record_block(d.data_dir, "192.168.0.12", "manual",
                             "blocked, then reviewed", forever=False)
    d.verify_blocks(probe=lambda ip: True, rearm=lambda ip: None)
    blockledger.record_review(d.data_dir, "192.168.0.12", "keep")
    d.verify_blocks(probe=lambda ip: True, rearm=lambda ip: None)
    d.flush_outbox()
    cards = [e for e in read_events(d.events_path)
             if e["from_tool"] == "block-reviewer"]
    assert len(cards) == 1                    # the verdict closes the ask


def test_verification_treats_probe_failure_as_standing(tmp_path):
    """When nftables cannot be read, the reviewer CANNOT claim a block
    left the wall: it stays silent rather than churn or lift anything."""
    d = mk_daemon(tmp_path)
    blockledger.record_block(d.data_dir, "198.51.100.3", "psad",
                             "sustained attack", forever=True)
    rearm_calls = []
    real_run = subprocess.run

    def boom(*args, **kwargs):
        raise OSError("nft unreadable")

    subprocess.run = boom
    try:
        assert d._firewall_has_block("198.51.100.3") is True
        d.verify_blocks(rearm=rearm_calls.append)
    finally:
        subprocess.run = real_run
    assert rearm_calls == []                  # nothing was touched


# ---- the helpers: contract from the tree, bins stubbed -------------------
SCRIPTS = {
    "block-ip": ROOT / "apply" / "block-ip.sh",
    "lift-block": ROOT / "apply" / "lift-block.sh",
    "block-review": ROOT / "apply" / "block-review.sh",
}


def _stub_bin(tmp_path, name, body):
    p = tmp_path / "bin" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    p.chmod(0o755)
    return p


def _nft_stub(tmp_path, state):
    return _stub_bin(tmp_path, "nft", '''#!/bin/bash
case "$*" in
  *"-f -"*) exit 0;;
  *"list table inet greywatch_blocks"*) [ "$STATE" = empty ] && exit 1 || exit 0;;
  *"get element"*"deny_v4"*) [ "$STATE" = absent ] && exit 1 || exit 0;;
  *"delete element"*) STATE=absent; exit 0;;
  *) exit 0;;
esac
''') or None


def _gw_env(tmp_path):
    env = dict(os.environ)
    env["GW_BLOCK_LEDGER"] = str(tmp_path / "led" / "blocked-ips.jsonl")
    (tmp_path / "bin").mkdir(exist_ok=True)
    env["PATH"] = f"{tmp_path / 'bin'}:{env['PATH']}"
    return env


def test_block_ip_helper_adds_and_records(tmp_path):
    _stub_bin(tmp_path, "nft", '''#!/bin/bash
case "$*" in
  *"-f -"*) exit 0;;
  *"list table inet greywatch_blocks"*) exit 1;;
  *"get element"*"deny_v4"*) exit 0;;
  *) exit 0;;
esac
''')
    env = _gw_env(tmp_path)
    out = subprocess.run(["/bin/bash", str(SCRIPTS["block-ip"]),
                          "203.0.113.9"], capture_output=True, text=True,
                         env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "blocked for good" in out.stdout
    lines = [json.loads(l) for l in
             (tmp_path / "led" / "blocked-ips.jsonl").read_text().splitlines()]
    assert lines[-1]["kind"] == "block" and lines[-1]["forever"] is True
    assert lines[-1]["source"] == "manual"
    # idempotent rerun: verified present, still rc 0
    again = subprocess.run(["/bin/bash", str(SCRIPTS["block-ip"]),
                            "203.0.113.9"], capture_output=True, text=True,
                           env=env)
    assert again.returncode == 0


def test_block_ip_helper_refuses_bad_input(tmp_path):
    env = _gw_env(tmp_path)
    noargs = subprocess.run(["/bin/bash", str(SCRIPTS["block-ip"])],
                            capture_output=True, env=env)
    assert noargs.returncode == 64
    badip = subprocess.run(["/bin/bash", str(SCRIPTS["block-ip"]),
                            "999.1.2.3"], capture_output=True, env=env)
    assert badip.returncode == 65


def test_lift_block_helper_releases_and_records(tmp_path):
    _stub_bin(tmp_path, "nft", '''#!/bin/bash
case "$*" in
  *"get element"*"deny_v4"*) exit 0;;
  *"delete element"*) exit 0;;
  *) exit 0;;
esac
''')
    _stub_bin(tmp_path, "psad", '#!/bin/bash\nexit 0\n')
    env = _gw_env(tmp_path)
    out = subprocess.run(["/bin/bash", str(SCRIPTS["lift-block"]),
                          "203.0.113.9"], capture_output=True, text=True,
                         env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    lines = [json.loads(l) for l in
             (tmp_path / "led" / "blocked-ips.jsonl").read_text().splitlines()]
    assert lines[-1]["kind"] == "release" and lines[-1]["source"] == "manual"
    assert "released" in out.stdout


def test_lift_block_helper_absent_from_set_is_still_ok(tmp_path):
    _stub_bin(tmp_path, "nft", '#!/bin/bash\nexit 1\n')
    _stub_bin(tmp_path, "psad", '#!/bin/bash\nexit 1\n')
    env = _gw_env(tmp_path)
    out = subprocess.run(["/bin/bash", str(SCRIPTS["lift-block"]),
                          "203.0.113.9"], capture_output=True, text=True,
                         env=env)
    assert out.returncode == 0, out.stdout + out.stderr


def test_block_review_helper_records_the_verdict_only(tmp_path):
    env = _gw_env(tmp_path)
    for verdict, rc in (("keep", 0), ("lift", 0), ("maybe", 65)):
        out = subprocess.run(["/bin/bash", str(SCRIPTS["block-review"]),
                              "192.168.0.5", verdict],
                             capture_output=True, text=True, env=env)
        assert out.returncode == rc, (verdict, out.stdout + out.stderr)
        if rc == 0:
            assert f"verdict {verdict} recorded" in out.stdout


# ---- polkit + wiring completeness ----------------------------------------
def test_polkit_actions_exist_for_the_three_helpers():
    src = (ROOT / "apply" / "polkit" / "greywatch.apply.policy").read_text()
    for action in ("block-ip", "lift-block", "block-review"):
        assert f"com.greywatch.apply.{action}" in src


def test_daemon_consumes_auto_block_into_the_ledger(tmp_path):
    d = mk_daemon(tmp_path)
    ev = d.consume("psad", "Nov  6 09:20:34 greyhost psad[1234]: "
                   "added iptables auto-block against 203.0.113.9 "
                   "timeout: 3600 sec")
    assert ev is not None and ev.interaction          # card rides along
    assert list(blockledger.active_blocks(d.data_dir)) == ["203.0.113.9"]
    d.consume("psad", "Nov  6 09:20:34 greyhost psad[1234]: "
              "removed iptables auto-block against 203.0.113.9")
    d.flush_outbox()
    assert blockledger.active_blocks(d.data_dir) == {}
