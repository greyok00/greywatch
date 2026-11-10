"""GW-205+/wave D: the rail shell, the Defense desk and its data path.

The two-system directive becomes the window: grouped rail (Watch, Defense,
Care, System), a Defense page fed by the daemon's public status digest
(the ledger and event store stay root-only), armor probes that answer
True/False/None and say UNKNOWN when they cannot look - never SAFE.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import blockledger
import greywatch_daemon as gd
from greywatch_daemon import Daemon
from ui import defense


def _stub_bin(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    p.chmod(0o755)
    return str(p)


def _reviewer_event(spec_id="block-reviewer:abc123", ts="2026-11-06T09:00:00+00:00"):
    return {"from_tool": "block-reviewer", "severity": "MEDIUM", "text": "asks",
            "ts": ts,
            "interaction": {"id": spec_id, "eyebrow": "Block Reviewer check",
                            "subject": "192.168.0.44 is blocked",
                            "question": "Keep blocking, or lift it?",
                            "options": [{"id": "keep", "helper":
                                         "block-review"}]}}


# ---- the digest -------------------------------------------------------------
def test_page_digest_reads_the_ledger(tmp_path):
    blockledger.record_block(tmp_path, "203.0.113.9", "psad",
                             "sustained attack")
    blockledger.record_block(tmp_path, "192.168.0.44", "psad",
                             "sustained attack")
    doc = blockledger.page_digest([], tmp_path)
    rows = {r["ip"]: r for r in doc["blocked"]}
    assert set(rows) == {"203.0.113.9", "192.168.0.44"}
    assert rows["192.168.0.44"]["cls"] == "own-infra"
    assert "own network range" in rows["192.168.0.44"]["why"]
    assert rows["203.0.113.9"]["cls"] == "datacenter"
    assert rows["203.0.113.9"]["reason"] == "sustained attack"


def test_page_digest_releases_lift_rows(tmp_path):
    blockledger.record_block(tmp_path, "203.0.113.9", "psad", "attack")
    blockledger.record_release(tmp_path, "203.0.113.9", "psad", "expired")
    doc = blockledger.page_digest([], tmp_path)
    assert doc["blocked"] == []


def test_page_digest_marks_reviewed_and_forever(tmp_path):
    blockledger.record_block(tmp_path, "192.168.0.44", "psad", "attack",
                             forever=True)
    blockledger.record_review(tmp_path, "192.168.0.44", "keep")
    (row,) = blockledger.page_digest([], tmp_path)["blocked"]
    assert row["forever"] is True and row["reviewed"] == "keep"


def test_page_digest_lists_only_unanswered_asks(tmp_path):
    evs = [_reviewer_event(), _reviewer_event(spec_id="block-reviewer:gone"),
           {"from_tool": "clamav", "severity": "CRITICAL",
            "text": "FOUND /x", "ts": "t",
            "interaction": {"id": "clamav:1", "options": []}}]
    doc = blockledger.page_digest(evs, tmp_path,
                                  answered=("block-reviewer:gone",))
    assert [a["spec"]["id"] for a in doc["asks"]] == ["block-reviewer:abc123"]


def test_page_digest_is_bounded(tmp_path):
    evs = [_reviewer_event(spec_id=f"block-reviewer:{i:04d}") for i in range(60)]
    doc = blockledger.page_digest(evs, tmp_path)
    assert len(doc["asks"]) == 50


# ---- the daemon publishes it -----------------------------------------------
def test_daemon_writes_the_defense_digest(tmp_path):
    d = Daemon(data_dir=tmp_path / "data", registry=gd.load_registry())
    blockledger.record_block(d.data_dir, "192.168.0.44", "psad", "attack")
    d.write_status()
    snap = json.loads((d.data_dir / "status.json").read_text())
    doc = snap["defense"]
    assert [r["ip"] for r in doc["blocked"]] == ["192.168.0.44"]
    assert doc["blocked"][0]["cls"] == "own-infra"
    # a reviewer event in the store shows up as one ask
    with open(d.events_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(_reviewer_event()) + "\n")
    d.write_status()
    snap = json.loads((d.data_dir / "status.json").read_text())
    assert len(snap["defense"]["asks"]) == 1


# ---- the armor probes ------------------------------------------------------
def test_psad_probes_read_true_false_and_none(tmp_path):
    conf = tmp_path / "psad.conf"
    conf.write_text("ENABLE_AUTO_IDS             Y;\n")
    kern = tmp_path / "kern.log"
    kern.write_text("PSAD-IN: x\n")
    missing_bin = _stub_bin(tmp_path, "no-nft", "#!/bin/sh\nexit 98\n")
    st = defense.psad_status(conf=conf, kern_log=kern, nft_bin=missing_bin,
                             systemctl_bin="true")
    assert st["armed"] is True and st["fed"] is True
    # an exit-2 probe means the reader cannot tell: unknown, never safe
    assert st["table"] is None
    off = tmp_path / "off.conf"
    off.write_text("ENABLE_AUTO_IDS             N;\n")
    st2 = defense.psad_status(conf=off, kern_log=tmp_path / "nope",
                              nft_bin="false", systemctl_bin="false")
    assert st2["armed"] is False and st2["fed"] is False
    assert st2["service"] is False
    ghost = tmp_path / "ghost.conf"
    st3 = defense.psad_status(conf=ghost, kern_log=kern,
                              nft_bin=missing_bin, systemctl_bin="true")
    assert st3["armed"] is None


def test_arp_probe_reads_pin_state_from_a_stub(tmp_path):
    ip = _stub_bin(tmp_path, "ip", """#!/bin/sh
case "$1" in
  -4) echo "default via 192.168.0.1 dev wlp3s0 proto dhcp src 192.168.0.2" ;;
  neigh) echo "192.168.0.1 dev wlp3s0 lladdr de:ad:be:ef:00:01 PERMANENT" ;;
esac
exit 0
""")
    proc = tmp_path / "proc/sys/net/ipv4/conf/all"
    proc.mkdir(parents=True)
    (proc / "arp_ignore").write_text("1")
    (proc / "arp_accept").write_text("0")
    old = defense.PROC_SYS
    defense.PROC_SYS = tmp_path / "proc"
    try:
        st = defense.arp_status(ip_bin=ip)
        assert st["pinned"] is True and st["sysctls"] is True
    finally:
        defense.PROC_SYS = old
    # the same router WITHOUT the permanent pin reads open, not unknown
    ip2 = _stub_bin(tmp_path, "ip2", """#!/bin/sh
case "$1" in
  -4) echo "default via 192.168.0.1 dev wlp3s0" ;;
  neigh) echo "192.168.0.1 dev wlp3s0 lladdr de:ad:be:ef:00:01 REACHABLE" ;;
esac
exit 0
""")
    st2 = defense.arp_status(ip_bin=ip2)
    assert st2["pinned"] is False


def test_arp_probe_leaves_sysctls_unknown_when_proc_read_fails(tmp_path):
    ip = _stub_bin(tmp_path, "ip", """#!/bin/sh
case "$1" in
  -4) echo "default via 192.168.0.1 dev wlp3s0" ;;
  neigh) echo "192.168.0.1 dev wlp3s0 REACHABLE" ;;
esac
exit 0
""")
    old = defense.PROC_SYS
    defense.PROC_SYS = tmp_path / "nothing-here"
    try:
        st = defense.arp_status(ip_bin=ip)
    finally:
        defense.PROC_SYS = old
    assert st["pinned"] is False and st["sysctls"] is None


def test_cve_rows_reads_active_rules(tmp_path):
    assert defense.cve_rows(tmp_path) is None    # never fetched: say so
    cache = tmp_path / "cve-cache.json"
    cache.write_text(json.dumps({"fetched_utc": "t", "queries": ["q"],
                                 "entries": [
        {"id": "CVE-2026-0001", "modified": "m", "tool": "clamav",
         "score": 9.8, "severity": "CRITICAL", "summary": "bad parse"},
        {"id": "CVE-2026-0002", "modified": "m", "tool": "clamav",
         "score": 5.1, "severity": "MEDIUM", "summary": "minor"}]}))
    rows = defense.cve_rows(tmp_path)
    assert [r["cve"] for r in rows] == ["CVE-2026-0001"]
    assert rows[0]["tool"] == "clamav"


def test_cve_rules_never_patch_anything():
    for name in ("ui/defense.py", "cverules.py", "blockledger.py"):
        src = (ROOT / name).read_text()
        for banned in ("apt upgrade", "apt-get", "apt install"):
            assert banned not in src, (name, banned)


# ---- the rail data ----------------------------------------------------------
def test_rail_groups_follow_the_two_system_design():
    from ui import shell
    # Rebuild round 2 (task 2): the owner's ten-page menu — the Overview
    # home row plus nine grouped rows; every key resolves in the stack
    # through the one legacy map.
    from ui.window import _LEGACY_PAGE
    keys = [k for group in shell.RAIL for k in group]
    assert keys == ["scans", "protect", "tools", "harden", "defense",
                    "thunter", "logs", "settings", "help"]
    # every rail key is unique and resolvable in the pane stack
    assert len(keys) == len(set(keys))
    for k in keys:
        assert _LEGACY_PAGE.get(k, k) in ("overview", "defense",
                                          "thunter", "services",
                                          "auditlog",
                                          "settings", "help")


def test_rail_keys_all_have_a_drawn_glyph():
    from ui import shell, themes
    for key in shell.RAIL_KEYS:
        assert key in themes._TAB_GLYPHS, key


def test_lane_tokens_exist_in_both_voices():
    from ui.themes import load_themes, gtk_css
    for name in ("paper", "graphite"):
        css = gtk_css(load_themes()[name])
        assert "--el-lane-threat" in str(load_themes()[name]), name
        assert ".gw-lane-threat" in css and ".gw-lane-tool" in css, name
        assert ".gw-rail-head" in css and ".gw-armor-open" in css, name


# ---- the view wiring (no display needed to pin the contract) ----------------
def test_defense_view_contract_is_importable_and_call_shaped():
    """The real window fixtures open real pages in test_tab_shell.py; this
    pin only guards the import surface: the class exists, refresh takes
    the status snapshot, and the row-level controls name real helpers.
    Re-rooted for rebuild task 7 (fw-A): the blocked row carries ONE
    Unblock through the lift-block lane (the reviewer-answer lane the
    old two-button row carried is the decisions machinery's), and the
    dock hands the Rules / psad / Open config groups."""
    gi = __import__("gi")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
    assert callable(defense.DefenseView.refresh)

    def buttons(host):
        out = []
        try:
            kids = list(host)
        except TypeError:
            return out
        for k in kids:
            out.extend(buttons(k))
        if isinstance(host, Gtk.Button):
            out.append(host)
        return out

    v = defense.DefenseView(win=None)
    row = v._blocked_row({"ip": "203.0.113.9", "ts": "", "reason": "auto"})
    assert [b.get_label() for b in buttons(row)] == ["Unblock"]
    assert [t for t, _ws in v.dock_groups()] == ["Rules", "psad",
                                                "Open config"]
    v.unparent()
