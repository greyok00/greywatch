"""T8: rules builders + wizard helpers (validation gates) — real tools where
they run as grey (yara), stubs elsewhere; never root."""
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import rules as R
import wiz.common as C
from rules import (ValidationError, arpwatch_env_file, fail2ban_filter,
                   fail2ban_jail, tetragon_policy, ufw_build,
                   ufw_exact_string, yara_source)
from wiz import arpwatch_wizard, fail2ban_wizard, tetragon_wizard, yara_wizard


# ── W1 UFW: exact string + validation ───────────────────────────────────

def test_ufw_exact_string():
    spec = {"action": "deny", "direction": "in", "from": "203.0.113.9",
            "port": "23", "proto": "tcp", "comment": "gw-W1-1"}
    assert ufw_exact_string(spec) == \
        "ufw deny in from 203.0.113.9 to any port 23 proto tcp comment gw-W1-1"


def test_ufw_rejects_every_bad_input():
    with pytest.raises(ValidationError):
        ufw_build({"action": "ACCEPT", "direction": "in"})          # case
    with pytest.raises(ValidationError):
        ufw_build({"action": "allow", "direction": "up"})           # dir
    with pytest.raises(ValidationError):
        ufw_build({"action": "allow", "direction": "in", "port": "99999",
                   "proto": "tcp"})                                  # range
    with pytest.raises(ValidationError):
        ufw_build({"action": "allow", "direction": "in", "port": "22",
                   "proto": "smb"})                                  # proto
    with pytest.raises(ValidationError):
        ufw_build({"action": "allow", "direction": "in",
                   "from": "203.0.113.256"})                         # ip
    with pytest.raises(ValidationError):
        ufw_build({"action": "allow", "direction": "in",
                   "comment": "bad;rm -rf"})                         # comment


# ── W2 Fail2ban: builder + validator rejects ────────────────────────────

def test_fail2ban_jail_default_3600_600_3():
    lines = fail2ban_jail("gwtest", 3600, 600, 3, "/var/log/fail2ban.log", "gwtest")
    assert lines[0] == "[gwtest]" and "bantime  = 3600" in lines
    assert "findtime = 600" in lines and "maxretry = 3" in lines


def test_fail2ban_rejects():
    with pytest.raises(ValidationError):
        fail2ban_jail("bad;jail", 3600, 600, 3, "/var/log/x", "f")
    with pytest.raises(ValidationError):
        fail2ban_jail("ok_jail", 0, 600, 3, "/var/log/x", "f")       # bantime 0
    with pytest.raises(ValidationError):
        fail2ban_filter("")                                          # empty
    with pytest.raises(ValidationError):
        fail2ban_filter("ok pattern" + "\nrm -rf")                   # newline


def test_fail2ban_sample_gate():
    samples = ["2026-10-22 18:00:32,110 fail2ban.actions [x]: NOTICE [gw] Ban 1.2.3.4"]
    assert fail2ban_wizard.test_regex(r"Ban .*?1\.2\.3\.4", samples)
    assert not fail2ban_wizard.test_regex(r"nomatch\d+", samples)


# ── W3 Tetragon: policy yaml ────────────────────────────────────────────

def test_tetragon_policy_shapes():
    b = tetragon_wizard.build("exec", "exec-tracer")
    assert b["target"].startswith("/etc/tetragon/tetragon.tp.d/70-greywatch-")
    assert "security_bprm_check" in "\n".join(b["lines"])
    b_block = tetragon_policy("file_write", "fw-watch", {}, "block")
    assert any("enforce: true" in l for l in b_block)
    with pytest.raises(ValidationError):
        tetragon_policy("nonsense", "x", {}, "log-only")


# ── W4 YARA: REAL compile gate ──────────────────────────────────────────

def test_real_yara_binary():
    assert pathlib.Path("/usr/bin/yara").exists()


def test_yara_compile_gate():
    ok, _ = yara_wizard.compile_gate("rule gw_test { condition: true }")
    assert ok, "simple rule must compile with the REAL yara binary"
    ok2, err = yara_wizard.compile_gate("rule bad { condition: bogus(")
    assert not ok2 and err, "broken rule must fail the gate with yara's error"


def test_yara_hit_test(tmp_path):
    eicar = 'rule gw_eicar { strings: $s = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" condition: $s }'
    sample = tmp_path / "sample.bin"
    sample.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-"
                      "TEST-FILE!$H+H*")
    hit, detail = yara_wizard.compile_and_test(eicar, str(sample))
    assert hit and "gw_eicar" in detail


# ── W0 arpwatch ─────────────────────────────────────────────────────────

def test_arpwatch_env_builder():
    lines = arpwatch_env_file("wlan0", "arpwatch", ["-N", "-p"], "")
    assert 'RUNAS="arpwatch"' in lines and 'ARGS="-N -p"' in lines
    with pytest.raises(ValidationError):
        arpwatch_env_file("eth0;", "arpwatch", [], "")
    with pytest.raises(ValidationError):
        arpwatch_env_file("ok0", "arpwatch", ["--eval"], "")
    with pytest.raises(ValidationError):
        arpwatch_env_file("ok0", "arpwatch", [], "filter;jam")


# ── helper scripts: argv table executed for real (fail-closed) ──────────

def _sh(script, *args):
    base = pathlib.Path(__file__).resolve().parents[1] / "apply"
    return subprocess.run(["bash", str(base / script), *args],
                          capture_output=True, text=True, timeout=15).returncode


def test_helpers_reject_missing_args():
    assert _sh("unban-ip.sh") == 64
    assert _sh("unban-ip.sh", "sshd") == 64                       # missing IP
    assert _sh("unban-ip.sh", "sshd", "1.2.3.4", "extra") == 64
    assert _sh("ufw-apply.sh", "frobnicate", "in") == 65
    assert _sh("ufw-apply.sh", "deny", "in", "from", "999.1.1.1") == 65
    assert _sh("arpwrite.sh") == 64
    assert _sh("arpwrite.sh", "eth0", "root", "bogus", "") == 65


def test_helpers_reject_injection_vectors():
    assert _sh("unban-ip.sh", "sshd; rm -rf /", "1.2.3.4") == 65
    assert _sh("widen-scan-ban.sh", "1.2.3.4/24 ") == 65
    assert _sh("drop-listener.sh", "deny", "in; shutdown", "1.2.3.4") == 65


def test_helpers_allowlist_only_paths():
    pol = pathlib.Path(__file__).resolve().parents[1] / "apply" / "polkit" / "greywatch.apply.policy"
    text = pol.read_text()
    for name in ("unban-ip", "drop-listener", "restore-quarantine",
                 "keep-quarantine", "keep-scan-ban", "widen-scan-ban"):
        assert f"__GW_HOME__/apply/{name}.sh" in text


def test_wiz_common_stub_helper(tmp_path, monkeypatch):
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\necho \"$2 $3\"\n")
    stub.chmod(0o755)
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", str(stub))
    import importlib
    importlib.reload(C)
    assert C.run_helper("unban-ip", ["sshd", "1.2.3.4"]) == 0


def test_backup_and_restore_roundtrip(tmp_path):
    src = tmp_path / "conf.file"
    src.write_text("original")
    bak = C.backup_file(str(src)) / 0 if False else None
    import wiz.common as C2
    bak = C2.backup_file(str(src))
    assert pathlib.Path(bak).read_text() == "original"
    src.write_text("changed")
    assert C2.restore_backup(bak, str(src))
    assert src.read_text() == "original"