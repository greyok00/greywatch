import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _stub_nft(tmp_path):
    state = tmp_path / "nft-state"
    log = tmp_path / "nft.log"
    body = f'''#!/bin/bash
printf '%s\\n' "$*" >> "{log}"
case "$*" in
  *"list table inet greywatch_netguard"*)
    if [ -f "{state}" ]; then
      echo "table inet greywatch_netguard {{"
      echo "  set scanners_v4 {{ type ipv4_addr ; flags timeout ; }}"
      echo "  set scanners_v6 {{ type ipv6_addr ; flags timeout ; }}"
      echo "  chain input {{ log prefix \\"GW-SCAN: \\" }}"
      echo "}}"
      exit 0
    fi
    exit 1;;
  *"-f -"*)
    cat >/dev/null
    echo "table inet greywatch_netguard {{ set scanners_v4 {{ }} set scanners_v6 {{ }} chain input {{ GW-SCAN: }} }}" > "{state}"
    exit 0;;
  *"get element"*"scanners_v4"*) exit 0;;
  *"add element"*) echo "$*" >> "{log}"; exit 0;;
  *"delete element"*"scanners_v4"*) exit 0;;
  *) exit 0;;
esac
'''
    p = tmp_path / "bin" / "nft"
    p.parent.mkdir(exist_ok=True)
    p.write_text(body)
    p.chmod(0o755)
    return p, state, log


def _env(tmp_path, nft):
    ledger = tmp_path / "data" / "blocked-ips.jsonl"
    return dict(os.environ,
                NFT_BIN=str(nft),
                GW_BLOCK_LEDGER=str(ledger),
                GW_NETGUARD_HELPER=str(ROOT / "apply" / "netguard.sh"))


def test_sensor_helper_arms_idempotently(tmp_path):
    nft, state, _log = _stub_nft(tmp_path)
    env = _env(tmp_path, nft)
    first = subprocess.run(["/bin/bash", str(ROOT / "apply" / "netguard.sh"),
                            "arm"], capture_output=True, text=True, env=env)
    assert first.returncode == 0, first.stdout + first.stderr
    assert state.exists()
    second = subprocess.run(["/bin/bash", str(ROOT / "apply" / "netguard.sh"),
                             "arm"], capture_output=True, text=True, env=env)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "already armed" in second.stdout


def test_sensor_helper_reports_missing_nft(tmp_path):
    env = dict(os.environ, NFT_BIN=str(tmp_path / "missing-nft"))
    out = subprocess.run(["/bin/bash", str(ROOT / "apply" / "netguard.sh"),
                          "arm"], capture_output=True, text=True, env=env)
    assert out.returncode == 66


def test_block_helper_adds_timeout_and_ledger(tmp_path):
    nft, _state, log = _stub_nft(tmp_path)
    arm = tmp_path / "bin" / "netguard-arm"
    arm.write_text("#!/bin/bash\nexit 0\n")
    arm.chmod(0o755)
    env = _env(tmp_path, nft)
    env["GW_NETGUARD_HELPER"] = str(arm)
    out = subprocess.run(
        ["/bin/bash", str(ROOT / "apply" / "netguard-block.sh"),
         "203.0.113.9", "1800"], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    args = log.read_text()
    assert "add element inet greywatch_netguard scanners_v4" in args
    assert "timeout 1800s" in args
    rec = json.loads((tmp_path / "data" / "blocked-ips.jsonl").read_text())
    assert rec["kind"] == "block" and rec["forever"] is False
    assert rec["ttl_s"] == 1800 and rec["expires_at"].endswith("Z")
    assert rec["source"] == "net-watch"


def test_block_helper_uses_the_ipv6_set(tmp_path):
    nft, _state, log = _stub_nft(tmp_path)
    arm = tmp_path / "bin" / "netguard-arm"
    arm.write_text("#!/bin/bash\nexit 0\n")
    arm.chmod(0o755)
    env = _env(tmp_path, nft)
    env["GW_NETGUARD_HELPER"] = str(arm)
    out = subprocess.run(
        ["/bin/bash", str(ROOT / "apply" / "netguard-block.sh"),
         "2001:db8::9", "900"], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    args = log.read_text()
    assert "add element inet greywatch_netguard scanners_v6" in args
    assert "timeout 900s" in args
    rec = json.loads((tmp_path / "data" / "blocked-ips.jsonl").read_text())
    assert rec["ip"] == "2001:db8::9"


def test_block_helper_rejects_bad_input(tmp_path):
    nft, _state, _log = _stub_nft(tmp_path)
    env = _env(tmp_path, nft)
    for args, rc in (([], 64), (["999.1.2.3"], 65),
                     (["203.0.113.9", "5"], 65)):
        out = subprocess.run(
            ["/bin/bash", str(ROOT / "apply" / "netguard-block.sh")] + args,
            capture_output=True, text=True, env=env)
        assert out.returncode == rc, (args, out.stdout + out.stderr)


def test_lift_helper_accepts_ipv6_and_records_the_release(tmp_path):
    nft, _state, log = _stub_nft(tmp_path)
    env = _env(tmp_path, nft)
    out = subprocess.run(
        ["/bin/bash", str(ROOT / "apply" / "lift-block.sh"),
         "2001:db8::9"], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "scanners_v6" in log.read_text()
    rec = json.loads((tmp_path / "data" / "blocked-ips.jsonl").read_text())
    assert rec["kind"] == "release" and rec["ip"] == "2001:db8::9"


def test_forever_block_helper_uses_the_ipv6_set(tmp_path):
    nft, _state, log = _stub_nft(tmp_path)
    env = _env(tmp_path, nft)
    out = subprocess.run(
        ["/bin/bash", str(ROOT / "apply" / "block-ip.sh"),
         "2001:db8::9"], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    args = log.read_text()
    assert "add element inet greywatch_blocks deny_v6" in args
    rec = json.loads((tmp_path / "data" / "blocked-ips.jsonl").read_text())
    assert rec["ip"] == "2001:db8::9" and rec["forever"] is True


def test_lift_helper_removes_the_temporary_set_too(tmp_path):
    nft, _state, _log = _stub_nft(tmp_path)
    psad = tmp_path / "bin" / "psad"
    psad.write_text("#!/bin/bash\nexit 0\n")
    psad.chmod(0o755)
    env = _env(tmp_path, nft)
    env["PSAD_BIN"] = str(psad)
    out = subprocess.run(
        ["/bin/bash", str(ROOT / "apply" / "lift-block.sh"),
         "203.0.113.9"], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    rec = json.loads((tmp_path / "data" / "blocked-ips.jsonl").read_text())
    assert rec["kind"] == "release"


def test_netguard_ruleset_parses_on_the_host_nft():
    """The shell helper's heredoc is executable truth; feed it to nft's
    parser so a bad flag/limit expression fails here, not at boot."""
    nft = shutil.which("nft")
    if nft is None:
        pytest.skip("nft not installed")
    text = (ROOT / "apply" / "netguard.sh").read_text()
    start = text.index("<<'NFT'")
    start = text.index("\n", start) + 1
    end = text.index("\nNFT", start)
    script = text[start:end].strip() + "\n"
    proc = subprocess.run([nft, "-f", "-"], input=script,
                          capture_output=True, text=True, timeout=10)
    err = proc.stderr or ""
    assert "syntax error" not in err, f"{err}\n--- ruleset ---\n{script}"


def test_block_review_helper_accepts_ipv6(tmp_path):
    ledger = tmp_path / "blocked-ips.jsonl"
    env = dict(os.environ, GW_BLOCK_LEDGER=str(ledger))
    out = subprocess.run(
        ["/bin/bash", str(ROOT / "apply" / "block-review.sh"),
         "2001:db8::9", "keep"], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    rec = json.loads(ledger.read_text())
    assert rec["ip"] == "2001:db8::9" and rec["verdict"] == "keep"
