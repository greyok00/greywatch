"""GW-199/200 (owner 2026-11-06): psad joins as a managed tool, the box
gains attack PREVENTION with a no-false-positives gate. GreyWatch's own
nftables only hooked output traffic, so inbound sweeps were invisible to
everything: psad-tune feeds it, hardening-arp closes the spoofing door,
and the parser turns psad's alerts into threat-lane events while keeping
daemon chatter silent."""
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from parsers import parse_psad
from events import lane_for

# ---- the parser: sweeps and signatures speak, chatter stays silent --------
def _j(text):
    """A journalctl-shaped transport line around a psad payload."""
    return f"Nov  5 02:20:34 greyhost psad[1234]: {text}"


def test_sweeps_and_signature_hits_are_threat_events():
    sweep = parse_psad(_j("src: 203.0.113.9, dst: 198.51.100.10, "
                          "tcp ports [22, 139, 443], danger level: 2"))
    assert sweep and sweep.severity == "HIGH"
    assert lane_for(sweep.to_dict()) == "threat"
    burst = parse_psad(_j("src: 203.0.113.9, messages: 3100, "
                          "danger level: 5"))
    assert burst.severity == "CRITICAL"
    sig = parse_psad(_j('signature match: "SCAN SYN Fin" (Sid: 615)'))
    assert sig.severity == "HIGH" and lane_for(sig.to_dict()) == "threat"


def test_single_probes_do_not_pop_and_noise_is_silence():
    probe = parse_psad(_j("src: 203.0.113.9, danger level: 1"))
    assert probe and probe.severity == "MEDIUM", (
        "danger level 1 never reaches the popups")
    for noise in ("kmsgsd started", "psadwatchd: restart psad",
                  "status: psad (pid 900) is running",
                  "restart of psad completed", "unknown shape entirely"):
        assert parse_psad(_j(noise)) is None


def test_psad_health_warnings_read_as_tool_lane():
    warn = parse_psad(_j("warning: found no firewall logging rules"))
    assert warn and warn.severity == "MEDIUM"
    assert lane_for(warn.to_dict()) == "tool"


def test_registry_carries_psad_as_a_managed_tool():
    reg = json.loads((ROOT / "registry.json").read_text())
    tools = reg if isinstance(reg, list) else reg.get("tools", [])
    psad = [t for t in tools if t.get("name") == "psad"]
    assert psad, "psad is registered"
    assert psad[0]["unit"] == "psad.service" and psad[0]["scope"] == "root"
    assert psad[0]["journal"]["filter"] == "-t psad"


# ---- the helpers: prevention, gated and idempotent -----------------------
SCRIPTS = {
    "psad-tune": ROOT / "apply" / "psad-tune.sh",
    "hardening-arp": ROOT / "apply" / "hardening-arp.sh",
}


def _stub_bin(tmp_path, name, body):
    p = tmp_path / "bin" / name
    p.parent.mkdir(exist_ok=True)
    p.write_text(body)
    p.chmod(0o755)
    return p


def test_psad_tune_arms_from_the_tree_with_stubbed_bins(tmp_path):
    """Run the helper end to end against fake nft/psad/ip binaries: the
    contract (chain, whitelist-first, danger level 5) is pinned in code
    the box will actually run."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    _stub_bin(tmp_path, "nft", '#!/bin/bash\ncase "$*" in *greywatch_psad*) exit 1;; esac\nexit 0\n')
    _stub_bin(tmp_path, "ip",
        '#!/bin/bash\n'
        'case "$*" in *"route show default"*) echo "default via 192.168.1.1 dev eth0";; '
        '*"addr show"*) echo "2 eth0    inet 192.168.254.9/24 brd 192.168.254.255 scope global eth0";; '
        'esac\nexit 0\n')
    _stub_bin(tmp_path, "systemctl", '#!/bin/bash\necho active\nexit 0\n')
    _stub_bin(tmp_path, "ufw", '#!/bin/bash\ncase "$*" in *"status verbose"*) echo "Logging: on (low)";; *) echo "Status: inactive";; esac\nexit 0\n')
    conf = tmp_path / "psad.conf"
    conf.write_text("ENABLE_AUTO_IDS             N;\nAUTO_IDS_DANGER_LEVEL    3;\n")
    wl = tmp_path / "psadwhitelist"
    (tmp_path / "kern.log").touch()
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH','')}",
               PSAD_CONF=str(conf), PSAD_WHITELIST=str(wl),
               KERN_LOG=str(tmp_path / "kern.log"))
    out = subprocess.run(["/bin/bash", str(SCRIPTS["psad-tune"])],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    text = out.stdout
    assert "whitelisted own LAN range 192.168.254.0/24" in text, text
    assert "block only at danger level 5" in text
    assert conf.read_text().count("ENABLE_AUTO_IDS             Y;") == 1
    assert "192.168.1.1" in wl.read_text()


def test_psad_tune_is_idempotent(tmp_path):
    bin_dir = tmp_path / "bin"
    conf = tmp_path / "psad.conf"
    conf.write_text("ENABLE_AUTO_IDS             Y;\nAUTO_IDS_DANGER_LEVEL    5;\n")
    wl = tmp_path / "psadwhitelist"; wl.write_text("192.168.254.0/24\n192.168.1.1\n")
    (tmp_path / "kern.log").touch()
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH','')}",
               PSAD_CONF=str(conf), PSAD_WHITELIST=str(wl),
               KERN_LOG=str(tmp_path / "kern.log"))
    for b in ("nft", "systemctl", "ip", "ufw", "sysctl"):
        s = bin_dir / b
        s.parent.mkdir(exist_ok=True)
        s.write_text("#!/bin/bash\nexit 0\n")
        s.chmod(0o755)
    _stub_bin(tmp_path, "nft", '#!/bin/bash\ncase "$*" in *greywatch_psad*) exit 0;; esac\nexit 0\n')
    _stub_bin(tmp_path, "systemctl", '#!/bin/bash\necho active\nexit 0\n')
    _stub_bin(tmp_path, "ip",
        '#!/bin/bash\n'
        'case "$*" in *"route show default"*) echo "default via 192.168.1.1 dev eth0";; '
        '*"addr show"*) echo "2 eth0    inet 192.168.254.9/24 brd 192.168.254.255 scope global eth0";; '
        'esac\nexit 0\n')
    out = subprocess.run(["/bin/bash", str(SCRIPTS["psad-tune"])],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0
    assert "already carries" in out.stdout
    assert "already armed" in out.stdout


def test_hardening_arp_pins_the_real_router(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH','')}")
    calls = tmp_path / "nft-calls.log"
    _stub_bin(tmp_path, "ip",
        '#!/bin/bash\n'
        'case "$*" in *"route show default"*) echo "default via 192.168.1.1 dev eth0";; '
        '*"neigh show 192.168.1.1"*) echo "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE";; '
        '*"neigh get 192.168.1.1"*) echo "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff PERMANENT";; '
        '*"neigh replace"*|*) exit 0;; esac\nexit 0\n')
    _stub_bin(tmp_path, "sysctl",
        '#!/bin/bash\ncase "$*" in *arp_ignore*) echo 1;; *arp_accept*) echo 0;; esac\nexit 0\n')
    out = subprocess.run(["/bin/bash", str(SCRIPTS["hardening-arp"])],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    assert ("verified" in out.stdout or "already pinned" in out.stdout), out.stdout


def test_hardening_arp_writes_the_pin_when_missing(tmp_path):
    import os
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    _stub_bin(tmp_path, "ip",
        '#!/bin/bash\n'
        'case "$*" in *"route show default"*) echo "default via 192.168.1.1 dev eth0";; '
        '*"neigh show 192.168.1.1"*) echo "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE";; '
        'esac\nexit 0\n')
    _stub_bin(tmp_path, "sysctl",
        '#!/bin/bash\ncase "$*" in *arp_ignore*) echo 0;; *arp_accept*) echo 1;; esac\nexit 0\n')
    procfile = tmp_path / "proc"
    (procfile / "all").mkdir(parents=True)
    # the helper writes to real /proc; without root we only assert the pin
    # attempt is made and the sysctl change is attempted (rc 0 either way)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH','')}")
    out = subprocess.run(["/bin/bash", str(SCRIPTS["hardening-arp"])],
                         capture_output=True, text=True, env=env)
    assert "gateway 192.168.1.1 at aa:bb:cc:dd:ee:ff" in out.stdout, out.stdout


# ---- the Harden page: honest cards, not silent gaps ----------------------
def test_hardening_controls_offer_psad_and_arp_cards():
    sys.path.insert(0, str(ROOT))
    import hardening.controls as hc
    found = {c.id for c in hc.load_controls(ROOT / "data")}
    assert "psad-armed" in found and "arp-spoof-resistant" in found
    src = (ROOT / "apply" / "polkit" / "greywatch.apply.policy").read_text()
    assert "com.greywatch.apply.psad-tune" in src
    assert "com.greywatch.apply.hardening-arp" in src
