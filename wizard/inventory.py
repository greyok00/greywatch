from __future__ import annotations

import pathlib

from hardening.detector import PASS
import wizard.detector as detector           # noqa: F401  (re-exported)

ROOT = pathlib.Path(__file__).resolve().parents[1]
from gwpaths import data_dir as _gw_data
DATA_DIR = _gw_data()
NET_DIR = pathlib.Path("/sys/class/net")

PACKAGES = (
    "openssh-server", "sshd", "avahi-daemon", "clamav", "freshclam",
    "docker.io", "podman", "ufw", "chrony", "ntpd", "systemd-timesyncd",
    "firefox-esr", "chromium", "brave-browser", "python3", "node", "ollama",
)

FRIENDLY = {
    "openssh-server": "the SSH server",
    "sshd": "the SSH server",
    "avahi-daemon": "the network discovery service (avahi)",
    "clamav": "the malware scanner (ClamAV)",
    "freshclam": "the malware definitions updater (freshclam)",
    "docker.io": "Docker",
    "podman": "Podman",
    "ufw": "the UFW firewall frontend",
    "chrony": "the time sync service (chrony)",
    "ntpd": "the time sync service (ntpd)",
    "systemd-timesyncd": "systemd time sync",
    "firefox-esr": "Firefox",
    "chromium": "Chromium",
    "brave-browser": "Brave",
    "python3": "Python 3",
    "node": "Node.js",
    "ollama": "Ollama",
}

NIST_BY_PKG = {
    "openssh-server": "AC-17",
    "sshd": "AC-17",
    "avahi-daemon": "CM-7",
    "clamav": "SI-3",
    "freshclam": "SI-3",
    "ufw": "SC-7",
}

CANT_WORDS = "could not be checked"
CANT_MARKER = "⚪"


def fresh_install(data_dir) -> object:
    path = pathlib.Path(data_dir) / "appfw" / "config.json"
    try:
        return not path.exists()
    except OSError:                       # unreadable parent: cannot tell
        return None


def wireless_present(net_dir=NET_DIR) -> object:
    net_dir = pathlib.Path(net_dir)
    try:
        ifaces = [p.name for p in net_dir.iterdir()]
    except OSError:
        return None
    if not ifaces:
        return None                       # nothing listed: cannot tell
    return any((net_dir / name / "wireless").exists() for name in ifaces)


def ufw_status(result) -> object:
    if getattr(result, "state", None) != PASS:
        return None
    value = getattr(result, "value", None)
    if not isinstance(value, list):
        return None
    for fact in value:
        tok = str(fact)
        if tok.startswith("ufw:"):
            word = tok.split(":", 1)[1].strip()
            return word or None
    return None                           # ufw did not answer this pass


def run_scan(runner=None, data_dir=None, net_dir=None) -> dict:
    runner = runner or detector.prod_runner
    data_dir = pathlib.Path(data_dir or DATA_DIR)
    net_dir = pathlib.Path(net_dir) if net_dir is not None else NET_DIR

    def answer(result):
        return result.value if result.state == PASS else None

    packages = {}
    for name in PACKAGES:
        probe = detector.pkg_has(name, runner)
        packages[name] = probe.value if probe.state == PASS else None

    ports = detector.listeners(runner)
    services = detector.services_running(runner)
    firewall = detector.firewall_state(runner)
    ipv6 = detector.sysctl_get("net.ipv6.conf.all.disable_ipv6", runner)
    encryption = detector.disk_encrypted(runner)
    desktop = detector.desktop_env()
    laptop = detector.form_factor(runner)

    scan = {
        "packages": packages,
        "fresh_install": fresh_install(data_dir),
        "wireless": wireless_present(net_dir),
        "ufw_status": ufw_status(firewall),
        "ipv6_disable": answer(ipv6),
        "facts": {
            "listening_ports": ports,
            "services_running": services,
            "firewall": firewall,
            "ipv6_disable": ipv6,
            "disk_encrypted": encryption,
            "desktop": desktop,
            "laptop": laptop,
        },
    }
    return scan


def inventory_lines(scan: dict) -> list[str]:
    out: list[str] = []
    packages = scan.get("packages")
    packages = packages if isinstance(packages, dict) else {}
    for name in PACKAGES:
        state = packages.get(name)
        label = FRIENDLY.get(name, name)
        nist = NIST_BY_PKG.get(name)
        if state is True:
            out.append(f"{_cap(label)} is installed"
                       + (f" — NIST {nist}" if nist else ""))
        elif state is None:
            out.append(f"{_cap(label)}: {CANT_WORDS}")
    ports = _value(scan, facts_key="listening_ports")
    if ports is not None:
        shown = ", ".join(str(int(p)) for p in sorted(ports)) or "none found"
        out.append(f"Listening ports: {shown}")
    else:
        out.append(f"Listening ports: {CANT_WORDS}")
    if 22 in (_value(scan, facts_key="listening_ports") or []) \
            and (packages.get("openssh-server") is True
                 or packages.get("sshd") is True):
        out.append("The SSH server is listening on port 22 — NIST AC-17")
    services = _value(scan, facts_key="services_running")
    if services is not None:
        shown = ", ".join(services[:6]) if services else "none"
        more = f" (and {len(services) - 6} more)" if len(services) > 6 else ""
        out.append(f"Services running: {shown}{more}")
    else:
        out.append(f"Services running: {CANT_WORDS}")
    ufw = scan.get("ufw_status")
    if isinstance(ufw, str):
        out.append(f"UFW firewall is {ufw}")
    else:
        out.append(f"UFW firewall state: {CANT_WORDS}")
    ipv6 = scan.get("ipv6_disable")
    out.append(
        ("IPv6 kernel disable_ipv6: " + str(ipv6))
        if ipv6 is not None else f"IPv6 kernel state: {CANT_WORDS}")
    encryption = _value(scan, facts_key="disk_encrypted")
    if encryption is None:
        out.append(f"Disk encryption: {CANT_WORDS}")
    else:
        out.append("The main disks are " + ("encrypted" if encryption
                                            else "NOT encrypted"))
    desktop = _value(scan, facts_key="desktop")
    if desktop is None:
        out.append(f"Desktop environment: {CANT_WORDS}")
    else:
        out.append(f"Desktop environment: {desktop}")
    laptop = _value(scan, facts_key="laptop")
    if laptop is None:
        out.append(f"Form factor: {CANT_WORDS}")
    else:
        out.append("This computer looks like a "
                   + ("laptop" if laptop else "desktop machine"))
    return out


def _value(scan: dict, facts_key: str):
    facts = scan.get("facts") or {}
    probe = facts.get(facts_key)
    if probe is None:
        return None
    return probe.value if getattr(probe, "state", None) == PASS else None


def _cap(text: str) -> str:
    return text[0].upper() + text[1:]
