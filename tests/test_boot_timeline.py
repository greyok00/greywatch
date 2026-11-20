"""boot timeline: single scheduling authority (plan Task 7, LAW-6).

Zero heavy work before t+10min; every scanner unit carries caps; the
watchdog timer is installed; no duplicate freshclam boot trigger is
created. Parsed from the SHIPPED unit templates (string contract) so
the test fails before a regressions ships, not on the live machine.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
DOC = REPO / "doc"
INSTALL = (REPO / "install.sh").read_text()

HEAVY = {
    "greywatch-boot-sweep.service": 25,
    "greywatch-feeds.service": 10,       # feeds refresh: the heaviest EARLY lane
}


def _sec(value: str) -> int:
    m = re.fullmatch(r"(\d+)min", value.strip())
    if m:
        return int(m.group(1)) * 60
    m = re.fullmatch(r"(\d+)", value.strip())
    if m:
        return int(m.group(1))
    raise ValueError(f"unparsable delay {value!r}")


def test_feeds_timer_starts_at_or_after_ten_minutes():
    text = (DOC / "greywatch-feeds.timer").read_text()
    on_boot = re.search(r"OnBootSec=(\S+)", text).group(1)
    assert _sec(on_boot) >= 10 * 60


def test_boot_sweep_sleep_hack_is_gone():
    text = (DOC / "greywatch-boot-sweep.service").read_text()
    assert "ExecStartPre" not in text or "sleep" not in text.split(
        "ExecStartPre")[1].split("\n")[0]


def test_every_shipped_scanner_unit_carries_caps():
    caps = re.compile(r"CPUQuota=\d+%")
    mem = re.compile(r"MemoryMax=\S+")
    for name in ("greywatch-boot-sweep.service", "greywatch-feeds.service",
                 "greywatch-cve.service"):
        text = (DOC / name).read_text()
        assert caps.search(text), f"{name}: no CPUQuota"
        assert mem.search(text), f"{name}: no MemoryMax"


def test_clamav_dropin_templates_record_their_retirement():
    # Superseded (owner 2026-11-17): the resident engine is retired and
    # MASKED by both installers; the cap templates stay as a record of
    # the retired design, and no installer line ever enables the daemon.
    clamd = (DOC / "clamav-daemon-limits.conf").read_text()
    fresh = (DOC / "freshclam-limits.conf").read_text()
    for text in (clamd, fresh):
        assert "RETIRED 2026-11-14" in text
    assert "RETIRED 2026-11-14" in INSTALL or         "caps retired" in INSTALL
    assert "enable --now clamav-daemon.service" not in INSTALL
    assert "enable clamav-daemon.service" not in INSTALL
    assert "mask clamav-daemon.service" in INSTALL


def test_boot_sweep_has_its_own_timer_no_sleep_hack():
    text = (DOC / "greywatch-boot-sweep.timer").read_text()
    assert _sec(re.search(r"OnBootSec=(\S+)", text).group(1)) >= 45 * 60


def test_watchdog_timer_installed_by_install_sh():
    assert "greywatch-watchdog.timer" in INSTALL
    assert "systemctl enable" in INSTALL or "create_unit" in INSTALL or \
        "install_unit" in INSTALL


def test_install_sh_never_creates_a_second_freshclam_boot_trigger():
    lines = INSTALL.splitlines()
    for i, line in enumerate(lines):
        low = line.lower()
        if "freshclam" in low and ("systemctl" in low or "install -d" in low
                                   or "enable" in low):
            window = low + (lines[i + 1].lower() if i + 1 < len(lines) else "")
            if "install -d" in window and "limits.conf" in window:
                continue        # the cap drop-in IS a freshclam touch (allowed)
            assert any(word in low for word in
                       ("disable", "remove", "rm ", "purge", "mask")), line


def test_boot_sweep_never_calls_a_scanner():
    """The sweep script is system-installed; the repo pins its unit
    template to a scanner-free ExecStart (clamav runs capped windows
    from its own timer, not from the boot sweep)."""
    text = (DOC / "greywatch-boot-sweep.service").read_text()
    exec_line = next((ln for ln in text.splitlines()
                      if ln.startswith("ExecStart")), "")
    assert "clam" not in exec_line.lower()
