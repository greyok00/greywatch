"""Per-lane tool actions and the safe helper allowlist.

The desks act only on the lanes they own: scan lanes expose a check, the
shared lanes restart GreyWatch, PSAD and YARA Watch get full service
control, and the helper refuses the daily clam timer and never stops the
GreyWatch daemon.
"""
import os
import subprocess
from pathlib import Path

from ui import toolactions


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "apply" / "tool-control.sh"


def test_scan_lanes_get_a_check_not_a_unit_action():
    actions = toolactions.actions_for(("rkhunter",))
    assert [a["kind"] for a in actions] == ["check"]
    assert actions[0]["scan_key"] == "rkhunter"


def test_app_firewall_gets_restart_greywatch_only():
    actions = toolactions.actions_for(("appfw", "ufw"))
    labels = {(a["label"], a["kind"]) for a in actions}
    assert ("Restart GreyWatch", "restart") in labels
    assert ("Start", "start") in labels
    assert ("Stop", "stop") in labels


def test_psad_gets_full_service_control():
    kinds = {a["kind"] for a in toolactions.actions_for(("psad",))}
    assert kinds == {"start", "stop", "restart"}


def test_helper_refuses_the_daily_clam_timer(tmp_path):
    systemctl = tmp_path / "systemctl"
    systemctl.write_text("#!/bin/sh\nexit 0\n")
    systemctl.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    helper = Path("apply/tool-control.sh").resolve()
    bad = subprocess.run(["bash", str(helper), "start",
                          "greywatch-clam-scan.timer"],
                         capture_output=True, text=True, env=env)
    assert bad.returncode == 65
    good = subprocess.run(["bash", str(helper), "restart", "psad.service"],
                          capture_output=True, text=True, env=env)
    assert good.returncode == 0
    stop = subprocess.run(["bash", str(helper), "stop", "greywatch.service"],
                          capture_output=True, text=True, env=env)
    assert stop.returncode == 65


def test_helper_resolves_the_arpwatch_interface_before_systemctl(tmp_path):
    calls = tmp_path / "calls.log"
    calls.write_text("")
    systemctl = tmp_path / "systemctl"
    systemctl.write_text(f'#!/bin/sh\necho "systemctl $*" >> "{calls}"\n'
                         "exit 0\n")
    systemctl.chmod(0o755)
    env = {**os.environ, "GW_IFACE": "eth9",
           "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    good = subprocess.run(["bash", str(HELPER), "start",
                           "arpwatch@{iface}.service"],
                          capture_output=True, text=True, env=env)
    assert good.returncode == 0, good.stderr
    log = calls.read_text()
    assert "systemctl start arpwatch@eth9.service" in log
    assert "{iface}" not in log
    # an arbitrary interface is not accepted
    bad = subprocess.run(["bash", str(HELPER), "start",
                          "arpwatch@eth0.service"],
                         capture_output=True, text=True, env=env)
    assert bad.returncode == 65


def test_start_all_never_arms_the_daily_scan_or_the_masked_engine(tmp_path):
    calls = tmp_path / "calls.log"
    calls.write_text("")
    systemctl = tmp_path / "systemctl"
    systemctl.write_text(f'#!/bin/sh\necho "systemctl $*" >> "{calls}"\n'
                         "exit 0\n")
    systemctl.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    good = subprocess.run(["bash", str(HELPER), "start-all"],
                          capture_output=True, text=True, env=env)
    assert good.returncode == 0, good.stderr
    log = calls.read_text()
    assert "start greywatch-clam-scan.timer" not in log
    assert "clamav-daemon.service" not in log
