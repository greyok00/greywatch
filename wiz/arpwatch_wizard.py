from rules import arpwatch_env_file
from wiz import common
import subprocess


def build(iface, runas="arpwatch", args_list=None, pcap_filter=""):
    lines = arpwatch_env_file(iface, runas, args_list or [], pcap_filter)
    return {"iface": iface, "lines": lines, "unit": f"arpwatch@{iface}.service"}


def apply_rule(b, runas, args_list, pcap_filter):
    return common.run_helper("arpwrite", [b["iface"], runas,
                                          " ".join(args_list or []), pcap_filter])


def verify(b):
    try:
        out = subprocess.run(["systemctl", "is-enabled", b["unit"]],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() == "enabled"
    except OSError:
        return False


def rollback(b):
    return common.restore_backup(f"/etc/arpwatch/{b['iface']}.iface.bak",
                                 f"/etc/arpwatch/{b['iface']}.iface")
