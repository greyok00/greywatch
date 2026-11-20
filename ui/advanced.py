"""The Advanced submenu (architecture v4): one row per tool.

The rail's Advanced row expands this list inline in a Gtk.Revealer;
there is no popover and no Settings toggle. Every row opens its desk as
a page in the main window, never a separate window -
state, the tool's own event feed, its digest, and the verbs it
answers. The surface list is the page map's own; merged walls stay
one desk (App Firewall carries the program gate and the host rules,
Virus Scan carries the engine and its updater, YARA Watch carries the
realtime watcher and the timed sweep).

NO DNS NEAR THE PUMP holds here too: the dnslog store is the Network
page's; this dropdown never beats the resolver.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


# rail name -> the tool ids the desk carries, and which digest leads
TOOLS = (
    ("App Firewall", ("appfw", "ufw"), "appfw"),
    ("Auto-responder", ("responderd",), "responderd"),
    ("Devices", ("arpwatch",), "arpwatch"),
    ("Port Scan Watch", ("psad",), "psad"),
    ("Bans", ("fail2ban",), "fail2ban"),
    ("Connections", ("net-watch",), "net-watch"),
    ("YARA Watch", ("yara-watch", "yara-tmp-scan"), "yara-watch"),
    ("Virus Scan", ("clamav", "freshclam"), "clamav"),
    ("Integrity", ("aide",), "aide"),
    ("Rootkit", ("rkhunter",), "rkhunter"),
    ("Hardening", ("lynis",), "lynis"),
    ("Kernel Watch", ("tetragon",), "tetragon"),
    ("Auditd", ("auditd",), "auditd"),
    ("Profiles", ("apparmor",), "apparmor"),
    ("Intel", ("cve-updater",), "cve-updater"),
)


GROUPS = (
    ("Network and access", ("App Firewall", "Bans", "Devices",
                            "Port Scan Watch", "Connections")),
    ("Scanning and integrity", ("YARA Watch", "Virus Scan", "Integrity",
                                "Rootkit", "Hardening")),
    ("System and audit", ("Kernel Watch", "Auditd", "Profiles",
                          "Auto-responder", "Intel")),
)


def desk_for(name):
    for label, ids, digest in TOOLS:
        if name == label or name in ids:
            return label, ids, digest
    raise KeyError(name)


def _open(window, label, tool_ids, digest) -> None:
    opener = getattr(window, "open_tool_page", None)
    if opener is not None:
        opener(label, tool_ids, digest)


def build_rows(window) -> list:
    """The submenu's rows: one button per tool surface, each opening its
    desk as a page in the main window. No dead rows: every row lands."""
    rows = []
    for label, tool_ids, digest in TOOLS:
        b = Gtk.Button(label=label)
        child = b.get_child()
        if isinstance(child, Gtk.Label):
            child.set_xalign(0.0)
            child.set_hexpand(True)
        b.set_halign(Gtk.Align.FILL)
        b.connect("clicked", lambda _b, l=label, ids=tool_ids,
                  d=digest: _open(window, l, ids, d))
        rows.append(b)
    return rows


