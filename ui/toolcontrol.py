"""The Tools page, rebuilt as the owner's t2 (round 2, task 9).

One full-width, self-contained card per registered tool. A card answers
everything about its tool on the card: what it is and whether it is
running (the dot and the one-line status the snapshots carry), which
lifecycle buttons have a real lane (the same tool-control / scan-lane /
polkit helpers the rest of the suite uses - a lane that does not exist
ships disabled with the honest reason, never a dead click), where its
schedule really lives (the systemd unit; this build has no editable
schedule value, so the row says so), the quick lanes that do exist, and
"Open config": the tool's RAW config file expanding inside the card, with
line-level validation, and an Apply through the config-write lane - then
the baseline permafix offer (rkhunter --propupd / aide --update) with
Yes / Later.

Cards live in ONE inner-scrolled list so the page chrome never
whole-scrolls, and an expanded editor scrolls inside its card.
Nothing here invents a power: every button names the helper script it
runs, every result is stated on the card, and every honest gap says so.
"""
from __future__ import annotations

import os
import pathlib
import re
import threading

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ui import metrics  # noqa: E402
from ui.models import status_words  # noqa: E402
from ui.plain import state_colour, friendly_name  # noqa: E402
from ui.cards import SCAN_MODES  # noqa: E402
from ui.toolicons import icon_name as tool_icon  # noqa: E402
from ui.eventclock import present_now  # noqa: E402

SCAN_KEYS = frozenset(m["key"] for m in SCAN_MODES)

# The units apply/tool-control.sh itself allows - the same case list the
# script carries. A unit outside this list has NO start/stop lane from a
# card, and the card says so instead of grey-buttoning a lie.
TOOL_CONTROL_UNITS = frozenset({
    "responderd.service", "tetragon.service", "clamav-daemon.service",
    "fail2ban.service", "ufw.service", "auditd.service",
    "arpwatch@{IFACE}.service", "aide-check.timer", "apparmor.service",
    "greywatch-cve.timer", "clamav-freshclam.service",
})

# The baseline permafix loop (owner law: the primaries): which card
# offers a baseline refresh after a config apply, and the words it asks in.
TOOL_PERMAFIX = {"rkhunter": "rkhunter", "aide": "aide"}
_PERMAFIX_WORDS = {
    "rkhunter": ("Refresh the baseline now? (rkhunter --propupd) - it "
                 "blesses the state you just reviewed, so a reviewed "
                 "warning stops re-firing. The previous baseline is "
                 "kept as an .old copy."),
    "aide": ("Refresh the baseline now? (aide --update) - it rebuilds "
             "the integrity database against the config you just "
             "applied. The previous baseline is kept as an .old copy."),
}

CONFIG_WRITE = "config-write"

# The tool -> raw config files the card can open, in the order they
# expand. `writable=False` means NO write lane exists for that path in
# this build - the editor then opens read-only and says so. Known-key
# sets are the keys a NEW line may add; a line that renames a key the
# file already has is always known.
TOOL_CONFIGS: dict[str, list[dict]] = {
    "rkhunter": [
        {"key": "rkhunter-default", "path": "/etc/default/rkhunter",
         "mode": "shell", "writable": True,
         "known": {"CRON_DAILY_RUN", "CRON_DB_UPDATE", "DB_UPDATE_EMAIL",
                   "REPORT_EMAIL", "APT_AUTOGEN", "NICE",
                   "RUN_CHECK_ON_BATTERY"}},
        {"key": "rkhunter-conf", "path": "/etc/rkhunter.conf",
         "mode": "kv", "writable": True,
         "known": {"ENABLE_TESTS", "DISABLE_TESTS", "MAIL_ON_WARNING",
                   "MAIL_CMD", "SCRIPTWHITELIST", "ALLOWHIDDENDIR",
                   "ALLOWHIDDENFILE", "ALLOWPROCDELFILE",
                   "ENABLE_CORUPHS"}},
    ],
    "psad": [
        {"key": "psad", "path": "/etc/psad/psad.conf", "mode": "psad",
         "writable": True,
         "known": {"ENABLE_AUTO_IDS", "ENABLE_AUTO_IDS_EMAILS",
                   "ENABLE_AUTO_IDS_REGEX", "ALERTING_METHODS",
                   "EMAIL_ADDRESSES", "EMAIL_ALERT_DANGER_LEVEL",
                   "AUTO_IDS_DANGER_LEVEL", "DANGER_LEVEL1",
                   "DANGER_LEVEL2", "DANGER_LEVEL3", "DANGER_LEVEL4",
                   "DANGER_LEVEL5"}},
    ],
    "aide": [
        {"key": "aide", "path": "/etc/aide/aide.conf", "mode": "aide",
         "writable": True,
         "known": {"database_in", "database_out", "database_new",
                   "report_url", "gzip_dbout", "Perms"}},
    ],
    "clamav": [
        {"key": "freshclam", "path": "/etc/clamav/freshclam.conf",
         "mode": "keyval", "writable": True,
         "known": {"Checks", "DatabaseMirror", "NotifyClamd",
                   "DatabaseOwner", "UpdateLogFile", "LogRotate",
                   "LogTime", "MaxAttempts", "ConnectTimeout",
                   "ReceiveTimeout", "TestDatabases", "ScriptedUpdates",
                   "Bytecode", "DNSDatabaseInfo", "DatabaseDirectory",
                   "LogVerbose", "LogSyslog", "LogFacility",
                   "LogFileMaxSize", "Foreground", "Debug",
                   "CompressLocalDatabase"}},
        {"key": "clamd", "path": "/etc/clamav/clamd.conf",
         "mode": "keyval", "writable": True,
         "known": {"LogFile", "LogTime", "LogSyslog", "PidFile",
                   "DatabaseDirectory", "LocalSocket", "TCPSocket",
                   "TCPAddr", "MaxThreads", "User", "DetectPUA",
                   "AlertEncrypted", "MaxScanSize"}},
    ],
    "freshclam": [
        {"key": "freshclam", "path": "/etc/clamav/freshclam.conf",
         "mode": "keyval", "writable": True,
         "known": {"Checks", "DatabaseMirror", "NotifyClamd"}},
    ],
    "arpwatch": [
        {"key": "arpwatch-default", "path": "/etc/default/arpwatch",
         "mode": "shell", "writable": True,
         "known": {"ARGS"}},
    ],
    "lynis": [
        {"key": "lynis", "path": "/etc/lynis/lynis.cfg", "mode": "kv",
         "writable": True, "known": {"plugin_dir", "log_file"}},
    ],
    "fail2ban": [
        # no write lane -> the editor opens READ-ONLY and says so on
        # its banner; it never fakes a save.
        {"key": "jail.conf", "path": "/etc/fail2ban/jail.conf",
         "mode": "ini", "writable": False},
    ],
    "ufw": [
        {"key": "ufw-default", "path": "/etc/default/ufw",
         "mode": "shell", "writable": False},
    ],
}

# The quick lanes a card offers besides the config editor: ONLY lanes
# that already exist in apply/. A tool with none shows the honest line.
QUICK_LANES: dict[str, list[dict]] = {
    "psad": [{"label": "Arm auto-block", "helper": "psad-tune", "args": [],
              "why": "psad-tune makes inbound traffic visible and arms "
                     "psad's conservative auto-block; it asks for your "
                     "password."}],
    "freshclam": [{"label": "Update now", "helper": "tool-control",
                   "args": ["start", "clamav-freshclam.service"],
                   "why": "starts the one-shot updater unit that keeps "
                          "the virus list current."}],
    "arpwatch": [{"label": "Pin the real router",
                  "helper": "hardening-arp", "args": [],
                  "why": "pins the real router in the ARP table and "
                         "closes the ARP-spoof sysctls; it asks for "
                         "your password."}],
    "rkhunter": [{"label": "Refresh baseline",
                  "helper": "baseline-update", "args": ["rkhunter"],
                  "why": "blesses the reviewed state (rkhunter "
                         "--propupd); the previous baseline is kept."}],
    "aide": [{"label": "Refresh baseline",
              "helper": "baseline-update", "args": ["aide"],
              "why": "rebuilds the integrity database against the "
                     "daily config; the previous baseline is kept."}],
    "appfw": [{"label": "App firewall switches", "kind": "navigate",
               "page": "services",
               "why": "the app firewall's mode and learning switches "
                      "live on the Protections page."}],
}


# ------------------------------------------------------------ validators
_MODE_RE = {
    "shell": re.compile(r"^(?P<k>[A-Za-z_]\w*)\s*=\s*(?P<v>.*)$"),
    "kv": re.compile(r"^(?P<k>[A-Za-z_]\w*)\s*=\s*(?P<v>.*)$"),
    "keyval": re.compile(r"^(?P<k>[A-Za-z_][\w.-]*)\s+(?P<v>\S.*)$"),
    "psad": re.compile(r"^(?P<k>[A-Z_][A-Z_0-9]*)\s+(?P<v>.+;\s*)$"),
    "ini": re.compile(r"^(?P<k>[A-Za-z_]\w*)\s*=\s*(?P<v>.*)$"),
}


def _keys_of(mode: str, text: str) -> set:
    """The keys `text` itself carries - a line that edits a key the file
    already has is always a known key, whatever the curated set says."""
    rx = _MODE_RE.get(mode) or _MODE_RE["kv"]
    out = set()
    for raw in str(text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith("["):
            continue
        m = rx.match(s)
        if m:
            out.add(m.group("k"))
    return out


def validate_config(conf: dict, text: str, original: str = "") -> list:
    """Line-level validation before anything is staged: comments and
    blanks pass, every other line must be a key line the file's syntax
    understands, and a NEW key must be in the file's own keys or its
    known-key set. Each error names its line and states that nothing
    was written."""
    mode = str(conf.get("mode") or "kv")
    known = set(conf.get("known") or ()) | _keys_of(mode, original)
    errs = []
    rx = _MODE_RE.get(mode)
    if rx is None:
        return [f"{conf.get('key')}: unknown syntax '{mode}'"]
    aide = mode == "aide"
    ini = mode == "ini"
    for i, raw in enumerate(str(text or "").splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if ini and s.startswith("["):
            continue                      # a section header, not a key
        if aide and (s.startswith("@@") or s.startswith("!")):
            continue                      # an include or a negation
        if aide and s[0] == "/":
            continue                      # an AIDE rule line: path + attrs
        m = rx.match(s)
        if m is None:
            errs.append(
                f"line {i}: not a config line this file understands - "
                "nothing was written")
            continue
        key = m.group("k")
        if key not in known:
            errs.append(
                f"line {i}: '{key}' is not a key this file knows - fix "
                "or remove the line; nothing was written")
    return errs


# -------------------------------------------------------------- schedule
_UNIT_DIRS = {
    "user": (".config/systemd/user", "usr/lib/systemd/user"),
    "root": ("etc/systemd/system", "lib/systemd/system",
             "usr/lib/systemd/system"),
}


def unit_file_paths(unit: str, scope: str = "root", roots=None):
    """Where a unit file actually lives. `roots` (absolute dirs) is the
    test seam; otherwise the standard systemd search paths."""
    if roots:
        cands = [pathlib.Path(str(r)) for r in roots]
    else:
        home = pathlib.Path.home()
        cands = [home / d for d in _UNIT_DIRS.get(
            "user" if scope == "user" else "root", _UNIT_DIRS["root"])]
    for d in cands:
        p = d / unit
        if p.is_file():
            return p
    return None


def _span_words(value: str) -> str:
    m = re.match(r"^(\d+)\s*(min|s|h|d|us|usec|msec)?", str(value or "")
                 .strip())
    if not m:
        return str(value or "")
    n, raw = m.group(1), m.group(2) or "min"
    unit = {"min": "min", "s": "sec", "h": "h", "d": "day",
            "us": "usec", "usec": "usec", "msec": "msec",
            "": "min"}.get(raw, raw)
    return f"{n} {unit}{'s' if n != '1' else ''}"


def _timer_words(path: pathlib.Path) -> str:
    """The [Timer] lines in their own names, worded for a person - the
    row shows the values the unit carries, never a made-up number."""
    if path is None:
        return "timed by systemd - the unit file is not readable here"
    cal, active, boot, section = [], "", "", ""
    try:
        for raw in path.read_text().splitlines():
            s = raw.split("#", 1)[0].strip()
            if s.startswith("["):
                section = s.strip("[]").lower()
                continue
            if section != "timer" or "=" not in s:
                continue
            k, v = (part.strip() for part in s.split("=", 1))
            if k == "OnCalendar":
                cal.append(v)
            elif k == "OnUnitActiveSec":
                active = v
            elif k == "OnBootSec":
                boot = v
    except OSError:
        return "timed by systemd - the unit file is not readable here"
    bits = []
    if active:
        bits.append(f"every {_span_words(active)}")
    if cal:
        bits.append("at " + ", ".join(f"{c} (calendar)" for c in cal))
    if boot and not active and not cal:
        bits.append(f"{_span_words(boot)} after each boot")
    return " · ".join(bits) if bits else "timed by systemd"


def schedule_words(tool: dict, roots=None) -> str:
    """The schedule row's honest words: where the schedule lives, what
    the unit carries, and - because no editable schedule value exists in
    this build - who owns it."""
    unit = tool.get("unit")
    if not unit:
        return "no schedule on file - it runs when you ask"
    if unit.endswith(".timer"):
        path = unit_file_paths(unit, tool.get("scope") or "root", roots)
        return _timer_words(path if path else None)
    return "a continuous service - it runs, there is no run-time"


def schedule_entry(tool: dict, roots=None) -> str:
    word = schedule_words(tool, roots)
    unit = tool.get("unit")
    if unit and unit.endswith(".timer"):
        return f"{word} - read-only - set in the systemd unit"
    if not unit:
        return word
    return f"{word} - no schedule to edit"


def default_iface() -> str:
    """The interface tool-control.sh itself reads (the first default route
    in /proc/net/route), resolved so the arpwatch unit in the script's
    allowlist can be named exactly."""
    try:
        with open("/proc/net/route") as fh:
            next(fh)
            for line in fh:
                fields = line.split()
                if len(fields) > 3 and fields[1] == "00000000":
                    return fields[0]
    except (OSError, IndexError, ValueError):
        return ""
    return ""


# -------------------------------------------------------- lifecycle plan
def lifecycle_plan(tool: dict, win=None) -> list:
    """Which lifecycle buttons a card mounts, each wired to the lane
    that exists (a helper through polkit, the app's own toggle lane, the
    validated scan-request write) - or shipping disabled with the honest
    reason. Nothing here invents a lever."""
    name = tool["name"]
    unit = tool.get("unit")
    scope = tool.get("scope") or "root"
    opts: list = []

    def disabled(op, label, why):
        opts.append({"op": op, "label": label, "sensitive": False,
                     "disabled": why})

    # run-now ------------------------------------------------------------
    scan_key = "yara-tmp-scan" if name == "yara-watch" else name
    if name == "yara-watch":
        disabled("run", "Run now",
                 "this watcher runs continuously - there is no manual "
                 "run; its timer twin is yara-tmp-scan")
    elif scan_key in SCAN_KEYS:
        opts.append({"op": "run", "label": "Run now", "scan": scan_key,
                     "why": "one validated scan request, the same write "
                            "the Scans page makes"})
    elif name == "freshclam":
        opts.append({"op": "run", "label": "Update now",
                     "helper": "tool-control",
                     "args": ["start", "clamav-freshclam.service"],
                     "why": "starts the one-shot updater unit"})
    elif unit:
        disabled("run", "Run now",
                 "a continuous service - start it and it runs; there is "
                 "no separate run lane")
    else:
        disabled("run", "Run now",
                 "no lane: this tool runs through its own logs only")

    # start / stop / restart --------------------------------------------
    def lane(op, label):
        if name == "appfw":
            # the app firewall's own enable lane (the engine flag the
            # window writes) - the real lever it always had
            opts.append({"op": op, "label": label, "kind": "toggle",
                         "pause": op == "stop",
                         "why": "the app firewall's own enable lane"})
            return
        if not unit:
            disabled(op, label,
                     "no unit - this tool runs on demand through its "
                     "scan lane, there is nothing to start or stop")
            return
        if unit == "greywatch.service":
            disabled(op, label,
                     "the app's own service carries the reads - no lane "
                     "stops or starts it from a card")
            return
        resolved = unit
        if "{IFACE}" in unit:
            iface = default_iface()
            resolved = unit.replace("{IFACE}", str(iface or "none"))
        if scope == "user":
            opts.append({"op": op, "label": label, "kind": "toggle",
                         "pause": op == "stop",
                         "why": "the app's own user-scope lane"
                                " (systemctl --user)"})
            return
        if resolved in TOOL_CONTROL_UNITS:
            opts.append({"op": op, "label": label,
                         "helper": "tool-control",
                         "args": [op, resolved],
                         "why": f"runs tool-control.sh {op} {resolved} "
                                "through polkit - it asks for your "
                                "password"})
            return
        disabled(op, label,
                 f"tool-control.sh's unit allowlist does not list "
                 f"{resolved} - no lane for this from a card")

    lane("start", "Start")
    lane("stop", "Stop")
    lane("restart", "Restart")
    return opts


# ---------------------------------------------------------------- editor
class ToolConfigEditor(Gtk.Box):
    """The RAW config file, in-card: a TextView over the real file, line
    validation, and Apply through the config-write polkit lane (the
    previous file is kept beside it as an .old copy). A path no lane can
    write opens read-only and says so on the banner."""

    def __init__(self, card=None, conf=None, data_dir=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._card = card
        self._conf = dict(conf or {})
        self._path = pathlib.Path(self._conf.get("path") or "")
        self._data_dir = data_dir
        self._original = ""
        self._busy = False

        self.banner = Gtk.Label(xalign=0, wrap=True)
        self.banner.set_xalign(0)
        self.banner.add_css_class("gw-meta")
        self.append(self.banner)

        self.buffer = Gtk.TextBuffer()
        view = Gtk.TextView(buffer=self.buffer, editable=True, wrap_mode=0)
        view.add_css_class("monospace")
        self.view = view
        # the fit law: the editor's own scroller - the card grows, the
        # page list never does
        self._scroll = Gtk.ScrolledWindow()
        self._scroll.set_name("tool-config")
        self._scroll.set_policy(Gtk.PolicyType.NEVER,
                                Gtk.PolicyType.AUTOMATIC)
        self._scroll.set_min_content_height(280)
        self._scroll.set_child(view)
        self.append(self._scroll)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.validate_btn = Gtk.Button(label="Validate")
        self.validate_btn.add_css_class("gw-mini")
        self.validate_btn.connect("clicked", self._on_validate)
        row.append(self.validate_btn)
        self.apply_btn = Gtk.Button(label="Apply")
        self.apply_btn.add_css_class("gw-primary")
        self.apply_btn.connect("clicked", self._on_apply)
        row.append(self.apply_btn)
        self.append(row)

        self.result = Gtk.Label(xalign=0, wrap=True)
        self.result.set_xalign(0)
        self.result.add_css_class("gw-meta")
        self.result.set_wrap(True)
        self.append(self.result)

    # -- load ------------------------------------------------------------
    def load(self):
        """Load the REAL file this config names. The banner states, in
        plain words, whether this view can write and how."""
        self._original = ""
        self.buffer.set_text("")
        try:
            text = self._path.read_text(errors="replace")
        except OSError:
            text = None
        if text is None:
            self.banner.set_text(
                f"{self._path} is not on this machine - nothing to edit "
                "here.")
            self.apply_btn.set_sensitive(False)
            self.view.set_editable(False)
            return
        self._original = text
        self.buffer.set_text(text)
        if self._editable():
            self.banner.set_text(
                f"edits {self._path} raw - Validate, then Apply writes "
                "it through the polkit lane; the previous file is kept "
                "beside it with an .old copy.")
            self.apply_btn.set_sensitive(True)
            self.view.set_editable(True)
        else:
            self.banner.set_text(
                f"read-only - {self._path} has no write lane in this "
                "build; open a write lane first")
            self.apply_btn.set_sensitive(False)
            self.view.set_editable(False)

    def open_for(self):
        self.load()

    def _editable(self) -> bool:
        return bool(self._conf.get("writable")) and self._original != ""

    def _text(self) -> str:
        return self.buffer.get_text(self.buffer.get_start_iter(),
                                    self.buffer.get_end_iter(), False)

    # -- run -------------------------------------------------------------
    def _on_validate(self, _btn=None):
        errs = validate_config(self._conf, self._text(), self._original)
        if errs:
            self.result.set_text(errs[0])
        else:
            self.result.set_text(
                "clean - the lines check out against this file's keys.")

    def _on_apply(self, _btn=None):
        errs = validate_config(self._conf, self._text(), self._original)
        if errs:
            self.result.set_text(errs[0] + " (Validate shows the rest.)")
            return
        words = (f"config-write {self._conf.get('key')} - you will be "
                 "asked for your password. The previous file is kept as "
                 "an .old copy, so this can be undone by hand.")
        d = Gtk.Dialog(title="Apply the config : are you sure?",
                       transient_for=self.get_root()
                       if isinstance(self.get_root(), Gtk.Window)
                       else None, modal=False)
        d.set_destroy_with_parent(True)
        body = d.get_content_area()
        body.set_margin_start(18)
        body.set_margin_end(18)
        body.set_margin_top(12)
        ask = Gtk.Label(xalign=0, wrap=True)
        ask.set_xalign(0)
        ask.set_text(words)
        body.append(ask)
        d.add_button("Cancel", Gtk.ResponseType.CANCEL)
        d.add_button("Write it", Gtk.ResponseType.OK)
        d.connect("response", self._on_confirm_response)
        present_now(d)

    def _on_confirm_response(self, d, rid):
        d.destroy()
        if rid == Gtk.ResponseType.OK:
            self._apply_now()

    def _apply_now(self, *_a):
        """The apply lane without the ask: validation, then stage, then
        the polkit helper, then - when the card carries a baseline
        permafix - the offer. Used live after a confirm and, in tests,
        directly."""
        if self._busy:
            return
        if not self._editable():
            self.result.set_text(
                "read-only - there is no write lane for this file; "
                "nothing was written.")
            return
        errs = validate_config(self._conf, self._text(), self._original)
        if errs:
            self.result.set_text(errs[0])
            return
        conf = self._conf
        staged = None
        if self._data_dir is not None:
            sdir = pathlib.Path(self._data_dir) / "config-staging"
            try:
                sdir.mkdir(parents=True, exist_ok=True)
                staged = sdir / f"{conf['key']}.staged"
                tmp = sdir / f"{conf['key']}.new"
                tmp.write_text(self._text())
                os.replace(tmp, staged)
            except OSError as e:
                self.result.set_text(
                    f"the edit could not be staged ({e}); the file on "
                    "disk is untouched.")
                return
        args = [conf["key"], str(staged)] if staged else [conf["key"]]
        self._busy = True
        self.apply_btn.set_sensitive(False)

        def worker():
            try:
                from ui.decisionlist import _helper_exec
                rc, err = _helper_exec(CONFIG_WRITE, list(args))
            except Exception:            # noqa: BLE001 - a lane crash is
                rc, err = -1, ""         # a did-not-finish, not a crash
            GLib.idle_add(self._after_apply, int(rc), str(err),
                          str(staged) if staged else "")

        threading.Thread(target=worker, daemon=True).start()

    def _after_apply(self, rc, err, staged) -> bool:
        self._busy = False
        self.apply_btn.set_sensitive(True)
        try:
            if staged:
                pathlib.Path(staged).unlink(missing_ok=True)
        except OSError:
            pass
        from wiz.common import helper_detail
        if rc == 0:
            self.result.set_text(
                f"applied to {self._path} - the previous file is kept "
                "beside it with an .old copy.")
            if self._card is not None:
                self._card.note(f"applied to {self._path} (previous "
                                "kept).")
                if self._card._permafix_tool():
                    self._card.offer_permafix()
        else:
            words = (f"the apply did not finish ({helper_detail(rc, err)})"
                     " - the file on disk is as it was.")
            self.result.set_text(words)
            if self._card is not None:
                self._card.note(words)
        return False


# ------------------------------------------------------------------ card
class ToolCard(Gtk.Box):
    """One tool, whole: glyph, name, dot, status; lanes with their honest
    states; the schedule in its own words; quick lanes; and the raw
    config expanding inside this card."""

    def __init__(self, page, tool: dict, win=None, configs=None,
                 on_navigate=None, on_scan=None, on_toggle=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.add_css_class("gw-card")
        self.set_hexpand(True)
        self._page = page
        self._tool = tool
        self._win = win
        self._data_dir = getattr(win, "data_dir", None)
        self._navigate = on_navigate if on_navigate is not None \
            else getattr(win, "_show", None)
        self._scan = on_scan if on_scan is not None \
            else getattr(win, "_hunter_scan", None)
        self._toggle = on_toggle if on_toggle is not None \
            else getattr(win, "_toggle_tool", None)
        self._busy = False
        self.name = tool["name"]
        self.configs = list(configs if configs is not None
                            else TOOL_CONFIGS.get(self.name, []))
        self.editors: list = []
        self.opts = lifecycle_plan(tool, win)

        # header -----------------------------------------------------------
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.glyph = Gtk.Image.new_from_icon_name(tool_icon(self.name))
        head.append(self.glyph)
        self.name_l = Gtk.Label(xalign=0)
        self.name_l.set_markup(
            f"<b>{friendly_name(self.name)}</b> · {self.name}")
        self.name_l.add_css_class("gw-headline")
        self.name_l.set_hexpand(True)
        head.append(self.name_l)
        self.dot = Gtk.Label(label="●")
        head.append(self.dot)
        self.append(head)

        self.status = Gtk.Label(xalign=0, wrap=True)
        self.status.set_xalign(0)
        self.status.add_css_class("gw-meta")
        self.append(self.status)

        self.result = Gtk.Label(xalign=0, wrap=True)
        self.result.set_xalign(0)
        self.result.add_css_class("gw-meta")
        self.append(self.result)

        # lifecycle row ------------------------------------------------------
        self.lane_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=6)
        self._lane_buttons: list = []
        for opt in self.opts:
            b = Gtk.Button(label=opt["label"])
            enabled = opt.get("sensitive", True) is not False
            if "helper" in opt:
                args = ", ".join(str(a) for a in opt.get("args") or [])
                b.set_tooltip_text(f"Runs {opt['helper']} {args} through "
                                   "polkit - you will be asked for your "
                                   "password.")
                b.connect("clicked", self._on_lane, opt)
            elif "kind" in opt and opt["kind"] == "toggle":
                b.set_tooltip_text(str(opt.get("why") or ""))
                b.connect("clicked", self._on_toggle_lane, opt)
            elif "scan" in opt:
                b.set_tooltip_text("one validated scan request - the "
                                   "daemon honours only the fixed keys.")
                b.connect("clicked", self._on_scan_lane, opt)
            elif "kind" in opt and opt["kind"] == "navigate":
                b.set_tooltip_text(str(opt.get("why") or ""))
                b.connect("clicked", self._on_navigate_lane, opt)
            if not enabled:
                b.set_sensitive(False)
                b.set_tooltip_text(str(opt.get("disabled") or ""))
            self.lane_box.append(b)
            self._lane_buttons.append((b, enabled))
        self.append(self.lane_box)

        # schedule row ---------------------------------------------------------
        self.schedule = Gtk.Label(xalign=0, wrap=True)
        self.schedule.set_xalign(0)
        self.schedule.add_css_class("gw-meta")
        self.schedule.set_text(schedule_entry(tool))
        self.append(self.schedule)

        # quick lanes -----------------------------------------------------------
        self.quick_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                                 spacing=6)
        lanes = QUICK_LANES.get(self.name, [])
        for lane in lanes:
            b = Gtk.Button(label=lane["label"])
            b.connect("clicked", self._on_quick, lane)
            b.set_tooltip_text(str(lane.get("why") or ""))
            self.quick_box.append(b)
        if not lanes:
            honest = Gtk.Label(xalign=0, wrap=True)
            honest.set_xalign(0)
            honest.add_css_class("gw-meta")
            honest.set_text(
                "no quick switch on file - this tool's real switches "
                "are its config, below, and the lanes other pages own.")
            self.quick_box.append(honest)
        self.append(self.quick_box)

        # the raw config, expanding INSIDE this card ---------------------------
        self.open_btn = Gtk.Button(label="Open config")
        self.open_btn.add_css_class("gw-mini")
        if not self.configs:
            self.open_btn.set_sensitive(False)
            self.open_btn.set_tooltip_text(
                "no config file is mapped for this tool - its knobs are "
                "its systemd unit and its own docs.")
        self.open_btn.connect("clicked", self._on_open_config)
        self.append(self.open_btn)

        self._reveal = Gtk.Revealer()
        self._reveal.set_transition_type(Gtk.RevealerTransitionType.NONE)
        self._config_body = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._reveal.set_child(self._config_body)
        self.append(self._reveal)

        self._permafix = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                 spacing=6)
        self.append(self._permafix)

        self._facts: dict = {}
        self.update({"state": "UNKNOWN", "paused": False,
                     "installed": None, "live": False})

    # -- the permafix loop ---------------------------------------------------
    def _permafix_tool(self):
        return TOOL_PERMAFIX.get(self.name)

    def offer_permafix(self):
        """The permafix primaries: Yes runs the baseline lane now, Later
        leaves it - either way the card says what happened."""
        tool = self._permafix_tool()
        if not tool:
            return
        from ui.decisionlist import _clear
        _clear(self._permafix)
        q = Gtk.Label(xalign=0, wrap=True)
        q.set_xalign(0)
        q.add_css_class("gw-meta")
        q.set_text(_PERMAFIX_WORDS.get(tool, "Refresh the baseline?"))
        self._permafix.append(q)
        yes = Gtk.Button(label="Yes, refresh it")
        yes.add_css_class("gw-primary")
        yes.set_tooltip_text(f"runs baseline-update.sh {tool} through "
                             "polkit; the previous baseline is kept.")
        yes.connect("clicked", self._on_permafix_yes, tool)
        self._permafix.append(yes)
        later = Gtk.Button(label="Later")
        later.add_css_class("gw-mini")
        later.connect("clicked", self._on_permafix_later, tool)
        self._permafix.append(later)

    def _on_permafix_yes(self, _btn, tool):
        self._run_opt_now({"op": "permafix", "label": "Refresh baseline",
                           "helper": "baseline-update", "args": [tool]})

    def _on_permafix_later(self, _btn, tool):
        from ui.decisionlist import _clear
        _clear(self._permafix)
        self.note("left for later - the configuration is applied; the "
                  f"{tool} baseline stays as it is until you ask.")

    # -- lanes ---------------------------------------------------------------
    def _on_lane(self, btn, opt):
        self._confirm_and_run(opt)

    def _on_toggle_lane(self, _btn, opt):
        if callable(self._toggle):
            self._toggle(self.name, bool(opt.get("pause")))
            self.note(f"{opt['label']} sent through the app's own lane.")

    def _on_scan_lane(self, _btn, opt):
        if callable(self._scan):
            self._scan(opt["scan"])
        self.note(f"the {friendly_name(opt['scan'])} run was requested - "
                  "it shows on the Scans page when the daemon takes it.")

    def _on_navigate_lane(self, _btn, opt):
        if callable(self._navigate):
            self._navigate(opt["page"])

    def _on_quick(self, btn, lane):
        if lane.get("kind") == "navigate":
            self._on_navigate_lane(btn, lane)
            return
        self._confirm_and_run(lane)

    def _confirm_and_run(self, opt: dict):
        helper = str(opt.get("helper") or "")
        args = ", ".join(str(a) for a in opt.get("args") or [])
        words = (f"{helper} {args} - you will be asked for your password."
                 if helper else "no lane names this ask.")
        label = f"{opt.get('label') or opt['op']}: {words}"
        d = Gtk.Dialog(title=f"{label.split(':')[0]} : are you sure?",
                       transient_for=self.get_root()
                       if isinstance(self.get_root(), Gtk.Window)
                       else None, modal=False)
        d.set_destroy_with_parent(True)
        body = d.get_content_area()
        body.set_margin_start(18)
        body.set_margin_end(18)
        body.set_margin_top(12)
        ask = Gtk.Label(xalign=0, wrap=True)
        ask.set_xalign(0)
        ask.set_text(label)
        body.append(ask)
        d.add_button("Cancel", Gtk.ResponseType.CANCEL)
        d.add_button(opt.get("label") or "Run", Gtk.ResponseType.OK)
        d.connect("response", self._on_confirm_response, opt)
        present_now(d)

    def _on_confirm_response(self, d, rid, opt=None):
        d.destroy()
        if rid == Gtk.ResponseType.OK:
            self._run_opt_now(opt or {})

    # -- the lane run and its result ------------------------------------------
    def set_busy(self, busy: bool):
        self._busy = busy
        for b, enabled in self._lane_buttons:
            b.set_sensitive(enabled and not busy)

    def note(self, text: str):
        """Every action states its result ON the card."""
        self.result.set_text(str(text))

    def _run_opt_now(self, opt: dict):
        if self._busy or not opt.get("helper"):
            return
        self.set_busy(True)
        self.note(f"running {opt['helper']}...")

        def worker():
            try:
                from ui.decisionlist import _helper_exec
                rc, err = _helper_exec(opt["helper"],
                                       list(opt.get("args") or []))
            except Exception:            # noqa: BLE001 - a lane crash is
                rc, err = -1, ""         # a did-not-finish, not a crash
            GLib.idle_add(self._after_opt, dict(opt), int(rc), str(err))

        threading.Thread(target=worker, daemon=True).start()

    def _after_opt(self, opt: dict, rc: int, err: str) -> bool:
        self.set_busy(False)
        from ui.decisionlist import _clear
        from wiz.common import helper_detail
        label = str(opt.get("label") or opt.get("op") or "")
        if rc == 0:
            if opt.get("helper") == "baseline-update":
                self.note(f"baseline refreshed - the old baseline is "
                          "kept beside the new one.")
                _clear(self._permafix)   # answered: the offer is done
            else:
                self.note(f"{label}: done ({opt['helper']} exited 0).")
        else:
            self.note(f"{label} did not finish ({helper_detail(rc, err)})"
                      " - nothing else was changed.")
        win = self._win
        if win is not None and hasattr(win, "refresh"):
            try:
                win.refresh()
            except Exception:            # noqa: BLE001 - the card
                pass                     # already said what happened
        return False

    # -- the config expansion ---------------------------------------------------
    def load_configs(self):
        """Build the in-card editors for this card's config files. Each
        editor loads its REAL file when the card is first opened."""
        if self.editors:
            return
        for conf in self.configs:
            ed = ToolConfigEditor(card=self, conf=conf,
                                  data_dir=self._data_dir)
            ed.open_for()
            self.editors.append(ed)
            self._config_body.append(ed)

    def _on_open_config(self, _btn=None):
        open_now = not self._reveal.get_reveal_child()
        if open_now:
            self.load_configs()
        else:
            for ed in self.editors:
                ed.open_for()            # closing re-reads: unapplied
                                          # edits do not survive a fold
        self._reveal.set_reveal_child(open_now)
        self.open_btn.set_label("Close config" if open_now
                                else "Open config")

    def results_running(self):
        """The live-only filter's test: is this tool actually running?"""
        facts = self._facts or {}
        return facts.get("state") == "GREEN" and not facts.get("paused")

    # -- paint -------------------------------------------------------------------
    def update(self, facts: dict):
        """The dot and the one-line status come from the state the window
        already computed; nothing here runs a probe."""
        self._facts = facts
        state = str(facts.get("state") or "UNKNOWN")
        paused = bool(facts.get("paused"))
        colour = state_colour(state, paused)
        self.dot.set_markup(f"<span foreground='{colour}'>●</span>")
        line = status_words(state, facts.get("installed"), paused)
        if facts.get("live"):
            line = f"{line} · a scan is running right now"
        self.status.set_text(line)
        self._apply_filter()

    def _apply_filter(self):
        switch = getattr(self._page, "show_switch", None)
        try:
            all_on = bool(switch.get_active()) if switch is not None \
                else True
        except Exception:                # noqa: BLE001 - dock-owned widget
            all_on = True
        self.set_visible(all_on or self.results_running())


# ------------------------------------------------------------------ page
class ToolControlPage(Gtk.Box):
    """The Tools desk as t2 cards: ONE inner-scrolled list of full-width
    self-contained cards, and the dock's Show / Schedule groups. Refresh
    paints; the cards keep their state, including any config editor the
    owner has open inside one."""

    def __init__(self, win=None, reg=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.set_vexpand(True)
        self._win = win
        self.registry = list(reg if reg is not None
                             else getattr(win, "registry", None) or ())
        head = Gtk.Label(
            label="Tools - what runs, how and when", xalign=0)
        head.add_css_class("gw-page-title")
        self.append(head)

        self.cards_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                 spacing=10)
        self._scroll = Gtk.ScrolledWindow()
        self._scroll.set_name("tools-list")
        self._scroll.set_policy(Gtk.PolicyType.NEVER,
                                Gtk.PolicyType.AUTOMATIC)
        self._scroll.set_vexpand(True)
        self._scroll.set_child(self.cards_box)
        self.append(self._scroll)

        self.cards: dict = {}
        for tool in self.registry:
            card = ToolCard(self, tool, win)
            self.cards[tool["name"]] = card
            self.cards_box.append(card)

        self._last_facts: dict = {}
        self.show_switch = Gtk.Switch()
        self.show_switch.set_active(True)
        self.show_switch.set_valign(Gtk.Align.CENTER)
        self.show_switch.set_tooltip_text(
            "show every tool; turn off to see only the ones running")
        self.show_switch.connect("notify::active", self._on_show)
        self.show_note = Gtk.Label(xalign=0, wrap=True)
        self.show_note.set_xalign(0)
        self.show_note.add_css_class("gw-meta")
        self.show_note.set_text(
            "live-only keeps running cards and hides stopped ones - the "
            "filter never unmounts a card, so an open config editor "
            "survives")
        # the boot sweep's stagger is not surfaced by the status digest:
        # the dock's toggle says so instead of pretending to work
        self.stagger = Gtk.Button(label="Stagger the boot sweep")
        self.stagger.set_sensitive(False)
        self.stagger.set_tooltip_text(
            "disabled - the boot sweep's stagger is not surfaced via "
            "status, so there is no honest toggle to wire here")
        self.sched_note = Gtk.Label(xalign=0, wrap=True)
        self.sched_note.set_xalign(0)
        self.sched_note.add_css_class("gw-meta")
        self.sched_note.set_text(
            "each card's schedule row names its real systemd unit; this "
            "build has no editable schedule value, so schedules are "
            "read-only there.")

    # -- dock ----------------------------------------------------------------
    def dock_groups(self):
        return [("Show", [self.show_switch, self.show_note]),
                ("Schedule", [self.stagger, self.sched_note])]

    def _on_show(self, *_a):
        for card in self.cards.values():
            card._apply_filter()

    # -- refresh ---------------------------------------------------------------
    def refresh(self, snap=None):
        """The same digest the window already loaded; the cards' dots and
        status lines repaint from it, and nothing else moves."""
        snap = snap or {}
        tools = snap.get("tools") or {}
        updated = snap.get("updated")
        live_scans = {}
        for key, val in (((self._scan_live() or {}).get("scanners"))
                         or {}).items():
            live_scans[key] = (val or {}).get("state")
        win = self._win
        facts_all = {}
        for tool in self.registry:
            name = tool["name"]
            info = tools.get(name) or {}
            state = info.get("state", "UNKNOWN")
            if win is not None and hasattr(win, "_display_state"):
                try:
                    state = win._display_state(name, info, updated)
                except Exception:        # noqa: BLE001 - a probe gap is
                    pass                 # honesty too: keep the digest's
            paused = False
            if win is not None and hasattr(win, "paused"):
                try:
                    paused = bool(win.paused.is_paused(name))
                except Exception:        # noqa: BLE001
                    paused = False
            facts_all[name] = {
                "state": state, "paused": paused,
                "installed": info.get("installed"),
                "live": live_scans.get(name) == "running"}
        self._last_facts = facts_all
        for name, card in self.cards.items():
            if name in facts_all:
                card.update(facts_all[name])
        return False

    def _scan_live(self):
        win = self._win
        cached = getattr(win, "_scan_live", None) if win else None
        if cached is not None:
            return cached
        try:
            from ui.scanview import read_live
            return read_live(getattr(win, "data_dir", None) or ".")
        except Exception:                # noqa: BLE001 - no live doc:
            return None                  # no card pretends a scan is on
