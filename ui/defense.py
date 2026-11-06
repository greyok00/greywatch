from __future__ import annotations

import datetime as _dt
import os
import pathlib
import re
import subprocess

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk    # noqa: E402

from cverules import active_rules, TOOL_LABEL
from ui import metrics
from ui.plain import escape

PROC_SYS = pathlib.Path("/proc")   # overridden by tests; /proc on the host


# ------------------------------------------------------- the armor probes
# Every probe answers True, False, or None. None means "this box would not
# tell me" - and the page says CANNOT READ, never SAFE. A reader that turns
# a closed probe into a green chip is how a defense page lies.

def psad_status(conf=None, kern_log=None, nft_bin=None, systemctl_bin=None):
    """How the wave-A defense chain is standing: the inbound log chain,
    armed auto-block, the kernel.log psad is fed from, the service."""
    conf = pathlib.Path(conf or os.environ.get("PSAD_CONF")
                        or "/etc/psad/psad.conf")
    kern_log = pathlib.Path(kern_log or os.environ.get("KERN_LOG")
                            or "/var/log/kern.log")
    nft_bin = nft_bin or os.environ.get("NFT_BIN") or "nft"
    systemctl_bin = systemctl_bin or os.environ.get("SYSTEMCTL_BIN") \
        or "systemctl"
    out = {}
    try:
        out["armed"] = bool(
            re.search(r"^ENABLE_AUTO_IDS\s+Y;", conf.read_text(), re.M))
    except OSError:
        out["armed"] = None
    try:
        out["fed"] = kern_log.exists()
    except OSError:
        out["fed"] = None
    try:
        rc = subprocess.run(
            [nft_bin, "list", "table", "inet", "greywatch_psad"],
            capture_output=True, timeout=5).returncode
        out["table"] = True if rc == 0 else False if rc == 1 else None
    except (OSError, subprocess.SubprocessError):
        out["table"] = None
    try:
        rc = subprocess.run([systemctl_bin, "is-active", "psad.service"],
                            capture_output=True, timeout=5).returncode
        out["service"] = rc == 0
    except (OSError, subprocess.SubprocessError):
        out["service"] = None
    return out


def arp_status(ip_bin=None):
    """The two things apply/hardening-arp.sh pins: a permanent neighbour
    entry for the real router, and the ARP-reply sysctls closed."""
    ip_bin = ip_bin or os.environ.get("IP_BIN") or "ip"

    def _out(*args):
        try:
            p = subprocess.run([ip_bin, *args], capture_output=True,
                               timeout=5, text=True)
            return p.returncode, p.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return None, ""
    out = {"pinned": None, "sysctls": None}
    rc, routes = _out("-4", "route", "show", "default")
    try:
        fields = routes.split("\n", 1)[0].split()
        gw, dev = fields[2], fields[4]
    except (IndexError, AttributeError):
        return out
    if not gw or not dev:
        return out
    nrc, neigh = _out("neigh", "get", gw, "dev", dev)
    out["pinned"] = True if (nrc == 0 and "PERMANENT" in neigh) else \
        False if nrc == 0 else None
    vals = []
    for name, want in (("arp_ignore", 1), ("arp_accept", 0)):
        try:
            got = int((PROC_SYS / f"sys/net/ipv4/conf/all/{name}")
                      .read_text().strip())
        except (OSError, ValueError):
            out["sysctls"] = None
            break
        vals.append(got == want)
    else:
        out["sysctls"] = all(vals)
    return out


def cve_rows(data_dir):
    """Active CVE rules for the managed tools, or None when this box has
    never fetched a cache (the page says so rather than 'nothing')."""
    cache = pathlib.Path(data_dir) / "cve-cache.json"
    if not cache.exists():
        return None
    try:
        return active_rules(cache)
    except Exception:
        return []


def _age(ts):
    try:
        when = _dt.datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return "held for some time"
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    mins = max(0, int((_dt.datetime.now(_dt.timezone.utc)
                       - when).total_seconds() // 60))
    if mins < 1:
        return "held just now"
    if mins < 60:
        return f"held {mins} min"
    if mins < 60 * 24:
        return f"held {mins // 60} h"
    return f"held {mins // (60 * 24)} d"


# --------------------------------------------------------------- the view

_BLOCK_OPTS = {
    "lift": ("Lift the block", "danger", "lift-block"),
    "keep": ("Record: keep blocking", "primary", "block-review"),
}


class DefenseView(Gtk.Box):
    """The network defense desk: who is blocked, what the Block Reviewer is
    asking, how the wave-A armor chain stands. The page never blocks or
    lifts anything itself: a blocked row defers to the window's
    confirm-then-helper pipeline, and a reviewer card runs the same
    decision machinery as the decisions window."""

    def __init__(self, win=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.add_css_class("gw-defense")
        self.add_css_class("gw-lane-threat")
        self._win = win
        self._answering = set()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        box.set_margin_top(metrics.PAGE_TOP)
        box.set_margin_bottom(metrics.PAGE_BOTTOM)
        box.set_margin_start(metrics.PAGE_X)
        box.set_margin_end(metrics.PAGE_X)
        self.append(box)
        for title, host in (
                ("Blocked addresses", "blocked"),
                ("Decisions waiting", "asks"),
                ("Network armor", "armor"),
                ("Browser Watch", "watch")):
            head = Gtk.Label(label=title, xalign=0)
            head.add_css_class("gw-page-title")
            box.append(head)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            box.append(body)
            setattr(self, f"_{host}", body)
        self._scroll = Gtk.ScrolledWindow()
        self._scroll.set_policy(Gtk.PolicyType.NEVER,
                                Gtk.PolicyType.AUTOMATIC)

    # -- data -------------------------------------------------------------

    def refresh(self, snap=None):
        from ui.decisionlist import _clear
        for host in (self._blocked, self._asks, self._armor, self._watch):
            _clear(host)
        doc = dict(snap or {}).get("defense") or {}
        rows = doc.get("blocked")
        self._paint_blocked(rows if isinstance(rows, list) else [])
        # the ONE decision list, all sources (rebuild Phase 1): the page no
        # longer reads reviewer-only digest asks, so a quarantine question
        # or a scanner-ban prompt shows here exactly as the pill counts it
        asks = (snap or {}).get("pending_list")
        if asks is None:            # older daemon that has not published
            asks = doc.get("asks")
        self._paint_asks(asks if isinstance(asks, list) else [])
        self._paint_armor()
        self._paint_watch((snap or {}).get("browser_watch"))

    def _quiet(self, host, text):
        lbl = Gtk.Label(label=text, xalign=0, wrap=True)
        lbl.add_css_class("gw-meta")
        host.append(lbl)

    def _paint_blocked(self, rows):
        if not rows:
            self._quiet(self._blocked, "Nothing is blocked right now.")
            return
        for row in rows:
            if isinstance(row, dict) and row.get("ip"):
                self._blocked.append(self._blocked_row(row))

    def _blocked_row(self, row):
        ip = str(row.get("ip", ""))
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.add_css_class("gw-card")
        title = Gtk.Label(
            label=escape(ip), xalign=0, wrap=True, selectable=True)
        title.add_css_class("gw-headline")
        why = " - ".join(x for x in (
            _age(str(row.get("ts", ""))),
            str(row.get("reason") or ""),
            str(row.get("why") or "")) if x)
        if row.get("forever"):
            why = "kept for good: " + why
        if row.get("reviewed") == "keep":
            why += " (a Block Reviewer question was answered: keep blocking)"
        elif row.get("reviewed") == "lift":
            why += " (a Block Reviewer question was answered: lift)"
        meta = Gtk.Label(label=why, xalign=0, wrap=True, selectable=True)
        meta.add_css_class("gw-meta")
        card.append(title)
        card.append(meta)
        row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for kind in ("lift", "keep"):
            label, tone, helper = _BLOCK_OPTS[kind]
            opt = {"id": kind, "label": label, "tone": tone,
                   "helper": helper, "args": [ip] if kind == "lift"
                   else [ip, "keep"]}
            b = Gtk.Button(label=label)
            b.add_css_class("gw-primary" if tone == "primary"
                            else "gw-danger")
            b.connect("clicked", self._run, dict(opt))
            row_box.append(b)
        card.append(row_box)
        return card

    def _paint_asks(self, asks):
        from ui.decisionlist import card_widget
        if not asks:
            self._quiet(self._asks, "Nothing is waiting for your answer.")
            return
        for ask in asks:
            spec = ask.get("spec") if isinstance(ask, dict) else None
            if isinstance(spec, dict) and spec.get("id"):
                self._asks.append(
                    card_widget(spec, str(ask.get("ts", "")),
                                self._on_answer))

    def _on_answer(self, _btn, spec, opt, buttons, state):
        sid = str(spec["id"])
        if sid in self._answering:
            return
        self._answering.add(sid)
        for b in buttons:
            b.set_sensitive(False)
        state.set_visible(True)
        state.set_text(f"running {opt.get('helper')}…")

        def work():
            try:
                from ui.decisionlist import _helper_exec
                rc = _helper_exec(opt.get("helper"),
                                  list(opt.get("args", [])))
            except Exception:
                rc = -1
            from gi.repository import GLib
            GLib.idle_add(self._after_answer, sid, opt, buttons, state, rc)

        import threading
        threading.Thread(target=work, daemon=True).start()

    def _after_answer(self, sid, opt, buttons, state, rc):
        from gi.repository import GLib
        self._answering.discard(sid)
        if rc == 0:
            import pathlib as _pl
            from ui.decisionlist import answer_record
            data_dir = getattr(self._win, "data_dir", None) or _pl.Path(
                os.environ.get("GW_DATA") or "/var/lib/greywatch")
            answer_record(data_dir, sid, opt["id"])
            state.set_text("Recorded. The ledger keeps your answer.")
        else:
            for b in buttons:
                b.set_sensitive(True)
            state.set_text(f"{opt.get('helper')} did not finish "
                           f"(exit code {rc}). You can try again.")
        return GLib.SOURCE_REMOVE

    def _run(self, _btn, opt):
        w = self._win
        if w is not None and hasattr(w, "_run_log_option"):
            w._run_log_option(_btn, dict(opt))

    def _armor_row(self, label, state, helper):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        chip = Gtk.Button(label=f"{label}: {self._ARMOR_WORDS[state]}",
                          sensitive=False)
        chip.add_css_class(self._ARMOR_CLASSES[state])
        row.append(chip)
        # the button is the row's own fix and lives nowhere else: only an
        # open or unreadable defense gets one, a good row gets nothing
        if state is not True:
            b = Gtk.Button(label=f"Arm: {label}")
            b.add_css_class("gw-primary")
            b.connect("clicked", self._run,
                      {"id": "arm", "label": label, "tone": "primary",
                       "helper": helper, "args": []})
            row.append(b)
        return row

    # -- browser watch panel (rebuild Phase 2) ----------------------------

    def _paint_watch(self, rows):
        if not isinstance(rows, list):
            self._quiet(self._watch,
                        "The daemon has not published a Browser Watch"
                        " digest yet; restarting the greywatch daemon"
                        " arms this section.")
            return
        rows = [r for r in rows if isinstance(r, dict)]
        if not rows:
            self._quiet(self._watch, "No browser findings to review.")
            return
        for f in rows:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            card.add_css_class("gw-card")
            top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            cat = Gtk.Label(
                label=(str(f.get("severity") or "FINDING")).upper(), xalign=0)
            cat.add_css_class("gw-eyebrow")
            cat.set_hexpand(True)
            top.append(cat)
            meta = " - ".join(str(x) for x in (f.get("ts"), f.get("asset"))
                              if x)
            if meta:
                lbl = Gtk.Label(label=meta, xalign=1, wrap=True)
                lbl.add_css_class("gw-meta")
                top.append(lbl)
            card.append(top)
            title = Gtk.Label(xalign=0, wrap=True, selectable=True)
            title.set_markup(
                "<b>" + escape(str(f.get("title") or f.get("rule") or "?"))
                + "</b>")
            card.append(title)
            what = str(f.get("what") or "")
            if what:
                d = Gtk.Label(label=what, xalign=0, wrap=True,
                              selectable=True)
                d.add_css_class("gw-meta")
                card.append(d)
            self._watch.append(card)

    # -- armor ------------------------------------------------------------

    # each probe row and the helper that stands the defense up if it is
    # open or unreadable; a good row carries nothing to click (rebuild
    # Phase 2: inline actions next to the thing they fix)
    _ARMOR_PROBES = (
        ("Sweep watcher feed", "fed", "psad-tune"),
        ("Inbound log chain", "table", "psad-tune"),
        ("Auto-block armed", "armed", "psad-tune"),
        ("psad service", "service", "psad-tune"),
        ("Router address pinned", "pinned", "hardening-arp"),
        ("ARP replies closed", "sysctls", "hardening-arp"))
    _ARMOR_WORDS = {True: "good", False: "open", None: "cannot read"}
    _ARMOR_CLASSES = {True: "gw-armor-good", False: "gw-armor-open",
                      None: "gw-armor-unknown"}

    def _paint_armor(self):
        psad = psad_status()
        arp = arp_status()
        wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        wrap.add_css_class("gw-armor")
        for label, key, helper in self._ARMOR_PROBES:
            state = (psad if key in ("fed", "table", "armed", "service")
                     else arp).get(key)
            wrap.append(self._armor_row(label, state, helper))
        self._armor.append(wrap)
        rules = cve_rows(getattr(self._win, "data_dir", "") or ".")
        if rules is None:
            self._quiet(self._armor,
                        "The flaw list has never been fetched; the CVE"
                        " refresh arms this section.")
            return
        if not rules:
            self._quiet(self._armor,
                        "No tracked flaw scoring 7.0+ touches a tool on"
                        " this machine.")
            return
        for rule in rules:
            who = TOOL_LABEL.get(rule.get("tool"), "a managed tool")
            txt = (f"{rule.get('cve')} (score {rule.get('score')} "
                   f"{rule.get('severity')}) affects {who}: "
                   f"{str(rule.get('summary') or '')[:180]}")
            meta = Gtk.Label(label=escape(txt), xalign=0, wrap=True,
                             selectable=True)
            meta.add_css_class("gw-meta")
            self._armor.append(meta)
