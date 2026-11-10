from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re
import subprocess
import threading
import time

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk    # noqa: E402

from ptp import load_map as ptp_load_map, DASH_PROSE
# The advisories/watchlist readers MOVED to ui/protectdesk.py (rebuild
# task 10): the Firewall page no longer renders CVE rows, the Protections
# page does, and these names stay importable here for the pins that read
# or monkeypatch through this module. The DefenseView's own watchlist
# panel resolves them through this module's globals, so a monkeypatch on
# one name still re-paints the page.
from ui.protectdesk import (cve_rows, ptp_rows, ptp_probe_failed,
                            ptp_high_count, ptp_watch_stamp)  # noqa: F401
from ui import metrics
from ui.plain import escape
from wiz.common import helper_detail

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
        proc = subprocess.run(
            [nft_bin, "list", "table", "inet", "greywatch_psad"],
            capture_output=True, timeout=5)
        err = proc.stderr or b""
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        rc = proc.returncode
        if rc == 0:
            out["table"] = True
        elif rc == 1 and "no such table" in err.lower() \
                and "not permitted" not in err.lower():
            # nft's own wording says the table is genuinely absent
            out["table"] = False
        else:
            # rc 1 from a permission error, or any other exit: the reader
            # was blind - unknown, never "open" (GW-B2/GW-214 pin)
            out["table"] = None
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

# The armor probes are subprocesses (nft, systemctl, ip): they never run
# on the UI thread (rebuild task 7). The page paints from the last cached
# read and a worker thread lands the fresh one, and a read inside the
# TTL is never re-run: a page re-show cannot cost the machine another
# probe round. One round in flight is a property of the VIEW (its own
# worker), never a module flag - a stale round somewhere else must never
# suppress this page's fresh read.
PROBE_TTL = 30.0
_PROBE_CACHE = {"when": 0.0, "psad": None, "arp": None}

_IP_RE = re.compile(
    r"^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$")


def _ipv4_ok(text):
    """A real dotted IPv4 address, 0..255 per group - nothing else gets
    a Block or Unblock button."""
    m = _IP_RE.match(text or "")
    return m is not None and all(int(g) <= 255 for g in m.groups())


def _group_state(*vals):
    """One group's chip state: good only when every probe answers True;
    one cannot-read answer keeps the whole group honest."""
    if any(v is None for v in vals):
        return None
    return all(bool(v) for v in vals)


class DefenseView(Gtk.Box):
    """The network defense desk, owner variant fw-A (rebuild round 2,
    task 7): a verdict strip that answers whether the wall is up, ONE
    decisions card for the published pending list, the blocked-address
    table with Unblock on the row and the armor chain as one chip line.
    The page never blocks or lifts anything itself: a blocked row defers
    to the window's confirm-then-helper pipeline through the lift-block
    lane, a decision card runs the same answer machinery as the
    decisions window, and the psad/arp probes run on a worker thread -
    the UI thread only paints."""

    _ARMOR_WORDS = {True: "good", False: "open", None: "cannot read"}
    _ARMOR_CLASSES = {True: "gw-armor-good", False: "gw-armor-open",
                      None: "gw-armor-unknown"}

    def __init__(self, win=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=metrics.PAGE_SPACING)
        self.add_css_class("gw-defense")
        self.add_css_class("gw-lane-threat")
        self._win = win
        self._answering = set()
        self._probe_thread = None
        self._floors = {"asks": 132, "blocked": 150, "watch": 132}
        # The fit law (2026-11-10): the page lays out to the window. The
        # three lists that can grow (asks, blocked, watch) each scroll
        # inside their own band - fixed-height title bands around an
        # inner-scrolled list that flexes - instead of the page growing
        # past the 1080p window (it measured 4910px against a 947px
        # budget when the digest was long).
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(metrics.PAGE_TOP)
        box.set_margin_bottom(metrics.PAGE_BOTTOM)
        box.set_margin_start(metrics.PAGE_X)
        box.set_margin_end(metrics.PAGE_X)
        self.append(box)
        strip = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(strip)
        self._strip = strip
        for title, host, ident, floor in (
                ("Decisions waiting", "asks", "defense-asks", 132),
                ("Blocked addresses", "blocked", "defense-blocked", 150),
                ("Network armor", "armor", None, 0),
                ("Browser Watch", "watch", "defense-watch", 132)):
            lbl = Gtk.Label(label=title, xalign=0)
            lbl.add_css_class("gw-page-title")
            box.append(lbl)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            box.append(body)
            if ident:
                # the band's one inner-scrolled container (the fit law);
                # the paint code keeps appending rows to the list box
                list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                   spacing=8)
                scroll = Gtk.ScrolledWindow()
                scroll.set_name(ident)
                scroll.set_policy(Gtk.PolicyType.NEVER,
                                  Gtk.PolicyType.AUTOMATIC)
                scroll.set_vexpand(True)
                scroll.set_min_content_height(floor)
                scroll.set_child(list_box)
                body.append(scroll)
                setattr(self, ident, scroll)
                setattr(self, f"_{host}", list_box)
            else:
                setattr(self, f"_{host}", body)
        self._build_dock()

    def _band_floor_paint(self):
        """A band reserves its scrolling floor only while it holds rows -
        an empty band is its one muted sentence (the bug-9 empty-section
        law), never a tall empty hole."""
        for host in ("asks", "blocked", "watch"):
            scroll = getattr(self, f"defense-{host}", None)
            if scroll is None:
                continue
            list_box = getattr(self, f"_{host}")
            n = 0
            ch = list_box.get_first_child()
            while ch is not None:
                n += 1
                ch = ch.get_next_sibling()
            # the quiet sentence is one label; rows are the band's work
            scroll.set_min_content_height(self._floors.get(host, 0)
                                          if n > 1 else 0)

    def _build_dock(self):
        """The dock's controls (fw-A), built once and handed over by
        dock_groups(): the Rules group, the psad knobs and the Open
        config buttons. Every control is enabled only where a lane
        exists; where none does it sits disabled with an honest
        tooltip, never a button that pretends to work."""
        # Rules
        self._rules_summary = Gtk.Label(
            xalign=0, wrap=True,
            label="Allow list: psad's whitelist and the appfw asks."
                  " Block list: the addresses below, held in nftables"
                  " and the ledger.")
        self._rules_summary.add_css_class("gw-meta")
        self._rules_entry = Gtk.Entry()
        self._rules_entry.set_placeholder_text("Address to block")
        self._rules_status = Gtk.Label(xalign=0, wrap=True)
        self._rules_status.add_css_class("gw-meta")
        self._rules_add = Gtk.Button(label="Block address")
        self._rules_add.add_css_class("gw-danger")
        self._rules_add.set_tooltip_text(
            "block-ip.sh holds the address out of nftables and writes"
            " the ledger; you will be asked for your password.")
        self._rules_add.connect("clicked", self._on_block_add)
        self._rules_allow = Gtk.Button(label="Allow address",
                                       sensitive=False)
        self._rules_allow.set_tooltip_text(
            "no lane writes an allow rule outside a live appfw ask -"
            " the app answers only when the firewall asks again, and"
            " psad's house list lives in /etc/psad/psadwhitelist.")
        # psad
        self._arm = Gtk.Button(label="Arm auto-block")
        self._arm.add_css_class("gw-primary")
        self._arm.set_tooltip_text(
            "psad-tune makes inbound traffic visible and arms psad's"
            " auto-block; you will be asked for your password.")
        self._arm.connect("clicked", self._run,
                          {"id": "arm", "label": "Arm auto-block",
                           "tone": "primary", "helper": "psad-tune",
                           "args": []})
        self._disarm = Gtk.Button(label="Disarm auto-block",
                                  sensitive=False)
        self._disarm.set_tooltip_text(
            "no helper disarms psad's auto-block; disarm by hand in"
            " psad.conf - the config editor lane arrives with the"
            " tools rebuild, and Open config hands off there.")
        self._alert = Gtk.Button(label="psad alert level",
                                 sensitive=False)
        self._alert.set_tooltip_text(
            "psad-tune pins the alert level while it arms; no lane"
            " turns the dial from here yet.")
        # Open config
        tip = ("opens the tools page, where this file's raw config"
               " editor expands inside its tool's card (task 9).")
        self._conf_nft = Gtk.Button(label="nftables rules")
        self._conf_nft.set_tooltip_text(tip)
        self._conf_nft.connect("clicked", self._open_tools)
        self._conf_psad = Gtk.Button(label="psad.conf")
        self._conf_psad.set_tooltip_text(tip)
        self._conf_psad.connect("clicked", self._open_tools)

    def dock_groups(self):
        """The fixed dock's three groups (fw-A): Rules, psad, Open
        config - window._defense_view hands these over as-is."""
        return [("Rules", [self._rules_summary, self._rules_entry,
                           self._rules_add, self._rules_status,
                           self._rules_allow]),
                ("psad", [self._arm, self._disarm, self._alert]),
                ("Open config", [self._conf_nft, self._conf_psad])]

    def _on_block_add(self, _btn=None):
        """The Rules block lane: one dotted IPv4 through block-ip.sh
        (the page's confirm pipeline); junk text never runs anything."""
        ip = (self._rules_entry.get_text() or "").strip()
        if not _ipv4_ok(ip):
            self._rules_status.set_text(
                f"{ip} is not an IPv4 address - nothing was blocked."
                if ip else "Enter an IPv4 address to block.")
            return
        self._rules_status.set_text("")
        self._run(None, {"id": "block", "label": f"Block {ip}",
                         "tone": "danger", "helper": "block-ip",
                         "args": [ip]})

    def _open_tools(self, _btn):
        """The in-card config-editor lane landed with the tools rebuild
        (task 9); the buttons hand off to the Tools page, where psad's
        card carries the raw psad.conf editor through the guided
        router (the greeting opens the Show group)."""
        w = self._win
        if w is None:
            return
        if hasattr(w, "handoff"):
            w.handoff("tools")
        elif hasattr(w, "_show"):
            w._show("tools")

    # -- data -------------------------------------------------------------

    def refresh(self, snap=None):
        from ui.decisionlist import _clear
        snap = snap or {}
        for host in (self._strip, self._asks, self._blocked,
                     self._armor, self._watch):
            _clear(host)
        rows = [r for r in ((snap.get("defense") or {}).get("blocked")
                            or []) if isinstance(r, dict)]
        self._paint_strip(snap, rows)
        # the ONE decision list, all sources: the page no longer reads
        # reviewer-only digest asks when the daemon publishes its own
        # pending list - both count the way the pill counts
        self._paint_asks(self._need_specs(snap))
        self._paint_blocked(rows)
        self._paint_armor()
        self._paint_watch(snap.get("browser_watch"))
        self._band_floor_paint()
        self._ensure_probe()

    def _pending_specs(self, snap):
        """The published pending list (the ONE list the pill counts),
        each row as (spec, ts); the reviewer-only digest asks are the
        fallback for an older daemon that has not published yet."""
        rows = snap.get("pending_list")
        if rows is None:
            rows = (snap.get("defense") or {}).get("asks")
        out = []
        for item in (rows if isinstance(rows, list) else []):
            spec = item.get("spec") if isinstance(item, dict) else None
            ts = str(item.get("ts", "")) if isinstance(item, dict) else ""
            if isinstance(spec, dict) and spec.get("id"):
                out.append((spec, ts))
        return out

    def _need_specs(self, snap):
        """The pending rows that actually need the user: the ones that
        carry an answer button. A spec without options is not an ask
        this page can serve, and one of those never inflates the count."""
        out = []
        for spec, ts in self._pending_specs(snap):
            if [o for o in (spec.get("options") or [])
                if isinstance(o, dict) and o.get("helper")]:
                out.append((spec, ts))
        return out

    # -- the verdict strip -------------------------------------------------
    def _paint_strip(self, snap, rows):
        """The wall verdict, owner fw-A: glyph + "Wall up" + the counts
        sentence + the psad age line. The strip reports the published
        digest only - the armor chips below carry the probe truth."""
        n_blocked = sum(1 for r in rows if r.get("ip"))
        n_need = len(self._need_specs(snap))
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.add_css_class("gw-card")
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        glyph = Gtk.Label(label="●", xalign=0)
        glyph.add_css_class("gw-pill")
        glyph.add_css_class("warn" if n_need else "ok")
        head = Gtk.Label(label="Wall up", xalign=0)
        head.add_css_class("gw-headline")
        head.set_hexpand(True)
        counts = Gtk.Label(
            xalign=0,
            label=(f"{n_blocked} blocked - " + ("1 needs you"
                    if n_need == 1 else f"{n_need} need you")))
        counts.add_css_class("gw-meta")
        top.append(glyph)
        top.append(head)
        top.append(counts)
        card.append(top)
        age = Gtk.Label(xalign=0, wrap=True)
        age.add_css_class("gw-meta")
        age.set_text(self._strip_age_text(snap))
        card.append(age)
        self._strip.append(card)
        self._strip_glyph = glyph
        self._strip_head = head
        self._strip_counts = counts
        self._strip_age = age

    @staticmethod
    def _psad_last(snap):
        """The newest psad word in the published feed - the page's own
        'live' reading of the inbound chain."""
        last = None
        for ev in (snap.get("recent") or []):
            if (isinstance(ev, dict)
                    and str(ev.get("from_tool", "")) == "psad"):
                ts = str(ev.get("ts") or "")
                if ts and (last is None or ts > last):
                    last = ts
        return last

    @staticmethod
    def _age_words(ts):
        """How long ago a feed row is, in spoken units ('1 h'); None
        never reaches here."""
        try:
            when = _dt.datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return "a while"
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        mins = max(0, int((_dt.datetime.now(_dt.timezone.utc)
                           - when).total_seconds() // 60))
        if mins < 1:
            return "moments"
        if mins < 60:
            return f"{mins} min"
        if mins < 60 * 24:
            return f"{mins // 60} h"
        return f"{mins // (60 * 24)} d"

    def _strip_age_text(self, snap):
        """One honest line: the digest's own age (the stale law's
        clause when the 90 s window is out) plus the psad age."""
        from ui.homepage import STALE_S
        parts = []
        updated = str(snap.get("updated") or "")
        when = None
        try:
            when = _dt.datetime.fromisoformat(updated)
        except (ValueError, TypeError):
            when = None
        if when is not None:
            if when.tzinfo is None:
                when = when.replace(tzinfo=_dt.timezone.utc)
            stamp = when.astimezone().strftime("%H:%M")
            span = max(0.0, (_dt.datetime.now(_dt.timezone.utc)
                             - when).total_seconds())
            tail = f"snapshot {stamp} · {int(span)} s ago"
            if span > STALE_S:
                tail += " - waiting for the daemon"
            parts.append(tail)
        last = self._psad_last(snap)
        if last:
            parts.append(f"psad spoke {self._age_words(last)} ago")
        else:
            parts.append("psad has not spoken in this window")
        return " · ".join(parts)

    # -- helpers shared by the cards ---------------------------------------
    def _quiet(self, host, text):
        lbl = Gtk.Label(label=text, xalign=0, wrap=True)
        lbl.add_css_class("gw-meta")
        host.append(lbl)

    def _run(self, btn, opt):
        w = self._win
        if w is not None and hasattr(w, "_run_log_option"):
            w._run_log_option(btn, dict(opt))

    # -- blocked addresses ---------------------------------------------------
    def _paint_blocked(self, rows):
        shown = [r for r in rows if r.get("ip")]
        if not shown:
            self._quiet(self._blocked, "Nothing is blocked right now.")
            return
        for row in shown:
            self._blocked.append(self._blocked_row(row))

    def _blocked_row(self, row):
        """One blocked row, fw-A: the address, WHY it is held, and its
        own Unblock through the lift-block lane. A row with no address
        (junk the digest could never produce but a caller might) carries
        no button."""
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
        if _ipv4_ok(ip):
            row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                              spacing=8)
            b = Gtk.Button(label="Unblock")
            b.add_css_class("gw-danger")
            b.connect("clicked", self._run,
                      {"id": "unblock", "label": "Unblock",
                       "tone": "danger", "helper": "lift-block",
                       "args": [ip]})
            row_box.append(b)
            card.append(row_box)
        return card

    # -- the decisions card ------------------------------------------------
    def _paint_asks(self, asks):
        """The one decisions card (fw-A): every published ask that waits
        renders its own card through the same machinery as the
        decisions window, and the card glows - the page's attention
        target while an answer is owed."""
        from ui.decisionlist import card_widget
        from ui import guided
        if not asks:
            self._quiet(self._asks, "Nothing is waiting for your answer.")
            return
        for spec, ts in asks:
            card = card_widget(spec, ts, self._on_answer)
            card._spec_id = str(spec["id"])     # the stable handoff key
            card.add_css_class(guided._PULSE)
            self._asks.append(card)

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
                rc, err = _helper_exec(opt.get("helper"),
                                       list(opt.get("args", [])))
            except Exception:
                rc, err = -1, ""
            from gi.repository import GLib
            GLib.idle_add(self._after_answer, sid, opt, buttons, state,
                          rc, err)

        threading.Thread(target=work, daemon=True).start()

    def _after_answer(self, sid, opt, buttons, state, rc, err=""):
        from gi.repository import GLib
        self._answering.discard(sid)
        if rc == 0:
            import pathlib as _pl
            from ui.decisionlist import RECORD_NOTE, answer_record
            data_dir = getattr(self._win, "data_dir", None) or _pl.Path(
                os.environ.get("GW_DATA") or "/var/lib/greywatch")
            done = answer_record(data_dir, sid, opt["id"])
            # The action ran; only a failed write-down may say so - the
            # card stays pending so the answer can still be recorded.
            state.set_text("Recorded. The ledger keeps your answer."
                           if done else
                           f"{opt.get('helper')} did finish, but "
                           f"{RECORD_NOTE}.")
        else:
            for b in buttons:
                b.set_sensitive(True)
            state.set_text(f"{opt.get('helper')} did not finish "
                           f"({helper_detail(rc, err)}). You can try "
                           "again.")
        return GLib.SOURCE_REMOVE

    # -- browser watch panel ------------------------------------------------
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

    # -- armor: the one chip line ------------------------------------------
    def _probe_snapshot(self):
        """The freshest cached (psad, arp) read, or None when no probe
        round has landed in this app run."""
        if _PROBE_CACHE.get("psad") is None:
            return None
        return (dict(_PROBE_CACHE.get("psad") or {}),
                dict(_PROBE_CACHE.get("arp") or {}))

    def _ensure_probe(self):
        """Kick one worker probe round while the cache is older than the
        TTL. The UI thread never waits on it - refresh has already
        painted - and this view's own round in flight (or a read younger
        than the TTL) never spawns a second one."""
        t = getattr(self, "_probe_thread", None)
        if t is not None and t.is_alive():
            return
        if time.time() - float(_PROBE_CACHE.get("when") or 0.0) < PROBE_TTL:
            return
        self._probe_thread = threading.Thread(target=self._probe_work,
                                              daemon=True)
        self._probe_thread.start()

    def _probe_work(self):
        """Worker: the two subprocess probes, off the UI thread."""
        try:
            psad, arp = psad_status(), arp_status()
        except Exception:
            psad, arp = {}, {}
        _PROBE_CACHE.update(when=time.time(), psad=dict(psad),
                            arp=dict(arp))
        try:
            GLib.idle_add(self._after_probe, dict(psad), dict(arp))
        except (RuntimeError, TypeError):
            pass                    # no main loop left; the cache keeps it

    def _after_probe(self, psad, arp):
        """Back on the UI thread: the chip line repaints from the fresh
        read. Nothing else on the page moves - the digest feed is its
        own paint."""
        from ui.decisionlist import _clear
        try:
            _clear(self._armor)
            self._paint_armor()
        except (RuntimeError, TypeError):
            pass                    # the page died mid-read; nothing lies
        try:
            return GLib.SOURCE_REMOVE
        except (RuntimeError, TypeError):
            return False

    def _paint_armor(self):
        """The armor chain as ONE chip line (owner fw-A): psad,
        nftables, arpwatch - the words good / open / cannot read, an
        all-green line only when every probe answers True, and the
        arming buttons where a chain is not standing. No cached read
        yet means the honest probing line, never green."""
        cached = self._probe_snapshot()
        wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        wrap.add_css_class("gw-armor")
        self._armor.append(wrap)
        if cached is None:
            self._quiet(wrap, "Probing psad, nftables and arp - the"
                        " chips fill in when the read lands.")
            self._paint_watchlist()
            return
        psad, arp = cached
        psad_state = _group_state(psad.get("armed"), psad.get("service"),
                                  psad.get("fed"))
        nft_state = psad.get("table")
        arp_state = _group_state(arp.get("pinned"), arp.get("sysctls"))
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        wrap.append(row)
        for label, state in (("psad", psad_state),
                             ("nftables", nft_state),
                             ("arpwatch", arp_state)):
            chip = Gtk.Button(label=f"{label}: {self._ARMOR_WORDS[state]}",
                              sensitive=False)
            chip.add_css_class(self._ARMOR_CLASSES[state])
            if label == "arpwatch":
                chip.set_tooltip_text(
                    "the arp hardening lane (hardening-arp): the"
                    " router's address stays permanent and the reply"
                    " sysctls stay closed")
            row.append(chip)
        if psad_state is True and nft_state is True and arp_state is True:
            note = Gtk.Label(xalign=0)
            note.set_text("all green - the chain is standing")
            note.add_css_class("gw-armor-good")
            wrap.append(note)
        else:
            acts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            wrap.append(acts)
            if psad_state is not True or nft_state is not True:
                self._arm_button(acts, "Arm psad", "psad-tune")
            if arp_state is not True:
                self._arm_button(acts, "Arm ARP", "hardening-arp")
        self._paint_watchlist()

    def _arm_button(self, host, label, helper):
        """The chain's own fix, next to the chips: only a group that is
        open or unreadable gets one, a standing chain gets nothing."""
        b = Gtk.Button(label=label)
        b.add_css_class("gw-primary")
        b.set_tooltip_text(
            f"apply/{helper}.sh stands the chain up through the apply"
            " lane; you will be asked for your password.")
        b.connect("clicked", self._run,
                  {"id": "arm", "label": label, "tone": "primary",
                   "helper": helper, "args": []})
        host.append(b)

    # -- watchlist panel (under the chip line) ------------------------------
    def _paint_watchlist(self):
        """The Patch the Planet watch rows, under the armor pack: the
        program's public map matched to what is installed on this box.
        The coverage file is the daemon's; the page never runs a package
        listing, and a missing map reads as 'never fetched', not as
        'nothing is covered'. Each row opens the project's map rows in a
        dialog, and the head carries the last watch stamp plus the user
        refresh channel."""
        dd = getattr(self._win, "data_dir", "") or "."
        rows = ptp_rows(dd)
        stamp = ptp_watch_stamp(dd)
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cap = ("Patch the Planet watchlist: code the world's AI-assisted"
               " reviewers are covering is installed here")
        if stamp:
            cap += f" - watchlist read {stamp}"
        meta = Gtk.Label(label=cap, xalign=0, wrap=True)
        meta.add_css_class("gw-meta")
        meta.set_hexpand(True)
        head.append(meta)
        head.append(Gtk.Button(label="Refresh map"))
        head.append(Gtk.Button(label="Explain"))
        self._armor.append(head)
        ask_btn = head.get_last_child()          # appended last
        refresh_btn = ask_btn.get_prev_sibling()
        refresh_btn.set_tooltip_text(
            "Read the public dashboard map now; coverage matching "
            "catches up either way on the daemon's next cycle.")
        refresh_btn.connect("clicked", self._refresh_watch)
        ask_btn.set_tooltip_text(
            "Open the assistant with a watchlist question; it answers "
            "from this machine's own watch file.")
        ask_btn.connect("clicked", self._ask_watch_explain)
        if rows is None:
            self._quiet(self._armor,
                        f"The {DASH_PROSE} watchlist has never been"
                        " read; the refresh above or the daemon arms"
                        " this section.")
            return
        if not rows:
            # GW-B2: an unreadable package channel means coverage is
            # UNKNOWN, not empty - the old sentence would have said
            # "nothing covered" over a probe that never answered.
            failed = ptp_probe_failed(dd)
            if failed:
                self._quiet(self._armor,
                            f"The package channel could not be read "
                            f"({', '.join(failed)}), so the watchlist's "
                            "coverage of this machine is UNKNOWN - "
                            "nothing was invented.")
            else:
                self._quiet(self._armor,
                            "The watchlist has been read, and nothing this"
                            " machine runs is inside the review map.")
            return
        for cov in rows:
            if not isinstance(cov, dict) or not cov.get("project"):
                continue
            pkg = ", ".join(cov.get("packages") or [])
            txt = ((f"{cov.get('project')} (as {pkg}): " if pkg else
                    f"{cov.get('project')}: ")
                   + f"{cov.get('findings', 0)} public findings"
                   + (f", {cov.get('high', 0)} HIGH" if cov.get("high") else "")
                   + " - verify the installed version when the"
                     " keeper chooses to")
            btn = Gtk.Button()
            btn.set_tooltip_text(
                f"Show the map rows for {cov.get('project')}")
            face = Gtk.Label(label=escape(txt), xalign=0, wrap=True)
            face.add_css_class("gw-meta")
            btn.set_child(face)
            btn.connect("clicked", self._open_project_cover,
                        str(cov.get("project")))
            self._armor.append(btn)

    def _project_findings(self, data_dir, project) -> list:
        """Every map row for one project, from the freshest map the
        machine has (runtime refresh, then the shipped snapshot)."""
        if not project:
            return []
        return [r for r in ptp_load_map(pathlib.Path(data_dir))
                if isinstance(r, dict) and r.get("project") == project]

    def _open_project_cover(self, _btn, project):
        """The project's own slice of the public map, in a dialog with
        its own scroll (the page stays short; the drill-down is on
        demand). Severity words read straight from the map."""
        findings = self._project_findings(
            getattr(self._win, "data_dir", "") or ".", project)
        dialog = Gtk.Dialog(title=f"{project} in the program's map",
                            transient_for=self.get_root(), modal=False)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        dialog.set_default_size(*metrics.dialog_size())
        body = dialog.get_content_area()
        body.set_margin_top(12)
        body.set_margin_bottom(12)
        body.set_margin_start(18)
        body.set_margin_end(18)
        body.set_spacing(8)
        head_text = (f"{project}: {len(findings)} findings in the map the"
                     " world's AI-assisted reviewers publish. This is"
                     " their coverage, not a scan of this machine."
                     if findings else
                     f"{project}: the program's map could not be read"
                     " just now, so the project's rows are unavailable.")
        head = Gtk.Label(xalign=0, wrap=True)
        head.set_xalign(0)
        head.set_text(head_text)
        head.add_css_class("gw-page-meta")
        body.append(head)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        for f in findings:
            sev = str(f.get("severity") or "-").upper()
            chip = Gtk.Label(label=sev)
            chip.add_css_class("gw-sev")
            chip.set_size_request(84, -1)
            text = Gtk.Label(
                label=str(f.get("finding") or "")
                + (f" ({f.get('status')})" if f.get("status") else ""),
                xalign=0, wrap=True)
            text.set_hexpand(True)
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            row.append(chip)
            row.append(text)
            box.append(row)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        scroll.set_child(box)
        body.append(scroll)
        dialog.connect("response", lambda d, _r: d.destroy())
        dialog.present()

    def _ask_watch_explain(self, _btn=None):
        """Route a real watchlist question to the assistant: the same
        channel any other page uses, answered from the machine's own
        watch file rather than from the page's guesses."""
        w = self._win
        if w is not None and hasattr(w, "_ask_assistant"):
            w._ask_assistant(
                "explain the Patch the Planet watchlist and whether "
                "this machine is covered")

    def _refresh_watch(self, btn):
        """The user-side refresh channel: the map refetch runs in a child
        process (same channel as a CVE refresh elsewhere), never on the
        UI thread, and coverage matching catches up on the daemon's next
        cycle in any case."""
        if getattr(self, "_watch_busy", False):
            return
        self._watch_busy = True
        btn.set_sensitive(False)
        btn.set_label("reading the map…")

        def work():
            try:
                from ui.updates import refresh_ptp
                rc = refresh_ptp()[0]
            except Exception:
                rc = -1
            from gi.repository import GLib
            GLib.idle_add(self._after_watch_refresh, rc)
            return False

        threading.Thread(target=work, daemon=True).start()

    def _after_watch_refresh(self, rc):
        from ui.decisionlist import _clear
        self._watch_busy = False
        _clear(self._armor)
        self._paint_armor()
        if rc == 0:
            self._quiet(self._watch, "The map was read again; fresh"
                        " coverage follows on the daemon's next cycle.")
        else:
            self._quiet(self._watch, f"The map refresh did not finish"
                        f" (exit code {rc}); the old map stands.")
        return False
