"""The Harden page (rebuild round 2, task 11, owner h1): the endpoint
baseline as a flat, self-applying checklist over one hardening-score
band.

What the owner verified for this variant:
  - ONE score band at the page top: the percent of the checks this page
    can change that already sit at baseline (an unreadable check counts
    as not earned, advisory rows never score), banded ok / warn / fail.
  - ONE flat checklist: every open row carries its own real fix button
    through the EXISTING harden changeset lane (the same verby_args ->
    planfile -> harden.sh apply contract the batch Apply always used),
    the row states what happened ("applied changeset ..."), and a
    resolved row collapses to one line. Manual changes say so instead of
    shipping a button that cannot work.
  - The dock: Profile (recommended / strict / paranoid - honest radios:
    the control set ships as ONE baseline and no profile lane exists,
    so they stay disabled with their reason) and Recheck (the recheck-
    after-apply the apply lane already runs, toggled off only by choice).
Nothing new can act on the machine: the polkit helper, the verby
allowlist and the journal are the same code as before this rebuild.
"""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib    # noqa: E402

from hardening import detector
from hardening.apply import build_plan, GREEN, RED, AMBER, ALLOWED_VERBS
from hardening.detector import cve_note
from hardening.journal import read_latest
from ui.models import MARK_BY_SEVERITY  # noqa: F401  (severity tags)
from ui.plain import (escape, ink as pc_ink, soft as pc_soft,
                      muted as pc_muted, warn as pc_warn,
                      ok as pc_ok, fail as pc_fail)

ROOT = pathlib.Path(__file__).resolve().parents[1]
from gwpaths import data_dir as _gw_data
DATA_DIR = _gw_data()          # state: journal, CVE cache
CONTROL_DIR = ROOT / "data"    # the control definitions ship with the app
JOURNAL_PATH = DATA_DIR / "hardening-journal.jsonl"


def verby_args(fix) -> dict:
    if not fix:
        return {}
    step = fix[0]
    if isinstance(step, str):
        parts = step.split(None, 1)
        verb, args = parts[0], parts[1:]
    else:
        verb, args = str(step[0]), [str(a) for a in step[1:]]
    if verb not in ALLOWED_VERBS:
        return {}
    if verb == "sh":
        return {"verb": "sh", "cmd": " ".join(args)}
    if verb == "sysctl-set" and len(args) >= 2:
        return {"verb": "sysctl-set", "key": args[0], "value": args[1]}
    if verb == "service-off" and len(args) >= 1:
        return {"verb": "service-off", "unit": args[0]}
    if verb in ("pkg-upgrade", "pending-restarts"):
        return {"verb": verb}
    if verb == "pkg-install" and len(args) >= 1:
        return {"verb": "pkg-install", "package": args[0]}
    if verb == "restart-units" and len(args) >= 1:
        return {"verb": "restart-units", "units": args[0]}
    if verb == "unit-install" and len(args) >= 2:
        if "{{unit}}" in args[0] or "{{unit}}" in args[1] \
                or args[1] == "TRANCHE":
            return {"verb": "unit-install", "unresolvable": True}
        return {"verb": "unit-install", "path": args[0], "text": args[1]}
    return {}


def planfile_entries(plan, controls) -> tuple[list[dict], list[dict]]:
    probe_by_id = {getattr(c, "id", ""): c for c in (controls or [])}
    entries, skipped = [], []
    for e in plan:
        got = verby_args(e.get("fix"))
        if not got or got.pop("unresolvable", False):
            skipped.append(e)
            continue
        got["id"] = e["id"]
        got["probe"] = getattr(probe_by_id.get(e["id"]), "probe", "") or ""
        got["probe_invert"] = bool(
            getattr(probe_by_id.get(e["id"]), "probe_invert", False))
        entries.append(got)
    return entries, skipped


def parse_apply_output(stdout: str) -> dict[str, str]:
    colors: dict[str, str] = {}
    for line in (stdout or "").splitlines():
        tok = line.split()
        if len(tok) == 3 and tok[0] == "VERBIFY":
            verb_rc = tok[2]
            colors[tok[1]] = AMBER if verb_rc == "none" \
                else (GREEN if verb_rc == "0" else RED)
        elif len(tok) == 3 and tok[0] == "APPLY" and tok[2] != "0":
            colors[tok[1]] = colors.get(tok[1], AMBER)
        elif len(tok) == 2 and tok[0] in ("ROLLBACK", "ROLLBACK-FAILED",
                                          "ROLLBACK-SKIP"):
            colors[tok[1]] = RED
    return colors


def hardening_score(findings, controls) -> tuple[int, str]:
    """The hardening percent and its band tone, from the checklist's own
    counts: the share of countable checks that already sit at baseline.

    Advisory rows never score (the suite never applies them); a check
    that could not be read counts as not earned, never as earned. Bands
    are the owner's law: >= 80 ok, 40-79 warn, < 40 fail; no countable
    check at all is "idle" instead of a lying 0%."""
    advisory_ids = {getattr(c, "id", "") for c in (controls or [])
                    if bool(getattr(c, "advisory", False))}
    counted = [f for f in (findings or [])
               if f.control_id not in advisory_ids]
    total = len(counted)
    if not total:
        return 0, "idle"
    at = sum(1 for f in counted if f.state == detector.PASS)
    pct = round(100.0 * at / total)
    tone = "ok" if pct >= 80 else ("warn" if pct >= 40 else "fail")
    return pct, tone


_VERB_LABEL = {
    "pkg-upgrade": "Apply package updates",
    "pkg-install": "Install the package",
    "sysctl-set": "Tighten the setting",
    "service-off": "Stop the service and turn it off at boot",
    "restart-units": "Restart the services",
    "sh": "Run this change",
}

_PROFILE_TIP = ("no profile lane yet: the control set ships as ONE "
                "recommended baseline, so these stay off until a "
                "reshape-the-checklist-by-profile lane exists")

_RECHECK_TIP = ("After a row's own fix the checks re-run, so the fixed "
                "row collapses to resolved and the score recomputes; "
                "turn off to keep the row's result line in place "
                "instead. The batch Apply always re-verifies.")

_RECHECK_NOTE = ("the score updates only on a recheck")

_APPLY_WORDS = {
    "GREEN": "fixed and verified",
    "RED": "the change did not hold (it rolled back)",
    "AMBER": "applied, not re-verified yet",
}


class HardenPage(Gtk.Box):

    def __init__(self, win=None, controls=None, runner=None, helper=None,
                 journal_path=None, cve_cache=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,
                         spacing=12)
        self.set_margin_top(26); self.set_margin_start(34)
        self.set_margin_end(34); self.set_margin_bottom(20)
        self._win = win              # reuse the window's heading helpers
        self._controls = controls    # injected (tests): a Control list
        self._runner = runner or detector.prod_runner
        self._helper = helper        # injected (tests): (args) -> (rc, out)
        self._journal = journal_path or JOURNAL_PATH
        self._cve_cache = cve_cache  # injected (tests); else read at scan
        self._findings = []
        self._scanned = False
        self._scanned_controls = []
        self._dead = False
        self._score_stale = False
        self._row_results: dict[str, Gtk.Label] = {}
        # The wording of the last apply per control — it survives the
        # recheck's row rebuild, so a fixed row keeps saying what its
        # apply did even after collapsing to one line.
        self._row_last_result: dict[str, str] = {}
        self.connect("destroy", self._on_dead)

        self.append(self._h1("Endpoint Hardening"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        # Theme tokens, not an inline span: the page lede used to hard-code
        # Inter at 13px, which ignored whichever theme was active (design
        # pass.
        intro.set_text("Baseline checks test this computer's security "
                       "settings. Each open row can apply its own fix in "
                       "place; nothing runs until you press it.")
        intro.add_css_class("gw-page-meta")
        intro.set_tooltip_text(
            "Each row shows where one check stands; its button runs the "
            "one change through the root lane and says what happened.")
        self.append(intro)

        # 1. the score band: one progress bar, the number beside it
        band = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.score_label = Gtk.Label(xalign=0)
        self.score_label.set_xalign(0)
        self.score_label.set_valign(Gtk.Align.CENTER)
        _score_tip = ("Percent of the checks this page can change that "
                      "already sit at baseline; a check that could not be "
                      "read counts as not earned and advisory rows never "
                      "score. Bands: 80+ good, 40-79 mid, under 40 low.")
        self.score_label.set_tooltip_text(_score_tip)
        self.score_label.add_css_class("gw-page-meta")
        band.append(self.score_label)
        self.score_bar = Gtk.ProgressBar()
        self.score_bar.add_css_class("gw-scanbar")
        self.score_bar.set_hexpand(True)
        self.score_bar.set_valign(Gtk.Align.CENTER)
        self.score_bar.set_tooltip_text(_score_tip)
        band.append(self.score_bar)
        self.append(band)
        self._paint_score()

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.status = Gtk.Label(xalign=0)
        self.status.set_xalign(0)
        self.status.set_hexpand(True)
        self.status.set_wrap(True)
        self.status.set_max_width_chars(64)
        self.status.set_text("Not run yet.")
        row.append(self.status)
        self.scan_btn = Gtk.Button(label="Run baseline checks")
        self.scan_btn.add_css_class("gw-primary")
        self.scan_btn.connect("clicked", self._on_scan)
        row.append(self.scan_btn)
        self.apply_btn = Gtk.Button(label="Apply all open")
        self.apply_btn.set_sensitive(False)
        self.apply_btn.connect("clicked", self._on_apply)
        row.append(self.apply_btn)
        self.undo_btn = Gtk.Button(label="Undo last change")
        self.undo_btn.set_sensitive(False)
        self.undo_btn.connect("clicked", self._on_undo)
        row.append(self.undo_btn)
        self.append(row)

        # Pending restarts after an update. Hidden until an update action
        # asks the helper what is still holding old libraries.
        self.restart_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                                   spacing=10)
        self.restart_box.set_visible(False)
        self.restart_banner = Gtk.Label(xalign=0)
        self.restart_banner.set_xalign(0)
        self.restart_banner.set_wrap(True)
        self.restart_banner.set_hexpand(True)
        self.restart_btn = Gtk.Button(label="Restart those services")
        self.restart_btn.add_css_class("gw-cta")
        self.restart_btn.connect("clicked", self._on_restart_services)
        later_btn = Gtk.Button(label="Leave them until later")
        later_btn.connect(
            "clicked", lambda _b: self.restart_box.set_visible(False))
        self.restart_box.append(self.restart_banner)
        self.restart_box.append(self.restart_btn)
        self.restart_box.append(later_btn)
        self.restart_units: list[str] = []
        self.append(self.restart_box)

        # Until a scan runs, the checklist area is empty; a blank
        # half-screen read as a broken page. One sentence says what will
        # appear here.
        self.empty = Gtk.Label(xalign=0)
        self.empty.set_xalign(0)
        self.empty.set_wrap(True)
        self.empty.set_valign(Gtk.Align.START)
        self.empty.add_css_class("gw-meta")
        self.empty.set_text(
            "Every setting this computer is checked against gets one row "
            "here, in order: where it stands and, when it is open, its "
            "own fix button. Press Run baseline checks to fill them in.")
        self.append(self.empty)

        # 2. THE flat checklist: one row per check, and the page's ONE
        # inner-scrolled container (window-fit law: the chrome fits and
        # the rows scroll; the page never scrolls as a whole).
        self.rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.rows_scroll = Gtk.ScrolledWindow()
        self.rows_scroll.set_name("harden-rows")
        self.rows_scroll.set_policy(Gtk.PolicyType.NEVER,
                                    Gtk.PolicyType.AUTOMATIC)
        self.rows_scroll.set_vexpand(True)
        self.rows_scroll.set_child(self.rows)
        self.append(self.rows_scroll)

        self.append(self._h2("Verification"))
        self.verify_label = Gtk.Label(xalign=0)
        self.verify_label.set_xalign(0)
        self.verify_label.set_wrap(True)
        self.verify_label.set_text("Nothing applied in this session yet.")
        self.append(self.verify_label)
        self._refresh_undo()
        self._build_dock()

    # ------------------------------------------------------------- dock
    def _build_dock(self) -> None:
        """The dock controls (built once; DockHost claims them). Profile
        is honest exactly because the machinery has no profile lane; the
        recheck toggle gates the one rescan the apply lane already runs."""
        self._profile_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                    spacing=4)
        pick = None
        for word in ("recommended", "strict", "paranoid"):
            rb = Gtk.CheckButton(group=pick, label=word)
            rb.set_sensitive(False)
            rb.set_tooltip_text(_PROFILE_TIP)
            self._profile_box.append(rb)
            pick = pick or rb
        self._profile_note = Gtk.Label(xalign=0)
        self._profile_note.set_xalign(0)
        self._profile_note.set_wrap(True)
        self._profile_note.add_css_class("gw-meta")
        self._profile_note.set_text(
            "the shipped set is one recommended baseline")
        self._recheck = Gtk.CheckButton(label="Recheck after apply")
        self._recheck.set_active(True)     # the apply lane rechecks by law
        self._recheck.set_tooltip_text(_RECHECK_TIP)

    def dock_groups(self):
        """("Title", [widgets]) groups for the fixed right dock."""
        return [("Profile", [self._profile_box, self._profile_note]),
                ("Recheck", [self._recheck,
                             Gtk.Label(label=_RECHECK_NOTE, xalign=0)])]

    # -------------------------------------------------------- headings
    def _h1(self, text):
        if self._win is not None:
            return self._win._h1(text)
        return HardenPage._static_h1(text)

    def _h2(self, text):
        if self._win is not None:
            return self._win._h2(text)
        return HardenPage._static_h2(text)

    @staticmethod
    def _static_h1(text):
        l = Gtk.Label(xalign=0)
        l.set_xalign(0)
        l.set_wrap(True)
        l.set_markup(f"<span size='18000' font_family='Barlow Condensed' "
                     f"weight='600'>{escape(text)}</span>")
        return l

    @staticmethod
    def _static_h2(text):
        l = Gtk.Label(xalign=0)
        l.set_xalign(0)
        l.set_wrap(True)
        l.set_markup(f"<span size='13000' font_family='Barlow Condensed' "
                     f"weight='600'>{escape(text)}</span>")
        return l

    # ---------------------------------------------------------- the bar
    def _set_score_tone(self, tone):
        for cls in ("ok", "warn", "fail", "idle"):
            self.score_bar.remove_css_class(cls)
        self.score_bar.add_css_class(tone)

    def _paint_score(self):
        if not self._scanned:
            self._set_score_tone("idle")
            self.score_bar.set_fraction(0.0)
            self.score_label.set_text("Hardening score: not scored yet")
            return
        pct, tone = hardening_score(self._findings, self._scanned_controls)
        self._set_score_tone(tone)
        self.score_bar.set_fraction(pct / 100.0)
        text = f"Hardening score: {pct}%"
        if self._score_stale:
            text += " - changes applied, recheck to rescore"
        self.score_label.set_text(text)

    # ---------------------------------------------------------- the scan
    def _on_scan(self, _btn):
        self.status.set_text("Running baseline checks (a few seconds)…")
        self.apply_btn.set_sensitive(False)
        self.scan_btn.set_sensitive(False)   # one scan at a time
        try:
            if self._controls is not None:     # injected (tests)
                controls = list(self._controls)
            else:
                from hardening.controls import load_controls
                # The definitions are part of the program, not of the
                # state directory: reading them from /var/lib found an
                # empty list on every real install and the page reported
                # "0 checks done".
                controls = load_controls(CONTROL_DIR) \
                    or load_controls(DATA_DIR)
        except Exception:
            controls = []
        if self._cve_cache is None:
            self._cve_cache = self._load_cve_cache()

        def worker():
            findings = None
            try:
                findings = detector.scan(controls, self._runner)
            except Exception as exc:              # never kill the UI
                findings = None
                GLib.idle_add(self._scan_failed, str(exc))
            GLib.idle_add(self._scan_done, findings, controls)
        threading.Thread(target=worker, daemon=True).start()

    def _on_dead(self, *_a):
        self._dead = True
        return False

    def _focus_primary(self):
        """One accent per view: whichever action comes next.

        Before a scan the accent sits on Run baseline checks; the moment
        there is something to apply it moves to Apply and Run drops back to
        a neutral fill, so the beige never becomes wallpaper."""
        apply_next = bool(self.apply_btn.get_sensitive())
        for btn, on in ((self.apply_btn, apply_next),
                        (self.scan_btn, not apply_next)):
            btn.remove_css_class("gw-primary")
            btn.remove_css_class("gw-cta")
            btn.add_css_class("gw-primary" if on else "gw-cta")

    def _scan_failed(self, msg):
        if self._dead:
            return False
        self.scan_btn.set_sensitive(True)
        fail_reason = f"The scan could not run: {msg}."
        fail_effect = ("Nothing was checked or applied. Apply stays "
                       "off until a scan runs.")
        self.status.set_text(fail_reason + " " + fail_effect)
        self._focus_primary()
        return False

    def _scan_done(self, findings, controls):
        if self._dead:
            return False
        self.scan_btn.set_sensitive(True)
        self._score_stale = False
        if findings is None:                 # failed scan: never look empty
            self._scanned = False
            self._findings = []
            self.apply_btn.set_sensitive(False)
            self.verify_label.set_text(
                "The scan failed. Nothing was checked. Run the checks "
                "again.")
            self._paint_score()
            self._focus_primary()
            return False
        self._findings = findings
        self._scanned = True
        self.empty.set_visible(not bool(findings))
        self._scanned_controls = list(controls)
        self._row_results = {}
        by_id = {getattr(c, "id", ""): c for c in controls}
        while True:
            child = self.rows.get_first_child()
            if child is None:
                break
            self.rows.remove(child)
        cant = [f for f in findings if f.state == detector.CANT]
        # Advisory rows are information only. build_plan never applies
        # them, so they must not count as gaps or hold Apply open:
        # counting them made Apply look broken on a machine whose only
        # "gaps" were advisory. An unknown state is
        # likewise never applied, but an advisory one going unknown must
        # not hold the whole panel hostage.
        advisory_ids = {getattr(c, "id", "") for c in controls
                        if bool(getattr(c, "advisory", False))}
        gating = [f for f in cant if f.control_id not in advisory_ids]
        gaps = [f for f in findings if f.state == detector.GAP
                and f.control_id not in advisory_ids]
        manual_ids = set()
        for f in gaps:
            got = verby_args(getattr(by_id.get(f.control_id), "fix", []))
            if not got or got.get("unresolvable"):
                manual_ids.add(f.control_id)
        for fnd in findings:
            self.rows.append(self._row(
                fnd, by_id.get(fnd.control_id),
                manual=fnd.control_id in manual_ids))
        n = len(findings)
        n_gap = len(gaps)
        n_manual = len(manual_ids)
        auto = n_gap - n_manual
        if gating:
            text = (f"{n} checks: {n_gap} gap(s) to tighten, {len(cant)} "
                    f"could NOT be checked. Applying stays off until every "
                    f"check can run.")
        else:
            if not n_gap:
                text = (f"{n} checks done: every changeable check already "
                        "passes.")
            elif auto and n_manual:
                text = (f"{n} checks done: {auto} gap(s) would be "
                        f"tightened, {n_manual} need(s) a change the helper "
                        "cannot make.")
            elif auto:
                text = (f"{n} checks done: {auto} gap(s) each row can "
                        "tighten in place.")
            else:
                text = (f"{n} checks done: {n_manual} gap(s) each need a "
                        "change the helper cannot make.")
            if advisory_ids:
                adv_n = len(advisory_ids)
                adv_words = ("row reports" if adv_n == 1
                             else "rows report")
                text += (f" {adv_n} advisory-only {adv_words} "
                         "information and are never applied")
                if cant:
                    text += (f"; {len(cant)} of them could NOT be checked "
                             "on this computer")
                text += "."
            if auto:
                text += " Press a row's own button, or Apply all open."
        self.status.set_text(text)
        if gating:
            self.apply_btn.set_tooltip_text(
                "Off because some checks could not run. An unknown state "
                "is never applied.")
        elif not auto:
            # Nothing here is the app's to change: either every check
            # already passes or the gaps need a person. A live Apply
            # button that can only report "nothing to apply" was read as
            # a failure.
            self.apply_btn.set_tooltip_text(
                "Off because there is nothing the app can change: every "
                "changeable check already passes.")
        else:
            self.apply_btn.set_tooltip_text("")
        self.apply_btn.set_sensitive(not gating and auto > 0)
        self._paint_score()
        self._focus_primary()
        return False

    # ------------------------------------------------------- the rows
    def _load_cve_cache(self) -> dict:
        try:
            raw = json.loads(
                (DATA_DIR / "cve-cache.json").read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            return {}

    def _cve_note_for(self, fnd, control) -> str:
        cache = self._cve_cache if isinstance(self._cve_cache, dict) else {}
        ids = [fnd.control_id] + list(
            getattr(control, "nist", None) or [])
        notes = [cve_note(x, cache) for x in ids]
        return "; ".join(dict.fromkeys(n for n in notes if n))

    def _row(self, fnd, control, manual=False):
        """One flat checklist row.

        A resolved row (already at baseline) collapses to ONE line - dot,
        state and subject - with no button and no body, so a healthy
        checklist reads in seconds. An open row carries its state, the
        subject's real wording and, when the allowlisted verbs can make
        the change, its own fix button whose result line lives on the
        row."""
        # The dot follows the CHECK RESULT, not the severity: a check
        # that already passes is good news and reads green; red is
        # reserved for a check that actually failed. A drawn dot in the
        # theme's status ink, not an emoji: emoji ignore the theme.
        advisory_flag = bool(getattr(control, "advisory", False))
        dot_ink = (pc_muted() if advisory_flag else
                   {detector.PASS: pc_ok(), detector.GAP: pc_warn(),
                    detector.FAIL: pc_fail(),
                    detector.CANT: pc_muted()}.get(fnd.state, pc_muted()))
        mark = f"<span foreground='{dot_ink}'>●</span>"
        words = {detector.PASS: "already at baseline",
                 detector.GAP: "NOT at baseline (would be tightened)",
                 detector.FAIL: "failed the check",
                 detector.CANT: "COULD NOT BE CHECKED"}.get(
                     fnd.state, fnd.state)
        advisory = advisory_flag
        if advisory:
            words = "ADVISORY (never applied)"
        elif manual:
            words = "NEEDS A MANUAL CHANGE (Apply cannot fix this one)"
        subject = (control.what if control is not None else fnd.control_id)
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        frame.dot_ink = dot_ink           # read by the UI tests
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(12); box.set_margin_bottom(12)
        box.set_margin_start(12); box.set_margin_end(12)
        collapsed = (fnd.state == detector.PASS
                     or (advisory and not getattr(control, "advisory_action",
                                                  None)))
        prior = self._row_last_result.get(fnd.control_id, "")
        if collapsed:
            head = Gtk.Label(xalign=0)
            head.set_xalign(0)
            head.set_wrap(True)
            line = f"{words} - {subject}"
            if prior:
                line += f" ({prior.rstrip('.')})"
            head.set_markup(
                f"<span size='13000' font_family='Inter'>{mark} "
                f"{escape(line)}</span>")
            box.append(head)
            frame.set_child(box)
            return frame
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        head.set_markup(
            f"<span size='15000' font_family='Inter'>{mark} "
            f"{escape(words)}</span>")
        box.append(head)
        body_text = fnd.note or subject
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        body.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_ink()}'>"
            + escape(body_text)
            + "</span>")
        box.append(body)
        cve_txt = self._cve_note_for(fnd, control)
        if cve_txt:
            note = Gtk.Label(xalign=0)
            note.set_xalign(0)
            note.set_wrap(True)
            note.set_markup(
                f"<span size='11000' font_family='Inter' "
                f"color='{pc_warn()}'>"
                + escape(cve_txt) + "</span>")
            box.append(note)
        tag_bits = [control.severity if control is not None else ""] \
            + [f"NIST {x}" for x in (control.nist or [])] \
            if control is not None else []
        tag_bits += [f"CIS {x}" for x in (control.cis or [])] \
            if control is not None else []
        tags = Gtk.Label(xalign=0)
        tags.set_xalign(0)
        tags.set_markup(
            f"<span size='11000' font_family='Inter' color='{pc_muted()}'>"
            + escape(" · ".join([fnd.control_id] + tag_bits))
            + "</span>")
        box.append(tags)
        if fnd.current:
            cur = Gtk.Label(xalign=0)
            cur.set_xalign(0)
            cur.set_wrap(True)
            cur.set_markup(
                f"<span size='11000' font_family='Inter' "
                f"color='{pc_soft()}'>"
                f"current: {escape(fnd.current[:200])}</span>")
            box.append(cur)
        # The row's own apply button follows the BATCH lane's law, not the
        # resolver's: a fix ships only on a GAP row, the one state the
        # batch Apply would actually plan. A FAIL or CANT-CHECK row says
        # its state honestly and ships NO button (the page's own tooltip
        # promises "an unknown state is never applied", so a row reading
        # COULD NOT BE CHECKED must never be able to write the sysctl).
        if not advisory and fnd.state == detector.GAP:
            fix_btn = self._row_fix_button(control)
            if fix_btn is not None:
                box.append(fix_btn)
                result = Gtk.Label(xalign=0)
                result.set_xalign(0)
                result.set_wrap(True)
                result.add_css_class("gw-meta")
                if prior:
                    result.set_text(prior)
                    result.set_visible(True)
                else:
                    result.set_visible(False)
                box.append(result)
                self._row_results[fnd.control_id] = result
        action_btn = self._action_button(control)
        if action_btn is not None:
            box.append(action_btn)
        frame.set_child(box)
        return frame

    _VERB_TIP = {
        "pkg-upgrade": "Upgrades every package with the safe flags - "
                       "nothing is removed and local config wins.",
        "pkg-install": "Installs the package the check is tested for.",
        "sysctl-set": "Writes one kernel setting through the root lane "
                      "and keeps the change in the journal.",
        "service-off": "Stops the service and turns it off at boot.",
        "sh": "Runs this one allowlisted command through the root lane.",
        "restart-units": "Restarts the units the check names.",
    }

    def _row_fix_button(self, control):
        """The row's own apply button, through the SAME changeset lane
        the batch Apply runs (verby_args + planfile + harden.sh apply).
        Controls whose fix is unresolvable (templates) or allowlist-empty
        never get a fake button - the row says a person is needed."""
        got = verby_args(getattr(control, "fix", []))
        if not got or got.get("unresolvable"):
            return None
        label = _VERB_LABEL.get(got["verb"], "Apply this fix")
        btn = Gtk.Button(label=label)
        btn.add_css_class("gw-cta")
        btn.set_halign(Gtk.Align.START)
        btn.set_tooltip_text(self._VERB_TIP.get(
            got["verb"], "Runs this one change through the root lane."))
        btn.connect("clicked", self._on_row_apply, control)
        return btn

    # -------------------------------------------------- row apply (h1)
    def _on_row_apply(self, _btn, control):
        self.status.set_text(
            "Applying this row. One password prompt, then the checks "
            "re-run…")
        _btn.set_sensitive(False)

        def worker():
            rc, out, err = -1, "helper failed", ""
            try:
                rc, out, err = self._run_steps(
                    control.id, getattr(control, "fix", []))
            except Exception as exc:              # never kill the UI
                err = f"helper failed: {exc}"
            GLib.idle_add(self._row_apply_done, control, rc, out, err)

        threading.Thread(target=worker, daemon=True).start()

    def _row_apply_done(self, control, rc, out, err):
        if self._dead:
            return False
        colors = parse_apply_output((out or "") + "\n" + (err or ""))
        color = colors.get(control.id, "")
        if rc == 0:
            meaning = _APPLY_WORDS.get(
                color, "the helper reported no results")
            line = f"applied changeset {control.id}: {color} - {meaning}."
            self.status.set_text(
                "Done. The row above says what happened"
                + (". Checks re-run now."
                   if self._recheck.get_active() else "."))
        else:
            line = (f"the changeset {control.id} did not hold: the "
                    f"helper exited with code {rc}. Nothing else was "
                    f"changed.")
            self.status.set_text(
                "The apply did not fully succeed - the row above says "
                "what happened.")
        lbl = self._row_results.get(control.id)
        if lbl is not None:
            lbl.set_text(line)
            lbl.set_visible(True)
        self._row_last_result[control.id] = line
        self.verify_label.set_text(
            "applied in this session: "
            + (f"{control.id} {color}" if color else line)
            + "\n" + line)
        if rc == 0 and self._recheck.get_active():
            self._on_scan(None)              # the same recheck, rescored
        else:
            self._score_stale = True
            self._paint_score()
        self._refresh_undo()
        return False

    # ------------------------------------------------- advisory actions
    _ACTION_LABEL = {
        "updates": "Apply updates",
        "install": "Install ClamAV",
        "manual": "Copy search command",
    }

    def _action_button(self, control):
        action = getattr(control, "advisory_action", None)
        if not action or not getattr(control, "advisory", False):
            return None
        kind = action.get("kind")
        btn = Gtk.Button(label=self._ACTION_LABEL.get(kind, "Do it"))
        btn.add_css_class("gw-cta")
        btn.set_halign(Gtk.Align.START)
        if kind == "manual":
            btn.connect("clicked", lambda _b: self._copy_command(
                action.get("command", "")))
        else:
            btn.connect("clicked", lambda _b: self._on_action(_b, control))
        return btn

    def _copy_command(self, command):
        if not command:
            return
        try:
            self.get_clipboard().set(command)
        except Exception:          # clipboard is best-effort on a bare test
            return
        self.status.set_text("Search command copied. Nothing was run.")

    _CONFIRM = {
        "updates": ("Apply pending updates?",
                    "Packages are replaced and cannot be undone. Services "
                    "are not restarted; a reboot may be needed."),
        "install": ("Install ClamAV?",
                    "The engine and definitions are installed. Nothing is "
                    "scanned automatically."),
    }

    def _confirm(self, spec):
        dialog = Gtk.AlertDialog()
        # : nothing greywatch raises for you is a screen-wide grab.
        dialog.set_modal(False)
        title, body = self._CONFIRM.get(
            spec["kind"], ("Run this action?", "This cannot be undone."))
        dialog.set_message(title)
        dialog.set_detail(body)
        dialog.set_buttons(["Cancel", "Run"])
        dialog.set_cancel_button(0)
        dialog.set_default_button(0)
        loop = GLib.MainLoop()
        result = {"choice": -1}

        def done(source, res):
            try:
                result["choice"] = source.choose_finish(res)
            except GLib.Error:
                result["choice"] = -1
            loop.quit()

        dialog.choose(None, None, done)
        loop.run()
        return result["choice"] == 1

    def _on_action(self, _btn, control):
        action = control.advisory_action or {}
        kind = action.get("kind")
        if kind not in ("updates", "install"):
            return
        spec = {"kind": kind, "package": action.get("package", ""),
                "control_id": control.id}
        if not self._confirm(spec):
            return
        fix = ([["pkg-upgrade"]] if kind == "updates"
               else [["pkg-install", action["package"]]])
        self.status.set_text("Running the advisory action. One password "
                             "prompt may appear…")

        def worker():
            rc, out, err = self._run_steps(control.id, fix)
            GLib.idle_add(self._action_done, rc, out, err, kind, control)

        threading.Thread(target=worker, daemon=True).start()

    def _run_steps(self, cid, fix):
        """One-entry plan through the same helper contract as Apply."""
        entries, _skipped = planfile_entries(
            [{"id": cid, "fix": fix}],
            self._scanned_controls or self._controls or [])
        fd, name = tempfile.mkstemp(prefix="gw-action-", suffix=".json")
        path = pathlib.Path(name)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump({"entries": entries}, fh)
            return self._helper_out(["apply", str(path)])
        finally:
            path.unlink(missing_ok=True)

    def _action_done(self, rc, out, err, kind, control=None):
        if self._dead:
            return False
        colors = parse_apply_output((out or "") + "\n" + (err or ""))
        if rc != 0:
            self.status.set_text(
                "The action did not complete. Nothing else was changed.")
        else:
            self.status.set_text("Done. The checks run again now.")
            if control is not None:
                cid = control.id
                color = colors.get(cid, "")
                word = _APPLY_WORDS.get(color, color or "done")
                line = f"applied changeset {cid}: {color} - {word}."
                self._row_last_result[cid] = line
                lbl = self._row_results.get(cid)
                if lbl is not None:
                    lbl.set_text(line)
                    lbl.set_visible(True)
            self._on_scan(None)
            if kind == "updates":
                self._check_restarts()
        if colors:
            self.verify_label.set_text(
                "\n".join(f"{cid} {color}" for cid, color in colors.items()))
        return False

    # pending restarts ---------------------------------------------------
    def _check_restarts(self):
        def worker():
            rc, out, err = self._run_steps("pending-restarts-read",
                                           [["pending-restarts"]])
            GLib.idle_add(self._restart_done, rc, out)

        threading.Thread(target=worker, daemon=True).start()

    def _restart_done(self, rc, out):
        if self._dead or rc != 0:
            return False
        doc = {}
        for line in (out or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    doc = json.loads(line)
                except ValueError:
                    doc = {}
                break
        if doc:
            self._show_restart_banner(doc)
        return False

    def _show_restart_banner(self, doc):
        import re
        units = [u for u in (doc.get("services") or [])
                 if isinstance(u, str)
                 and re.fullmatch(r"[A-Za-z0-9@._-]+", u)]
        self.restart_units = units
        self.restart_box.set_visible(True)
        if units:
            line = ("These services still hold old libraries: "
                    + ", ".join(units))
        elif doc.get("reboot_required"):
            line = "A reboot is needed to finish the update."
        else:
            line = "No restart is needed."
        self.restart_banner.set_text(line)
        self.restart_btn.set_sensitive(bool(units))

    def _on_restart_services(self, _btn):
        if not self.restart_units:
            return
        if not self._confirm({"kind": "restart"}):
            return
        units = ",".join(self.restart_units)
        self.restart_btn.set_sensitive(False)

        def worker():
            rc, out, err = self._run_steps(
                "restart-services", [["restart-units", units]])
            GLib.idle_add(self._restart_action_done, rc)

        threading.Thread(target=worker, daemon=True).start()

    def _restart_action_done(self, rc):
        if self._dead:
            return False
        self.restart_box.set_visible(False)
        self.status.set_text(
            "Services restarted." if rc == 0
            else "Some services could not be restarted. See the logs.")
        return False

    # ------------------------------------------------------ batch / undo
    def _on_apply(self, _btn):
        self.apply_btn.set_sensitive(False)
        self.status.set_text("Applying the baseline. One password prompt, "
                             "then verification…")
        try:
            plan, advisories = build_plan(self._findings,
                                          self._scanned_controls)
            entries, skipped = planfile_entries(plan, self._scanned_controls)
            if not entries:
                self.apply_btn.set_sensitive(False)
                advisory_ids = {c.id for c in self._scanned_controls
                                if bool(getattr(c, "advisory", False))}
                gaps = [f for f in self._findings
                        if f.state == detector.GAP
                        and f.control_id not in advisory_ids]
                advisories = [f for f in self._findings
                              if f.control_id in advisory_ids]
                if not gaps:
                    # Nothing is wrong: saying "every gap needs a manual
                    # change" here read as nine failures.
                    self.apply_btn.set_tooltip_text(
                        "Off because there is nothing to change: every "
                        "mechanical check already passes.")
                    self.status.set_text(
                        "Nothing to apply: every changeable check already "
                        "passes. "
                        + (f"The {len(advisories)} ADVISORY rows are "
                           "information only and are never changed "
                           "automatically. " if advisories else "")
                        + "Run the checks again after a system update.")
                else:
                    self.apply_btn.set_tooltip_text(
                        "Each gap needs a manual change the helper cannot "
                        "make.")
                    self.status.set_text(
                        f"Nothing the app can apply: {len(gaps)} gap(s) "
                        "each need a manual change, so none was "
                        "attempted. The rows name the change for each "
                        "one.")
                self._focus_primary()
                return False
            planfile = pathlib.Path(tempfile.mkstemp(
                prefix="harden-plan-", suffix=".json")[1])
            planfile.write_text(
                json.dumps({"entries": entries}) + "\n", encoding="utf-8")

            def worker():
                rc, out, err = -1, "helper failed", ""
                try:
                    rc, out, err = self._helper_out(["apply", str(planfile)])
                except Exception as exc:          # never kill the UI
                    err = f"helper failed: {exc}"
                finally:
                    try:
                        planfile.unlink()
                    except OSError:
                        pass
                GLib.idle_add(self._apply_done, rc, out, err, skipped)
            threading.Thread(target=worker, daemon=True).start()
        except Exception as exc:                  # noqa: BLE001
            self.status.set_text(f"The plan could not be built: {exc}")
        return False

    def _helper_out(self, args):
        if self._helper is not None:              # tests: injectable
            got = self._helper(args)
            if len(got) == 3:
                return got
            return got[0], got[1], ""
        import os
        import subprocess
        script = ROOT / "apply" / "harden.sh"
        if os.environ.get("GREYWATCH_HELPER_CMD"):   # test-only override
            cmd = [os.environ["GREYWATCH_HELPER_CMD"], "harden"] + args
        else:                                        # desktop session: pkexec
            cmd = ["pkexec", str(script)] + args
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return p.returncode, p.stdout or "", p.stderr or ""

    def _apply_done(self, rc, out, err, skipped):
        if self._dead:
            return False
        colors = parse_apply_output((out or "") + "\n" + (err or ""))
        lines = ["GREEN = fixed and verified. RED = the fix did not "
                 "hold. AMBER = not re-verified."]
        lines += [f"{cid} {color}" for cid, color in colors.items()] or \
            ["The helper reported no results. Nothing was verified."]
        if skipped:
            lines.append("skipped by the GUI (manual change needed): "
                         + ", ".join(e["id"] for e in skipped))
        if rc != 0:
            lines.append(f"Helper exited with code {rc}. See the logs.")
            self.status.set_text(
                "The apply did not fully succeed - the rows below show "
                "the current state.")
        else:
            # The checks run again at once: gaps the apply just closed
            # collapse to resolved rows without the user re-running
            # anything (the recheck toggle only mutes the ROW lane's
            # own recheck, never this batch one's — the batch lane's
            # whole contract is fix-and-verify in one pass).
            self._on_scan(None)
        self.verify_label.set_text("\n".join(lines))
        self._refresh_undo()
        return False

    def _on_undo(self, _btn):
        entry = read_latest(self._journal)
        if not entry:
            self.undo_btn.set_sensitive(False)
            return False
        eid = str(entry.get("id", ""))
        self.undo_btn.set_sensitive(False)
        self.status.set_text(f"Restoring the before-values of {eid}…")

        def worker():
            rc, out, err = -1, "helper failed", ""
            try:
                rc, out, err = self._helper_out(
                    ["undo", eid, str(self._journal)])
            except Exception as exc:          # never kill the UI
                err = f"helper failed: {exc}"
            GLib.idle_add(self._undo_done, rc, out, err, eid)
        threading.Thread(target=worker, daemon=True).start()
        return False

    def _undo_done(self, rc, out, err, eid):
        if self._dead:
            return False
        self.verify_label.set_text(
            f"undo {eid}: {'restored' if rc == 0 else 'FAILED'}\n"
            f"{out.strip()}\n{err.strip()}".strip())
        self.status.set_text(
            f"Undo of {eid} {'succeeded' if rc == 0 else 'failed'}. "
            f"Re-run the baseline checks to see the honest state.")
        self._refresh_undo()
        return False

    def _refresh_undo(self):
        try:
            has = read_latest(self._journal) is not None
        except Exception:
            has = False
        self.undo_btn.set_sensitive(bool(has))
