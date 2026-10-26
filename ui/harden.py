from __future__ import annotations

import json
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
                      muted as pc_muted, warn as pc_warn)

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
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
    if verb == "pkg-upgrade":
        return {"verb": "pkg-upgrade"}
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


class HardenView(Gtk.Box):

    def __init__(self, win=None, controls=None, runner=None, helper=None,
                 journal_path=None, cve_cache=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
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
        self.connect("destroy", self._on_dead)

        self.append(self._h1("Harden the endpoint"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            "<span size='13000' font_family='Inter'>Baseline checks test "
            "this computer's security settings. Nothing is applied until "
            "you press Apply.</span>")
        intro.set_tooltip_text(
            "Each check shows where it stands and what applying it "
            "would change.")
        self.append(intro)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.status = Gtk.Label(xalign=0)
        self.status.set_xalign(0)
        self.status.set_hexpand(True)
        self.status.set_wrap(True)
        self.status.set_max_width_chars(64)
        row.append(self.status)
        self.scan_btn = Gtk.Button(label="Run baseline checks")
        self.scan_btn.add_css_class("gw-cta")
        self.scan_btn.connect("clicked", self._on_scan)
        row.append(self.scan_btn)
        self.apply_btn = Gtk.Button(label="Apply baseline")
        self.apply_btn.set_sensitive(False)
        self.apply_btn.connect("clicked", self._on_apply)
        row.append(self.apply_btn)
        self.undo_btn = Gtk.Button(label="Undo last change")
        self.undo_btn.set_sensitive(False)
        self.undo_btn.connect("clicked", self._on_undo)
        row.append(self.undo_btn)
        self.append(row)

        self.cards = Gtk.FlowBox()
        self.cards.set_max_children_per_line(3)
        self.cards.set_min_children_per_line(2)
        self.cards.set_selection_mode(Gtk.SelectionMode.NONE)
        self.cards.set_hexpand(True)
        self.cards.set_vexpand(True)
        self.append(self.cards)
        self.append(self._h2("Verification"))
        self.verify_label = Gtk.Label(xalign=0)
        self.verify_label.set_xalign(0)
        self.verify_label.set_wrap(True)
        self.verify_label.set_text("Nothing applied in this session yet.")
        self.append(self.verify_label)
        self._refresh_undo()

    def _h1(self, text):
        if self._win is not None:
            return self._win._h1(text)
        return HardenView._static_h1(text)

    def _h2(self, text):
        if self._win is not None:
            return self._win._h2(text)
        return HardenView._static_h2(text)

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

    def _on_scan(self, _btn):
        self.status.set_text("Running baseline checks (a few seconds)…")
        self.apply_btn.set_sensitive(False)
        self.scan_btn.set_sensitive(False)   # one scan at a time
        try:
            if self._controls is not None:     # injected (tests)
                controls = list(self._controls)
            else:
                from hardening.controls import load_controls
                controls = load_controls(DATA_DIR)
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

    def _scan_failed(self, msg):
        if self._dead:
            return False
        self.scan_btn.set_sensitive(True)
        fail_reason = f"The scan could not run: {msg}."
        fail_effect = ("Nothing was checked or applied. Apply stays "
                       "off until a scan runs.")
        self.status.set_text(fail_reason + " " + fail_effect)
        return False

    def _scan_done(self, findings, controls):
        if self._dead:
            return False
        self.scan_btn.set_sensitive(True)
        if findings is None:                 # failed scan: never look empty
            self._scanned = False
            self._findings = []
            self.apply_btn.set_sensitive(False)
            self.verify_label.set_text(
                "The scan failed. Nothing was checked. Run the checks "
                "again.")
            return False
        self._findings = findings
        self._scanned = True
        self._scanned_controls = list(controls)
        by_id = {getattr(c, "id", ""): c for c in controls}
        while True:
            child = self.cards.get_first_child()
            if child is None:
                break
            self.cards.remove(child)
        cant = [f for f in findings if f.state == detector.CANT]
        # An unknown state is never applied — but advisory cards are
        # never applied at anything, so when ONLY advisory checks came
        # back uncheckable they must not hold the whole panel hostage.
        advisory_ids = {getattr(c, "id", "") for c in controls
                        if bool(getattr(c, "advisory", False))}
        gating = [f for f in cant if f.control_id not in advisory_ids]
        manual_ids = set()
        for f in findings:
            if f.state == detector.GAP:
                got = verby_args(getattr(by_id.get(f.control_id), "fix", []))
                if not got or got.get("unresolvable"):
                    manual_ids.add(f.control_id)
        for fnd in findings:
            self.cards.append(self._card(
                fnd, by_id.get(fnd.control_id),
                manual=fnd.control_id in manual_ids))
        n = len(findings)
        gaps = sum(1 for f in findings if f.state == detector.GAP)
        auto = gaps - len(manual_ids)
        if gating:
            self.status.set_text(
                f"{n} checks: {gaps} gap(s) to tighten, {len(cant)} could "
                f"NOT be checked. Applying stays off until every check "
                f"can run.")
        elif cant:
            self.status.set_text(
                f"{n} checks: {gaps} gap(s) to tighten, {len(cant)} could "
                f"NOT be checked (advisory-only; nothing is applied from "
                f"them). Review the cards, then Apply if you agree.")
        else:
            lead = (f"{n} checks done: {auto} gap(s) would be tightened."
                    if auto else f"{n} checks done: every gap needs a "
                    f"manual change.")
            extra = (f" {len(manual_ids)} more need(s) a change the "
                     f"helper cannot make." if manual_ids else "")
            self.status.set_text(
                lead + extra + " Review the cards, then Apply if you "
                "agree.")
        if gating:
            self.apply_btn.set_tooltip_text(
                "Off because some checks could not run. An unknown state "
                "is never applied.")
        else:
            self.apply_btn.set_tooltip_text("")
        self.apply_btn.set_sensitive(not gating)
        return False

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

    def _card(self, fnd, control, manual=False):
        # The head badge follows the CHECK RESULT, not the severity: a
        # check that already passes is good news and reads green; red is
        # reserved for a check that actually failed. Severity lives in the
        # tag line at the bottom of the card.
        mark = ("📄" if bool(getattr(control, "advisory", False)) else
                {detector.PASS: "🟢", detector.GAP: "🟡",
                 detector.FAIL: "🔴", detector.CANT: "⚪"}.get(fnd.state, "⚪"))
        words = {detector.PASS: "already at baseline",
                 detector.GAP: "NOT at baseline (would be tightened)",
                 detector.FAIL: "failed the check",
                 detector.CANT: "COULD NOT BE CHECKED"}
        advisory = bool(getattr(control, "advisory", False))
        if advisory:
            words = {fnd.state: "ADVISORY (never applied)"}
        elif manual:
            words = {fnd.state: "NEEDS A MANUAL CHANGE (Apply cannot "
                                 "fix this one)"}
        frame = Gtk.Frame()
        frame.add_css_class("gw-card")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(12); box.set_margin_bottom(12)
        box.set_margin_start(12); box.set_margin_end(12)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        head.set_markup(
            f"<span size='15000' font_family='Inter'>{mark} "
            f"{escape(words.get(fnd.state, fnd.state))}</span>")
        box.append(head)
        body_text = fnd.note or (control.what if control is not None
                                 else fnd.control_id)
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
                f"<span size='11000' font_family='Inter' color='{pc_warn()}'>"
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
                f"<span size='11000' font_family='Inter' color='{pc_soft()}'>"
                f"current: {escape(fnd.current[:200])}</span>")
            box.append(cur)
        frame.set_child(box)
        return frame

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
                self.apply_btn.set_tooltip_text(
                    "Each gap needs a manual change the helper cannot "
                    "make.")
                self.status.set_text(
                    "Nothing to apply: every gap needs a manual change. "
                    "None was attempted. Run the checks again or review "
                    "the cards.")
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
        else:                                        # owner runtime: pkexec
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
                "The apply did not fully succeed — the cards below show "
                "the current state.")
        else:
            # The checks run again at once: gaps the apply just closed turn
            # green on the cards without the owner re-running anything.
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
