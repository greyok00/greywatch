from __future__ import annotations

import datetime
import json
import pathlib
import tempfile
import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib            # noqa: E402

from ui.harden import parse_apply_output, verby_args    # noqa: E402
from ui.plain import escape, ink, soft, warn    # noqa: E402

from hardening.controls import load_controls   # noqa: E402
import wizard.baseline as baseline            # noqa: E402
import wizard.changeset as changeset          # noqa: E402
import wizard.detector as detector            # noqa: E402
from wizard.inventory import (inventory_lines, run_scan,   # noqa: E402
                              CANT_WORDS)

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"

STEPS = ("welcome", "scan", "preview", "apply", "verify", "finish")
STEP_LABELS = {
    "welcome": "Welcome & role",
    "scan": "System scan",
    "preview": "Adaptive preview",
    "apply": "Apply",
    "verify": "Verify results",
    "finish": "Finish & undo",
}
ROLES = (
    ("workstation", "Workstation: balanced (default)"),
    ("hardened", "Hardened: stricter baseline"),
    ("custom", "Custom: review every card before anything applies"),
)
ROLE_HINTS = {
    "workstation":
        "Balanced: safety-critical controls pre-checked; risky cards left "
        "unticked.",
    "hardened":
        "Stricter: every card still shown. Nothing applies unticked.",
    "custom":
        "Everything starts unticked. You choose each card yourself.",
}
GREEN, AMBER, RED, WHITE = "GREEN", "AMBER", "RED", "WHITE"
PASS = "PASS"
CANT = "CANT-CHECK"
WHITE_MARK = "⚪"


def now_journal_id(dt=None) -> str:
    stamp = dt or datetime.datetime.now()
    return stamp.strftime("%Y%m%d-%H%M%S")


def pass_journal_path(data_dir, journal_id) -> pathlib.Path:
    return pathlib.Path(data_dir) / "harden" / "journal" / str(journal_id) \
 / "journal.jsonl"


def fragment_path(data_dir, journal_id, control_id) -> pathlib.Path:
    return pathlib.Path(data_dir) / "harden" / "journal" / str(journal_id) \
 / f"{control_id}.json"


def plan_entries(controls, cards) -> tuple[dict, list[str]]:
    by_id = {getattr(c, "id", ""): c for c in (controls or [])}
    fragments: dict[str, dict] = {}
    skipped: list[str] = []
    for card in cards:
        if not isinstance(card, dict) or not card.get("checked"):
            continue
        if card.get("action") not in (baseline.APPLY_ACTION, None):
            skipped.append(card["control_id"])
            continue
        control = by_id.get(card["control_id"])
        fix = (list(getattr(control, "fix", []) or [])
               if control is not None else [])
        entry = verby_args(fix)
        if not entry or entry.pop("unresolvable", False):
            skipped.append(card["control_id"])
            continue
        entry["id"] = card["control_id"]
        entry["probe"] = getattr(control, "probe", "") or ""
        entry["probe_invert"] = bool(getattr(control, "probe_invert", False))
        fragments[entry["id"]] = {"entries": [entry]}
    return fragments, skipped


def preview_rows(cards) -> list[dict]:
    rows = []
    for card in cards:
        if not isinstance(card, dict):
            continue
        rows.append({
            "control_id": card.get("control_id", ""),
            "control": card.get("title", ""),
            "nist": ", ".join(card.get("nist") or []),
            "cis": ", ".join(card.get("cis") or []),
            "current": card.get("current", "") or "",
            "recommended": card.get("recommended", "") or "",
            "checked": bool(card.get("checked")),
            "risk": card.get("risk", "") or "",
        })
    return rows


def parse_strip(stdout: str, stderr: str) -> dict:
    both = "\n".join(part for part in (stdout or "", stderr or "") if part)
    colors = parse_apply_output(both)
    white: list[str] = []
    if not colors:
        refused = next((line.strip() for line in (stderr or "").splitlines()
                        if line.strip().startswith("CHANGES-")), "")
        if refused:
            white.append("The helper refused the pass: " + refused)
        else:
            white.append("The helper reported no results. This pass "
                         "could not be checked.")
    return {"colors": colors, "white": white}


def apply_pass(controls, cards, journal_id, doc_path, data_dir,
               helper) -> dict:
    fragments, skipped = plan_entries(controls, cards)
    report = {"journal_id": str(journal_id), "doc_path": str(doc_path),
              "skipped": skipped, "fragments": sorted(fragments),
              "errors": [], "rc": None, "colors": {}, "white": [],
              "out": "", "err": ""}
    if not fragments:
        report["white"] = [
            ("Nothing was checked for apply. No change was planned, "
             "nothing ran.") if not skipped else
            ("Nothing in the checked cards can be applied "
             "by the helper. Nothing ran. Skipped: "
             + ", ".join(skipped))]
        return report
    applied = [card for card in cards
               if isinstance(card, dict) and card.get("checked")
               and card["control_id"] in fragments]
    changeset_doc = changeset.build(journal_id, applied)
    errors = changeset.write_document(changeset_doc, controls, doc_path)
    if errors:
        report["errors"] = list(errors)
        return report
    fragment_path(data_dir, journal_id, "_").parent.mkdir(parents=True,
                                                          exist_ok=True)
    for control_id, fragment in fragments.items():
        fragment_path(data_dir, journal_id, control_id).write_text(
            json.dumps(fragment) + "\n", encoding="utf-8")
    rc, out, err = -1, "helper failed", ""
    try:
        got = helper(["--apply", str(doc_path)])
        rc, out, err = got if len(got) == 3 else (got[0], got[1], "")
    except Exception as exc:          # noqa: BLE001 - never kill the UI
        err = f"helper failed: {exc}"
    stripped = parse_strip(out, err)
    report.update(rc=rc, colors=stripped["colors"],
                  white=stripped["white"], out=out or "", err=err or "")
    if rc != 0:
        report["white"].append(
            f"The helper exited with code {rc}. See the pass journal "
            f"data/harden/journal/{journal_id}/")
    return report


def undo_pass(journal_id, data_dir, helper) -> dict:
    rc, out, err = -1, "helper failed", ""
    try:
        got = helper(["--undo", str(journal_id),
                      str(pass_journal_path(data_dir, journal_id))])
        rc, out, err = got if len(got) == 3 else (got[0], got[1], "")
    except Exception as exc:          # noqa: BLE001
        err = f"helper failed: {exc}"
    good = rc == 0
    if good:
        words = ("The last change was undone. The before-values are "
                 "restored and the pass re-verified.")
    elif rc == 3:
        words = ("The before-values were restored, but the checks no "
                 "longer pass. Read the pass journal before the next "
                 "step.")
    else:
        words = "The undo FAILED. The restore itself did not hold."
    return {"rc": rc, "out": out or "", "err": err or "", "undoed": good,
            "words": words, "journal_id": str(journal_id)}


class SetupWizard(Gtk.Box):

    def __init__(self, win=None, data_dir=None, controls=None, runner=None,
                 helper=None, open_dashboard=None, open_chooser=None,
                 net_dir=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(26)
        self.set_margin_start(34)
        self.set_margin_end(34)
        self.set_margin_bottom(20)
        self._win = win
        self._data_dir = pathlib.Path(data_dir or DATA_DIR)
        self._controls = controls
        self._runner = runner or detector.prod_runner
        self._helper = helper          # injected (tests) args->(rc, out[, err])
        self._net_dir = net_dir        # /sys/class/net override (tests)
        self._open_dashboard = open_dashboard
        self._open_chooser = open_chooser
        self._profile = "workstation"
        self._scan = None
        self._cards: list = []
        self._journal_id = None
        self._verify_colors: dict = {}
        self._verify_white: list = []

        self.append(self._heading(
            "The Setup Wizard: every protection, one pass"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            f"<span size='13000' font_family='Inter'>"
            f"{escape('Six steps: scan, preview, apply, verify.')} "
            f"{escape('One password applies checked changes with a full '
                      'backup.')} "
            f"{escape('Anything that fails verify rolls back '
                      'automatically.')} "
            f"{escape('Nothing runs until you click. Unknown states '
                      'show white.')}</span>")
        self.append(intro)

        self.stack = Gtk.Stack()
        self.stack.set_vexpand(True)
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.append(self.stack)
        builders = {"welcome": self._build_welcome,
                    "scan": self._build_scan,
                    "preview": self._build_preview,
                    "apply": self._build_apply,
                    "verify": self._build_verify,
                    "finish": self._build_finish}
        for step_no, step in enumerate(STEPS, start=1):
            page = builders[step](step_no)
            self.stack.add_named(page, step)
        self._step("welcome")

    @staticmethod
    def _heading(text):
        l = Gtk.Label(xalign=0)
        l.set_xalign(0)
        l.set_wrap(True)
        l.set_markup(
            f"<span size='20000' font_family='Barlow Condensed' "
            f"weight='600'>{escape(text)}</span>")
        return l

    def _words(self, size=13000, color=None):
        l = Gtk.Label(xalign=0)
        l.set_xalign(0)
        l.set_wrap(True)
        l._tag = (size, color)
        self.fill(l, "")
        return l

    def fill(self, label, text):
        size, color = getattr(label, "_tag", (13000, None))
        color = color or ink()          # theme-aware, never a hardcoded gray
        label.set_markup(
            f"<span size='{size}' font_family='Inter' color='{color}'>"
            f"{escape(text or '')}</span>")
        return label

    def _btn(self, label, handler, sensitive=True):
        b = Gtk.Button(label=label)
        b.set_sensitive(sensitive)
        b.connect("clicked", handler)
        return b

    def _step_nav(self, step, back=None):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        if back:
            row.append(self._btn(back[0],
                                 lambda *_b: self._step(back[1])))
        title = self._words(size=11000, color=soft())
        title.set_halign(Gtk.Align.START)
        self.fill(title, f"Step {STEPS.index(step) + 1} of 6: "
                     f"{STEP_LABELS[step]}")
        row.append(title)
        return row

    def _go(self, target):
        return lambda *_b: self._step(target)

    def _step(self, step):
        if step == "preview":
            self._preview_ready()          # the table always reads fresh cards
        if step == "verify":
            self._render_strip()           # the strip always renders fresh
        if step == "finish" and self._journal_id is not None \
                and not getattr(self, "_enable_all_fired", False):
            self._enable_all_fired = True
            self._on_enable_all(None, auto=True)   # completion contract
        if step in STEPS:
            self.stack.set_visible_child_name(step)
            return step
        return self._step("welcome")

    def _build_welcome(self, _step_no):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        role_intro = self._words(size=13000)
        role_q = "Role: how strict should the baseline be?"
        role_rest = ("The safety rules are identical in every role. Only "
                     "the emphasis changes.")
        self.fill(role_intro, role_q + " " + role_rest)
        box.append(role_intro)
        self._roles_store: dict[str, Gtk.CheckButton] = {}
        first = None
        for value, label in ROLES:
            radio = Gtk.CheckButton(label=label)
            if first is None:
                first = radio
            else:
                radio.set_group(first)
            radio.set_active(value == "workstation")
            radio.set_tooltip_text(ROLE_HINTS[value])
            radio.connect("toggled", self._on_role, value)
            self._roles_store[value] = radio
            box.append(radio)
        self._roles_first = first
        self._role_hint = self._words(size=12000, color=soft())
        self.fill(self._role_hint, ROLE_HINTS["workstation"])
        box.append(self._role_hint)

        facts = Gtk.Frame()
        facts.add_css_class("gw-card")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        inner.set_margin_top(12)
        inner.set_margin_bottom(12)
        inner.set_margin_start(12)
        inner.set_margin_end(12)
        probed = self._words(size=12000)
        self.fill(probed, "What will be probed (2-5 minutes, nothing "
                  "applied):")
        probed.set_tooltip_text("The probe runs in your user context only.")
        inner.append(probed)
        for line in ("installed packages (SSH server, ClamAV, UFW, "
                     "Docker and more)",
                     "services that are running and the ports that "
                     "listen (ports only)",
                     "the firewall and firewall-frontend state",
                     "kernel sysctls (IPv6, kptr, dmesg, BPF)",
                     "whether the disks are encrypted",
                     "the desktop environment and laptop/desktop fact"):
            bullet = self._words(size=12000)
            self.fill(bullet, "• " + line)
            inner.append(bullet)
        framing = self._words(size=12000, color=soft())
        framing_q = "Every card shows its NIST and CIS tag in plain words."
        framing_rest = "A probe that cannot run shows white, never safe."
        self.fill(framing, framing_q + " " + framing_rest)
        inner.append(framing)
        facts.set_child(inner)
        box.append(facts)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        if self._open_chooser is not None:
            chooser = self._btn("Guided tool setup…",
                                lambda *_b: self._open_chooser())
            chooser.set_halign(Gtk.Align.START)
            actions.append(chooser)
        start = self._btn("Continue: start the scan", self._on_continue)
        start.add_css_class("gw-cta")
        start.set_halign(Gtk.Align.END)
        start.set_hexpand(True)
        actions.append(start)
        self._start_button = start
        box.append(actions)
        return box

    def _on_role(self, radio, value):
        if not radio.get_active() or not hasattr(self, "_roles_first"):
            return
        self._profile = value
        self.fill(self._role_hint, ROLE_HINTS[value])

    def _on_continue(self, _btn):
        self._step("scan")
        self._on_start_scan(None)

    def _build_scan(self, _step_no):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._scan_progress = self._words(size=12000)
        self.fill(self._scan_progress, "The scan has not started. Press "
                  "Continue on the welcome step.")
        box.append(self._scan_progress)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._retry = self._btn("Try again", self._on_start_scan,
                                sensitive=False)
        row.append(self._retry)
        self._review_btn = self._btn("Review the changes",
                                     self._go("preview"), sensitive=False)
        self._review_btn.add_css_class("gw-cta")
        self._review_btn.set_halign(Gtk.Align.END)
        self._review_btn.set_hexpand(True)
        row.append(self._review_btn)
        box.append(row)
        self._inventory_frame = Gtk.Frame()
        self._inventory_frame.add_css_class("gw-card")
        self._inventory_frame.set_vexpand(True)
        self._inventory_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=3)
        self._inventory_frame.set_child(self._inventory_box)
        box.append(self._inventory_frame)
        return box

    def _on_start_scan(self, _btn):
        self._retry.set_sensitive(False)
        self._review_btn.set_sensitive(False)
        scan_now = ("Scanning this computer: packages, services, ports, "
                    "firewall, encryption.")
        scan_then = "A few seconds. Nothing is applied."
        self.fill(self._scan_progress, scan_now + " " + scan_then)
        if self._controls is None:
            self._controls = load_controls(self._data_dir)

        def worker():
            scan = None
            failed = ""
            try:
                scan = run_scan(runner=self._runner,
                                data_dir=self._data_dir,
                                net_dir=self._net_dir)
            except Exception as exc:   # noqa: BLE001 - never kill the UI
                failed = str(exc)
            GLib.idle_add(self._scan_done, scan, failed)

        threading.Thread(target=worker, daemon=True).start()

    def _scan_done(self, scan, failed):
        self._retry.set_sensitive(True)
        if scan is None:               # failed battery: honest words only
            self.fill(self._scan_progress, f"The scan could not run: "
                      f"{failed}. Nothing was checked and nothing was "
                      f"applied. Try again.")
            return False
        self._scan = scan
        self._cards = baseline.generate(scan, self._controls, self._profile)
        self._render_inventory()
        self.fill(self._scan_progress, "Scan done: the inventory is "
                  "below. The next step summarizes the changes.")
        self._review_btn.set_sensitive(True)
        self._review_btn.grab_focus()
        return False

    def _render_inventory(self):
        child = self._inventory_box.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self._inventory_box.remove(child)
            child = next_child
        for line in inventory_lines(self._scan) \
                if self._scan is not None else []:
            cant = line.endswith(CANT_WORDS)
            words = self._words(size=12000)
            mark = WHITE_MARK if cant else "✓"
            self.fill(words, f"{mark} {line}")
            self._inventory_box.append(words)

    def _build_preview(self, _step_no):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self._white_strip = self._words(size=12000, color=soft())
        box.append(self._white_strip)
        self._table_store = Gtk.ListStore(str, str, str, str, str, str,
                                          bool)
        view = Gtk.TreeView(model=self._table_store, headers_visible=True)
        for idx, (title, width) in enumerate(
                (("Control", 340), ("NIST", 90), ("CIS", 80),
                 ("Current", 160), ("Recommended", 210))):
            col = Gtk.TreeViewColumn(
                title, Gtk.CellRendererText(), text=idx)
            col.set_fixed_width(width)
            col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
            view.append_column(col)
        apply_col = Gtk.TreeViewColumn("Apply?")
        toggle = Gtk.CellRendererToggle()
        toggle.connect("toggled", self._on_row_toggled)
        apply_col.pack_start(toggle, True)
        apply_col.add_attribute(toggle, "active", 6)
        view.append_column(apply_col)
        table_frame = Gtk.Frame()
        table_frame.add_css_class("gw-card")
        table_frame.set_vexpand(True)
        table_wrap = Gtk.ScrolledWindow()
        table_wrap.set_policy(Gtk.PolicyType.AUTOMATIC,
                              Gtk.PolicyType.AUTOMATIC)
        table_wrap.set_vexpand(True)
        table_wrap.set_child(view)
        table_frame.set_child(table_wrap)
        self._table_view = view
        box.append(table_frame)
        self._risk_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.append(self._risk_box)
        self._apply_btn = self._btn(
            "Apply the checked changes", self._on_apply_clicked,
            sensitive=False)
        self._apply_btn.add_css_class("gw-cta")
        self._apply_btn.set_halign(Gtk.Align.END)
        box.append(self._apply_btn)
        box.append(self._step_nav("preview", back=(
            "Back: scan again", "welcome")))
        return box

    def _on_row_toggled(self, _renderer, path):
        row = self._table_store[path]
        row[6] = not row[6]
        for card in self._cards:
            if card.get("control_id") == row[0]:
                card["checked"] = bool(row[6])
                break
        self._update_apply_button()

    def _update_apply_button(self):
        checked, risky = [], []
        for card in self._cards:
            if not card.get("checked"):
                continue
            checked.append(card["control_id"])
            risk = card.get("risk", "")
            if "Break risk medium" in risk or "Break risk high" in risk:
                risky.append(card["control_id"])
        self._apply_btn.set_sensitive(bool(checked))
        self._apply_btn.set_label(
            f"Apply the {len(checked)} checked change(s)" if checked
            else "Apply the checked changes")
        self._apply_btn.set_tooltip_text(
            ("Checked cards this may break your workflow for: "
             + ", ".join(risky)) if risky else "")

    def _fill_table(self):
        self._table_store.clear()
        for row in preview_rows(self._cards):
            self._table_store.append([row["control_id"], row["control"],
                                      row["nist"], row["cis"],
                                      row["current"], row["recommended"],
                                      row["checked"]])
        white_lines = [line for line in inventory_lines(self._scan)
                       if line.endswith(CANT_WORDS)]
        self.fill(self._white_strip,
                  f"{WHITE_MARK} Could not be checked (nothing is "
                  f"guessed past these): {len(white_lines)} fact(s)")
        child = self._risk_box.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self._risk_box.remove(child)
            child = next_child
        for card in self._cards:
            risk = card.get("risk", "")
            if not card.get("checked") or not risk:
                continue
            if "Break risk medium" in risk or "Break risk high" in risk:
                warn_lab = self._words(size=12000, color=warn())
                self.fill(warn_lab, "⚠ " + risk)
                self._risk_box.append(warn_lab)
        self._update_apply_button()

    def _on_apply_clicked(self, _btn):
        return self._step("apply")

    def _build_apply(self, _step_no):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._apply_progress = self._words(size=12000)
        apply_once = "The confirm dialog asks once. Applying is one password prompt."
        apply_then = "It backs up, applies, re-probes, and rolls back anything that failed."
        apply_go = "Press the button to start."
        self.fill(self._apply_progress,
                  apply_once + " " + apply_then + " " + apply_go)
        box.append(self._apply_progress)
        self._apply_go = self._btn("Apply: one password prompt",
                                   self._ask_confirm)
        self._apply_go.add_css_class("gw-cta")
        self._apply_go.set_halign(Gtk.Align.END)
        box.append(self._apply_go)
        box.append(self._btn("Back: review the cards",
                             self._go("preview")))
        self._apply_progress2 = self._words(size=12000)
        self.fill(self._apply_progress2, "")
        box.append(self._apply_progress2)
        return box

    def _ask_confirm(self, _btn):          # noqa: C901 - one confirm dialog
        checked = [card["control_id"] for card in self._cards
                   if card.get("checked")]
        dlg = Gtk.Dialog(title="Apply the checked changes?")
        if self._win is not None:
            dlg.set_transient_for(self._win)
        dlg.set_modal(True)
        body = Gtk.Label(xalign=0)
        body.set_xalign(0)
        body.set_wrap(True)
        confirm_one = "One password prompt. Every touched file is backed up."
        confirm_two = "Every fix is re-probed; failures roll back automatically."
        body.set_markup(
            f"<span size='13000' font_family='Inter'>Apply "
            f"{escape(str(len(checked)))} checked change(s) to this "
            "computer?</span>\n"
            f"<span size='12000' font_family='Inter' color='{soft()}'>"
            f"{escape(confirm_one)} {escape(confirm_two)}</span>")
        content = dlg.get_content_area()
        content.set_margin_top(14)
        content.set_margin_bottom(14)
        content.set_margin_start(20)
        content.set_margin_end(20)
        content.append(body)
        dlg.add_button("Not yet", Gtk.ResponseType.CANCEL)
        apply_b = dlg.add_button("Apply: one password prompt",
                                 Gtk.ResponseType.OK)

        def on_rsp(d, rid, *_a):
            d.destroy()
            if rid == Gtk.ResponseType.OK:
                self._launch_apply()

        dlg.connect("response", on_rsp)
        try:
            apply_b.grab_focus()
        except Exception:
            pass
        dlg.present()
        return dlg

    def _launch_apply(self):
        self._apply_go.set_sensitive(False)
        if self._journal_id is None:
            self._journal_id = now_journal_id()
        self.fill(self._apply_progress2, "Applying: one password "
                  "prompt. The strip lands on the next step.")
        doc_path = pathlib.Path(tempfile.mkstemp(
            prefix="greywatch-setup-", suffix=".json")[1])
        controls = list(self._controls)
        cards = [dict(c) for c in self._cards]
        journal_id, data_dir, helper = (self._journal_id, self._data_dir,
                                        self._run_helper)

        def worker():
            try:
                report = apply_pass(controls, cards, journal_id, doc_path,
                                    data_dir, helper)
            except Exception as exc:   # noqa: BLE001 - never kill the UI
                report = {"errors": [f"the apply step itself failed: "
                                     f"{exc}"], "colors": {}, "white": [],
                          "rc": None, "skipped": [],
                          "journal_id": journal_id}
            finally:
                try:
                    doc_path.unlink()
                except OSError:
                    pass
            GLib.idle_add(self._apply_done, report)

        threading.Thread(target=worker, daemon=True).start()

    def _run_helper(self, args):
        import os                     # noqa: PLC0415
        import subprocess             # noqa: PLC0415
        if self._helper is not None:  # tests: injected directly
            got = self._helper(args)
            return got if len(got) == 3 else (got[0], got[1], "")
        script = ROOT / "apply" / "harden.sh"
        env_cmd = os.environ.get("GREYWATCH_HELPER_CMD")   # test-only
        cmd = ([env_cmd, "harden"] + args if env_cmd
               else ["pkexec", str(script)] + args)
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=600)
        return p.returncode, p.stdout or "", p.stderr or ""

    def _apply_done(self, report):
        errors = report.get("errors") or []
        if errors:
            self._verify_colors = {}
            self._verify_white = [
                "The changeset was REFUSED (schema validation). "
                "Nothing ran, nothing was written: " + errors[0]]
        else:
            self._verify_colors = report.get("colors") or {}
            self._verify_white = report.get("white") or []
            skipped = report.get("skipped") or []
            if skipped:
                self._verify_white.append(
                    "Skipped this pass (the helper cannot make this "
                    "change): " + ", ".join(skipped)
                    + ". These need the owner's own click.")
        self._step("verify")

    def _build_verify(self, _step_no):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        head = self._words(size=12000)
        strip_a = "The strip below is the helper's own answer, re-probed after apply."
        strip_b = "Green verified. Amber applied, re-probe did not run."
        strip_c = "Red failed and rolled back (before-values restored)."
        strip_d = "White could not check: never counted as safe."
        self.fill(head, strip_a + " " + strip_b + " " + strip_c + " " + strip_d)
        box.append(head)
        self._verify_strip = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=2)
        strip_frame = Gtk.Frame()
        strip_frame.add_css_class("gw-card")
        strip_frame.set_vexpand(True)
        strip_inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                              spacing=2)
        strip_inner.set_margin_top(12)
        strip_inner.set_margin_bottom(12)
        strip_inner.set_margin_start(12)
        strip_inner.set_margin_end(12)
        strip_frame.set_child(strip_inner)
        box.append(strip_frame)
        self._strip_box = strip_inner
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cont = self._btn("Continue: finish the wizard",
                         self._go("finish"))
        cont.add_css_class("gw-cta")
        cont.set_halign(Gtk.Align.END)
        cont.set_hexpand(True)
        row.append(cont)
        row.append(self._btn("Back: preview",
                             self._on_verify_back))
        box.append(row)
        self._continue_button = cont
        return box

    def _on_verify_back(self, _btn):
        self._preview_ready()
        return self._step("preview")

    def _render_strip(self):
        child = self._strip_box.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self._strip_box.remove(child)
            child = next_child
        lines = []
        for line in (self._verify_white or []):
            lines.append(("⚪ " + line))
        for control_id, color in (self._verify_colors or {}).items():
            mark = {"GREEN": "🟢", "AMBER": "🟡", "RED": "🔴"}.get(color,
                                                                 WHITE_MARK)
            lines.append(f"{mark} {control_id} {color}")
        if not lines:
            lines = [f"{WHITE_MARK} Nothing applied in this session yet."]
        for line in lines:
            words = self._words(size=12000)
            self.fill(words, line)
            self._strip_box.append(words)

    def _preview_ready(self):
        self._fill_table()

    def _build_finish(self, _step_no):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        done_intro = self._words(size=12000)
        done_a = "All done."
        done_b = ("The pass journal keeps every before-value, so changes "
                  "can be undone.")
        self.fill(done_intro, done_a + " " + done_b)
        done_intro.set_tooltip_text("Pass journal: data/harden/journal")
        box.append(done_intro)
        self._finish_note = self._words(size=12000)
        self.fill(self._finish_note, "")
        box.append(self._finish_note)
        enable_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                             spacing=8)
        self._enable_btn = self._btn("Enable all protections",
                                     self._on_enable_all)
        self._enable_btn.add_css_class("gw-cta")
        enable_row.append(self._enable_btn)
        box.append(enable_row)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._undo_btn = self._btn("Undo last change", self._on_undo,
                                   sensitive=self._journal_id is not None)
        self._undo_btn.add_css_class("gw-cta")
        row.append(self._undo_btn)
        self._done_btn = self._btn("Done: close the wizard",
                                   self._close_host)
        self._done_btn.set_halign(Gtk.Align.END)
        self._done_btn.set_hexpand(True)
        row.append(self._done_btn)
        self._dash_btn = self._btn("Open Dashboard", self._open_board)
        row.append(self._dash_btn)
        box.append(row)
        return box

    def _enable_all_helper(self):
        from wiz.common import run_helper            # noqa: PLC0415
        return run_helper("tool-control", ["start-all"], timeout=240)

    def _on_enable_all(self, _btn, auto=False):
        if getattr(self, "_enable_all_busy", False):
            return False
        self._enable_all_busy = True
        if getattr(self, "_enable_btn", None) is not None:
            self._enable_btn.set_sensitive(False)
        if not auto:
            self.fill(self._finish_note, "Starting every protection. One "
                      "password prompt…")
        appfw_rc = {"on": False}

        def worker():
            rc = -1
            try:
                rc = self._enable_all_helper()
            except Exception:            # noqa: BLE001
                pass
            try:
                from appfw.engine import write_enabled   # noqa: PLC0415
                write_enabled(self._data_dir, True)
                appfw_rc["on"] = True
            except Exception:            # noqa: BLE001
                pass
            GLib.idle_add(self._enable_all_done, rc, appfw_rc["on"])

        threading.Thread(target=worker, daemon=True).start()
        return False

    def _enable_all_done(self, rc, appfw_on):
        self._enable_all_busy = False
        if getattr(self, "_enable_btn", None) is not None:
            self._enable_btn.set_sensitive(True)
        if rc == 0:
            text = "🟢 All protections started (app firewall ON)."
        else:
            tried = "🟡 Every unit was attempted."
            skipped = "Units that do not fit this host are skipped."
            text = tried + " " + skipped
        if appfw_on:
            text += " The app firewall switch is ON."
        self.fill(self._finish_note, text)
        return False

    def _close_host(self, *_a):
        host = self.get_root()
        if host is not None:
            try:
                host.destroy()
            except Exception:
                pass
        return False

    def _open_board(self, *_a):
        if self._open_dashboard is not None:
            try:
                self._open_dashboard()
            except Exception:
                pass
        self._close_host()
        return False

    def _on_undo(self, _btn):
        if self._journal_id is None:
            self.fill(self._finish_note, "Nothing was applied in this "
                      "session. Nothing to undo.")
            return False
        self._undo_btn.set_sensitive(False)
        self.fill(self._finish_note, f"Undoing pass {self._journal_id}: "
                  "one password prompt…")
        jid = self._journal_id

        def worker():
            try:
                result = undo_pass(jid, self._data_dir, self._run_helper)
            except Exception as exc:   # noqa: BLE001
                result = {"rc": -1, "undoed": False, "out": "",
                          "err": str(exc),
                          "words": "The undo could not run",
                          "journal_id": jid}
            GLib.idle_add(self._undo_done, result)

        threading.Thread(target=worker, daemon=True).start()

    def _undo_done(self, result):
        mark = "🟢" if result["undoed"] else "🔴"
        self.fill(self._finish_note, mark + " " + result["words"])
        self._undo_btn.set_sensitive(True)
        return False

class SetupWizardWindow(Gtk.Window):

    def __init__(self, parent=None, open_dashboard=None, open_chooser=None):
        super().__init__(title="greywatch: Setup Wizard")
        from gi.repository import Gdk
        screen_h = 1000
        try:
            mons = Gdk.Display.get_default().get_monitors()
            if mons is not None and mons.get_n_items() > 0:
                screen_h = mons.get_item(0).get_geometry().height
        except Exception:              # noqa: BLE001 - size is cosmetic
            pass
        self.set_default_size(880, min(760, max(480, screen_h - 90)))
        self.set_resizable(True)
        if parent is not None:
            self.set_transient_for(parent)
        self.wizard = SetupWizard(
            win=self,
            open_dashboard=open_dashboard,
            open_chooser=open_chooser)
        self.wizard.set_vexpand(True)
        self.set_child(self.wizard)
