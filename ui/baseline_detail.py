"""Baseline detail: the standard's table, the hardening catalog and the
CVE rows, as the Baseline tab's content.

Every read here is a cached store read; the verifier runs only when the
owner presses Run baseline checks, and both that and patching ride
`actions.run_async`, so the GTK main thread never waits on the CLI.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import actions, charts, cliapi, cveview, labels
from ui.widgets import card, count_word, cta_button, eyebrow, meta

_STATE_LEVEL = {"ENABLED": "ok", "PRESENT": "ok", "ARMED": "ok",
                "FRESH": "ok", "OFF-BY-DESIGN": "mute"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# The UI kills its CLI subprocess at these budgets. Each must outlast the
# CLI's own helper budget (3600 s for --affected, 1800 s for --all) so the
# CLI can still query dpkg and write the partial ledger before it dies.
# One home for both cards keeps them from drifting apart again.
AFFECTED_CALL_TIMEOUT = 3900
UPGRADE_CALL_TIMEOUT = 2100


def build(window) -> Gtk.Widget:
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page._gw_verify = {}
    page._gw_verify_slots = {}
    page._gw_patching = False

    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    button = actions.action_button(
        "Run baseline checks", lambda: _verify(page, button), cls="gw-cta")
    row.append(button)
    page.append(card(row, cls="gw-card gw-card-quiet"))

    page.append(_tools_card(page))
    page.append(_hardening_card(page))
    page._gw_cve_slot = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                spacing=4)
    page._gw_cve_slot.append(_cve_card(page))
    page.append(page._gw_cve_slot)
    return page


def refresh(page: Gtk.Widget) -> None:
    """Repaint from the cached data only; no verifier call here."""
    doc = getattr(page, "_gw_verify", None)
    if doc is not None:
        _fill(page, doc)
    _repaint_cves(page)


def _verify(page, button):
    actions.run_async(
        button,
        lambda: cliapi.jcall("verify", timeout=180),
        lambda doc: _fill(page, doc),
        pending="Reading the verifier...",
        done="Run baseline checks",
    )


def _fill(page, doc):
    page._gw_verify = doc or {}
    tools = page._gw_verify_slots.get("tools")
    if tools is not None:
        _clear(tools)
        tools.append(_tools_rows(page))
    hardening = page._gw_verify_slots.get("hardening")
    if hardening is not None:
        _clear(hardening)
        hardening.append(_hardening_rows(page))


def _clear(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


def _slots_of(page) -> dict:
    slots = getattr(page, "_gw_verify_slots", None)
    if slots is None:
        slots = {}
        page._gw_verify_slots = slots
    return slots


def _tools_card(page) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    slots = _slots_of(page)
    slots["tools"] = box
    box.append(_tools_rows(page))
    return box               # the rows' own card carries the frame


def _tools_rows(page) -> Gtk.Widget:
    doc = getattr(page, "_gw_verify", None)
    rows = (doc or {}).get("tool_baseline") or []
    if not rows:
        return card(eyebrow("Baseline table"),
                    meta("The table did not load. 'greywatch verify' "
                         "builds it; Run baseline checks retries."))
    table = [[labels.display_name(r.get("tool")),
              r.get("check") or "",
              labels.baseline_state(r.get("state"))[0],
              r.get("fix") or ""]
             for r in rows]
    scroller, _store = _tree((("Tool", 140), ("What the standard wants",
                                              330), ("State", 100),
                              ("The fix", 240)), table, kind="tools")
    _ = _store
    fails = [r for r in rows if r.get("state") not in _STATE_LEVEL]
    if not fails:
        return card(eyebrow(f"Baseline table - "
                        f"{count_word(len(rows), 'row')}"),
                    meta("What the standard expects per tool. A failing "
                         "row carries its fix in the row."), scroller)
    return card(eyebrow(f"Baseline table - "
                        f"{count_word(len(rows), 'row')}, "
                        f"{len(fails)} to fix"),
                meta("What the standard expects per tool. A failing "
                     "row carries its fix in the row."), scroller)


def _hardening_card(page) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    slots = _slots_of(page)
    slots["hardening"] = box
    box.append(_hardening_rows(page))
    return box               # the rows' own card carries the frame


def _hardening_rows(page) -> Gtk.Widget:
    doc = getattr(page, "_gw_verify", None)
    hard = (doc or {}).get("hardening") or {}
    gaps = hard.get("gaps") or []
    rows = [[labels.baseline_state(g.get("state"))[0],
             g.get("control") or "", g.get("current") or ""]
            for g in gaps]
    scroller, _s = _tree((("State", 110), ("Control", 140),
                          ("What the check read", 330)), rows,
                         kind="hardening")
    return card(eyebrow(f"Hardening catalog - {hard.get('pass', 0)} "
                        f"pass, {count_word(len(gaps), 'gap')}"),
                meta("Rows as the check reads them. Fixes run through "
                     "'greywatch harden' and the journaled helper."),
                scroller)


def _repaint_cves(page) -> None:
    slot = getattr(page, "_gw_cve_slot", None)
    if slot is None:
        return
    _clear(slot)
    slot.append(_cve_card(page))


def _patch_busy(page) -> bool:
    return bool(getattr(page, "_gw_patching", False))


def _set_patch_buttons(page, sensitive: bool) -> None:
    """Sibling buttons share the one dpkg lock, so they all wait while
    any patch runs."""
    for button in getattr(page, "_gw_patch_buttons", ()):
        button.set_sensitive(sensitive)


def _patch(page, package, button):
    if _patch_busy(page):
        return
    page._gw_patching = True
    actions.run_async(
        button,
        lambda: cliapi.call("patch", package, timeout=UPGRADE_CALL_TIMEOUT),
        lambda result: _patch_done(page, result),
        pending="Installing...",
        done=f"Patch {package}",
    )
    _set_patch_buttons(page, False)


def _patch_affected(page, button):
    if _patch_busy(page):
        return
    page._gw_patching = True
    actions.run_async(
        button,
        lambda: cliapi.call("patch", "--affected",
                            timeout=AFFECTED_CALL_TIMEOUT),
        lambda result: _patch_done(page, result),
        pending="Installing...",
        done="Patch affected packages",
    )
    _set_patch_buttons(page, False)


def _patch_all(page, button):
    if _patch_busy(page):
        return
    page._gw_patching = True
    actions.run_async(
        button,
        lambda: cliapi.call("patch", "--all", timeout=UPGRADE_CALL_TIMEOUT),
        lambda result: _patch_done(page, result),
        pending="Upgrading...",
        done="Upgrade the system",
    )
    _set_patch_buttons(page, False)


def _result_line(result) -> str:
    if isinstance(result, Exception):
        return str(result) or result.__class__.__name__
    try:
        rc, out, err = result
    except (TypeError, ValueError):
        return str(result)
    text = (out or err).strip().splitlines()
    return text[-1] if text else f"patch rc {rc}"


def _patch_done(page, result) -> None:
    """Land a patch result. The runner has already restored the button;
    this clears the shared guard, repaints the ledger and says what
    happened."""
    page._gw_patching = False
    line = _result_line(result)
    _repaint_cves(page)
    status = getattr(page, "_gw_cve_status", None)
    if status is not None:
        status.set_text(line)
    window = getattr(page, "_gw_window", None)
    if window is not None:
        window.note(line)


def _cve_card(page=None) -> Gtk.Widget:
    entries, doc = cveview.open_rows()
    if not entries:
        return card(
            eyebrow("CVE rows"),
            meta("No package-aware CVE row is open. The Debian tracker "
                 "refresh writes them; a package patched to its fixed "
                 "version drops out."),
            cls="gw-card gw-card-quiet")
    entries = sorted(entries, key=lambda e:
                     _SEVERITY_RANK.get(str(e.get("severity", "")).upper(),
                                        9))
    rows = [[str(e.get("id") or ""),
             str(e.get("package") or ""),
             str(e.get("severity") or "").upper(),
             str(e.get("installed") or ""),
             str(e.get("fixed") or "no fix")]
            for e in entries[:40]]
    scroller, _s = _tree((("Address", 140), ("Package", 130),
                          ("Severity", 90), ("Installed", 110),
                          ("Fixed", 110)), rows, kind="cves")
    _ = _s
    # One button per package in the visible rows; the install-all action
    # covers the rest without building a thousand widgets.
    packages = sorted({str(e.get("package")) for e in entries[:40]})
    action_row = Gtk.FlowBox()
    action_row.set_selection_mode(Gtk.SelectionMode.NONE)
    action_row.set_max_children_per_line(3)
    action_row.set_min_children_per_line(1)
    action_row.set_column_spacing(8)
    action_row.set_row_spacing(8)
    buttons = []
    for package in packages:
        button = Gtk.Button(label=f"Patch {package}")
        button.add_css_class("gw-secondary")
        button.connect(
            "clicked",
            lambda _b, p=package, btn=button: _patch(page, p, btn))
        action_row.insert(button, -1)
        buttons.append(button)
    status = meta("")
    if page is not None:
        page._gw_cve_status = status
    affected_button = cta_button(
        "Patch affected packages",
        lambda _b: _patch_affected(page, affected_button))
    all_button = actions.action_button(
        "Upgrade the system",
        lambda: _patch_all(page, all_button),
        parent=getattr(page, "_gw_window", None),
        confirm="Every installed package may be upgraded, not only the "
                "ones with an open CVE. This can take several minutes.")
    buttons.extend([affected_button, all_button])
    if page is not None:
        page._gw_patch_buttons = buttons
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for e in entries:
        key = (str(e.get("severity") or "").upper())
        if key in counts:
            counts[key] += 1
    donut_parts = [("Critical", counts["CRITICAL"], "fail"),
                   ("High", counts["HIGH"], "warn"),
                   ("Medium", counts["MEDIUM"], "info"),
                   ("Low", counts["LOW"], "ok")]
    if any(v for _l, v, _k in donut_parts):
        d, legend = charts.donut(donut_parts, size=110)
        drow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        drow.append(d)
        drow.append(legend)
    else:
        drow = meta("No severity counts to chart.")
    suite = str(doc.get("suite") or "?")
    tally = cveview.counts(entries, doc)
    installed = int(tally.get("installed") or 0)
    cap = ""
    if tally.get("capped") and int(tally.get("total") or 0) > \
            int(tally.get("rows") or 0):
        cap = (f" Showing {tally['rows']} of "
               f"{count_word(int(tally['total']), 'open row')} in the "
               "cache.")
    shown = min(40, len(entries))
    shown_line = (meta(f"Showing {shown} of "
                       f"{count_word(len(entries), 'open CVE row')}.")
                  if shown < len(entries) else None)
    args = [eyebrow(f"CVE rows - "
                    f"{count_word(len(entries), 'open package row')}"),
            meta(f"Debian tracker, suite {suite}, {installed} "
                 f"installed. A patched package drops out; "
                 f"announcement is not patching.{cap}")]
    if shown_line is not None:
        args.append(shown_line)
    args.extend([drow, scroller, status, action_row,
                 affected_button, all_button])
    return card(*args)


def _tree(cols, rows, kind: str = ""):
    from ui.network import _tree
    scroller, _store = _tree(columns=cols, rows=rows)
    scroller._gw_kind = kind
    return scroller, _store
