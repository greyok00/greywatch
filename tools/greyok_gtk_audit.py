#!/usr/bin/env python3
"""GreyWatch's GTK adapter for `greyok-doctor ui --probe`.

The doctor core is framework-neutral. This adapter owns the GTK knowledge:
it starts a private Xvfb, builds every registered page with isolated seed
data, and reports structural failures the static checks cannot see. It emits
the doctor adapter protocol on stdout and never touches the live display or
the live state directory.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PAGES = ("Security Center", "Network", "Tools", "Timeline", "Assistant", "Help")
TOOLS = (
    "clamav", "freshclam", "yara-watch", "yara-tmp-scan", "ufw", "appfw",
    "psad", "fail2ban", "arpwatch", "net-watch", "auditd", "apparmor",
    "tetragon", "responderd", "rkhunter", "lynis", "aide", "cve-updater",
)


def _finding(check: str, severity: str, message: str, detail: str = "",
             path: str = "") -> dict:
    out = {"check": check, "severity": severity, "message": message}
    if detail:
        out["detail"] = detail[:8000]
    if path:
        out["path"] = path
    return out


def _seed(path: pathlib.Path) -> None:
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    tools = {
        name: {"label": name.replace("-", " ").title(), "state": "GREEN",
               "unit_state": "active", "last_event": now,
               "unit": f"{name}.service"}
        for name in TOOLS
    }
    (path / "status.json").write_text(json.dumps({
        "updated": now, "tools": tools, "defense": {"blocked": []},
        "pending_list": [], "browser_watch": {"projects": [], "rows": []},
    }), encoding="utf-8")
    (path / "posture.json").write_text(json.dumps({
        "version": 1, "built_at": now, "score": 73,
        "inputs": {
            "lynis_hardening": {"value": 72, "direction": "higher-is-better",
                                "how": "adapter seed"},
            "baseline_pass": {"value": 80, "direction": "higher-is-better",
                              "how": "adapter seed"},
            "cve_exposure": {"value": 2, "direction": "lower-is-better",
                             "how": "adapter seed"},
            "apparmor_exposure": {"value": 25, "direction": "higher-is-better",
                                  "how": "adapter seed"},
        },
    }), encoding="utf-8")
    (path / "events.jsonl").write_text(
        json.dumps({"ts": now, "tool": "clamav", "severity": "info",
                    "text": "adapter seed"}) + "\n", encoding="utf-8")


def _xvfb() -> tuple[subprocess.Popen | None, str | None]:
    exe = shutil.which("Xvfb")
    if not exe:
        return None, "Xvfb unavailable"
    for num in range(95, 140):
        sock = pathlib.Path(f"/tmp/.X11-unix/X{num}")
        if sock.exists():
            continue
        proc = subprocess.Popen(
            [exe, f":{num}", "-screen", "0", "1440x900x24", "-nolisten", "tcp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(60):
            if sock.exists():
                return proc, f":{num}"
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        proc.terminate()
    return None, "no free Xvfb display"


def _widget_text(widget) -> str:
    try:
        text = widget.get_label()
        if text:
            return str(text)
    except Exception:  # noqa: BLE001
        pass
    try:
        text = widget.get_text()
        if text:
            return str(text)
    except Exception:  # noqa: BLE001
        pass
    return ""


def _walk(widget):
    yield widget
    child = widget.get_first_child() if hasattr(widget, "get_first_child") else None
    while child is not None:
        yield from _walk(child)
        child = child.get_next_sibling()


def _audit_window(win) -> list[dict]:
    findings: list[dict] = []
    # Every registry label must have a built page and a rail row.
    for label in PAGES:
        page = win._pages.get(label)
        if page is None:
            findings.append(_finding("ui-gtk-page", "fail",
                                     f"registered page did not build: {label}"))
            continue
        if label not in getattr(win, "_rail_rows", {}):
            findings.append(_finding("ui-gtk-rail", "warn",
                                     f"registered page has no rail row: {label}"))
    sec = (win._page_widgets.get("Security Center")
           or win._pages.get("Security Center"))
    body = getattr(sec, "_gw_body", None) if sec is not None else None
    overview = getattr(body, "_gw_overview", None) if body is not None else None
    if overview is not None:
        children = []
        child = overview.get_first_child()
        while child is not None:
            children.append(child)
            child = child.get_next_sibling()
        order = [getattr(body, key, None) for key in
                 ("_gw_head", "_gw_hero", "_gw_grid", "_gw_scan_block")]
        if all(item is not None for item in order):
            indexes = [children.index(item) for item in order]
            if indexes != sorted(indexes):
                findings.append(_finding(
                    "ui-gtk-order", "fail",
                    "Security Center order is wrong: expected headline, score, cards, scan desk.",
                    detail=f"child indexes: {indexes}",
                ))
        else:
            findings.append(_finding(
                "ui-gtk-order", "warn",
                "Security Center order anchors are incomplete; cannot prove the page order.",
            ))
    tools = (win._page_widgets.get("Tools")
             or win._pages.get("Tools"))
    tree = next((w for w in _walk(tools) if w.__class__.__name__ == "TreeView"
                 and hasattr(w, "get_model")), None) if tools is not None else None
    if tree is not None:
        parent = tree.get_parent()
        if parent is not None and hasattr(parent, "get_policy"):
            _horizontal, vertical = parent.get_policy()
            # Gtk.PolicyType.NEVER == 2; enum .name is not available in PyGObject.
            if int(vertical) != 2:
                findings.append(_finding(
                    "ui-gtk-table", "warn",
                    "Tools table has its own vertical scroller and can clip its last row.",
                    path="ui/tools.py:card_tree",
                ))
        model = tree.get_model()
        rows = model.iter_n_children(None) if model is not None else 0
        if rows < len(TOOLS):
            findings.append(_finding(
                "ui-gtk-table", "warn",
                f"Tools table holds {rows} rows; expected at least {len(TOOLS)}.",
            ))
    # A conservative a11y pass: only buttons/entries with no discoverable name.
    unnamed = []
    for widget in _walk(win):
        name = widget.__class__.__name__
        if name not in {"Button", "Entry", "SearchEntry"}:
            continue
        if _widget_text(widget):
            continue
        if widget.get_tooltip_text():
            continue
        accessible = getattr(widget, "get_accessible_role", None)
        if accessible is None:
            unnamed.append(name)
    if unnamed:
        findings.append(_finding(
            "ui-gtk-a11y", "info",
            f"{len(unnamed)} interactive widget(s) have no text or tooltip name.",
            detail=", ".join(sorted(set(unnamed))),
        ))
    return findings


def _run() -> dict:
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        from gi.repository import Gio, GLib
    except Exception as exc:  # noqa: BLE001
        return {"schema": 1, "skip": f"GTK4 unavailable: {exc}"}
    xvfb, display = _xvfb()
    if xvfb is None or display is None:
        return {"schema": 1, "skip": display or "no display"}
    os.environ["DISPLAY"] = display
    os.environ["GDK_BACKEND"] = "x11"
    os.environ["GDK_DISABLE"] = "gl,vulkan"
    findings: list[dict] = []
    seed = tempfile.TemporaryDirectory(prefix="gw-gtk-audit-")
    os.environ["GREYWATCH_DATA_DIR"] = seed.name
    _seed(pathlib.Path(seed.name))
    try:
        from ui import app as app_mod
        app = app_mod.App()
        app.set_flags(Gio.ApplicationFlags.NON_UNIQUE)
        box: dict = {}

        def pump(n: int = 30) -> None:
            ctx = GLib.main_context_default()
            for _ in range(n):
                ctx.iteration(False)
                time.sleep(0.005)

        def activate(_app):
            try:
                app_mod.App.do_activate(_app)
                win = _app._win
                if win is None:
                    findings.append(_finding("ui-gtk-shell", "fail", "window did not open"))
                    _app.quit()
                    return
                for label in PAGES:
                    win.show_page(label)
                    pump(35)
                findings.extend(_audit_window(win))
                box["ok"] = True
            except Exception as exc:  # noqa: BLE001
                findings.append(_finding("ui-gtk-shell", "fail",
                                         "GTK page build raised an exception.",
                                         detail=repr(exc)))
            finally:
                _app.quit()

        app.connect("activate", activate)
        app.run(None)
    except Exception as exc:  # noqa: BLE001
        findings.append(_finding("ui-gtk-shell", "fail",
                                 "GTK audit could not start.", detail=repr(exc)))
    finally:
        seed.cleanup()
        xvfb.terminate()
        try:
            xvfb.wait(timeout=4)
        except subprocess.TimeoutExpired:
            xvfb.kill()
    return {"schema": 1, "findings": findings, "meta": {"framework": "gtk4"}}


def main() -> int:
    try:
        json.load(sys.stdin)
    except ValueError:
        pass
    print(json.dumps(_run()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
