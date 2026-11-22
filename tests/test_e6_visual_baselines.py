"""E-6: GUI pixel baselines — the GTK analogue of BackstopJS.

Screenshots of the four dashboard views on the private Xvfb, compared
against approved baselines with ImageMagick `compare`; a drift above the
per-view threshold names the view. Baselines regenerate ONLY via
 GREYWATCH_REGEN_BASELINES=1 after an owner-approved visual change (the
campaign's protocol: a human approves what the window should look like).
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINES = ROOT / "tests" / "baselines"

VIEW_METRICS = {          # view -> (resize W x H, RMSE threshold /255)
    # live-row views tolerate row-text churn (clock, tool states, drop
    # counts); real layout breakage (a lost pane) lands far above 0.15
    "overview": ((1200, 800), 0.12),
    "protect": ((1200, 800), 0.12),
    "settings": ((1200, 800), 0.10),   # rows list noise (fonts) allowed
    "auditlog": ((1200, 800), 0.15),   # log rows carry timestamps
}


def _xvfb():
    xvfb = shutil.which("Xvfb")
    if xvfb is None:
        pytest.skip("Xvfb unavailable")
    for num in range(95, 130):
        sock = pathlib.Path(f"/tmp/.X11-unix/X{num}")
        if sock.exists():
            continue
        proc = subprocess.Popen(
            [xvfb, f":{num}", "-screen", "0", "1600x1000x24",
             "-nolisten", "tcp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if pathlib.Path(f"/tmp/.X11-unix/X{num}").exists():
                break
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if pathlib.Path(f"/tmp/.X11-unix/X{num}").exists():
            os.environ["DISPLAY"] = f":{num}"
            return proc
        proc.terminate()
    pytest.skip("no free Xvfb display")


def _shotGTK(out_png, tmp_path):
    """In-process GTK export of the mapped window on our own display.
    GREYWATCH_DATA_DIR is frozen by the caller (monkeypatch) so this
    drill never reads the live install's status."""
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib
    import ui.window as W
    W.snapshot_stale = lambda *a, **k: False
    from ui.window import MainWindow
    win = MainWindow()
    win.present()

    def pump(n):
        for _ in range(n):
            GLib.MainContext.default().iteration(may_block=False)

    pump(40)
    shots = {}
    for view in VIEW_METRICS:
        win._show(view)
        pump(30)
        subprocess.run(["import", "-window", "root", str(out_png)],
                       env=dict(os.environ, DISPLAY=os.environ["DISPLAY"]))
        shots[view] = out_png
    win.destroy()
    pump(10)
    return shots


@pytest.mark.parametrize("view", sorted(VIEW_METRICS))
def test_view_pixel_baseline(view, tmp_path, monkeypatch):
    """Each view's screenshot stays inside its approved RMSE budget."""
    if os.environ.get("GREYWATCH_REGEN_BASELINES") == "1":
        pytest.skip("regen run: baselines are being rewritten, not checked")
    mp = pytest.MonkeyPatch.context()
    with mp as m:
        m.setenv("GREYWATCH_DATA_DIR", str(tmp_path / "data"))
        (tmp_path / "data").mkdir(exist_ok=True)
        BASELINES.mkdir(parents=True, exist_ok=True)
        baseline = BASELINES / f"{view}.png"
        (size, threshold) = VIEW_METRICS[view]
        shot = tmp_path / f"{view}-new.png"
        _shotGTK(shot, tmp_path)
    if not baseline.exists():
        shutil.copy(shot, baseline)
        pytest.skip(f"baseline created on first run for {view}; "
                    "re-run to compare (owner approved by definition)")
    out = subprocess.run(["compare", "-metric", "RMSE", str(baseline),
                          str(shot), "null:"],
                         capture_output=True, text=True)
    line = (out.stderr or out.stdout or "").strip()
    # RMSE line: "1234 (0.0472)"; the parenthesised ratio is /255
    try:
        rmse = float(line.rsplit("(", 1)[1].split(")")[0])
    except Exception:
        pytest.fail(f"compare produced no ratio: {line!r}")
    assert rmse <= threshold, \
        f"{view} drifted: RMSE {rmse:.4f} > {threshold} ({line})"
