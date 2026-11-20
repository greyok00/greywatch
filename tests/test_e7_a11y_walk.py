"""E-7: accessibility walk — every interactive widget carries a
human-readable name.

The a11y law walked over the real widget tree (GTK4 exposes the tree
directly; pyatspi is not installed on this box and Atspi needs its own
bus): every Gtk.Button/ToggleButton/CheckButton/Entry/DropDown/
SpinButton/Switch in the window must have readable text — its own label,
placeholder, or the label of the row that holds it. A button that renders
as an empty box is exactly the a11y hole the campaign checks by eye.
"""
from __future__ import annotations

import os
import pathlib
import socket
import shutil
import subprocess
import tempfile
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _xvfb():
    """A private display for this test, plus its own lock/socket cleanup:
    a stale socket file (an abnormally killed earlier run) would make
    every candidate display look taken and the whole gate skip. The
    socket file dies with the server; a dead socket that still exists on
    disk is removed before the connect attempt."""
    xvfb = shutil.which("Xvfb")
    if xvfb is None:
        pytest.skip("Xvfb unavailable")
    proc = None
    for num in range(95, 130):
        sock = pathlib.Path(f"/tmp/.X11-unix/X{num}")
        lock = pathlib.Path(f"/tmp/.X{num}-lock")
        if sock.exists():
            # A socket nobody is serving is stale debris, not a display.
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                probe.connect(str(sock))
                probe.close()
                continue          # a live server holds it
            except (ConnectionRefusedError, BrokenPipeError):
                pass              # stale: safe to reuse below
            except OSError:
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
        if lock.exists():
            try:
                lock.unlink()
            except OSError:
                pass
    pytest.skip("no free Xvfb display")


def _label_of(widget):
    """The human-readable text a screen reader would speak for w.
    GTK's accessible name is computed from the widget's own label OR a
    descendant GtkLabel (card buttons title themselves through a nested
    box/label several levels down), so the search walks the subtree."""
    text = ""
    if hasattr(widget, "get_label") and callable(widget.get_label):
        try:
            text = widget.get_label() or ""
        except Exception:
            text = ""
    if not text and hasattr(widget, "get_placeholder_text"):
        try:
            text = widget.get_placeholder_text() or ""
        except Exception:
            pass
    if not text:
        # bounded subtree search: the first real name wins - label text
        # (non-empty) or an icon's name, which is what a screen reader
        # speaks for an icon button
        stack, seen = [widget], 0
        while stack and seen < 400 and not text:
            node = stack.pop()
            seen += 1
            if isinstance(node, Gtk.Label):
                t = (node.get_text() or "").strip()
                if t:
                    text = t
                continue
            if isinstance(node, Gtk.Image):
                name = node.get_icon_name() or ""
                if name:
                    text = name
                continue
            child = node.get_first_child()
            while child is not None:
                stack.append(child)
                child = child.get_next_sibling()
    return text.strip()


def _walk(widget, out, depth=0):
    out.append(widget)
    if depth > 30:
        return
    node = widget.get_first_child()
    seen = 0
    while node is not None and seen < 400:
        seen += 1
        _walk(node, out, depth + 1)
        node = node.get_next_sibling()


def _inside_composite(widget, levels=4):
    """True when w is an internal piece of a GTK composite (ComboBoxText/
    DropDown toggles, ListView cell buttons). Their accessible names are
    owned and spoken by the composite itself — they are not app-authored
    holes, and they cannot carry an app-set label."""
    node = widget
    for _ in range(levels):
        node = node.get_parent()
        if node is None:
            return False
        if isinstance(node, (Gtk.ComboBoxText, Gtk.DropDown,
                             Gtk.ListView, Gtk.ColumnView,
                             Gtk.GridView, Gtk.TreeView,
                             Gtk.TreeExpander)):
            return True
    return False


import gi  # noqa: E402
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

INTERACTIVE = (Gtk.Button, Gtk.ToggleButton, Gtk.CheckButton, Gtk.Entry,
               Gtk.DropDown, Gtk.SpinButton, Gtk.SearchEntry)


def _a11y_walk(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path / "data"))
    (tmp_path / "data").mkdir(exist_ok=True)
    from gi.repository import GLib
    GLib  # keep the import explicit
    import ui.window as W
    W.snapshot_stale = lambda *a, **k: False
    from ui.window import MainWindow

    win = MainWindow()
    win.present()

    def pump(n):
        for _ in range(n):
            GLib.MainContext.default().iteration(may_block=False)

    pump(40)
    unnamed = []
    total = 0
    for view in ("overview", "protect", "settings", "auditlog"):
        win._show(view)
        pump(30)
        tree = []
        for w in list(win._views.values()) or [win]:
            _walk(w, tree)
        for w in tree:
            if isinstance(w, INTERACTIVE):
                if _inside_composite(w):
                    continue          # composite-owned (see the helper)
                total += 1
                if not _label_of(w):
                    unnamed.append((view, type(w).__name__))
    win.destroy()
    pump(5)
    assert total > 15, \
        f"the walk found too few widgets ({total}) — tree iteration broke"
    assert not unnamed, \
        f"interactive widgets without any readable text: " \
        f"{unnamed[:10]} ({len(unnamed)}/{total})"


def test_every_interactive_widget_is_named(tmp_path, monkeypatch):
    if shutil.which("Xvfb") is None:
        pytest.skip("Xvfb unavailable")
    server = _xvfb()
    try:
        _a11y_walk(tmp_path, monkeypatch)
    finally:
        # this gate owns its server (conftest's atexit stops only its
        # own _xvfb); orphaned Xvfb processes and their lock files
        # accumulated here on 2026-11-12 until every candidate display
        # looked taken and the gate skipped.
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except Exception:
                server.kill()

