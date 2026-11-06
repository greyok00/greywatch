"""The decisions list window keeps its own geometry (GW-161).

The pill opens a 760 px list window; every row in it must fit without
horizontal scrolling or clipped lines when the store is at its ugliest
(long subjects, long details, three answer buttons). GTK measures a
non-wrapping label as its single-line width, so these pins hold the
measured minimum under the window's own width after a real paint.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi_required = pytest.importorskip("gi")
gi_required.require_version("Gtk", "4.0")

from gi.repository import GLib, Gtk  # noqa: E402

import greywatch_daemon as dm  # noqa: E402

from tests.test_gw161_fixes import _event  # noqa: E402  (fixture reuse)

W_WIDTH = 760
LIMIT = 748          # window minus a margin's worth of slack


def _paint(w, n=80):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def _min_widths(widget, out):
    try:
        m = widget.measure(Gtk.Orientation.HORIZONTAL, -1)[0]
    except Exception:
        return
    if m > 0:
        out.append((m, type(widget).__name__))
    if isinstance(widget, Gtk.Root):
        return
    try:
        kids = list(widget)
    except Exception:
        return
    for c in kids:
        _min_widths(c, out)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "DATA_DIR", tmp_path)
    # rebuild Phase 1: the decision pipeline resolves through gwpaths, so
    # steering lives on the env side (same rule the rest of the suite uses)
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def test_decisions_list_rows_never_demand_their_window(store):
    long_subject = "The absolutely longest subject line a rule can mint " \
        "so a wrapped paint can not demand a single 900px line"
    long_detail = "a very long signature name (sha256:abcdef) · " \
        "/home/user/Documents/somewhere/deep in the tree/sample.bin " \
        "and then even more words after that to stretch the detail line"
    rows = [json.dumps(_event("2026-11-01T01:00:00+00:00", "responderd:abc",
                              subject=long_subject))
            for _ in range(3)]
    (store / "events.jsonl").write_text("\n".join(
        [row.replace('"sig · /tmp/x"', json.dumps(long_detail))
         for row in rows]) + "\n")

    from ui.decisionlist import DecisionsWindow
    w = DecisionsWindow()
    w.set_default_size(W_WIDTH, 540)
    w.present()
    _paint(w)
    out = []
    _min_widths(w, out)
    offenders = sorted([o for o in out if o[0] > LIMIT], reverse=True)[:8]
    assert not offenders, f"window demands {LIMIT}px but got {offenders}"
    w.destroy()
