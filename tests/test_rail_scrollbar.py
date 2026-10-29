# tests/test_rail_scrollbar.py
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_rail_scroller_drops_the_overlay_scrollbar():
    """The rail ends on its own pause/play buttons; the GTK4 floating
    grey pill painted over them reads as a broken overlay (owner report
    2026-10-29). Structural pin, in the spirit of the Gtk3-era API ban
    list checks."""
    assert "sc.set_overlay_scrolling(False)" in (
        ROOT / "ui" / "window.py").read_text()
