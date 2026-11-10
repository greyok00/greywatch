"""Task 6 of the 2026-11-03 full-UI redesign, re-rooted to the round-2
voices (2026-11-09): Appearance in Settings is two radios — Paper (light)
/ Graphite (dark) — and the checked one applies through the theme store,
persists, and rebuilds the pages. The owner's real settings file is kept
out of the loop with a monkeypatched path; the test restores the in-memory
pick at the end."""
import os
import pathlib
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import GLib  # noqa: E402

if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

from ui import themes  # noqa: E402


def pump(n=20):
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


@pytest.fixture
def sealed_settings():
    settings = pathlib.Path(tempfile.mkdtemp()) / "settings.json"
    monkey = pytest.MonkeyPatch()
    monkey.setattr(themes, "SETTINGS_PATH", settings)
    yield settings
    monkey.undo()
    themes.set_active_theme("graphite")


def test_appearance_radios_flip_persist_and_rebuild(sealed_settings):
    assert themes.active_theme() == "graphite"
    from ui.window import MainWindow
    win = MainWindow()
    win.present()
    pump(30)
    try:
        win._show("settings")
        pump(10)
        win._settings_stack.set_visible_child_name("look")
        pump(10)
        assert win._radio_graphite.get_active()
        # One click applies, persists into the patched settings file, and
        # schedules the page rebuild.
        win._radio_paper.set_active(True)
        pump(30)
        assert themes.active_theme() == "paper"
        assert themes.load_setting() == "paper"
        # The rebuild recreated the settings page; the new radios carry
        # the freshly picked voice.
        win._show("settings")
        pump(10)
        assert win._radio_paper.get_active()
        assert not win._radio_graphite.get_active()
        # And back, the same way, so the machine is left where it began.
        win._radio_graphite.set_active(True)
        pump(30)
        assert themes.active_theme() == "graphite"
        assert themes.load_setting() == "graphite"
    finally:
        win.destroy()


def test_appearance_radios_carry_the_voice_names(sealed_settings):
    from ui.window import MainWindow
    win = MainWindow()
    win.present()
    pump(30)
    try:
        win._show("settings")
        pump(10)
        assert win._radio_paper.get_label() == "Paper, light"
        assert win._radio_graphite.get_label() == "Graphite, dark"
    finally:
        win.destroy()
