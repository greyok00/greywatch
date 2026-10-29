# tests/test_assistant_window.py
import pathlib, sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def test_assistant_intent_dispatch_routes_to_toggle_helpers(
        tmp_path, monkeypatch):
    # Headless-safe: exercise dispatch logic without opening the window.
    # Redirect the audit ledger into pytest's tmp dir — no real writes.
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import window as W

    class FakeWin:
        actions = []

        def _pause_selected(self):
            FakeWin.actions.append(("pause", self._selected_tool))

        def _resume_selected(self):
            FakeWin.actions.append(("resume", self._selected_tool))

        def _open_detail(self, tool):
            FakeWin.actions.append(("details", tool))

    win = FakeWin()
    W.MainWindow._assistant_intent(win, "pause", "ufw")
    W.MainWindow._assistant_intent(win, "details", "apparmor")
    assert FakeWin.actions == [("pause", "ufw"), ("details", "apparmor")]


def test_rail_builder_exists_and_panel_importable():
    from ui.window import MainWindow
    from ui.assistant import AssistantPanel
    assert hasattr(MainWindow, "_build_assistant_rail")
    assert hasattr(MainWindow, "_assistant_intent")
