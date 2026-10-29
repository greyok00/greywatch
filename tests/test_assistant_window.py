# tests/test_assistant_window.py
import pathlib, sys

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
    # ui.window imports the panel itself, so a broken AssistantPanel class
    # body fails this import too (the plain "panel importable" property).
    assert hasattr(MainWindow, "_build_assistant_rail")
    assert hasattr(MainWindow, "_assistant_intent")


def test_assistant_pause_outcome_recorded_once(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import window as W
    calls = []
    monkeypatch.setattr(W.audit, "record",
                        lambda action, tool, ok: calls.append((action, tool, ok)))
    class FakeWin:
        fired = []
        def _pause_selected(self):
            FakeWin.fired.append("pause")
        def _resume_selected(self):
            FakeWin.fired.append("resume")
        def _open_detail(self, tool):
            FakeWin.fired.append(tool)
    win = FakeWin()
    W.MainWindow._assistant_intent(win, "pause", "ufw")
    assert FakeWin.fired == ["pause"]
    assert win._assistant_pending == ("pause", "ufw")
    assert calls == []                    # nothing recorded before the outcome
    W.MainWindow._assistant_record_outcome(win, False)
    assert calls == [("pause", "ufw", False)]
    W.MainWindow._assistant_record_outcome(win, True)   # cleared: no-op
    assert calls == [("pause", "ufw", False)]
