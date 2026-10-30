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


def test_intent_plan_confirms_without_stream():
    """kind=intent plans go straight to the confirm gate — no model
    stream, no slop text between the question and the dialog."""
    from ui.assistant import AssistantPanel
    from assistant.intents import Intent

    class Stub:
        _turn_seq = 1
        _friendly = {"ufw": ("Firewall", "Blocks unwanted connections.")}

        def __init__(self):
            self.confirmed = []

        def _confirm(self, intent):
            self.confirmed.append(intent)

    texts = []

    class Holder:
        def set_text(self, t):
            texts.append(t)
    stub = Stub()
    ret = AssistantPanel._turn_planned(
        stub, 1, Holder(),
        {"kind": "intent", "intent": Intent("pause", "ufw")}, {})
    assert ret is False
    assert stub.confirmed == [Intent("pause", "ufw")]
    assert texts and "Firewall" in texts[0]


def test_theme_intent_runs_the_theme_store(tmp_path, monkeypatch):
    """The exec switch drives the same ThemeStore/combo/retheme path the
    Settings picker uses, records one audit line with the kit id, and
    blocks the combo's own handler while stepping it (no double apply)."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import window as W
    calls = []
    monkeypatch.setattr(W.audit, "record",
                        lambda action, tool, ok: calls.append((action, tool, ok)))

    class FakeStore:
        applied = []

        def apply(self, kit):
            self.applied.append(kit)
            return kit

    class FakeCombo:
        steps = []

        def handler_block_by_func(self, func):
            self.steps.append("block")

        def set_active_id(self, kit):
            self.steps.append("set:" + kit)

        def handler_unblock_by_func(self, func):
            self.steps.append("unblock")

    # Headless stub: only the attributes the theme branch touches.
    class FakeWin:
        _on_theme_pick = staticmethod(lambda *_a: None)   # never fires
        _retheme = staticmethod(lambda: None)

    win = FakeWin()
    win._theme_store = store = FakeStore()
    win.theme_combo = combo = FakeCombo()
    win._tick_id = lambda func, ms: combo.steps.append("retheme")

    W.MainWindow._assistant_intent(win, "theme", "", "light mode")
    assert store.applied == ["swiss"]        # spoken name -> the kit id
    assert combo.steps == ["block", "set:swiss", "unblock", "retheme"]
    assert calls == [("theme", "swiss", True)]


def test_retheme_snapshots_the_chat_and_reopens_the_feed(tmp_path,
                                                         monkeypatch):
    """_retheme is the only path both symptoms came from (owner 2026-10-30):
    the chat must be handed to the rebuilt panel, and the fresh activity
    store must not depend on the seen-guard or it stays empty."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    from ui import window as W

    class FakePanel:
        def snapshot_transcript(self):
            return {"rows": [("change theme to light mode", True)]}

    class FakeStack:
        def get_visible_child_name(self):
            return "tools"

        def remove(self, *_a):
            pass

    class FakeWin:
        stack = FakeStack()
        assistant_panel = FakePanel()
        rebuilt = {}
        views = {}
        shown = []

        def _show(self, key):
            self.shown.append(key)
            self._views = {}

        def refresh(self):
            self.refreshed = True

    win = FakeWin()
    win._views = {"logs": object(), "tools": object()}
    win._recent_seen = [1, 2, 3]
    W.MainWindow._retheme(win)
    assert win._chat_snapshot is not None
    assert "change theme to light mode" in win._chat_snapshot["rows"][0]
    assert win._recent_seen is None      # refresh() must refill the feed
    assert win.shown == ["tools"]
    assert win.refreshed


def test_chat_transcript_survives_a_retheme_rebuild():
    """The rebuilt panel must inherit the conversation and the anchors."""
    from ui.assistant import AssistantPanel

    def make():
        return AssistantPanel(
            registry=[], get_status=lambda: {"tools": {}},
            get_recent=lambda: [], get_llm=lambda: None,
            on_intent=lambda *a: None)

    panel = make()
    panel._bubble("change theme to light mode", mine=True)
    panel._bubble("Switch the app's look to the Light theme?")
    row = {"tool": "appfw", "severity": "MEDIUM", "text": "deny x",
           "ts": "2026-10-30T09:00:00+00:00"}
    panel._last_rows = [row]
    panel._last_tool = "appfw"
    snap = panel.snapshot_transcript()
    assert snap and snap["rows"] == [
        ("change theme to light mode", True),
        ("Switch the app's look to the Light theme?", False)]
    assert snap["last_rows"] == [row] and snap["last_tool"] == "appfw"

    fresh = make()
    n_before = len(list(fresh.stream.observe_children()))  # intro only
    fresh.restore_transcript(snap)
    grown = list(fresh.stream.observe_children())
    assert len(grown) == n_before + 2
    assert fresh._last_rows == [row] and fresh._last_tool == "appfw"


def test_event_plan_remembers_shown_rows_for_followups():
    """The panel must keep the rows of its last event listing so the next
    referential question can point at them."""
    from ui.assistant import AssistantPanel

    class Stub:
        _turn_seq = 2
        _friendly = {}
        _last_rows = []

    rows = [{"tool": "appfw", "severity": "MEDIUM",
             "text": "deny x (answered: deny)", "ts": "2026-10-29T13:57:09+00:00"}]
    texts = []

    class Holder:
        def set_text(self, t):
            texts.append(t)
    stub = Stub()
    AssistantPanel._turn_planned(
        stub, 2, Holder(),
        {"kind": "template", "slot": "explain_event",
         "text": "Newest events (local times): …", "rows": rows}, {})
    assert stub._last_rows == rows and texts
