"""The pause contract: a pause is only ever shown when the protection is
really stopped, the label never names an actor, and the panic lockdown
path enables everything. These run headless by binding the window's
methods onto stand-in objects (window instantiation needs a display)."""
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import greywatch_daemon as daemon_mod    # noqa: E402
import ui.window                          # noqa: E402
from ui.models import status_words        # noqa: E402


class Store:
    def __init__(self, names=()):
        self.paused = set(names)
        self.sets = []

    def is_paused(self, name):
        return name in self.paused

    def set(self, name, value):
        (self.paused.add if value else self.paused.discard)(name)
        self.sets.append((name, value))
        return True


class FakeWin:
    """Stand-in exposing exactly what the real methods touch."""

    def __init__(self, registry, store, tools=None, appfw="running"):
        self.registry = registry
        self.paused = store
        self._state_override = {}
        self._snap = dict(tools or {})
        self._snap["appfw_engine"] = appfw
        self._snap["updated"] = "2026-10-26T00:00:00+00:00"
        self.refreshes = 0
        self.messages = []

    def refresh(self):
        self.refreshes += 1

    def _display_state(self, name, info, updated):
        ov = self._state_override.get(name)
        if ov:
            return ov[0]
        return (self._snap.get("tools", {}).get(name, {})
                or {}).get("state", "UNKNOWN")


def _registry(*names):
    return [{"name": n, "unit": f"{n}.stub"} for n in names]


def test_a_running_protection_cannot_be_labelled_paused():
    fake = FakeWin(_registry("appfw", "responderd", "fail2ban"),
                   Store(("appfw", "responderd")))
    fake._snap["tools"] = {
        "appfw": {"state": "GREEN"},
        "responderd": {"state": "GREEN"},
        "fail2ban": {"state": "RED"},
    }
    ui.window.MainWindow._reconcile_pause_markers(fake, fake._snap)
    assert fake.paused.paused == set(), fake.paused.paused
    assert ("appfw", False) in fake.paused.sets
    assert ("responderd", False) in fake.paused.sets


def test_an_actually_stopped_protection_keeps_its_marker():
    fake = FakeWin(_registry("responderd"), Store(("responderd",)))
    fake._snap["tools"] = {"responderd": {"state": "RED"}}
    ui.window.MainWindow._reconcile_pause_markers(fake, fake._snap)
    assert fake.paused.paused == {"responderd"}, fake.paused.paused


def test_appfw_running_engine_overrides_a_paused_marker():
    fake = FakeWin(_registry("appfw"), Store(("appfw",)),
                   tools={"appfw": {"state": "GREEN"}})
    ui.window.MainWindow._reconcile_pause_markers(fake, fake._snap)
    assert fake.paused.paused == set()


def test_a_store_without_set_is_skipped_not_crashed():
    class ReadOnly:
        paused = {"appfw"}

        def is_paused(self, name):
            return name in self.paused

    fake = FakeWin(_registry("appfw"), ReadOnly(),
                   tools={"appfw": {"state": "GREEN"}})
    ui.window.MainWindow._reconcile_pause_markers(fake, fake._snap)
    assert ReadOnly.paused == {"appfw"}


def test_words_for_a_pause_never_name_anyone():
    assert status_words("RED", True, True) == "paused"
    assert status_words("GREEN", True, True) == "paused"
    assert "you" not in status_words("RED", True, True)


def test_panic_enables_everything_and_unpauses(monkeypatch, capsys):
    fake = FakeWin(_registry("appfw", "fail2ban"), Store(("appfw",)))
    fake._snap["tools"] = {
        "appfw": {"state": "GREEN"},
        "fail2ban": {"state": "GREEN"},
    }
    monkeypatch.setattr(daemon_mod, "load_status", lambda *_a: fake._snap)
    started = []
    fake._toggle_tool = lambda name, pause: started.append((name, pause))
    fake.appfw_checks = []
    fake._ensure_appfw_enabled = lambda: fake.appfw_checks.append(1)
    try:
        ui.window.MainWindow._enable_everything(fake)
    finally:
        pass
    assert started == [], started          # everything was already running
    assert fake.appfw_checks == [1], fake.appfw_checks
    assert fake.paused.paused == set(), fake.paused.paused
    assert fake.refreshes == 1, fake.refreshes
    assert ("Cleared stale pause records: appfw."
            in capsys.readouterr().out)


def test_panic_starts_whatever_is_down(monkeypatch):
    fake = FakeWin(_registry("appfw", "fail2ban"), Store())
    fake._snap["tools"] = {
        "appfw": {"state": "GREEN"},
        "fail2ban": {"state": "GREEN"},
    }
    monkeypatch.setattr(daemon_mod, "load_status", lambda *_a: fake._snap)
    fake._state_override = {"fail2ban": ("RED", None)}
    started = []
    fake._toggle_tool = lambda name, pause: started.append((name, pause))
    fake.appfw_checks = []
    fake._ensure_appfw_enabled = lambda: fake.appfw_checks.append(1)
    ui.window.MainWindow._enable_everything(fake)
    assert started == [("fail2ban", False)], started
    assert fake.appfw_checks == [1], fake.appfw_checks


def test_startup_keep_on_is_silent_when_all_is_well(monkeypatch):
    fake = FakeWin(_registry("appfw", "responderd"), Store())
    fake._snap["tools"] = {
        "appfw": {"state": "GREEN"},
        "responderd": {"state": "GREEN"},
    }
    monkeypatch.setattr(daemon_mod, "load_status", lambda *_a: fake._snap)
    resumes = []
    fake._resume_tool = lambda name: resumes.append(name)
    fake.appfw_checks = []
    fake._ensure_appfw_enabled = lambda: fake.appfw_checks.append(1)
    ui.window.MainWindow._ensure_default_on(fake)
    assert resumes == [], resumes          # nothing was down, nothing run
    assert fake.appfw_checks == [1], fake.appfw_checks


def test_startup_keep_on_resumes_a_down_responder(monkeypatch):
    fake = FakeWin(_registry("responderd"), Store())
    fake._snap["tools"] = {"responderd": {"state": "RED"}}
    monkeypatch.setattr(daemon_mod, "load_status", lambda *_a: fake._snap)
    resumes = []
    fake._resume_tool = lambda name: resumes.append(name)
    fake.appfw_checks = []
    fake._ensure_appfw_enabled = lambda: fake.appfw_checks.append(1)
    ui.window.MainWindow._ensure_default_on(fake)
    assert resumes == ["responderd"], resumes
    assert fake.appfw_checks == [1], fake.appfw_checks