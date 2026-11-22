import json
from ui import pageutil


def test_signature_changes_when_a_state_file_changes(tmp_path, monkeypatch):
    from ui import cliapi
    monkeypatch.setattr(cliapi, "state_path",
                        lambda name: str(tmp_path / name))
    (tmp_path / "posture.json").write_text(json.dumps({"score": 1}))
    first = pageutil.signature("posture.json", "missing.json")
    (tmp_path / "posture.json").write_text(json.dumps({"score": 2}))
    second = pageutil.signature("posture.json", "missing.json")
    assert first != second
    assert "missing.json:-" in first


def test_scroll_to_widget_gives_up_on_a_never_realized_widget(monkeypatch):
    """GW-10 regression: the idle retry chain must terminate. A test
    shell never realizes its widgets, so an undecremented retry counter
    would keep the default main context forever pending and every later
    _pump() in the suite would spin."""
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib, Gtk
    from ui import pageutil

    scroller = Gtk.ScrolledWindow()
    widget = Gtk.Box()                     # never realized: no geometry
    # count only THIS chain's callback invocations: the suite shares one
    # default main context, so a global event count is never hermetic
    runs = []

    def recording_idle(cb, *args):
        runs.append(1)
        cb(*args)                          # put() requeues by hand now
        return False

    real_idle = GLib.idle_add
    monkeypatch.setattr(GLib, "idle_add", recording_idle)
    try:
        pageutil.scroll_to_widget(scroller, widget, retries=8)
    finally:
        GLib.idle_add = real_idle
    # the old bug requeued with the SAME tries value forever; the fixed
    # chain stops after at most one run per retry plus the first
    assert len(runs) <= 8 + 1, len(runs)
