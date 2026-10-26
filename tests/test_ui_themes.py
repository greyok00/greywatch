import pathlib
import sys
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ui import themes as T
from ui.themes import (dark_default, gtk_css, load_setting, load_themes,
                       persist)


@pytest.fixture
def clean_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "SETTINGS_PATH", tmp_path / "settings.json")
    return tmp_path


def test_real_kit_loads_eleven_greyok_themes():
    ts = load_themes()
    assert len(ts) == 11
    assert all("--el-bg" in toks for toks in ts.values())


def test_dark_default_is_dark():
    ts = load_themes()
    pick = dark_default(sorted(ts))
    assert pick in ts
    bg = ts[pick]["--el-bg"].strip()
    assert not bg.startswith("#f"), "default must be DARK"


def test_gtk_css_emits_real_values():
    ts = load_themes()
    css = gtk_css(ts["terminal"] if "terminal" in ts else list(ts)[0])
    assert "window" in css and "treeview" in css
    assert "--el-" not in css             # no tokens left (GTK3 no var())
    assert "#" in css or "rgb" in css


def test_persist_and_load_roundtrip(clean_settings):
    assert persist("cockpit", path=clean_settings / "s.json")
    assert load_setting(path=clean_settings / "s.json") == "cockpit"
    assert load_setting(path=clean_settings / "missing.json") == ""

def test_gtk_css_never_emits_unsupported_properties():
    ts = load_themes()
    import re
    bad = {"filter", "transform", "transition", "grid-gap", "will-change"}
    for name in ts:
        css = gtk_css(ts[name])
        for line in css.splitlines():
            m = re.match(r"\s*([a-z-]+)\s*:", line)
            if m:
                assert m.group(1) not in bad, f"{name}: bad CSS prop {m.group(1)}"


def test_css_loads_in_gtk_provider():
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
    ts = load_themes()
    for name in ts:
        p = Gtk.CssProvider()
        try:
            p.load_from_string(gtk_css(ts[name]))
            assert p.to_string() is not None
        except Exception as e:
            raise AssertionError(f"theme {name}: GTK rejected its CSS: {e}")


def test_circle_draw_uses_only_four_arg_rgba():
    import gi
    gi.require_version("Gtk", "4.0")
    rec = []

    class FakeCR:
        def __getattr__(self, name):
            def f(*a, **k):
                if name == "set_source_rgba":
                    rec.append(len(a))
                if name == "text_extents":
                    return (0, 0, 10, 10, 0, 0)
                return FakeCR()
            return f

    from ui.window import ProgressCircle
    inst = ProgressCircle.__new__(ProgressCircle)
    inst.text = "scan"
    inst._running = True
    inst._tick = 0.25
    import time as _t
    inst._started = _t.monotonic()

    drew = ProgressCircle._draw(inst, FakeCR(), FakeCR(), 170, 170)
    assert drew is False, drew          # a GTK4 draw func returns False
    assert rec, "the GTK4 draw func never painted"
    assert all(a == 4 for a in rec), rec
