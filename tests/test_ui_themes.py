import json
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


def test_real_kit_loads_twelve_greyok_themes():
    ts = load_themes()
    assert len(ts) == 12
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

def test_persist_merges_and_keeps_other_settings(clean_settings):
    s = clean_settings / "s.json"
    s.write_text(json.dumps({"mini_tile": True}))
    assert persist("cockpit", path=s)
    cfg = json.loads(s.read_text())
    assert cfg == {"theme": "cockpit", "mini_tile": True}
    assert persist("console", path=s)
    assert json.loads(s.read_text())["mini_tile"] is True

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


def test_assistant_header_styles_are_emitted():
    """The chat panel's identity block (2026-10-29) needs its own type
    scale; a missing rule leaves the title looking like body text."""
    ts = load_themes()
    css = gtk_css(ts[list(ts)[0]])
    assert ".gw-assistant-title" in css
    assert ".gw-assistant-sub" in css
    assert ".gw-assistant-head" in css


def test_light_theme_is_cream_paper_with_the_brass_mark():
    """Owner 2026-10-30: "make the light ui creme". The Light pick is
    `swiss`, and it must read as cream paper stock — warm, never white —
    carrying the same aged-brass accent as the dark theme so both modes
    are one instrument. The earlier neutral grey (the UMGC library paper)
    was superseded by this request."""
    assert T.THEME_CHOICES["Light"] == "swiss"
    sw = load_themes()["swiss"]
    assert sw["--el-bg"] == "#efe8d9"
    assert sw["--el-panel"] == "#faf5ea"
    assert sw["--el-line"] == "#d3c9b4"
    assert sw["--el-ink"] == "#201b13"
    assert sw["--el-accent"] == "#6b5230"
    # Cream means a warm cast: red > green > blue on the page field.
    h = sw["--el-bg"].lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    assert r > g > b, sw["--el-bg"]


def _lum(hexc):
    h = hexc.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))

    def pick(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * pick(r) + 0.7152 * pick(g) + 0.0722 * pick(b)


def _ratio(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_both_themes_meet_contrast_floor():
    themes = load_themes()
    for name in ("obsidian", "swiss"):
        t = themes[name]
        assert _ratio(t["--el-ink"], t["--el-panel"]) >= 10.0, name
        assert _ratio(t["--el-ink-soft"], t["--el-panel"]) >= 4.5, name
        assert not t["--el-panel"].lower().startswith("#fff"), name


def test_the_pair_shares_geometry_and_type():
    themes = load_themes()
    assert themes["obsidian"]["--el-radius"] == "10px"
    assert themes["swiss"]["--el-radius"] == "10px"
    for name in ("obsidian", "swiss"):
        assert "Inter" in themes[name]["--el-font-body"]


def test_generated_css_has_no_card_shadow_and_uses_the_scale():
    css = gtk_css(load_themes()["obsidian"])
    assert ".gw-card" in css
    card_rule = css.split(".gw-card", 1)[1].split("}", 1)[0]
    assert "box-shadow" not in card_rule
    assert "font-size: 13px" in css
    assert "font-size: 28px" in css


def test_contrast_helper_is_exposed():
    from ui.themes import contrast
    assert contrast("#000000", "#ffffff") > 20
    assert 1.0 <= contrast("#777777", "#777777") <= 1.01


def test_cards_and_scrollbars_follow_the_no_slab_rule():
    css = gtk_css(load_themes()["obsidian"])
    # No card anywhere casts a shadow: elevation belongs to modals only.
    for block in css.split(".gw-card"):
        rule = block.split("}", 1)[0]
        assert "box-shadow: none" in rule or "box-shadow" not in rule
    assert "scrollbar trough { background: transparent;" in css
