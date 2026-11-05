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


def test_exactly_two_voices_ship():
    """2026-11-03: the greyok kit is retired; the app ships the owner's two
    approved voices and nothing else (pinned in detail in
    tests/test_theme_tokens.py)."""
    ts = load_themes()
    assert sorted(ts) == ["agency", "aperture"]
    assert all("--el-bg" in toks for toks in ts.values())


def test_dark_default_is_dark():
    ts = load_themes()
    pick = dark_default(sorted(ts))
    assert pick in ts
    tokens = ts[pick]
    dark_sum = sum(int(tokens["--el-bg"].strip().lstrip("#")[i:i + 2], 16)
                   for i in (0, 2, 4))
    assert dark_sum < 200


def test_gtk_css_emits_real_values():
    ts = load_themes()
    css = gtk_css(ts["aperture"])
    assert "window" in css and "treeview" in css
    assert "--el-" not in css             # no tokens left (GTK3 no var())
    assert "#" in css or "rgb" in css


def test_persist_and_load_roundtrip(clean_settings):
    assert persist("agency", path=clean_settings / "s.json")
    assert load_setting(path=clean_settings / "s.json") == "agency"
    assert load_setting(path=clean_settings / "missing.json") == ""

def test_persist_merges_and_keeps_other_settings(clean_settings):
    s = clean_settings / "s.json"
    s.write_text(json.dumps({"mini_tile": True}))
    assert persist("agency", path=s)
    cfg = json.loads(s.read_text())
    assert cfg == {"theme": "agency", "mini_tile": True}
    assert persist("aperture", path=s)
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


def test_the_pair_shares_geometry_and_differs_in_type():
    """The two approved voices are one instrument: the same quiet radii for
    every control, body type shared, and only the display voice changed
    (General Sans for the plate, Unbounded for the graphite pages)."""
    ts = load_themes()
    for name in ("agency", "aperture"):
        assert ts[name]["--el-radius"].strip() == "4px", name
        assert "Inter" in ts[name]["--el-font-body"], name
    assert "General Sans" in ts["agency"]["--el-font-display"]
    assert "Unbounded" in ts["aperture"]["--el-font-display"]


def test_generated_css_has_no_card_shadow_and_uses_the_scale():
    css = gtk_css(load_themes()["aperture"])
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
    css = gtk_css(load_themes()["aperture"])
    # No card anywhere casts a shadow: elevation belongs to modals only.
    for block in css.split(".gw-card"):
        rule = block.split("}", 1)[0]
        assert "box-shadow: none" in rule or "box-shadow" not in rule
    assert "scrollbar trough { background: transparent;" in css


def test_wizard_step_rail_is_themed_in_every_theme():
    """GW-107: Gtk.Assistant's rail is its own surface. Unthemed, a light
    theme's ink landed on Adwaita's grey rail and the step titles vanished."""
    for name, toks in load_themes().items():
        css = gtk_css(toks)
        rail = css.split(".assistant .sidebar {", 1)
        assert len(rail) == 2, f"{name}: the assistant rail is not themed"
        surface = rail[1].split("}", 1)[0]
        assert "background-color:" in surface, name
        assert "border-right:" in surface, name
        body = css.split(".assistant .sidebar label {", 1)[1].split("}", 1)[0]
        assert "color:" in body, name
        # The current step keeps theme ink for contrast; accent is the
        # outline and tint, not the text colour — on the plate the accent
        # IS the ink, on graphite a 2.9:1 mark otherwise.
        mark = css.split(".assistant .sidebar label.highlight {", 1)[1] \
            .split("}", 1)[0]
        assert toks["--el-ink"] in mark, name
        assert toks["--el-accent"] in mark, name