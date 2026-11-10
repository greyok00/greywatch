# tests/test_theme_voices.py
import ui.themes as themes

def test_graphite_is_default():
    assert themes.DEFAULT_THEME == "graphite"
    assert "paper" in themes.THEMES and "graphite" in themes.THEMES

def test_sheets_parse_and_carry_tokens():
    names = themes.load_themes().keys()
    assert {"graphite", "paper"} <= set(names)
    for name in names:
        css = themes.themes_css_text()  # helper the test reads the sheet through
        assert "--el-accent" in css and "--el-ok" in css

def test_migrated_pick_graphite_default(monkeypatch, tmp_path):
    monkeypatch.setattr(themes, "THEMES_CSS", tmp_path / "themes.css")
    # a saved pick of a RETIRED voice (agency/aperture) resolves to graphite
    (tmp_path / "state.json").write_text('{"theme": "aperture"}')
    assert themes.active_theme(path=tmp_path / "state.json") == "graphite"


def test_startup_apply_honors_a_migrated_pick(monkeypatch, tmp_path):
    """F1 (review round 1): the startup apply resolves the saved pick
    through the same migration every theme read honors. A persisted
    `agency` pick applies PAPER — the light intent survives first boot;
    the dark default only covers absent or unknown picks."""
    monkeypatch.setattr(themes, "THEMES_CSS", tmp_path / "themes.css")
    from ui.window import saved_apply_pick
    names = sorted(themes.load_themes())
    assert saved_apply_pick("agency", names) == "paper"
    assert saved_apply_pick("aperture", names) == "graphite"
    assert saved_apply_pick("obsidian", names) == "graphite"
    assert saved_apply_pick("swiss", names) == "paper"
    # absent and unknown picks: the dark default, nothing overwritten
    assert saved_apply_pick("", names) == "graphite"
    assert saved_apply_pick("cockpit", names) == "graphite"
