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
    persist_path = tmp_path / "theme"
    monkeypatch.setattr(themes, "THEMES_CSS", tmp_path / "themes.css")
    # a saved pick of a RETIRED voice (agency/aperture) resolves to graphite
    import json
    (tmp_path / "state.json").write_text('{"theme": "aperture"}')
    assert themes.active_theme(path=tmp_path / "state.json") == "graphite"
