"""Task 1 of the 2026-11-03 full-UI redesign: the app ships exactly two
themes, and their token tables are the owner's frozen greyok values.

Agency (light) = the agency-mono-plate voice: warm plate, near-black ink
where the ink IS the accent, 2px keylines, mono labels. Aperture (dark) =
the aperture-motion voice: graphite panels, one burnt-orange accent, warm
ink. The cream/brass palette they replace may not reappear."""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ui import themes as T
from ui.themes import (THEMES, THEME_CHOICES, active_theme, dark_default,
                       gtk_css, load_setting, load_themes, set_active_theme)

APPROVED = ("agency", "aperture")

AGENCY = {
    "--el-bg": "#f4f4f2",
    "--el-panel": "#fbfbf9",
    "--el-panel-2": "#ececea",
    "--el-panel-3": "#e1e1dc",
    "--el-line": "#d9d9d4",
    "--el-line-2": "#c3c3bc",
    "--el-line-strong": "#171715",
    "--el-ink": "#171715",
    "--el-ink-soft": "#4c4c46",
    "--el-mute": "#63625a",
    "--el-on-accent": "#f4f4f2",
    "--el-accent": "#171715",
    "--el-accent-hover": "#000000",
    "--el-ok": "#41684b",
    "--el-warn": "#8a5d14",
    "--el-fail": "#a83a2a",
    "--el-info": "#4e5d68",
}

APERTURE = {
    "--el-bg": "#131313",
    "--el-panel": "#1a1a1a",
    "--el-panel-2": "#212121",
    "--el-panel-3": "#2b2b2b",
    "--el-line": "#2c2c2c",
    "--el-line-2": "#242424",
    "--el-line-strong": "#404040",
    "--el-ink": "#f4f1eb",
    "--el-ink-soft": "#aba49a",
    "--el-mute": "#948b7d",
    "--el-on-accent": "#131313",
    "--el-accent": "#ff7a1a",
    "--el-accent-hover": "#ff9a45",
    "--el-ok": "#4fd083",
    "--el-warn": "#ffc53d",
    "--el-fail": "#ff4a33",
    "--el-info": "#7aa2ff",
}


def test_exactly_two_approved_voices_ship():
    assert THEMES == APPROVED
    theme_tokens = load_themes()
    assert sorted(theme_tokens) == sorted(APPROVED), (
        "the old greyok kit is retired; only agency + aperture ship")
    assert all("--el-bg" in toks for toks in theme_tokens.values())


def test_agency_is_the_light_mono_plate():
    toks = load_themes()[APPROVED[0]]
    for name, value in AGENCY.items():
        assert toks[name].strip().lower() == value, f"{name}: {toks[name]}"
    # The plate is light: luminance of ink next to the page must be the
    # near-black-on-paper pair the owner picked, and the accent is the ink.
    ratio = T.contrast(toks["--el-bg"], toks["--el-ink"])
    assert ratio >= 12.0, ratio
    assert toks["--el-accent"] == toks["--el-ink"]


def test_aperture_is_the_dark_graphite_voice():
    toks = load_themes()[APPROVED[1]]
    for name, value in APERTURE.items():
        assert toks[name].strip().lower() == value, f"{name}: {toks[name]}"
    # Dark voice: warm ink and a burnt-orange accent, both far brighter
    # than the graphite ground they sit on.
    def channel_sum(hexc):
        h = hexc.strip().lstrip("#")
        return sum(int(h[i:i + 2], 16) for i in (0, 2, 4))
    assert channel_sum(toks["--el-ink"]) > 700
    assert channel_sum(toks["--el-accent"]) > channel_sum(toks["--el-bg"])


def test_defaults_point_at_the_two_voices():
    assert THEME_CHOICES == {"Dark": "aperture", "Light": "agency"}
    assert dark_default(sorted(load_themes())) == "aperture"
    tokens = load_themes()
    def channel_sum(hexc):
        h = hexc.strip().lstrip("#")
        return sum(int(h[i:i + 2], 16) for i in (0, 2, 4))
    assert channel_sum(tokens["agency"]["--el-bg"]) > 600
    assert channel_sum(tokens["aperture"]["--el-bg"]) < 200


def test_no_accent_bleed_between_themes():
    agency_css = gtk_css(load_themes()[APPROVED[0]])
    aperture_css = gtk_css(load_themes()[APPROVED[1]])
    # Aperture's burnt orange must never appear in the agency voice, and
    # agency's paper tones must stay out of the graphite pages.
    assert "#ff7a1a" not in agency_css
    assert "#ff7a1a" in aperture_css
    assert "#131313" not in agency_css
    assert "#f4f1eb" in aperture_css
    assert "--el-" not in agency_css and "--el-" not in aperture_css


def _lum(hexc):
    h = hexc.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))

    def pick(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * pick(r) + 0.7152 * pick(g) + 0.0722 * pick(b)


def _ratio(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_both_voices_meet_the_contrast_floor():
    for name in APPROVED:
        t = load_themes()[name]
        assert _ratio(t["--el-ink"], t["--el-panel"]) >= 10.0, name
        assert _ratio(t["--el-ink-soft"], t["--el-panel"]) >= 4.5, name
        assert _ratio(t["--el-fail"], t["--el-panel"]) >= 2.6, name


@pytest.fixture
def clean_state(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(T, "_ACTIVE", "")
    return tmp_path


def test_set_active_theme_flips_and_persists(clean_state):
    assert active_theme() == "aperture"      # dark default before any pick
    assert set_active_theme("agency") is True
    assert active_theme() == "agency"
    assert load_setting() == "agency"
    assert set_active_theme("aperture") is True
    assert active_theme() == "aperture"


def test_unknown_theme_names_are_refused(clean_state):
    assert set_active_theme("cockpit") is False
    assert set_active_theme("obsidian") is False
    assert active_theme() == "aperture"
    assert load_setting() == ""


def test_persisted_picks_from_the_old_kit_migrate(clean_state):
    """Installs written before the two-voice wave carry 'obsidian' or
    'swiss'; the migration keeps each pick's light/dark intent instead of
    dumping everyone on the dark default."""
    for old, new in (("obsidian", "aperture"), ("swiss", "agency")):
        (T.SETTINGS_PATH).write_text(f'{{"theme": "{old}"}}')
        assert active_theme() == new, old


# --- Task 3: the wolf avatar (owner 2026-11-03) -------------------------
# One artwork file only: assets/logo/greywatch-icon-256.png. The dark
# theme's avatar derives from it in memory (channel inversion); no
# second wolf image is ever committed.

LOGO = pathlib.Path(__file__).resolve().parents[1] / "assets" / "logo" \
    / "greywatch-icon-256.png"


def test_the_wolf_helpers_are_the_one_art_file():
    assert LOGO.exists() and LOGO.stat().st_size > 1000
    pb = T.logo_pixbuf(24)
    assert pb is not None and pb.get_width() == pb.get_height() == 24
    inv = T.logo_pixbuf_inverted(24)
    assert inv is not None and inv.get_width() == inv.get_height() == 24
    # Same call, same cached object: the decode is not redone per widget.
    assert T.logo_pixbuf(24) is pb


def test_inversion_flips_the_bright_circle_to_dark():
    orig = T.logo_pixbuf(64)
    inv = T.logo_pixbuf_inverted(64)

    def rowstride(w):                       # tight 4-channel RGBA buffer
        return w * 4

    w = orig.get_width()
    raw_o = orig.read_pixel_bytes().get_data()
    raw_i = inv.read_pixel_bytes().get_data()
    # Find the brightest fully-opaque pixel (a point inside the white
    # circle) and compare it at the same slot after inversion.
    best = 0
    for y in range(orig.get_height()):
        for x in range(w):
            base = y * rowstride(w) + x * 4
            if raw_o[base + 3] == 255:
                s = raw_o[base] + raw_o[base + 1] + raw_o[base + 2]
                if s > best:
                    best = s
                    at = base
    assert best > 600, "the badge should carry a bright circle"
    assert raw_o[at + 3] == 255 and raw_i[at + 3] == 255
    assert raw_i[at] + raw_i[at + 1] + raw_i[at + 2] < 150


def test_inversion_is_exact_byte_flipping_not_art():
    """Every opaque pixel inverts channel-for-channel (255 - byte) and
    every transparent corner keeps alpha 0 — inversion, not a redraw."""
    orig = T.logo_pixbuf(48)
    inv = T.logo_pixbuf_inverted(48)
    w, n = orig.get_width(), orig.get_n_channels()
    raw_o = orig.read_pixel_bytes().get_data()
    raw_i = inv.read_pixel_bytes().get_data()
    has_alpha = orig.get_has_alpha()
    assert has_alpha and n == 4
    checked = 0
    for y in range(orig.get_height()):
        for x in range(w):
            base = y * orig.get_rowstride() + x * n
            if raw_o[base + 3] == 0:
                assert raw_i[base + 3] == 0           # corner stays empty
                continue
            for c in range(3):
                assert raw_i[base + c] == 255 - raw_o[base + c]
            assert raw_i[base + 3] == raw_o[base + 3]
            checked += 1
    assert checked > 200, f"only {checked} opaque pixels checked"

def test_the_on_chip_label_carries_the_on_accent_colour():
    """The bare `label { color: ink }` rule beats any colour a button
    inherits, so the on-chip's label must set the on-accent explicitly
    (the active All chip shipped ink-on-ink — found in the README shot
    pass, 2026-11-03)."""
    for name in APPROVED:
        css = gtk_css(load_themes()[name])
        onaccent = load_themes()[name]["--el-on-accent"]
        assert f"button.gw-chip.gw-chip-on label {{ color: {onaccent}; }}" \
            in css, name
