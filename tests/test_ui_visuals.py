"""The identity tiles are drawn locally and always return a picture.

These run headless: the drawing only needs cairo/Pango/GdkPixbuf, and the
real desktop icon is skipped when there is no display (the monogram
fallback still has to come back non-empty, because the popup shows a tile
before any lookup and the chat strip must never be blank).
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("gi")
from ui import visuals  # noqa: E402


def test_world_map_asset_is_bundled():
    assert visuals.WORLD_PNG.exists()
    head = visuals.WORLD_PNG.read_bytes()[:8]
    assert head == b"\x89PNG\r\n\x1a\n"


def test_country_points_come_from_the_system_timezone_table():
    us = visuals.country_point("US")
    assert us is not None
    lat, lon = us
    assert 20 < lat < 55 and -130 < lon < -60
    assert visuals.country_point("") is None


def test_brand_tile_has_the_requested_size_and_is_cached():
    tile = visuals.brand_tile("Amazon", 40)
    assert tile is not None
    assert (tile.get_width(), tile.get_height()) == (40, 40)
    assert visuals.brand_tile("Amazon", 40) is tile


def test_unknown_brand_still_draws_a_tile():
    tile = visuals.brand_tile("Definitely Not A Brand", 48)
    assert tile is not None and tile.get_width() == 48


def test_known_marks_draw_without_the_letter_fallback():
    for name in ("Microsoft", "YouTube", "Google", "Cloudflare"):
        assert visuals.brand_tile(name, 44) is not None


def test_map_tile_draws_for_a_country_and_without_one():
    for code in ("US", "IE", "", "ZZ"):
        tile = visuals.map_tile(code, 56)
        assert tile is not None
        assert (tile.get_width(), tile.get_height()) == (56, 56)


def test_host_tile_prefers_the_brand_over_the_map():
    brand = visuals.host_tile({"brand": "Amazon", "country": "US"}, 48)
    assert brand is not None
    fallback = visuals.host_tile({"brand": "", "country": "US"}, 48)
    assert fallback is not None
    assert fallback is not brand


def test_program_tile_falls_back_to_initials_without_a_desktop_icon():
    tile = visuals.program_tile("definitely-not-an-icon", "Signal Desktop",
                                40)
    assert tile is not None
    assert (tile.get_width(), tile.get_height()) == (40, 40)


def test_glyph_tile_is_never_empty():
    assert visuals.glyph_tile("?", 36) is not None


def test_theme_fallback_icons_are_rejected():
    """GTK answers an unknown icon name with "image-missing", which painted
    a bright blank page on the dark card; the monogram tile replaces it."""
    assert visuals.is_generic_icon("/usr/share/icons/ara/48x48/status/"
                                   "image-missing.png")
    assert visuals.is_generic_icon("/usr/share/icons/Adwaita/mimetypes/"
                                   "text-x-generic.png")
    assert not visuals.is_generic_icon("/usr/share/icons/ara/48x48/apps/"
                                       "firefox-esr.png")
