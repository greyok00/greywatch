# ui/visuals.py
"""Small identity pictures: brand tiles, map tiles, program tiles.

The firewall prompt and the assistant answer used to be text only, so
"an Amazon server" and "208.82.238.129" looked equally faceless (owner
report 2026-10-29: "make it more visual"). Every tile here is drawn
locally — nothing is downloaded and no trademarked artwork ships:

  * brand tile    — the brand's own colour and initial, e.g. a dark tile
                    with an orange "a" and smile for Amazon, four squares
                    for Microsoft, a red tile with a play mark for
                    YouTube. A drawn mark, never a copied logo file.
  * map tile      — a square crop of the bundled Natural Earth land map
                    (public domain, ``assets/maps/world.png``) centred on
                    the destination country, with a pin. This is the
                    default when no brand is known.
  * program tile  — the program's real desktop icon when the system has
                    one, otherwise a neutral tile with its initials.

Only cairo, Pango and GdkPixbuf are used (all already part of the GTK
stack), so no new dependency is added. Everything is cached by content
key; the tiles are cheap enough to draw on the UI thread.
"""
from __future__ import annotations

import math
import pathlib
import re

import cairo

import gi

gi.require_version("GdkPixbuf", "2.0")
gi.require_version("Pango", "1.0")
gi.require_version("PangoCairo", "1.0")
from gi.repository import GdkPixbuf, Pango, PangoCairo  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORLD_PNG = ROOT / "assets" / "maps" / "world.png"

# The bundled map is equirectangular over this latitude band. Antarctica
# is cut off (a solid white band at this size) and the top stops where
# there is no land above 84°N.
LAT_TOP = 84.0
LAT_BOTTOM = -58.0
LAT_SPAN = LAT_TOP - LAT_BOTTOM

OCEAN = (0.043, 0.075, 0.110)          # #0b131c
LAND = (0.333, 0.400, 0.470)          # #556678
GRID = (1.0, 1.0, 1.0, 0.05)
PIN = (1.0, 0.62, 0.20)               # warm pin, reads on grey land

# Icon names a theme resolves for anything it does not have. GTK returns
# the generic "missing picture" for every unknown name (probed
# 2026-10-30), which painted a bright blank page on the dark card; a
# drawn monogram tile reads better than a fallback nobody meant.
_GENERIC_ICONS = frozenset({
    "image-missing", "text-x-generic", "application-x-executable",
    "unknown", "empty", "x-office-document", "package-x-generic",
})

# Brand → (background, foreground, mark). Marks are drawn, not loaded:
# "letter" is the brand initial, "microsoft" the four-square mark,
# "youtube" the play badge, "amazon" the lowercase a with its smile.
_BRAND_STYLE = {
    "amazon": ("#24303f", "#ffffff", "amazon"),
    "google": ("#ffffff", "#4285f4", "letter"),
    "youtube": ("#ff0000", "#ffffff", "youtube"),
    "microsoft": ("#ffffff", "#000000", "microsoft"),
    "windows update": ("#0067b8", "#ffffff", "letter"),
    "microsoft office": ("#d83b01", "#ffffff", "letter"),
    "apple": ("#111113", "#ffffff", "letter"),
    "icloud": ("#1c8ef9", "#ffffff", "letter"),
    "facebook": ("#1877f2", "#ffffff", "letter"),
    "instagram": ("#c13584", "#ffffff", "letter"),
    "whatsapp": ("#25d366", "#ffffff", "letter"),
    "meta": ("#0866ff", "#ffffff", "letter"),
    "x": ("#0b0b0c", "#ffffff", "letter"),
    "twitter": ("#0b0b0c", "#ffffff", "letter"),
    "netflix": ("#e50914", "#ffffff", "letter"),
    "spotify": ("#191414", "#1db954", "letter"),
    "discord": ("#5865f2", "#ffffff", "letter"),
    "telegram": ("#26a5e4", "#ffffff", "letter"),
    "slack": ("#4a154b", "#ffffff", "letter"),
    "github": ("#24292f", "#ffffff", "letter"),
    "cloudflare": ("#f38020", "#ffffff", "letter"),
    "akamai": ("#009cde", "#ffffff", "letter"),
    "steam": ("#1b2838", "#c7d5e0", "letter"),
    "snap store": ("#fffc00", "#111111", "letter"),
    "ubuntu": ("#e95420", "#ffffff", "letter"),
    "mozilla": ("#20123a", "#ffffff", "letter"),
    "firefox": ("#20123a", "#ffffff", "letter"),
    "dropbox": ("#0061ff", "#ffffff", "letter"),
    "zoom": ("#2d8cff", "#ffffff", "letter"),
    "adobe": ("#fa0f00", "#ffffff", "letter"),
    "reddit": ("#ff4500", "#ffffff", "letter"),
    "tiktok": ("#010101", "#ffffff", "letter"),
    "pinterest": ("#e60023", "#ffffff", "letter"),
    "epic games": ("#2a2a2a", "#ffffff", "letter"),
    "blizzard": ("#148eff", "#ffffff", "letter"),
    "proton": ("#6d4aff", "#ffffff", "letter"),
    "signal": ("#3a76f0", "#ffffff", "letter"),
    "skype": ("#00aff0", "#ffffff", "letter"),
    "brave": ("#fb542b", "#ffffff", "letter"),
    "python": ("#306998", "#ffd43b", "letter"),
    "node.js": ("#339933", "#ffffff", "letter"),
    "docker": ("#2496ed", "#ffffff", "letter"),
}

# Distinct, calm fills for names without a known brand colour. Chosen by
# a stable hash so the same name always gets the same tile.
_NEUTRAL_FILLS = (
    "#2f3b4a", "#3a3345", "#2f4440", "#413a30", "#333c50",
    "#44323a", "#2c4149", "#3d4232",
)


# --------------------------------------------------------------------------
# cache + surface helpers
# --------------------------------------------------------------------------

_tiles: dict[tuple, GdkPixbuf.Pixbuf | None] = {}
_world: cairo.ImageSurface | None = None
_world_missing = False
_points: dict[str, tuple[float, float]] | None = None


def _rgb(hex_colour: str) -> tuple[float, float, float]:
    hex_colour = hex_colour.lstrip("#")
    return tuple(int(hex_colour[i:i + 2], 16) / 255.0 for i in (0, 2, 4))


def _surface_to_pixbuf(surface: cairo.ImageSurface) -> GdkPixbuf.Pixbuf | None:
    """cairo keeps premultiplied BGRA; a PNG round-trip gives GdkPixbuf
    the straight RGBA it expects (and the tiles are only a few KB)."""
    import io
    buf = io.BytesIO()
    surface.write_to_png(buf)
    loader = GdkPixbuf.PixbufLoader.new_with_type("png")
    loader.write(buf.getvalue())
    loader.close()
    return loader.get_pixbuf()


def _rounded(ctx: cairo.Context, w: float, h: float, r: float) -> None:
    r = min(r, w / 2, h / 2)
    ctx.new_sub_path()
    ctx.arc(w - r, r, r, -math.pi / 2, 0)
    ctx.arc(w - r, h - r, r, 0, math.pi / 2)
    ctx.arc(r, h - r, r, math.pi / 2, math.pi)
    ctx.arc(r, r, r, math.pi, 3 * math.pi / 2)
    ctx.close_path()


def _draw_text(ctx, text, cx, cy, size, colour, weight=Pango.Weight.BOLD):
    layout = PangoCairo.create_layout(ctx)
    desc = Pango.FontDescription()
    desc.set_family("Sans")
    desc.set_weight(weight)
    desc.set_absolute_size(size * Pango.SCALE)
    layout.set_font_description(desc)
    layout.set_text(text, -1)
    tw, th = layout.get_pixel_size()
    ctx.set_source_rgba(*_rgb(colour), 1.0)
    ctx.move_to(cx - tw / 2, cy - th / 2)
    PangoCairo.show_layout(ctx, layout)


def _initial(name: str) -> str:
    words = re.findall(r"[A-Za-z0-9]", name or "")
    return words[0].upper() if words else "?"


def _initials(name: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", name or "")
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].upper()
    return (words[0][0] + words[1][0]).upper()


# --------------------------------------------------------------------------
# country points (offline, from the system timezone table)
# --------------------------------------------------------------------------

_COORD_RE = re.compile(
    r"([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?")


def _load_points() -> dict[str, tuple[float, float]]:
    """One representative point per country: the circular mean of the
    cities listed in /usr/share/zoneinfo/zone.tab. Offline, no database."""
    global _points
    if _points is not None:
        return _points
    pts: dict[str, list[tuple[float, float]]] = {}
    try:
        text = pathlib.Path("/usr/share/zoneinfo/zone.tab").read_text(
            errors="replace")
    except OSError:
        text = ""
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        m = _COORD_RE.fullmatch(parts[1])
        if not m:
            continue
        lat = (int(m.group(2)) + int(m.group(3)) / 60
               + int(m.group(4) or 0) / 3600)
        lon = (int(m.group(6)) + int(m.group(7)) / 60
               + int(m.group(8) or 0) / 3600)
        if m.group(1) == "-":
            lat = -lat
        if m.group(5) == "-":
            lon = -lon
        pts.setdefault(parts[0].upper(), []).append((lat, lon))
    out: dict[str, tuple[float, float]] = {}
    for code, rows in pts.items():
        lat = sum(r[0] for r in rows) / len(rows)
        sin_lon = sum(math.sin(math.radians(r[1])) for r in rows)
        cos_lon = sum(math.cos(math.radians(r[1])) for r in rows)
        out[code] = (lat, math.degrees(math.atan2(sin_lon, cos_lon)))
    _points = out
    return out


def country_point(code: str):
    """(lat, lon) for a country code, or None when the table has none."""
    code = (code or "").strip().upper()
    if not code:
        return None
    return _load_points().get(code)


# --------------------------------------------------------------------------
# brand tiles
# --------------------------------------------------------------------------

def _brand_parts(name: str):
    key = (name or "").strip().lower()
    if key in _BRAND_STYLE:
        return _BRAND_STYLE[key]
    # A hash that is stable across runs (Python's own str hash is salted).
    digest = 0
    for ch in key:
        digest = (digest * 131 + ord(ch)) & 0xFFFFFFFF
    return (_NEUTRAL_FILLS[digest % len(_NEUTRAL_FILLS)], "#ffffff", "letter")


def brand_tile(name: str, size: int = 48) -> GdkPixbuf.Pixbuf | None:
    """A drawn brand mark: the service's colour and initial, or a mark
    for the few shapes that are unmistakable (Microsoft, YouTube,
    Amazon)."""
    key = ("brand", (name or "").strip().lower(), size)
    if key in _tiles:
        return _tiles[key]
    name = (name or "").strip() or "?"
    bg, fg, mark = _brand_parts(name)
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ctx = cairo.Context(surface)
    _rounded(ctx, size, size, size * 0.24)
    ctx.set_source_rgb(*_rgb(bg))
    ctx.fill()

    if mark == "microsoft":
        pad = size * 0.26
        gap = size * 0.06
        box = (size - 2 * pad - gap) / 2
        colours = ("#f25022", "#7fba00", "#00a4ef", "#ffb900")
        for i, colour in enumerate(colours):
            x = pad + (box + gap) * (i % 2)
            y = pad + (box + gap) * (i // 2)
            ctx.rectangle(x, y, box, box)
            ctx.set_source_rgb(*_rgb(colour))
            ctx.fill()
    elif mark == "youtube":
        ctx.set_source_rgb(1, 1, 1)
        cx = cy = size / 2
        ctx.move_to(cx - size * 0.10, cy - size * 0.15)
        ctx.line_to(cx + size * 0.17, cy)
        ctx.line_to(cx - size * 0.10, cy + size * 0.15)
        ctx.close_path()
        ctx.fill()
    elif mark == "amazon":
        _draw_text(ctx, "a", size * 0.50, size * 0.38, size * 0.46, fg)
        # The smile: an arc under the letter, the way the mark reads.
        ctx.save()
        ctx.set_line_width(max(1.5, size * 0.065))
        ctx.set_line_cap(cairo.LINE_CAP_ROUND)
        ctx.set_source_rgb(*_rgb("#ff9900"))
        ctx.new_sub_path()          # do not join the letter's current point
        ctx.arc(size * 0.50, size * 0.79, size * 0.15,
                math.radians(12), math.radians(168))
        ctx.stroke()
        ctx.restore()
    else:
        _draw_text(ctx, _initial(name.upper())[:1], size / 2, size / 2 - size * 0.02,
                   size * 0.52, fg)
    pixbuf = _surface_to_pixbuf(surface)
    _tiles[key] = pixbuf
    return pixbuf


# --------------------------------------------------------------------------
# map tiles
# --------------------------------------------------------------------------

def _world_surface():
    global _world, _world_missing
    if _world is not None or _world_missing:
        return _world
    try:
        _world = cairo.ImageSurface.create_from_png(str(WORLD_PNG))
    except Exception:
        _world_missing = True
        _world = None
    return _world


def map_tile(code: str, size: int = 48) -> GdkPixbuf.Pixbuf | None:
    """A square map crop around the country, with a pin.

    No country (or no coordinate) draws the whole world map letterboxed
    and unmarked: still a map, never a made-up location.
    """
    key = ("map", (code or "").strip().upper(), size)
    if key in _tiles:
        return _tiles[key]
    world = _world_surface()
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ctx = cairo.Context(surface)
    _rounded(ctx, size, size, size * 0.14)
    ctx.set_source_rgb(*OCEAN)
    ctx.fill()
    ctx.save()
    _rounded(ctx, size, size, size * 0.14)
    ctx.clip()

    if world is None:
        # Missing asset: a plain ocean tile with a faint globe ring.
        ctx.set_source_rgba(1, 1, 1, 0.12)
        ctx.set_line_width(max(1.0, size * 0.035))
        ctx.arc(size / 2, size / 2, size * 0.28, 0, 2 * math.pi)
        ctx.stroke()
        pixbuf = _surface_to_pixbuf(surface)
        _tiles[key] = pixbuf
        return pixbuf

    ws, hs = world.get_width(), world.get_height()
    point = country_point(code)
    if point is not None:
        lat, lon = point
        # Show ~52° of longitude; pick the matching latitude span so the
        # tile keeps the same ground scale on both axes.
        span_lon = 52.0
        span_lat = span_lon * (ws / hs) * (LAT_SPAN / 360.0)
        x_deg = (lon + 180.0) / 360.0 * ws
        y_deg = (LAT_TOP - lat) / LAT_SPAN * hs
        half_x = span_lon / 360.0 * ws / 2
        half_y = span_lat / LAT_SPAN * hs / 2
        x0 = x_deg - half_x
        y0 = y_deg - half_y
        k = (2 * half_x) / size          # world pixels per tile pixel
    else:
        # Whole world, letterboxed, no pin.
        k = ws / size
        x0 = 0.0
        y0 = (hs - size * k) / 2
        half_x = half_y = 0.0
        y_deg = -1

    pattern = cairo.SurfacePattern(world)
    pattern.set_filter(cairo.FILTER_BILINEAR)
    pattern.set_matrix(cairo.Matrix(k, 0, 0, k, x0, y0))
    ctx.set_source_rgb(*LAND)
    ctx.mask(pattern)

    # Graticule over the land as well: an inland crop is a solid grey
    # field otherwise, and the faint lines are what make it read as a
    # map at 36 px rather than a coloured square.
    ctx.set_source_rgba(*GRID)
    ctx.set_line_width(max(0.5, size * 0.006))
    for d in range(-180, 181, 30):
        x = ((d + 180.0) / 360.0 * ws - x0) / k
        ctx.move_to(x, 0)
        ctx.line_to(x, size)
    for d in range(-60, 85, 20):
        y = ((LAT_TOP - d) / LAT_SPAN * hs - y0) / k
        ctx.move_to(0, y)
        ctx.line_to(size, y)
    ctx.stroke()

    if point is not None:
        _draw_pin(ctx, size, (x_deg - x0) / k, (y_deg - y0) / k)

    # A hairline inside the rounded corner keeps the tile from bleeding
    # into the card behind it.
    ctx.set_source_rgba(1, 1, 1, 0.10)
    ctx.set_line_width(max(1.0, size * 0.02))
    _rounded(ctx, size, size, size * 0.14)
    ctx.stroke()
    ctx.restore()
    pixbuf = _surface_to_pixbuf(surface)
    _tiles[key] = pixbuf
    return pixbuf


def _draw_pin(ctx, size, x, y):
    x = min(max(x, size * 0.10), size * 0.90)
    y = min(max(y, size * 0.10), size * 0.90)
    ctx.set_source_rgba(1, 1, 1, 0.16)
    ctx.arc(x, y, size * 0.115, 0, 2 * math.pi)
    ctx.fill()
    ctx.set_source_rgba(1, 1, 1, 0.90)
    ctx.arc(x, y, size * 0.058, 0, 2 * math.pi)
    ctx.fill()
    ctx.set_source_rgb(*PIN)
    ctx.arc(x, y, size * 0.036, 0, 2 * math.pi)
    ctx.fill()


def host_tile(ident: dict, size: int = 48) -> GdkPixbuf.Pixbuf | None:
    """The destination's picture: the brand mark when the network has a
    recognisable name, otherwise the geoip map tile."""
    ident = ident or {}
    brand = str(ident.get("brand") or "").strip()
    if brand:
        return brand_tile(brand, size)
    return map_tile(str(ident.get("country") or ""), size)


# --------------------------------------------------------------------------
# program tiles
# --------------------------------------------------------------------------

def is_generic_icon(path: str) -> bool:
    """True for the fallback pictures a theme hands out for unknown names."""
    return pathlib.Path(path or "").stem.lower() in _GENERIC_ICONS


def _icon_pixbuf(icon_name: str, size: int) -> GdkPixbuf.Pixbuf | None:
    """The real desktop icon, when the system has one and a display exists.
    Never raises: this is decoration, not data."""
    name = (icon_name or "").strip()
    if not name:
        return None
    try:
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        from gi.repository import Gdk, Gtk
        display = Gdk.Display.get_default()
        if display is None:
            return None
        theme = Gtk.IconTheme.get_for_display(display)
        icon = theme.lookup_icon(
            name, None, size, 1, Gtk.TextDirection.NONE,
            Gtk.IconLookupFlags(0))
        if icon is None:
            return None
        gfile = icon.get_file()
        path = gfile.get_path() if gfile is not None else None
        if not path:
            return None
        if is_generic_icon(path):
            return None
        return GdkPixbuf.Pixbuf.new_from_file_at_scale(path, size, size, True)
    except Exception:
        return None


def program_tile(icon_name: str, title: str, size: int = 44,
                 accent: str = "#2c3642", binary: str = "",
                 package: str = "") -> GdkPixbuf.Pixbuf | None:
    """The program's own icon, or a drawn tile with its initials.

    Icon names are not always what the desktop file says: on Debian the
    ``firefox`` launcher is a wrapper for ``firefox-esr``, so the binary,
    the owning package and the title are tried in turn before giving up.
    """
    for candidate in (icon_name, binary, package, (title or "").lower()):
        real = _icon_pixbuf(candidate, size)
        if real is not None:
            return real
    key = ("prog", (title or "").strip(), size)
    if key in _tiles:
        return _tiles[key]
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ctx = cairo.Context(surface)
    _rounded(ctx, size, size, size * 0.22)
    ctx.set_source_rgb(*_rgb(accent))
    ctx.fill()
    _draw_text(ctx, _initials(title), size / 2, size / 2, size * 0.40,
               "#dfe7f0")
    pixbuf = _surface_to_pixbuf(surface)
    _tiles[key] = pixbuf
    return pixbuf


def glyph_tile(glyph: str, size: int = 44,
               accent: str = "#2c3642") -> GdkPixbuf.Pixbuf | None:
    key = ("glyph", glyph, size, accent)
    if key in _tiles:
        return _tiles[key]
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ctx = cairo.Context(surface)
    _rounded(ctx, size, size, size * 0.22)
    ctx.set_source_rgb(*_rgb(accent))
    ctx.fill()
    _draw_text(ctx, glyph, size / 2, size / 2, size * 0.44, "#9fb0c2")
    pixbuf = _surface_to_pixbuf(surface)
    _tiles[key] = pixbuf
    return pixbuf
