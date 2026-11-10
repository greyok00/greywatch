from __future__ import annotations

import functools
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
THEMES_CSS = ROOT / "ui" / "themes.css"
from gwpaths import data_dir as _gw_data
SETTINGS_PATH = _gw_data() / "greywatch-ui-settings.json"
DEFAULT_THEME = "graphite"          # the graphite dark voice; paper is light

THEME_CHOICES = {"Dark": "graphite", "Light": "paper"}   # the two shipped voices

# The two approved voices and nothing else. Older saved
# picks map to the voice that preserves their light/dark intent.
THEMES = ("graphite", "paper")
_MIGRATE = {"obsidian": "graphite", "swiss": "paper",
            "aperture": "graphite", "agency": "paper"}


def themes_css_text(path=THEMES_CSS) -> str:
    """The raw theme sheet text (the tokens live in `[data-theme=...]`
    blocks); callers read the sheets through this."""
    try:
        return pathlib.Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return ""

_TOKEN_RE = re.compile(r"--el-([a-z0-9-]+):\s*([^;]+);")
_THEME_RE = re.compile(r'\[data-theme="([a-z0-9-]+)"\]\s*\{([^}]*)\}', re.S)


def load_themes(path=THEMES_CSS) -> dict:
    try:
        text = pathlib.Path(path).read_text()
    except (OSError, ValueError):
        return {}
    out = {}
    for name, body in _THEME_RE.findall(text):
        toks = {f"--el-{k}": v for k, v in _TOKEN_RE.findall(body)}
        if toks:
            out[name] = toks
    return out


def dark_default(names: list) -> str:
    if DEFAULT_THEME in names:
        return DEFAULT_THEME
    return names[0] if names else ""


_ACTIVE = ""   # module pick; ThemeStore.apply() and set_active_theme() set it


def resolve_pick(picked: str, names: list) -> str:
    """A raw saved pick resolved onto the shipped voices: retired names
    (agency, aperture, obsidian, swiss) migrate to the voice that keeps
    their light/dark intent, a shipped pick stands, and anything absent
    or unknown falls to the dark default. Floor: the store's actual
    sheets (`names`), so a sheet-less pick can never be applied."""
    if picked in _MIGRATE:
        picked = _MIGRATE[picked]
    if picked in THEME_CHOICES.values() and picked in names:
        return picked
    return dark_default(names)


def active_theme(path=None, picked=None) -> str:
    """The theme name currently in charge, resolved from the module pick,
    then the saved setting (migrated off retired names), then the dark
    default. Never a hard-coded legacy value. `path` reads a settings
    file other than the app's own (tests, and the first-boot probe);
    `picked` hands in an already-read raw saved pick (the startup apply)
    so it resolves through the same migration instead of re-reading."""
    if _ACTIVE:
        return _ACTIVE
    if picked is None:
        picked = load_setting(path)
    return resolve_pick(picked, sorted(load_themes()))


def set_active_theme(name: str, store=None, path=None) -> bool:
    """Approve exactly one of the two voices as the app's theme. With a
    live ThemeStore the swap happens through it (CSS + persistence); a bare
    call records the pick for the next apply."""
    if name not in THEMES:
        return False
    if store is not None:
        return store.apply(name)
    global _ACTIVE
    _ACTIVE = name
    persist(name, path)
    return True


CURRENT = dict()          # the applied theme's tokens; canvas widgets (the


def contrast(a: str, b: str) -> float:
    """WCAG contrast ratio between two #rgb/#rrggbb colours."""
    def lum(hexc: str) -> float:
        h = hexc.lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        try:
            r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
        except (ValueError, TypeError):
            return 0.5

        def pick(c):
            return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        return 0.2126 * pick(r) + 0.7152 * pick(g) + 0.0722 * pick(b)

    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def gtk_css(tokens: dict) -> str:
    def tok(name, fallback):
        return tokens.get(name, fallback)

    bg = tok("--el-bg", "#0d1117")
    panel = tok("--el-panel", "#161b22")
    panel2 = tok("--el-panel-2", "#1c2330")
    panel3 = tok("--el-panel-3", "#252c36")
    line = tok("--el-line", "#2a3140")
    line2 = tok("--el-line-2", "#3a4252")
    # The strongest hairline in a theme: a switch track needs to read as a
    # track, not as another background step.
    line_strong = tok("--el-line-strong", "#4c4f55")
    ink = tok("--el-ink", "#dde5f2")
    ink_soft = tok("--el-ink-soft", "#8b9bb0")
    accent = tok("--el-accent", "#5b8def")
    accent_soft = tok("--el-accent-soft", "rgba(91,141,239,.15)")
    ok = tok("--el-ok", "#4dd07a")
    warn = tok("--el-warn", "#ffc940")
    fail = tok("--el-fail", "#ff5a52")
    # Lane tokens, wave D: threat surfaces vs tool surfaces read apart.
    lane_t = tok("--el-lane-threat", fail)
    lane_u = tok("--el-lane-tool", ok)
    # The spacing scale (wave D): new components use steps, not ad-hoc px.
    tok("--el-s-2", "4px")
    s3 = tok("--el-s-3", "8px")
    tok("--el-s-4", "12px")
    tok("--el-s-5", "18px")
    tok("--el-s-6", "26px")
    mono = tok("--el-font-mono", "monospace")
    display = tok("--el-font-display", "Inter")
    mute = tok("--el-mute", "#8b9bb0")
    body = tok("--el-font-body", "Inter")
    # Sharp edges are a theme choice, not a global one: obsidian sets 0px,
    # every other theme keeps its previous rounded corners.
    radius = tok("--el-radius", "6px")
    focus = tok("--el-focus-ring", "rgba(10,132,255,.6)")
    onaccent = tok("--el-on-accent", bg)

    def _lum(hexc):
        h = hexc.lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        try:
            r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
        except ValueError:
            return 0.5
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    def _toward(hexc, target, amt):
        h = hexc.lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        try:
            r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            return hexc
        r = int(r + (target - r) * amt); g = int(g + (target - g) * amt)
        b = int(b + (target - b) * amt)
        return f"#{r:02x}{g:02x}{b:02x}"

    for _ in range(3):
        gap = _lum(ink) - _lum(panel)
        if abs(gap) < 0.55:
            if _lum(ink) >= 0.5:                       # dark theme: bluer ink
                ink = _toward(ink, 238, 0.35)
                ink_soft = _toward(ink_soft, 178, 0.25)
            else:                                      # light theme: deeper ink
                panel = _toward(panel, 12, 0.3)
                panel2 = _toward(panel2, 16, 0.3)
        else:
            break

    # macOS-quality surface logic: hairlines instead of hard
    # 1px borders, a sidebar a shade off the content, and one soft card
    # elevation. All derived from the theme's own luminance so light themes
    # stay light.
    dark = _lum(bg) < 0.5
    hair = "rgba(255,255,255,0.07)" if dark else "rgba(0,0,0,0.08)"
    hair2 = "rgba(255,255,255,0.11)" if dark else "rgba(0,0,0,0.14)"
    hover = "rgba(255,255,255,0.05)" if dark else "rgba(0,0,0,0.04)"
    # macOS puts the sidebar a touch BELOW the content tone in dark mode
    # (window #1c1c1e over content #242426), and a touch above in light.
    sidebar = _toward(bg, 0, 0.035) if dark else _toward(bg, 0, 0.03)
    # Zebra tint for long tables: faint enough to read as texture, not bands.
    stripe = "rgba(255,255,255,0.022)" if dark else "rgba(0,0,0,0.022)"
    accent_hover = tok("--el-accent-hover", accent)

    CURRENT.clear()
    CURRENT.update({"bg": bg, "panel": panel, "panel2": panel2, "line": line,
                    "line2": line2, "ink": ink, "ink_soft": ink_soft,
                    "mute": mute,
                    "accent": accent, "ok": ok, "warn": warn, "fail": fail,
                    "display": display, "mono": mono})

    return f"""
/* READABILITY: bigger type + air */
* {{ font-size: 15px; letter-spacing: 0.1px; }}
row, treeview row {{ min-height: 38px; padding: 5px 10px; }}
button {{ padding: 8px 16px; font-size: 14px; letter-spacing: 0.2px; }}
entry, searchentry {{ padding: 9px 13px; font-size: 14px; }}
notebook tab {{ padding: 11px 24px; font-size: 14px; }}
label {{ padding: 3px 0; }}
.gw-card {{ padding: 16px; }}

/* window + every child follows the theme - the grey that would not change
   was GTK's default row/base colors; ALL of them are set here. */
window, dialog {{ background-color: {bg}; color: {ink}; }}
window {{ color: {ink}; }}
label {{ color: {ink}; }}
/* GTK4 dropped the -GtkTreeView-* style properties - spacing now lives
   in the min-height/padding rule up top. */
treeview, treeview .view {{
  background-color: {panel}; color: {ink};
}}
treeview row {{ background-color: {panel}; color: {ink}; }}
treeview row:nth-child(even) {{ background-color: {panel2}; }}
treeview row:selected {{ background-color: {accent}; color: {bg}; }}
treeview row:selected:backdrop {{ background-color: {line}; color: {ink}; }}
treeview row:hover {{ background-color: {accent_soft}; }}
treeview header {{ background-color: {panel}; color: {ink_soft}; }}
.scrolledwindow {{ background-color: {panel}; }}
textview view, textview {{ background-color: {panel}; color: {ink}; }}
/* No blanket `box` rule: it painted EVERY nested box with the page colour,
   which is why cards looked banded and a chat header came out as a dark
   slab. Boxes are transparent by default in GTK4; surfaces come from the
   window, the cards and the rail, not from layout containers. */
stack, notebook {{ background-color: {bg}; }}
tooltip {{ background-color: {panel2}; color: {ink}; border-radius: {radius}; }}
popover, popover list {{ background-color: {panel}; color: {ink}; }}
menubar {{ background-color: {bg}; color: {ink}; }}
spinbutton {{ background-color: {panel2}; color: {ink}; }}
linkbutton {{ color: {accent}; }}
.gw-panel {{ background-color: {panel}; }}
treeview .gw-panel {{ background-color: {panel}; }}
.gw-rail {{ background-color: {bg}; border-right: 1px solid {line}; }}
.gw-rail-label {{ color: {ink}; }}
.gw-card {{ background-color: {panel}; color: {ink};
  border: 1px solid {line}; border-radius: {radius}; }}
.gw-card > box {{ background-color: {panel}; }}
/* The blanket `box` rule paints EVERY nested box with the page colors, so
   a box nested INSIDE a card rendered as a near-black band in the Tools
   view. Inside a card, every descendant box shares
   the card's panel: */
.gw-card box {{ background-color: {panel}; }}
/* ...but a box INSIDE a button is the button's own content, not a band:
   without this the wider `.gw-card box` selector out-specifies the plain
   `button box {{ transparent }}` rule, so an icon+label button in a card
   drew a dark pill over its accent fill AND the symbolic icon inherited
   the button's on-accent ink against that dark pill - the icon vanished
   (scan strip,. */
.gw-card button box {{ background-color: transparent; }}
frame.gw-card {{ background-color: {panel}; }}
.gw-cta {{
  background-color: {accent}; color: {bg}; font-weight: 600;
  border: none; border-radius: {radius}; font-family: {display};
}}
/* ONE raised tone: buttons, the active rail tile and the
   boxed treeview headers read as DIFFERENT shades near each other; they are
   now ONE chrome tone: panel2 fill + line border everywhere). */
.gw-rail button {{ background-color: transparent; border: none;
                   outline: none; }}
.gw-rail button:hover {{ background-color: {accent_soft}; }}
.gw-rail image {{ color: {ink}; }}
.gw-rail .gw-active image {{ color: {accent}; }}
.gw-rail button.gw-active {{ background-color: {panel2};
  border: 1px solid {line}; border-radius: {radius}; }}
.gw-rail button.gw-active:hover {{ background-color: {accent_soft}; }}
.gw-rail .gw-active label {{ color: {accent}; }}
treeview header button {{ background-color: {panel2}; color: {ink_soft};
  border: 1px solid {line}; border-radius: {radius}; }}
treeview {{ color: {ink}; }}
treeview:selected {{ background: {accent}; }}
sidebar list {{ background-color: {bg}; }}
label.dim {{ color: {ink_soft}; }}
entry, searchentry {{
  background-color: {panel2}; color: {ink};
  border: 1px solid {line}; border-radius: {radius}; padding: 4px 8px;
}}
combobox stack, combobox entry {{ background-color: {panel2}; color: {ink}; }}
menu {{ background-color: {panel}; color: {ink}; }}
menuitem {{ color: {ink}; }}
menuitem:hover {{ background-color: {accent_soft}; }}
/* Combo and menu-button popups render their items as modelbutton nodes
   (GTK 4.18 GtkTreePopover). The system theme styles those nodes DIRECTLY
   (Breeze paints popovers dark, white text), so with no rule of ours the
   text kept the theme's white and vanished against our panel background
   (light mode). Ink beats the direct theme rule here. */
modelbutton {{ color: {ink}; }}
modelbutton:hover, modelbutton:active {{
  background-color: {accent_soft}; color: {ink}; }}
modelbutton:checked {{ background-color: {accent_soft}; color: {ink};
  font-weight: 600; }}
popover > contents, popover scrolledwindow, popover stack {{
  background-color: {panel}; color: {ink}; border: none; }}
separator {{ background-color: {line}; }}
notebook header {{ background-color: {bg}; }}
notebook tab {{ background-color: {panel2}; color: {ink_soft}; padding: 5px 12px; }}
notebook tab:checked {{ background-color: {panel}; color: {ink};
  border-bottom: 2px solid {accent}; }}
/* Adwaita paints a button's background as a background-IMAGE gradient, which
   covers a plain background-color from a lower-priority rule. Kill the image
   so our flat tones (panel2 fill, accent fill for primary) actually show
   (a screenshot check: "Allow once" had an accent border but the
   dark default fill). */
button {{
  background-image: none;
  background-color: {panel2}; color: {ink};
  border: 1px solid {line}; border-radius: {radius}; padding: 5px 12px;
}}
/* the child Box of a button (rail tile icon+label, treeview column header)
   used to paint bg over the button's own fill - the two-shade ring that
   read as different chrome shades; inside any button it is transparent */
button box {{ background-color: transparent; }}
button:hover {{ background-color: {accent_soft}; }}
.gw-ok {{ color: {ok}; }}
.gw-warn {{ color: {warn}; }}
.gw-fail {{ color: {fail}; }}
.gw-line {{ background-color: {line}; }}
.gw-header {{ background-color: {panel2}; }}

/* ---- design pass: macOS type/space, Windows 11 structure ---- */
* {{ font-family: {body}; }}
window, dialog {{ font-family: {body}; }}
.gw-titlebar {{
  background-color: {bg}; border-bottom: 1px solid {line};
  padding: 14px 22px; min-height: 46px;
}}
.gw-titlebar label {{ padding: 0; }}
.gw-title {{
  font-family: {display}; font-size: 16px; font-weight: 600;
  letter-spacing: -0.1px; color: {ink};
}}
.gw-subtitle {{ font-size: 12px; letter-spacing: 0.3px; color: {mute}; }}
.gw-pill {{
  background-color: transparent; border: 1px solid {line};
  border-radius: {radius}; padding: 3px 11px; font-size: 12px;
  letter-spacing: 0.3px; color: {ink_soft};
}}
.gw-pill.ok {{ color: {ok}; border-color: {ok}; }}
.gw-pill.warn {{ color: {warn}; border-color: {warn}; }}
.gw-pill.fail {{ color: {fail}; border-color: {fail}; }}
.gw-eyebrow {{
  font-size: 11px; font-weight: 600; letter-spacing: 1.6px;
  text-transform: uppercase; color: {mute};
}}
.gw-headline {{
  font-family: {display}; font-size: 19px; font-weight: 600;
  letter-spacing: -0.15px; color: {ink};
}}
.gw-meta {{ font-size: 13px; color: {ink_soft}; font-family: {mono};
  font-feature-settings: "tnum" 1; }}
/* Chat assistant identity: it should look
   like an assistant - a small mark, a real title, and a sentence
   saying what it is, above the state line. */
.gw-assistant-head {{ padding: 2px 0 4px 0; }}
.gw-assistant-title {{
  font-family: {display}; font-size: 15px; font-weight: 600;
  letter-spacing: -0.1px; color: {ink};
}}
.gw-assistant-sub {{ font-size: 12px; color: {mute}; }}
.gw-assistant-intro {{ color: {ink_soft}; }}
/* Decision popup (OpenSnitch grammar): one subject, two buttons. */
.gw-popup {{ background-color: {panel}; border: 1px solid {line2}; }}
.gw-popup-header {{
  background-color: {panel2}; border-bottom: 1px solid {line};
  padding: 18px 22px;
}}
.gw-popup-body {{ padding: 16px 22px; }}
.gw-popup-actions {{
  padding: 10px 18px; border-top: 1px solid {line};
  background-color: {bg};
}}
.gw-popup-actions button {{ min-height: 30px; padding: 6px 13px;
  font-size: 13px; }}
/* "Who is this?" card inside a decision popup:
   could not tell who was on the other end of an address like
   57.144.134.145:443, so every prompt now names the program and the
   network in plain words before the buttons. */
.gw-idcard {{
  background-color: {panel2}; border: 1px solid {line};
  border-radius: 10px; padding: 16px 18px;
}}
.gw-idname {{ font-size: 16px; font-weight: 650; color: {ink}; }}
.gw-idline {{ font-size: 13px; color: {ink_soft}; }}
.gw-idkey  {{ font-size: 12px; color: {mute}; }}
.gw-idval  {{ font-size: 12px; color: {ink_soft}; font-family: {mono};
  font-feature-settings: "tnum" 1; }}
.gw-idwarn {{ font-size: 12px; color: {warn}; }}
.gw-idicon {{ color: {accent}; }}
/* Destination picture: a drawn brand mark, or a map tile
   pinned on the country. The art carries its own rounded corners, so
   the widget is only a sizing box. */
.gw-idtile {{ min-width: 56px; min-height: 56px; }}
.gw-popup-actions button {{ min-height: 38px; font-size: 14px; }}
button.gw-primary {{
  background-image: none; background-color: {accent}; color: {onaccent};
  border: 1px solid {accent}; font-weight: 650;
}}
/* GTK paints button text through a child label, which our global
   `label {{ color: ink }}` rule would otherwise win - set it explicitly. */
button.gw-primary label {{ color: {onaccent}; }}
button.gw-primary:hover {{ background-color: {accent}; color: {onaccent}; opacity: .9; }}
button.gw-danger {{
  background-image: none; background-color: transparent; color: {fail};
  border: 1px solid {fail}; font-weight: 600;
}}
button.gw-danger label {{ color: {fail}; }}
button.gw-danger:hover {{ background-color: rgba(196,123,107,.14); }}
button.gw-quiet {{ background-image: none;
  background-color: transparent; border: 1px solid {line}; }}
button.gw-quiet label {{ color: {ink}; }}
/* The learning-mode escape hatch is a footnote to the answers, not a
   second footer: no own band, smaller type, and it sits inside the same
   footer background as the buttons above it. */
.gw-popup-learn {{ padding: 0 22px 14px; background-color: {bg};
  border-top: none; }}
button.gw-learn {{ padding: 6px 14px; font-size: 13px; }}
button:focus {{ outline: 2px solid {focus}; outline-offset: 1px; }}
/* Scrollbars: GTK4's default Adwaita trough is a grey slab that reads as
   a stray overlay on top of our surfaces, and its flat 8px thumb was the
   "weird grey overlay" seen on dark surfaces. The trough is transparent
   everywhere and the thumb is a thin, quiet rail that brightens on hover.
   The thumb is a translucent tint of the theme's own ink, not an opaque
   line colour: an opaque 10px band down the page edge still read as a slab
   in the screenshot pass. */
scrollbar {{ background: transparent; border: none; }}
scrollbar trough {{ background: transparent; border: none; box-shadow: none; }}
scrollbar slider {{
  background-color: alpha({line_strong}, 0.85); border: none;
  border-radius: 3px; min-width: 5px; min-height: 28px; margin: 3px;
}}
scrollbar slider:hover {{ background-color: alpha({ink_soft}, 0.85); }}
scrollbar slider:active {{ background-color: alpha({ink}, 0.75); }}
/* The tool rail is the one scroller that ends on its own pause/play
   buttons, so its bar is hidden outright (wheel scrolling still works)
   rather than painted across them. */
.gw-rail-scroll scrollbar {{ opacity: 0; min-width: 0; min-height: 0; }}
.gw-rail-scroll scrollbar slider {{ background: transparent;
  min-width: 0; min-height: 0; margin: 0; }}
/* Rail rows are a list of 17, not a data table: compact enough that the
   whole rail - header, all seventeen protections and the footer controls -
   fits the 720px minimum window without a scrollbar. Global row metrics
   (40px) stay untouched for treeviews and the event table. The macOS pass
   below this block restates the row metrics; keep the two in step. */

/* =====================================================================
 macOS-quality pass. Hairline surfaces, capsule chips, one soft
   card elevation, a real sidebar, and a calmer type scale. Placed last so
   it wins over the earlier flat/square rules without deleting history.
   ===================================================================== */
* {{ font-size: 14px; letter-spacing: 0.1px; }}
label {{ padding: 0; }}
window, dialog {{ background-color: {bg}; }}

/* --- titlebar ------------------------------------------------------- */
.gw-titlebar {{
  background-color: {sidebar}; border-bottom: 1px solid {hair};
  padding: 11px 22px; min-height: 50px;
}}
.gw-title {{ font-size: 15px; font-weight: 700; letter-spacing: -0.2px; }}
.gw-subtitle {{ font-size: 11.5px; letter-spacing: 0.2px; color: {mute}; }}
.gw-pill {{
  background-color: {hover}; border: 1px solid {hair2};
  border-radius: 999px; padding: 4px 12px; font-size: 12px;
  font-weight: 600; letter-spacing: 0.1px; color: {ink_soft};
}}
/* One type scale for both themes: 11 tag lines, 13 body, 15 card head,
   20 section head, 28 page title. */
.gw-headline {{
  font-size: 28px; font-weight: 700; letter-spacing: -0.7px; color: {ink};
}}
.gw-h2 {{
  font-size: 15px; font-weight: 650; letter-spacing: -0.1px; color: {ink};
}}
.gw-page-meta {{ font-size: 13px; color: {ink_soft}; font-family: {body}; }}
.gw-eyebrow {{
  font-size: 10.5px; font-weight: 700; letter-spacing: 1.4px;
  text-transform: uppercase; color: {mute};
}}

switch:checked slider {{ background-color: #ffffff; }}

/* --- sidebar -------------------------------------------------------- */
.gw-rail {{
  background-color: {sidebar}; border-right: 1px solid {hair};
  padding: 10px 10px 14px;
}}
.gw-rail button {{
  background-image: none; background-color: transparent;
  border: 1px solid transparent; border-radius: 8px;
  padding: 0 10px; min-height: 34px; box-shadow: none;
}}
.gw-rail button:hover {{ background-color: {hover}; border-color: transparent; }}
.gw-rail button.gw-active {{
  background-color: {accent_soft}; border-color: transparent;
}}
.gw-rail button.gw-active:hover {{ background-color: {accent_soft}; }}
.gw-rail button label {{
  font-size: 13px; font-weight: 500; color: {ink_soft};
}}
.gw-rail button.gw-active label {{ color: {accent}; font-weight: 650; }}
.gw-rail image {{ color: {ink_soft}; }}
.gw-rail button.gw-active image {{ color: {accent}; }}
.gw-side-cap {{
  font-size: 10.5px; font-weight: 700; letter-spacing: 1.2px;
  text-transform: uppercase; color: {mute}; padding: 12px 10px 4px;
}}

/* --- wizard step rail ----------------------------------------------- */
/* Gtk.Assistant's rail is its own surface (a Box carrying Adwaita's
   .sidebar class), so it painted Adwaita's grey while the page content
   took the theme's paper: a light theme's near-black ink landed on that
   grey and the step titles disappeared. The rail now uses the
   same surface logic as the main window's rail, and the current step is
   marked with an accent-tinted pill instead of Adwaita's white highlight. */
.assistant .sidebar {{
  background-color: {sidebar}; border-right: 1px solid {hair};
  padding: 8px 6px 10px;
}}
.assistant .sidebar label {{
  color: {ink_soft}; padding: 4px 8px;
}}
.assistant .sidebar label.highlight {{
  color: {ink}; background-color: {accent_soft};
  border: 1px solid {accent}; border-radius: {radius};
  font-weight: 650;
}}

/* --- cards ---------------------------------------------------------- */
/* No card casts a shadow design pass): hierarchy comes from
   type size and whitespace; elevation belongs to modals alone. */
.gw-card {{
  background-color: {panel}; border: 1px solid {line};
  border-radius: {radius}; padding: 16px; box-shadow: none;
}}
.gw-card box {{ background-color: {panel}; }}
.gw-card button box {{ background-color: transparent; }}
frame.gw-card, frame.gw-card > box {{ background-color: {panel}; }}
/* Settings rows have the grouped-list hairline macOS draws between rows.
   The line sits at the row's top edge, so the card's own spacing provides
   the air on both sides. */
.gw-srow {{ border-top: 1px solid {hair}; padding-top: 10px; }}
.gw-srow:first-child {{ border-top: none; padding-top: 0; }}

/* A protection row (Tools page): one line of facts rather than a card.
   The frame keeps the card surface and radius but no inner padding - the
   row's own box owns its margins, so the row stays 34px tall. */
frame.gw-prow {{
  background-color: {panel}; border: 1px solid {line};
  border-radius: {radius}; padding: 0; box-shadow: none;
}}
frame.gw-prow > box, .gw-prow box {{ background-color: {panel}; }}
.gw-prow button box {{ background-color: transparent; }}
/* Same missing tint as the rail rows: symbolic glyphs otherwise fall back
   to the system icon colour (white), which vanishes on light themes. */
.gw-prow image {{ color: {ink_soft}; }}
/* The merged Protections page: every protection is a
   full-width row. A 3px stripe carries the live state at a glance; the
   scan half adds a sentence, a bar and the scanner's own last lines. */
frame.gw-prow.red {{ border-left: 3px solid {fail}; }}
frame.gw-prow.warn {{ border-left: 3px solid {warn}; }}
frame.gw-prow.ok {{ border-left: 3px solid {ok}; }}
frame.gw-prow:hover {{ border-color: {hair2}; }}
.gw-scanline {{ font-size: 12px; color: {ink_soft}; }}
/* Scan state on the row edge: working now, waiting, finished, needs a
   look. The bar beside it moves; the stripe tells the page at a glance. */
frame.gw-prow.scan-run {{ border-left: 3px solid {accent}; }}
frame.gw-prow.scan-queued {{ border-left: 3px solid {line_strong}; }}
frame.gw-prow.scan-ok {{ border-left: 3px solid {ok}; }}
frame.gw-prow.scan-fail {{ border-left: 3px solid {fail}; }}
/* Shared desk selection tint (desk.py): a picked row reads via the
   accent-soft tint on any row the desk mounts, frames included. */
.gw-frow.gw-row-on {{ background-color: {accent_soft}; }}
frame.gw-prow.gw-row-on {{ background-color: {accent_soft}; }}
.gw-scanlog {{
  font-family: {mono}; font-size: 10.5px; color: {mute};
  background-color: {panel2}; border-radius: 6px; padding: 4px 8px;
}}
progressbar.gw-scanbar, progressbar.gw-scanbar trough,
progressbar.gw-scanbar progress {{ min-height: 6px; }}
progressbar.gw-scanbar trough {{
  background-color: {line}; border: none; border-radius: 99px;
}}
progressbar.gw-scanbar progress {{
  background-color: {accent}; border-radius: 99px;
}}
progressbar.gw-scanbar.ok progress {{ background-color: {ok}; }}
progressbar.gw-scanbar.fail progress {{ background-color: {fail}; }}
progressbar.gw-scanbar.idle progress {{ background-color: {line_strong}; }}
/* A finding is a button: clicking it opens the meaning and the actions. */
button.gw-finding {{
  background-color: transparent; border: 1px solid {hair};
  border-radius: 8px; padding: 6px 10px; min-height: 28px;
}}
button.gw-finding:hover {{ background-color: {hover}; border-color: {hair2}; }}
button.gw-finding.sev-high {{ border-left: 3px solid {fail}; }}
button.gw-finding.sev-critical {{ border-left: 3px solid {fail}; }}
button.gw-finding.sev-medium {{ border-left: 3px solid {warn}; }}
button.gw-finding.sev-low, button.gw-finding.sev-info {{
  border-left: 3px solid {line_strong};
}}
.gw-fixhint {{ font-size: 11.5px; color: {accent}; }}
.gw-advice {{ font-size: 12.5px; color: {ink}; }}
/* Settings index: a quiet list of sections, the selected one on the accent
   tint. No borders - the rows are the navigation, not a table. */
.gw-index {{ background-color: transparent; }}
.gw-index row {{
  background-color: transparent; border-radius: 8px;
  min-height: 32px; padding: 1px 10px; margin-bottom: 1px;
}}
.gw-index row:hover {{ background-color: {hover}; }}
.gw-index row:selected {{ background-color: {accent_soft}; }}
.gw-index row:selected label {{ color: {accent}; font-weight: 600; }}
.gw-index-label {{ font-size: 13px; }}
.gw-index image {{ color: {ink_soft}; }}
.gw-index row:selected image {{ color: {accent}; }}
/* Help protection rows: quiet, one line each, hover like a list. */
.gw-help-row {{ padding: 3px 8px; border-radius: 8px; }}
.gw-help-row:hover {{ background-color: {hover}; }}
.gw-help-row image {{ color: {ink_soft}; }}
button.gw-mini {{
  padding: 1px 6px; min-height: 22px; border-radius: 7px;
  font-size: 11.5px; font-weight: 550;
}}

/* --- controls ------------------------------------------------------- */
button {{
  background-image: none; background-color: {panel2}; color: {ink};
  border: 1px solid {hair2}; border-radius: 8px;
  padding: 8px 16px; min-height: 34px; font-size: 13.5px; font-weight: 500;
  box-shadow: none;
}}
button:hover {{ background-color: {hover}; }}
button:active {{ background-color: {line}; }}
/* A dimmed action has to LOOK dimmed: the explicit fill/ink above wins over
   Adwaita's disabled state, so an insensitive button sat bright over an
   empty list (Settings,. */
button:disabled, button:disabled label, button:disabled image {{
  opacity: 0.42;
}}
/* A focus ring is a keyboard affordance, not decoration: on launch the
   first rail button takes focus, and the brass box around Security read
   as a second selection. */
button:focus {{ outline: none; }}
button:focus-visible {{ outline: 2px solid {focus}; outline-offset: 1px; }}
.gw-rail button:focus, .gw-rail button:focus-visible {{ outline: none; }}
button.gw-primary {{
  background-color: {accent}; border-color: {accent}; color: {onaccent};
  font-weight: 650;
}}
button.gw-primary label {{ color: {onaccent}; }}
button.gw-primary:hover {{
  background-color: {accent_hover}; border-color: {accent_hover};
}}
/* The old `.gw-cta` was an accent fill, so every card action and all six
   scan tiles painted a wall of beige. macOS reserves the accent for ONE
   primary per view; ordinary actions are a neutral grey fill. */
button.gw-cta {{
  background-color: {panel3}; border: 1px solid {hair}; color: {ink};
  font-weight: 600; box-shadow: none;
}}
button.gw-cta:hover {{ background-color: {panel2}; }}
button.gw-cta image {{ color: {ink_soft}; }}
button.gw-quiet {{ background-color: transparent; border-color: {hair2}; }}
button.gw-chip, .gw-chips button {{
  background-color: transparent; border: 1px solid {hair2};
  border-radius: 999px; padding: 4px 13px; min-height: 28px;
  font-size: 12.5px; font-weight: 500; color: {ink_soft};
}}
button.gw-chip:hover, .gw-chips button:hover {{
  background-color: {hover}; color: {ink};
}}
/* Active filter (Browser Watch severity chips): the chip fills with ink
   while the page's voice owns the accent, so an on-chip reads as chosen
   without shouting. The bare label rule that sets ink beats any colour
   the button inherits, so the on-chip's label sets its own. */
button.gw-chip.gw-chip-on {{
  background-color: {ink}; border-color: {ink};
}}
button.gw-chip.gw-chip-on label {{ color: {onaccent}; }}
/* The selected finding in the hunter feed lifts one plate darker. */
.gw-row-on {{ background-color: {panel2}; border-radius: 10px; }}

entry, searchentry {{
  background-color: {panel2}; color: {ink};
  border: 1px solid {hair2}; border-radius: 10px; padding: 9px 13px;
  font-size: 14px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.20);
}}
entry:focus, entry:focus-within, searchentry:focus-within {{
  border-color: {accent};
}}

/* macOS switch: a grey track with a white knob, accent track when on.
   The knob was onaccent when checked, and onaccent is the dark ink meant
   for text ON the accent - so an "on" switch read as a hole punched in a
   brass pill instead of a raised knob. */
switch {{
  background-color: {line_strong}; border: none; border-radius: 999px;
  min-width: 34px; min-height: 20px; box-shadow: none;
}}
switch:checked {{ background-color: {accent}; }}
switch slider {{
  background-color: #ffffff; background-image: none;
  border: none; border-radius: 999px;
  min-width: 16px; min-height: 16px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.35);
}}
switch:checked slider {{ background-color: #ffffff; }}

/* --- lists ---------------------------------------------------------- */
.gw-rail-rows {{
  background-color: transparent; border-radius: 10px;
}}
.gw-rail-rows row {{
  min-height: 21px; padding: 0 8px; border-radius: 8px;
  border: none; background-color: transparent;
}}
.gw-rail-rows row:hover {{ background-color: {hover}; }}
.gw-rail-rows row:selected {{ background-color: {accent_soft}; }}
/* Row controls are glyph-only until hover: a bordered box on every one of
   seventeen rows read like a spreadsheet, not a macOS list. */
.gw-rail-rows button {{
  background-color: transparent; background-image: none;
  border: 1px solid transparent; border-radius: 6px; padding: 0;
  min-width: 20px; min-height: 20px; box-shadow: none;
}}
.gw-rail-rows button:hover {{ background-color: {hover}; border-color: transparent; }}
.gw-rail-rows button image {{ color: {ink_soft}; }}
/* Symbolic icons take their tint from CSS `color`; without a rule here
   GTK falls back to the system icon colour, which is white - so in the
   light theme every protection row drew a white glyph on a white card. */
.gw-rail-rows row image {{ color: {ink_soft}; }}
.gw-rail-rows row:selected label {{ color: {ink}; }}
.gw-rail-rows row:selected image {{ color: {accent}; }}
listview, list {{ background-color: transparent; }}
.gw-segmented button {{
  border-radius: 0; border-right-width: 0; margin: 0;
}}
.gw-segmented button:first-child {{ border-radius: 9px 0 0 9px; }}
.gw-segmented button:last-child {{
  border-radius: 0 9px 9px 0; border-right-width: 1px;
}}

/* --- tables --------------------------------------------------------- */
treeview, treeview .view {{ background-color: transparent; }}
treeview row {{ background-color: transparent; }}
treeview row:nth-child(even) {{ background-color: {stripe}; }}
treeview row:hover {{ background-color: {hover}; }}
treeview row:selected {{ background-color: {accent_soft}; color: {ink}; }}
treeview row:selected:backdrop {{ background-color: {hover}; color: {ink}; }}
treeview header {{ background-color: transparent;
  border-bottom: 1px solid {hair}; }}
treeview header button {{
  background-color: transparent; border: none; border-radius: 0;
  color: {mute}; font-size: 11.5px; font-weight: 600;
  min-height: 26px; padding: 2px 6px;
}}
treeview header button:hover {{ background-color: transparent; color: {ink}; }}
/* Column headers are plain labels (see window.py: a stock header centres
   its title over the column, which never lines up with left-aligned cells). */
.gw-th {{
  font-size: 10.5px; font-weight: 700; letter-spacing: 1.1px;
  text-transform: uppercase; color: {mute}; padding: 1px 0;
}}
.gw-th-row {{
  border-bottom: 1px solid {hair}; padding-bottom: 7px; margin-bottom: 2px;
}}

/* --- assistant chat ------------------------------------------------- */
.gw-chat {{
  background-color: {panel}; border: 1px solid {line_strong};
  border-radius: {radius}; padding: 12px 16px 12px; box-shadow: none;
}}
/* The assistant should be identifiable at a glance, not just by its text:
   the header sits on its own strip under a hairline, and the card carries
   a stronger edge than the other cards, so the chat area reads as its
   own surface. */
.gw-assistant-head {{
  border-bottom: 1px solid {hair}; padding: 0 0 8px 0; margin-bottom: 2px;
}}
/* Clear only the layout chrome. A bare `.gw-chat box` would out-specify
   `.gw-bubble` and paint every bubble transparent. */
.gw-chat > box, .gw-chat scrolledwindow,
.gw-chat scrolledwindow viewport, .gw-chat viewport,
.gw-chat .gw-stream {{
  background-color: transparent; padding: 4px 0;
}}
.gw-bubble {{
  background-color: {panel2}; border: 1px solid {hair};
  border-radius: 13px; padding: 9px 13px;
}}
.gw-bubble label {{ font-size: 13.5px; color: {ink}; }}
.gw-bubble-mine {{
  background-color: {accent_soft}; border-color: transparent;
}}
/* Picture strip under a connection answer: program icon on
   the left, destination brand mark or map pin on the right, each with a
   name and one factual line. Same fill as an assistant bubble so the two
   read as one turn, but without the bubble's padding-heavy text block. */
.gw-evidence {{
  background-color: {panel2}; border: 1px solid {hair};
  border-radius: 12px; padding: 8px 12px;
}}
.gw-ev-head {{ font-size: 13px; font-weight: 650; color: {ink}; }}
.gw-ev-line {{ font-size: 11.5px; color: {ink_soft}; }}
.gw-assistant-sub {{ font-size: 11.5px; color: {mute}; }}
.gw-banner {{
  font-size: 12.5px; color: {fail}; padding: 0 0 2px 0;
}}
.gw-composer {{ padding-top: 2px; }}
.gw-composer entry {{ background-color: {bg}; }}
button.gw-send {{
  background-color: {accent}; border-color: {accent}; color: {onaccent};
  border-radius: 10px; padding: 5px 18px; font-weight: 650;
}}
button.gw-send label {{ color: {onaccent}; }}
button.gw-send:hover {{ background-color: {accent_hover}; }}

/* --- the rail (wave D shell) ------ */
/* Grouped pages down the left edge: group headings are small uppercase
   mono, rows keep the glyph-plus-label language the plates had, and the
   active row tints in the accent. The collapsed rail hides labels but
   never the badges. */
.gw-rail {{
  background-color: {panel}; border-right: 1px solid {hair};
  padding: 8px 4px;
}}
.gw-rail-head {{
  font-size: 10px; font-weight: 700; letter-spacing: 1.2px;
  text-transform: uppercase; font-family: {mono}; color: {mute};
  margin: 8px 6px 2px 6px;
}}
.gw-rail button {{
  background-color: transparent; border: none; border-radius: {radius};
  padding: 5px 6px; min-height: 26px; margin: 0;
}}
.gw-rail button:hover {{ background-color: {hover}; }}
.gw-rail button.gw-active {{
  background-color: {accent_soft}; box-shadow: none; border: none;
}}
.gw-rail button:focus, .gw-rail button:focus-visible {{ outline: none; }}
.gw-rail .gw-rail-label {{
  font-size: 11px; font-weight: 600; letter-spacing: 0.2px; color: {ink};
}}
.gw-rail button.gw-active .gw-rail-label {{
  color: {accent}; font-weight: 700;
}}
/* Unread pill on a rail row: fail red, white number (mockup spec). */
.gw-badge {{
  background-color: {fail}; color: #ffffff; font-size: 9px;
  font-weight: 700; border-radius: 999px; padding: 1px 6px; min-height: 0;
}}
/* The Overview home row: HEADINGS[0] made clickable - a large title,
   not a group label; and the sun/moon at the rail's bottom-left. */
.gw-rail button.gw-rail-home {{ min-height: 36px; padding: 8px 6px; }}
.gw-rail .gw-rail-home .gw-rail-label {{
  font-size: 16px; font-weight: 700; color: {ink};
}}
.gw-rail .gw-rail-home.gw-active .gw-rail-label {{ color: {accent}; }}
.gw-voice-toggle {{
  color: {ink_soft}; margin: 4px 6px 6px 8px; padding: 3px 12px;
  font-size: 16px; background-color: transparent; border: none;
}}
.gw-voice-toggle:hover {{ background-color: {hover}; }}

/* --- Home suite lead: the verdict reads first ---------------- */
.gw-suite .gw-eyebrow {{ margin-bottom: 4px; }}
.gw-suite-verdict {{
  font-size: 17px; font-weight: 650; color: {ink}; padding: 1px 0;
}}

/* --- Browser Watch desk (, --- */
/* The desk is one instrument: a command strip on top, a five-tile stat
   band, the hunt channels' coverage strip, then the feed and the selected
   finding's dossier side by side. Everything reads hunter-written files;
   these classes only dress the layout. */
.gw-desk-cmd {{ border-radius: {radius}; }}
.gw-mono {{ font-family: {mono}; }}
.gw-suite-chip {{
  background-color: {panel2}; border: 1px solid {hair};
  border-radius: 999px; padding: 5px 12px;
}}
.gw-tile {{
  background-color: {panel2}; border: 1px solid {hair};
  border-radius: 10px; padding: 9px 12px; box-shadow: none;
}}
.gw-tile-k {{
  font-size: 10px; font-weight: 650; letter-spacing: 1.1px;
  text-transform: uppercase; color: {mute};
}}
.gw-tile-v {{
  font-size: 20px; font-weight: 700; color: {ink};
  font-family: {mono};
}}
.gw-tile-s {{ font-size: 11px; color: {ink_soft}; }}
.gw-tile-gap {{
  background-color: transparent; border: 1px dashed {line2};
  box-shadow: none;
}}
.gw-tile-gap .gw-tile-k {{ color: {mute}; font-weight: 550; }}
.gw-feedbody {{ padding: 0 14px 10px; }}
.gw-day {{
  font-size: 10px; font-weight: 700; letter-spacing: 1.2px;
  text-transform: uppercase; color: {mute}; padding: 12px 0 5px;
}}
.gw-frow {{
  padding: 9px 10px; border-radius: 9px; margin-top: 2px;
  background-color: transparent;
}}
.gw-frow:hover {{ background-color: {hover}; }}
.gw-frow.gw-row-on {{ background-color: {accent_soft}; }}
.gw-fmeta {{ font-size: 10.5px; color: {mute}; padding-left: 2px; }}
.gw-feedhead {{
  border-bottom: 1px solid {hair}; padding: 10px 14px; margin-bottom: 4px;
}}
.gw-feedfoot {{
  border-top: 1px solid {hair}; padding: 8px 14px; font-size: 10.5px;
  color: {mute};
}}
.gw-feed-empty {{ padding: 4px 14px 6px; font-size: 12px; color: {mute}; }}
.gw-dhead {{
  border-bottom: 1px solid {hair}; padding: 12px 14px 10px;
}}
.gw-dtitle {{
  font-size: 15.5px; font-weight: 700; color: {ink};
}}
.gw-dtitle-empty {{ font-size: 12px; color: {mute}; font-weight: 500; }}
.gw-dlead {{ font-size: 12.5px; color: {mute}; }}

.gw-pill {{
  background-color: {panel2}; border: 1px solid {hair};
  border-radius: 999px; padding: 3px 13px; font-size: 9.5px;
  font-weight: 700; color: {ink_soft};
}}
.gw-pill-fail {{ border-color: {fail}; background-color: transparent; }}
.gw-pill-warn {{ border-color: {warn}; background-color: transparent; }}
.gw-dbody {{ padding: 12px 14px; }}
.gw-dlabel {{
  font-size: 10px; font-weight: 700; letter-spacing: 1.1px;
  text-transform: uppercase; color: {mute}; margin-top: 2px;
}}
.gw-prose {{ font-size: 13px; color: {ink}; }}
.gw-facts {{
  font-family: {mono}; font-size: 11px; color: {ink_soft};
  background-color: {panel2}; border: 1px solid {hair};
  border-radius: 8px; padding: 8px 10px;
}}
.gw-facts-line {{ font-family: {mono}; font-size: 11px; color: {ink_soft}; }}
.gw-next {{
  background-color: {accent_soft}; border-radius: 9px; padding: 9px 12px;
  border: 1px solid transparent;
}}
.gw-next label {{ font-size: 12.5px; color: {ink}; }}
.gw-reply {{
  background-color: {panel2}; border: 1px solid {hair};
  border-radius: 10px; padding: 8px 11px;
}}
.gw-related {{ border-top: 1px solid {hair}; padding: 9px 14px 11px; }}
.gw-rel-where {{
  font-size: 9.5px; font-weight: 700; letter-spacing: 1.1px;
  font-family: {mono}; color: {mute}; min-width: 86px;
}}
.gw-rel-what {{ font-size: 11px; color: {ink_soft}; }}

/* --- popups --------------------------------------------------------- */
.gw-popup, .gw-popup > contents {{ border-radius: 14px; }}
.gw-idcard {{ border-radius: 12px; }}

/* --- wave D: lanes, defense desk, armor chips ------------------------ */
/* The two-system directive made visible: threat surfaces carry the
   danger side-line, tool surfaces the care side-line. */
.gw-lane-threat .gw-card {{ border-left: 3px solid {lane_t}; }}
.gw-lane-tool .gw-card {{ border-left: 3px solid {lane_u}; }}
.gw-page-title {{
  font-size: 15px; font-weight: 650; color: {ink}; margin-top: 2px;
}}
.gw-defense .gw-card {{ padding: 10px 12px; }}
.gw-armor {{ background-color: {panel2}; border-radius: {radius};
  padding: {s3}; }}
.gw-armor button {{
  background-color: {panel3}; border: 1px solid {hair};
  border-radius: 6px; padding: 4px 9px; font-size: 11px;
}}
.gw-armor-good {{ color: {ok}; }}
.gw-armor-open {{ color: {fail}; }}
.gw-armor-unknown {{ color: {mute}; }}
""".replace("{css_bg(bg)}", "")


def persist(name: str, path=None) -> bool:
    p = pathlib.Path(path if path is not None else SETTINGS_PATH)
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cfg = {}
    cfg["theme"] = name
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        # Temp + rename like every other settings file: two writers hit
        # this path (a theme click and its follow-up store write) and a
        # torn read lands a default theme instead of the stored pick.
        from appfw.atomicio import write_json_atomic
        write_json_atomic(p, cfg)
        return True
    except OSError:
        return False


def load_setting(path=None) -> str:
    try:
        p = path if path is not None else SETTINGS_PATH
        return json.loads(pathlib.Path(p).read_text()).get("theme", "")
    except (OSError, ValueError):
        return ""


class ThemeStore:

    def __init__(self, widget, themes_css=THEMES_CSS):
        import gi
        gi.require_version("Gtk", "4.0")
        from gi.repository import Gtk
        self._Gtk = Gtk
        self.widget = widget
        self.themes = load_themes(themes_css)
        self._provider = None

    def names(self):
        return sorted(self.themes)

    def apply(self, name: str) -> bool:
        toks = self.themes.get(name)
        if not toks:
            return False
        css = gtk_css(toks)
        from gi.repository import Gdk
        display = (
            self.widget.get_display()
            if hasattr(self.widget, "get_display") else None
        )
        if display is None:
            display = Gdk.Display.get_default()
        if self._provider:
            self._Gtk.StyleContext.remove_provider_for_display(
                display, self._provider)
        self._provider = self._Gtk.CssProvider()
        self._provider.load_from_string(css)
        self._Gtk.StyleContext.add_provider_for_display(
            display, self._provider,
            self._Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        persist(name)
        return True


# --- the wolf avatar --------------------------------
# One artwork file only: the wolf badge ships as
# assets/logo/greywatch-icon-256.png and is never redrawn or re-authored
# (memory HARD rules). The dark theme's avatar derives from it in memory —
# every colour channel flipped — so a new image file is not committed.
LOGO_PNG = ROOT / "assets" / "logo" / "greywatch-icon-256.png"


def _decode_logo(size: int):
    import gi
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf, Gio
    stream = Gio.MemoryInputStream.new_from_data(LOGO_PNG.read_bytes(), None)
    return GdkPixbuf.Pixbuf.new_from_stream_at_scale(
        stream, size, size, True, None)


def _tight_pixels(pb):
    """The pixbuf's pixels as a tight RGBA buffer (no row padding), so a
    rebuilt pixbuf can be handed back to GTK with a plain rowstride."""
    w, n = pb.get_width(), pb.get_n_channels()
    src = pb.read_pixel_bytes().get_data()
    stride = pb.get_rowstride()
    if stride == w * n:
        return bytearray(src)
    out = bytearray(w * n * pb.get_height())
    for y in range(pb.get_height()):
        row = y * stride
        out[y * w * n:(y + 1) * w * n] = src[row:row + w * n]
    return out


@functools.lru_cache(maxsize=None)
def logo_pixbuf(size: int):
    """The wolf badge at `size` px, decoded from the one artwork file."""
    try:
        return _decode_logo(size)
    except Exception:
        return None


@functools.lru_cache(maxsize=None)
def logo_pixbuf_inverted(size: int):
    """The wolf badge with every colour channel flipped (255 - byte): on
    the graphite dark voice the white circle reads as a dark one and the
    wolf reads bright. Alpha is untouched, so the round badge keeps its
    shape. Derivation is runtime-only (no second artwork file) and fails
    safe to the original art."""
    pb = logo_pixbuf(size)
    if pb is None:
        return None
    try:
        from gi.repository import GdkPixbuf, GLib
        w, n = pb.get_width(), pb.get_n_channels()
        has_alpha = pb.get_has_alpha()
        raw = _tight_pixels(pb)
        skip = n - 1 if has_alpha else -1
        for i in range(len(raw)):
            if i % n == skip:
                continue               # alpha keeps its value
            raw[i] ^= 0xFF
        return GdkPixbuf.Pixbuf.new_from_bytes(
            GLib.Bytes(bytes(raw)), GdkPixbuf.Colorspace.RGB, has_alpha, 8,
            w, pb.get_height(), w * n)
    except Exception:
        return pb                      # an inverted avatar is a nicety


def logo_image(size: int):
    """A ready Gtk.Image of the wolf avatar for the active theme: exact
    art on light voices, the inverted twin on dark ones. Returns None if
    the artwork file is missing."""
    image = active_theme() == "graphite"
    pb = logo_pixbuf_inverted(size) if image else logo_pixbuf(size)
    if pb is None:
        return None
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk, Gdk
    # GTK 4.18: a pixbuf image is deprecated; the texture paints the same
    # pixels without the warning.
    pic = Gtk.Image.new_from_paintable(Gdk.Texture.new_for_pixbuf(pb))
    pic.set_pixel_size(size)
    return pic


# --- tab symbols (the plates treatment) -----
# A drawn glyph over each tab name. No raster assets and no new colours:
# the strokes read the CURRENT voice's tokens, and the shell re-queues
# these widgets when the voice changes.

_TAB_GLYPHS = {}


def _glyph(name):
    def deco(fn):
        _TAB_GLYPHS[name] = fn
        return fn
    return deco


def _round_pen(cr, scale):
    import cairo
    cr.set_line_width(1.8 * scale)
    cr.set_line_cap(cairo.LineCap.ROUND)
    cr.set_line_join(cairo.LineJoin.ROUND)


@_glyph("home")
def _g_home(cr, s):
    # roof, then the walls under it
    cr.move_to(3 * s, 10.5 * s)
    cr.line_to(12 * s, 3 * s)
    cr.line_to(21 * s, 10.5 * s)
    cr.stroke()
    cr.move_to(5.5 * s, 9.5 * s)
    cr.line_to(5.5 * s, 20 * s)
    cr.line_to(18.5 * s, 20 * s)
    cr.line_to(18.5 * s, 9.5 * s)
    cr.stroke()


@_glyph("scans")
def _g_scans(cr, s):
    import math
    cr.arc(12 * s, 12 * s, 8.5 * s, 0, 2 * math.pi)
    cr.stroke()
    for x0, y0, x1, y1 in ((12, 3.5, 12, 7.5), (20.5, 12, 16.5, 12),
                           (12, 20.5, 12, 16.5), (3.5, 12, 7.5, 12)):
        cr.move_to(x0 * s, y0 * s)
        cr.line_to(x1 * s, y1 * s)
    cr.stroke()
    cr.arc(12 * s, 12 * s, 2.4 * s, 0, 2 * math.pi)
    cr.stroke()


@_glyph("protect")
def _g_protect(cr, s):
    # a plain-sided shield with the check inside
    cr.move_to(12 * s, 3.5 * s)
    for x, y in ((19, 6), (18, 15.5), (12, 20.5), (6, 15.5),
                 (5, 11.5), (5, 6)):
        cr.line_to(x * s, y * s)
    cr.close_path()
    cr.stroke()
    cr.move_to(9 * s, 12 * s)
    cr.line_to(11.2 * s, 14.2 * s)
    cr.line_to(15.5 * s, 10 * s)
    cr.stroke()


@_glyph("tools")
def _g_tools(cr, s):
    import math
    cr.arc(12 * s, 12 * s, 4.8 * s, 0, 2 * math.pi)
    cr.stroke()
    cr.arc(12 * s, 12 * s, 1.4 * s, 0, 2 * math.pi)
    cr.fill()
    for i in range(8):
        a = i * math.pi / 4
        cr.move_to(12 * s + 6.6 * s * math.cos(a),
                   12 * s + 6.6 * s * math.sin(a))
        cr.line_to(12 * s + 8.6 * s * math.cos(a),
                   12 * s + 8.6 * s * math.sin(a))
    cr.stroke()


@_glyph("thunter")
def _g_thunter(cr, s):
    import math
    cr.arc(12 * s, 12 * s, 8.5 * s, 0, 2 * math.pi)
    cr.stroke()
    cr.arc(12 * s, 12 * s, 4.6 * s, 0, 2 * math.pi)
    cr.stroke()
    for x0, y0, x1, y1 in ((12, 1.8, 12, 5.8), (12, 18.2, 12, 22.2),
                           (22.2, 12, 18.2, 12), (6, 12, 1.8, 12)):
        cr.move_to(x0 * s, y0 * s)
        cr.line_to(x1 * s, y1 * s)
    cr.stroke()


@_glyph("settings")
def _g_settings(cr, s):
    import math
    for y in (7.5, 12, 16.5):
        cr.move_to(4.5 * s, y * s)
        cr.line_to(19.5 * s, y * s)
    cr.stroke()
    for x, y in ((9.5, 7.5), (15.5, 12), (10.5, 16.5)):
        cr.arc(x * s, y * s, 1.9 * s, 0, 2 * math.pi)
    cr.fill()


@_glyph("defense")
def _g_defense(cr, s):
    cr.move_to(12 * s, 3.2 * s)
    cr.line_to(19.5 * s, 6.4 * s)
    cr.line_to(19.5 * s, 12.4 * s)
    cr.curve_to(19.5 * s, 17.4 * s, 16.4 * s, 20.6 * s, 12 * s, 21.4 * s)
    cr.curve_to(7.6 * s, 20.6 * s, 4.5 * s, 17.4 * s, 4.5 * s, 12.4 * s)
    cr.line_to(4.5 * s, 6.4 * s)
    cr.close_path()
    cr.stroke()
    cr.move_to(12 * s, 8.2 * s)
    cr.line_to(12 * s, 14.6 * s)
    cr.stroke()


@_glyph("harden")
def _g_harden(cr, s):
    import math
    cr.rectangle(5.5 * s, 10.5 * s, 13 * s, 9.5 * s)
    cr.stroke()
    for cx, cy in ((6.5, 10.8), (17.5, 10.8)):
        cr.arc(cx * s, cy * s, 2.9 * s, math.pi, 2 * math.pi)
    cr.stroke()
    cr.arc(12 * s, 15.2 * s, 1.7 * s, 0, 2 * math.pi)
    cr.fill()


@_glyph("overview")
def _g_overview(cr, s):
    # a screen with a pulse line across it: the suite at a glance
    cr.rectangle(3.5 * s, 4.5 * s, 17 * s, 14 * s)
    cr.stroke()
    cr.move_to(6.5 * s, 12 * s)
    cr.line_to(9.5 * s, 12 * s)
    cr.line_to(11 * s, 8.5 * s)
    cr.line_to(13.5 * s, 15.5 * s)
    cr.line_to(15 * s, 12 * s)
    cr.line_to(17.5 * s, 12 * s)
    cr.stroke()


@_glyph("services")
def _g_services(cr, s):
    import math
    # three service rows, each led by a state dot
    for y0 in (7, 12, 17):
        cr.move_to(4 * s, y0 * s)
        cr.line_to(20 * s, y0 * s)
        cr.stroke()
        cr.arc(4 * s, y0 * s, 0.9 * s, 0, 2 * math.pi)
        cr.fill()


@_glyph("auditlog")
def _g_auditlog(cr, s):
    # a ledger: ruled lines, the last one shorter (still being written)
    for y0, x1 in ((6.5, 19), (10.5, 19), (14.5, 19), (18.5, 13)):
        cr.move_to(5 * s, y0 * s)
        cr.line_to(x1 * s, y0 * s)
    cr.stroke()


@_glyph("logs")
def _g_logs(cr, s):
    for y0 in (6.5, 10.5, 14.5, 18.5):
        cr.move_to(5 * s, y0 * s)
        cr.line_to(19 * s, y0 * s)
    cr.stroke()


@_glyph("help")
def _g_help(cr, s):
    import math
    cr.arc(12 * s, 12 * s, 8.6 * s, 0, 2 * math.pi)
    cr.stroke()
    cr.move_to(9.6 * s, 9.4 * s)
    cr.curve_to(10.2 * s, 7.6 * s, 13.9 * s, 7.6 * s, 13.9 * s, 9.9 * s)
    cr.curve_to(13.9 * s, 11.6 * s, 12 * s, 11.9 * s, 12 * s, 13.6 * s)
    cr.stroke()
    cr.arc(12 * s, 17 * s, 0.7 * s, 0, 2 * math.pi)
    cr.fill()


def _hex_rgba(colour, fallback=(0.45, 0.45, 0.45, 1.0)):
    """CURRENT tokens are #rgb/#rrggbb strings; cairo wants RGBA."""
    try:
        h = str(colour).strip().lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
        return (r, g, b, 1.0)
    except (ValueError, TypeError):
        return fallback


def tab_symbol(key, size=22):
    """A drawn tab glyph ( plates): plain cairo strokes in the
    CURRENT voice's tokens — resting tabs draw in ink_soft, the active
    one in accent. The shell flips these with tab_symbol_active and
    re-queues them when the voice changes."""
    import gi
    gi.require_version("Gtk", "4.0")
    from gi.repository import Gtk
    area = Gtk.DrawingArea()
    area.set_size_request(size, size)
    area._gw_key = str(key)
    area._gw_active = False

    def _draw(_area, cr, width, height):
        scale = min(width, height) / 24.0
        if scale <= 0:
            return
        _round_pen(cr, scale)
        toks = CURRENT
        colour = toks.get("accent" if area._gw_active else "ink_soft")
        cr.set_source_rgba(*_hex_rgba(colour))
        glyph = _TAB_GLYPHS.get(str(area._gw_key))
        if glyph is not None:
            glyph(cr, scale)

    area.set_draw_func(_draw)
    return area


def tab_symbol_active(symbol, on: bool) -> None:
    """Flip a tab glyph between resting and active ink; no repaint when
    nothing changed."""
    on = bool(on)
    if getattr(symbol, "_gw_active", False) is not on:
        symbol._gw_active = on
        symbol.queue_draw()
