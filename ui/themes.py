from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
THEMES_CSS = ROOT / "ui" / "themes.css"
from gwpaths import data_dir as _gw_data
SETTINGS_PATH = _gw_data() / "greywatch-ui-settings.json"
DEFAULT_THEME = "obsidian"          # sharp-edge dark, macOS/Windows-11 hybrid

THEME_CHOICES = {"Dark": "obsidian", "Light": "swiss"}   # owner pick 2026-10-27

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


CURRENT = dict()          # the applied theme's tokens; canvas widgets (the


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

    # macOS-quality surface logic (2026-10-29): hairlines instead of hard
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
    card_hi = "rgba(255,255,255,0.045)" if dark else "rgba(255,255,255,0.75)"
    # Zebra tint for long tables: faint enough to read as texture, not bands.
    stripe = "rgba(255,255,255,0.022)" if dark else "rgba(0,0,0,0.022)"
    shadow = ("0 1px 2px rgba(0,0,0,0.35), 0 10px 30px rgba(0,0,0,0.16)"
              if dark else
              "0 1px 2px rgba(0,0,0,0.05), 0 10px 30px rgba(0,0,0,0.06)")
    accent_hover = tok("--el-accent-hover", accent)

    CURRENT.clear()
    CURRENT.update({"bg": bg, "panel": panel, "panel2": panel2, "line": line,
                    "line2": line2, "ink": ink, "ink_soft": ink_soft,
                    "mute": mute,
                    "accent": accent, "ok": ok, "warn": warn, "fail": fail,
                    "display": display, "mono": mono})

    return f"""
/* READABILITY (owner: it's cramped/hurts to look at): bigger type + air */
* {{ font-size: 15px; letter-spacing: 0.1px; }}
row, treeview row {{ min-height: 40px; padding: 6px 10px; }}
button {{ padding: 7px 14px; font-size: 14px; letter-spacing: 0.2px; }}
entry, searchentry {{ padding: 8px 12px; font-size: 14px; }}
notebook tab {{ padding: 11px 24px; font-size: 14px; }}
label {{ padding: 3px 0; }}
.gw-card {{ padding: 12px; }}

/* window + every child follows the theme — the grey that would not change
   was GTK's default row/base colors; ALL of them are set here. */
window, dialog {{ background-color: {bg}; color: {ink}; }}
window {{ color: {ink}; }}
label {{ color: {ink}; }}
/* GTK4 dropped the -GtkTreeView-* style properties — spacing now lives
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
.gw-rail {{ background-color: {bg}; border-right: 1px solid {line}; }}
.gw-rail-label {{ color: {ink}; }}
.gw-card {{ background-color: {panel}; color: {ink};
  border: 1px solid {line}; border-radius: {radius}; }}
.gw-card > box {{ background-color: {panel}; }}
/* The blanket `box` rule paints EVERY nested box with the page colors, so
   a box nested INSIDE a card rendered as a near-black band in the Tools
   view (owner 2026-10-25). Inside a card, every descendant box shares
   the card's panel: */
.gw-card box {{ background-color: {panel}; }}
frame.gw-card {{ background-color: {panel}; }}
.gw-cta {{
  background-color: {accent}; color: {bg}; font-weight: 600;
  border: none; border-radius: {radius}; font-family: {display};
}}
treeview .gw-panel {{ background-color: {panel}; }}
.gw-rail {{ background-color: {bg}; border-right: 1px solid {line}; }}
.gw-rail-label {{ color: {ink}; }}
.gw-card {{ background-color: {panel}; color: {ink};
  border: 1px solid {line}; border-radius: {radius}; }}
.gw-card > box {{ background-color: {panel}; }}
/* The blanket `box` rule paints EVERY nested box with the page colors, so
   a box nested INSIDE a card rendered as a near-black band in the Tools
   view (owner 2026-10-25). Inside a card, every descendant box shares
   the card's panel: */
.gw-card box {{ background-color: {panel}; }}
/* ...but a box INSIDE a button is the button's own content, not a band:
   without this the wider `.gw-card box` selector out-specifies the plain
   `button box {{ transparent }}` rule, so an icon+label button in a card
   drew a dark pill over its accent fill AND the symbolic icon inherited
   the button's on-accent ink against that dark pill — the icon vanished
   (scan strip, 2026-10-27). */
.gw-card button box {{ background-color: transparent; }}
frame.gw-card {{ background-color: {panel}; }}
.gw-cta {{
  background-color: {accent}; color: {bg}; font-weight: 600;
  border: none; border-radius: {radius}; font-family: {display};
}}
button.gw-cta image {{ color: {onaccent}; }}
/* ONE raised tone (owner 2026-10-25: buttons, the active rail tile and the
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
   (light mode, owner 2026-10-25). Ink beats the direct theme rule here. */
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
   (owner screenshot 2026-10-28: "Allow once" had an accent border but the
   dark default fill). */
button {{
  background-image: none;
  background-color: {panel2}; color: {ink};
  border: 1px solid {line}; border-radius: {radius}; padding: 5px 12px;
}}
/* the child Box of a button (rail tile icon+label, treeview column header)
   used to paint bg over the button's own fill — the two-shade ring that
   read as different chrome shades; inside any button it is transparent */
button box {{ background-color: transparent; }}
button:hover {{ background-color: {accent_soft}; }}
.gw-ok {{ color: {ok}; }}
.gw-warn {{ color: {warn}; }}
.gw-fail {{ color: {fail}; }}
.gw-line {{ background-color: {line}; }}
.gw-header {{ background-color: {panel2}; }}

/* ---- 2026-10-27 design pass: macOS type/space, Windows 11 structure ---- */
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
/* Chat assistant identity (2026-10-29): the owner asked for it to look
   like an AI assistant — a small mascot, a real title, and a sentence
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
/* "Who is this?" card inside a decision popup (2026-10-28): the owner
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
/* Destination picture (2026-10-29): a drawn brand mark, or a map tile
   pinned on the country. The art carries its own rounded corners, so
   the widget is only a sizing box. */
.gw-idtile {{ min-width: 56px; min-height: 56px; }}
.gw-popup-actions button {{ min-height: 38px; font-size: 14px; }}
button.gw-primary {{
  background-image: none; background-color: {accent}; color: {onaccent};
  border: 1px solid {accent}; font-weight: 650;
}}
/* GTK paints button text through a child label, which our global
   `label {{ color: ink }}` rule would otherwise win — set it explicitly. */
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
   footer background as the buttons above it (owner screenshot
   2026-10-28). */
.gw-popup-learn {{ padding: 0 22px 14px; background-color: {bg};
  border-top: none; }}
button.gw-learn {{ padding: 6px 14px; font-size: 13px; }}
button:focus {{ outline: 2px solid {focus}; outline-offset: 1px; }}
/* Scrollbars: GTK4's default Adwaita trough is a grey slab that reads as
   a stray overlay on top of our surfaces, and its flat 8px thumb was the
   "weird grey overlay" the owner kept seeing. The trough is transparent
   everywhere and the thumb is a thin, quiet rail that brightens on hover. */
scrollbar {{ background: transparent; border: none; }}
scrollbar trough {{ background: transparent; border: none; box-shadow: none; }}
scrollbar slider {{
  background-color: {line}; border: none; border-radius: 4px;
  min-width: 6px; min-height: 28px; margin: 2px;
}}
scrollbar slider:hover {{ background-color: {ink_soft}; }}
scrollbar slider:active {{ background-color: {ink}; }}
/* The tool rail is the one scroller that ends on its own pause/play
   buttons, so its bar is hidden outright (wheel scrolling still works)
   rather than painted across them. */
.gw-rail-scroll scrollbar {{ opacity: 0; min-width: 0; min-height: 0; }}
.gw-rail-scroll scrollbar slider {{ background: transparent;
  min-width: 0; min-height: 0; margin: 0; }}
/* Rail rows are a list of 17, not a data table: compact enough that the
   whole rail — header, all seventeen protections and the footer controls —
   fits the 720px minimum window without a scrollbar. Global row metrics
   (40px) stay untouched for treeviews and the event table. The macOS pass
   below this block restates the row metrics; keep the two in step. */

/* =====================================================================
   2026-10-29 macOS-quality pass (owner: "still not osx like ... much
   higher quality looking"). Hairline surfaces, capsule chips, one soft
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
.gw-headline {{
  font-size: 27px; font-weight: 700; letter-spacing: -0.7px; color: {ink};
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

/* --- cards ---------------------------------------------------------- */
.gw-card {{
  background-color: {panel}; border: 1px solid {hair};
  border-radius: 14px; padding: 18px;
  box-shadow: 0 1px 0 {card_hi} inset, {shadow};
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
   The frame keeps the card surface and radius but no inner padding — the
   row's own box owns its margins, so the row stays 34px tall. */
frame.gw-prow {{
  background-color: {panel}; border: 1px solid {hair};
  border-radius: 10px; padding: 0;
  box-shadow: 0 1px 0 {card_hi} inset;
}}
frame.gw-prow > box, .gw-prow box {{ background-color: {panel}; }}
.gw-prow button box {{ background-color: transparent; }}
/* Settings index: a quiet list of sections, the selected one on the accent
   tint. No borders — the rows are the navigation, not a table. */
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
button.gw-mini {{
  padding: 1px 6px; min-height: 22px; border-radius: 7px;
  font-size: 11.5px; font-weight: 550;
}}

/* --- controls ------------------------------------------------------- */
button {{
  background-image: none; background-color: {panel2}; color: {ink};
  border: 1px solid {hair2}; border-radius: 8px;
  padding: 5px 14px; min-height: 30px; font-size: 13px; font-weight: 500;
  box-shadow: none;
}}
button:hover {{ background-color: {hover}; }}
button:active {{ background-color: {line}; }}
/* A dimmed action has to LOOK dimmed: the explicit fill/ink above wins over
   Adwaita's disabled state, so an insensitive button sat bright over an
   empty list (Settings, 2026-10-29). */
button:disabled, button:disabled label, button:disabled image {{
  opacity: 0.42;
}}
/* A focus ring is a keyboard affordance, not decoration: on launch the
   first rail button takes focus, and the brass box around Security read
   as a second selection (owner screenshot, 2026-10-29). */
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

entry, searchentry {{
  background-color: {panel2}; color: {ink};
  border: 1px solid {hair2}; border-radius: 10px; padding: 8px 12px;
  font-size: 14px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.20);
}}
entry:focus, entry:focus-within, searchentry:focus-within {{
  border-color: {accent};
}}

/* macOS switch: a grey track with a white knob, accent track when on.
   The knob was onaccent when checked, and onaccent is the dark ink meant
   for text ON the accent — so an "on" switch read as a hole punched in a
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
.gw-rail-rows row:selected label {{ color: {ink}; }}
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
  background-color: {panel}; border: 1px solid {line2};
  border-radius: 14px; padding: 12px 16px 12px;
  box-shadow: 0 1px 0 {card_hi} inset, {shadow};
}}
/* The assistant should be identifiable at a glance, not just by its text:
   the header sits on its own strip under a hairline, and the card carries
   a stronger edge than the other cards (owner: "a border or something
   around the chat so you can tell it's the AI Assistant"). */
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
/* Picture strip under a connection answer (2026-10-29): program icon on
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

/* --- popups --------------------------------------------------------- */
.gw-popup, .gw-popup > contents {{ border-radius: 14px; }}
.gw-idcard {{ border-radius: 12px; }}
""".replace("{css_bg(bg)}", "")


def persist(name: str, path=SETTINGS_PATH) -> bool:
    p = pathlib.Path(path)
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cfg = {}
    cfg["theme"] = name
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
        return True
    except OSError:
        return False


def load_setting(path=SETTINGS_PATH) -> str:
    try:
        return json.loads(pathlib.Path(path).read_text()).get("theme", "")
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
