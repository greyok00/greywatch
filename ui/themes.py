from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
THEMES_CSS = ROOT / "ui" / "themes.css"
SETTINGS_PATH = ROOT / "data" / "greywatch-ui-settings.json"
DEFAULT_THEME = "console"           # dark, calm (GitHub-dark-like, blue accent)

THEME_CHOICES = {"Dark Mode": "console", "Light Mode": "swiss"}   # owner pick 2026-10-25

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
    line = tok("--el-line", "#2a3140")
    line2 = tok("--el-line-2", "#3a4252")
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

    CURRENT.clear()
    CURRENT.update({"bg": bg, "panel": panel, "panel2": panel2, "line": line,
                    "line2": line2, "ink": ink, "ink_soft": ink_soft,
                    "mute": mute,
                    "accent": accent, "ok": ok, "warn": warn, "fail": fail,
                    "display": display, "mono": mono})

    return f"""
/* READABILITY (owner: it's cramped/hurts to look at): bigger type + air */
* {{ font-size: 16px; }}
row, treeview row {{ min-height: 42px; padding: 6px 10px; }}
button {{ padding: 10px 18px; font-size: 15px; }}
entry, searchentry {{ padding: 9px 12px; font-size: 15px; }}
notebook tab {{ padding: 12px 26px; font-size: 15px; }}
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
box, stack, notebook {{ background-color: {bg}; }}
tooltip {{ background-color: {panel2}; color: {ink}; border-radius: 4px; }}
popover, popover list {{ background-color: {panel}; color: {ink}; }}
menubar {{ background-color: {bg}; color: {ink}; }}
spinbutton {{ background-color: {panel2}; color: {ink}; }}
linkbutton {{ color: {accent}; }}
.gw-panel {{ background-color: {panel}; }}
.gw-rail {{ background-color: {bg}; border-right: 1px solid {line}; }}
.gw-rail-label {{ color: {ink}; }}
.gw-card {{ background-color: {panel}; color: {ink};
  border: 1px solid {line}; border-radius: 10px; }}
.gw-card > box {{ background-color: {panel}; }}
/* The blanket `box` rule paints EVERY nested box with the page colors, so
   a box nested INSIDE a card rendered as a near-black band in the Tools
   view (owner 2026-10-25). Inside a card, every descendant box shares
   the card's panel: */
.gw-card box {{ background-color: {panel}; }}
frame.gw-card {{ background-color: {panel}; }}
.gw-cta {{
  background-color: {accent}; color: {bg}; font-weight: 600;
  border: none; border-radius: 7px; font-family: {display};
}}
treeview .gw-panel {{ background-color: {panel}; }}
.gw-rail {{ background-color: {bg}; border-right: 1px solid {line}; }}
.gw-rail-label {{ color: {ink}; }}
.gw-card {{ background-color: {panel}; color: {ink};
  border: 1px solid {line}; border-radius: 10px; }}
.gw-card > box {{ background-color: {panel}; }}
/* The blanket `box` rule paints EVERY nested box with the page colors, so
   a box nested INSIDE a card rendered as a near-black band in the Tools
   view (owner 2026-10-25). Inside a card, every descendant box shares
   the card's panel: */
.gw-card box {{ background-color: {panel}; }}
frame.gw-card {{ background-color: {panel}; }}
.gw-cta {{
  background-color: {accent}; color: {bg}; font-weight: 600;
  border: none; border-radius: 7px; font-family: {display};
}}
/* ONE raised tone (owner 2026-10-25: buttons, the active rail tile and the
   boxed treeview headers read as DIFFERENT shades near each other; they are
   now ONE chrome tone: panel2 fill + line border everywhere). */
.gw-rail button {{ background-color: transparent; border: none;
                   outline: none; }}
.gw-rail button:hover {{ background-color: {accent_soft}; }}
.gw-rail button.gw-active {{ background-color: {panel2};
  border: 1px solid {line}; border-radius: 10px; }}
.gw-rail button.gw-active:hover {{ background-color: {accent_soft}; }}
.gw-rail .gw-active label {{ color: {accent}; }}
treeview header button {{ background-color: {panel2}; color: {ink_soft};
  border: 1px solid {line}; border-radius: 6px; }}
treeview {{ color: {ink}; }}
treeview:selected {{ background: {accent}; }}
sidebar list {{ background-color: {bg}; }}
label.dim {{ color: {ink_soft}; }}
entry, searchentry {{
  background-color: {panel2}; color: {ink};
  border: 1px solid {line}; border-radius: 4px; padding: 4px 8px;
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
button {{
  background-color: {panel2}; color: {ink};
  border: 1px solid {line}; border-radius: 6px; padding: 5px 12px;
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
