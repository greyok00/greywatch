"""Pins for the rebuilt v4 shell and its first page.

The old-ui pins (85 files listed in /tmp/gw-ui-importers.txt) were held
aside when the owner deleted the ui/ tree; they are rewritten page by
page as the new surfaces land. These are the new pins: the theme law,
the rail's honesty, the labels law, and the Security Center's blocks
reading fixture state files instead of the live daemon.
"""

from __future__ import annotations

import json
import pathlib
import re

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from ui import themes


# -- the theme law ------------------------------------------------------

def test_two_voices_only_graphite_default():
    names = sorted(themes.load_themes())
    assert names == ["graphite", "paper"]
    assert themes.DEFAULT_THEME == "graphite"
    assert themes.dark_default(names) == "graphite"
    # the redo law: the brief brutal-index voice is gone from the store
    assert "brutal-index" not in names


def test_retired_picks_migrate_to_their_light_or_dark_intent():
    names = sorted(themes.load_themes())
    for dark in ("obsidian", "aperture", "brutal-index"):
        assert themes.resolve_pick(dark, names) == "graphite"
    for light in ("swiss", "agency"):
        assert themes.resolve_pick(light, names) == "paper"
    assert themes.resolve_pick("unknown-thing", names) == "graphite"
    assert themes.resolve_pick("", names) == "graphite"


def test_graphite_is_the_proven_dark_voice():
    toks = themes.load_themes()["graphite"]
    assert toks["--el-bg"] == "#14161a"
    assert toks["--el-ink"] == "#e9e7e2"
    assert toks["--el-accent"] == "#b5b3ab"
    assert toks["--el-radius"] == "4px"


def test_advanced_open_rail_scrollbar_has_a_visible_thumb():
    css = themes.gtk_css(themes.load_themes()["graphite"])
    assert ".gw-rail-scroll.gw-advanced-open scrollbar slider {" in css
    thumb = css.split(
        ".gw-rail-scroll.gw-advanced-open scrollbar slider {", 1)[1]
    thumb = thumb.split("}", 1)[0]
    assert "background-color:" in thumb
    assert "min-width: 5px;" in thumb
    assert "min-height: 28px;" in thumb


def test_both_sheets_load_into_gtk_without_parse_errors():
    for name, toks in themes.load_themes().items():
        provider = Gtk.CssProvider()
        provider.load_from_string(themes.gtk_css(toks))
        css = provider.to_string()
        # the generated sheet carries the voice's own ground colour;
        # GTK normalises hex to rgb() so the pin reads it the same way
        h = toks["--el-bg"].lstrip("#")
        rgb = f"rgb({int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)})"
        assert rgb in css, f"{name}: ground colour absent from the sheet"


# -- the shell ----------------------------------------------------------

def _app() -> Gtk.Application:
    return Gtk.Application(application_id="org.greywatch.test")


def test_rail_shows_exactly_the_available_pages():
    # Pages build on first show now; the rail is built from the modules, so
    # it lists every reachable page without pre-assembling any of them.
    from ui import app as app_mod
    win = app_mod.Window(_app())
    expected = {label for label, _ in app_mod.REGISTRY
                if label in win._page_modules}
    assert "Security Center" in expected
    assert set(win._rail_rows) == expected | set(
        ["Advanced"] if "Advanced" in win._rail_rows else [])


def test_advanced_is_an_inline_submenu_not_a_popover_or_settings_page():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    assert "Advanced" in win._rail_rows
    revealer = win._advanced_revealer
    assert revealer is not None
    assert not revealer.get_reveal_child()
    win._rail_rows["Advanced"].emit("clicked")
    assert revealer.get_reveal_child()
    assert isinstance(revealer, Gtk.Revealer)
    assert not isinstance(revealer, Gtk.Popover)
    assert "Settings" not in win._page_modules
    assert "Settings" not in win._rail_rows


def test_security_has_the_three_tabs():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win.show_page("Security Center")
    body = win._pages["Security Center"]._gw_body
    titles = [page.get_title() for page in body._gw_tab_stack.get_pages()]
    assert titles == ["Overview", "Findings", "Baseline detail"]


def test_retired_rail_rows_are_gone():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    assert "Response" not in win._page_modules
    assert "Baseline" not in win._page_modules
    assert set(win._rail_rows) == {
        "Security Center", "Network", "Tools", "Timeline",
        "Assistant", "Help", "Advanced"}


def test_an_advanced_tool_opens_as_a_page_not_a_popup():
    from ui import app as app_mod
    win = app_mod.Window(_app())
    win.open_tool_page("Virus Scan", ("clamav", "freshclam"), "clamav")
    assert "Virus Scan" in win._page_modules
    page = win._pages.get("Virus Scan")
    assert page is not None
    assert win._stack.get_visible_child() is page
    assert win._advanced_rows["Virus Scan"].has_css_class("gw-active")


def test_no_parenthetical_in_any_label_anywhere(tmp_path, monkeypatch):
    """The labels law (owner 2026-11-15): no page name, rail item, button
    or status line carries a parenthetical. Data rows from the stores are
    not labels; they are exempt by construction, and this pin walks only
    the app-authored labels: the rail, the page heads, the card heads,
    the pills and the buttons."""
    from ui import app as app_mod
    win = app_mod.Window(_app())
    labels = list(win._rail_rows)
    for label, page in win._pages.items():
        body = getattr(page, "_gw_body", page)
        labels.extend(_walk_labels(body))
    for text in labels:
        assert "(" not in text, f"parenthetical label: {text!r}"
    _ = tmp_path, monkeypatch


def _walk_labels(w) -> list:
    out = []
    try:
        text = w.get_label()
    except AttributeError:
        text = None
    if isinstance(text, str):
        # a label's own text arrives as its markup; the app-authored
        # words sit inside the tags
        text = re.sub(r"<[^>]+>", "", text)
    if text and not isinstance(w, Gtk.Entry):
        cls = {c for c in w.get_css_classes()}
        if cls & {"gw-eyebrow", "gw-headline", "gw-pill", "gw-title",
                  "gw-side-cap"}:
            out.append(text)
        elif w.get_parent() is not None and _inside_button(w):
            out.append(text)
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        out.extend(_walk_labels(child))
        child = child.get_next_sibling()
    return out


def _inside_button(w) -> bool:
    p = w.get_parent()
    while p is not None:
        if isinstance(p, Gtk.Button):
            return True
        p = p.get_parent()
    return False


# -- the Security Center ------------------------------------------------

def _fixture_data(tmp_path: pathlib.Path, score=None,
                  state="GREEN") -> pathlib.Path:
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "status.json").write_text(json.dumps({
        "updated": "2026-11-15T08:00:00+00:00",
        "tools": {
            "clamav": {"label": "Virus Scan", "state": state,
                       "last_event": None},
            "freshclam": {"label": "Signatures", "state": state,
                          "last_event": None},
            "ufw": {"label": "Firewall", "state": state,
                    "last_event": None},
            "fail2ban": {"label": "Bans", "state": state,
                         "last_event": None},
            "appfw": {"label": "App Firewall", "state": state,
                      "last_event": None},
            "aide": {"label": "Integrity", "state": state,
                     "last_event": None},
            "tetragon": {"label": "Kernel Watch", "state": state,
                         "last_event": None},
            "apparmor": {"label": "Profiles", "state": state,
                         "last_event": None},
            "cve-updater": {"label": "Intel", "state": state,
                            "last_event": None},
        },
        "defense": {"blocked": []},
    }))
    # a withheld report withholds by unreadable inputs, not by fiat: the
    # score is None because lynis and apparmor could not be read here
    lynis = None if score is None else 86
    aa = None if score is None else 40
    (d / "posture.json").write_text(json.dumps({
        "version": 1, "built_at": "2026-11-15T08:00:00+00:00",
        "score": score, "scale": "0-100, higher is better",
        "inputs": {
            "lynis_hardening": {"value": lynis, "weight": 0.35,
                                "direction": "higher-is-better",
                                "how": "fixture"},
            "baseline_pass": {"value": 100, "weight": 0.30,
                              "direction": "higher-is-better",
                              "how": "fixture"},
            "cve_exposure": {"value": 12, "weight": 0.20,
                             "direction": "lower-is-better",
                             "how": "fixture"},
            "apparmor_exposure": {"value": aa, "weight": 0.15,
                                  "direction": "higher-is-better",
                                  "how": "fixture"},
        },
        "renormalized_over": ["baseline_pass", "cve_exposure"],
        "unknown_inputs": ["lynis_hardening", "apparmor_exposure"]
        if score is None else ["apparmor_exposure"],
    }))
    return d


def _build_page(tmp_path, monkeypatch, **kw):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_fixture_data(tmp_path,
                                                                **kw)))
    from ui import security
    window = _ShellStub()
    page = security.build(window)
    monkeypatch.delenv("GREYWATCH_DATA_DIR")
    return security, page


class _ShellStub:
    """What a page needs from the shell, without the whole window."""
    ROOT = pathlib.Path(__file__).resolve().parents[1]

    def has_page(self, label: str) -> bool:
        return False

    def show_page(self, label: str) -> None:
        raise AssertionError(f"unexpected page switch: {label}")

    def note(self, text: str) -> None:
        self.last_note = text


def test_withheld_score_names_its_two_readable_inputs(tmp_path,
                                                      monkeypatch):
    security, page = _build_page(tmp_path, monkeypatch, score=None)
    body = getattr(page, "_gw_body", page)
    texts = _all_texts(body)
    assert any("withheld" in t.lower() for t in texts)
    assert any("2 of 4 inputs" in t for t in texts)


def test_score_bands_speak_the_three_marks(tmp_path, monkeypatch):
    for score, want in ((85, "secure"), (70, "needs attention"),
                        (40, "at risk")):
        security, page = _build_page(tmp_path, monkeypatch, score=score)
        body = getattr(page, "_gw_body", page)
        texts = " ".join(_all_texts(body)).lower()
        assert want in texts, f"{score}: {want} missing"


def test_cards_read_the_fixture_states(tmp_path, monkeypatch):
    security, page = _build_page(tmp_path, monkeypatch)
    body = getattr(page, "_gw_body", page)
    texts = _all_texts(body)
    assert any("Live" in t for t in texts)   # the state word, not the token
    assert not any("GREEN" in t.upper() for t in texts)
    assert any("pending decisions" in t.lower() for t in texts)


def test_cve_row_carries_its_direction(tmp_path, monkeypatch):
    security, page = _build_page(tmp_path, monkeypatch)
    body = getattr(page, "_gw_body", page)
    texts = " ".join(_all_texts(body)).lower()
    assert "lower is better" in texts


def test_scan_desk_follows_the_headline_and_cards(tmp_path, monkeypatch):
    security, page = _build_page(tmp_path, monkeypatch)
    body = getattr(page, "_gw_body", page)
    overview = body._gw_overview
    children = []
    child = overview.get_first_child()
    while child is not None:
        children.append(child)
        child = child.get_next_sibling()
    order = [children.index(body._gw_head),
             children.index(body._gw_hero),
             children.index(body._gw_grid),
             children.index(body._gw_scan_block)]
    assert order == sorted(order), f"Security Center order: {order}"


def _all_texts(w) -> list:
    out = []
    label = w.get_label() if isinstance(w, Gtk.Label) else None
    if label:
        out.append(label)
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        out.extend(_all_texts(child))
        child = child.get_next_sibling()
    return out


def test_mount_page_forces_every_page_to_fill():
    """The shell sets expansion on the page it mounts, so a page root
    that never asks to expand cannot collapse to its minimum height."""
    import types
    from ui import app as app_mod
    stub = types.SimpleNamespace(
        _pages={}, _page_widgets={}, _stack=Gtk.Stack())
    page = Gtk.Box()
    page.set_hexpand(False)
    page.set_vexpand(False)
    wrapper = app_mod.Window._mount_page(stub, "Tools", page)
    assert page.get_vexpand() is True
    assert page.get_hexpand() is True
    assert wrapper.get_vexpand() is True
