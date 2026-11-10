"""Settings = st2 (owner pick, rebuild round 2 task 12): group nav + tunables.

The owner-verified design: the content area splits into the group nav list
(Appearance / Behavior / Assistant / Notifications first, the round-2
groups a person actually tunes, then the operational groups that already
had panes) and a one-group-at-a-time pane on the right. The dock carries
the "Search" group: one entry that finds the right group by keyword and
selects the best match. Every tunable saves on the spot through the
greywatch-ui-settings.json seam and states in plain words what changed.
"""
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402


if not (os.environ.get("GREYWATCH_TEST_DISPLAY") == "1"
        or os.environ.get("GREYWATCH_XVFB") == "1"):
    pytest.skip(
        "GUI tests open real windows and run only on an explicit test"
        " display (the private Xvfb conftest starts, or"
        " GREYWATCH_TEST_DISPLAY=1 on purpose), never the owner's desktop.",
        allow_module_level=True)

from ui import guided, shell  # noqa: E402


def pump(n=20):
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


@pytest.fixture()
def sealed_paths(monkeypatch, tmp_path):
    """Both seam readers point at one sealed settings file, so a tunable
    write never touches the owner's real greywatch-ui-settings.json."""
    import ui.themes as themes
    p = tmp_path / "settings.json"
    monkeypatch.setattr(themes, "SETTINGS_PATH", p)
    monkeypatch.setattr(guided, "SETTINGS_PATH", p)
    return p


@pytest.fixture(scope="module")
def win():
    import tempfile
    from ui.window import MainWindow
    old = os.environ.get("GREYWATCH_DATA_DIR")
    os.environ["GREYWATCH_DATA_DIR"] = tempfile.mkdtemp(
        prefix="gw-settings-st2-")
    w = MainWindow()
    w.present()
    pump(30)
    w._show("settings")
    pump(10)          # the page builds lazily; the index needs a pass
    yield w
    w.destroy()
    if old is None:
        os.environ.pop("GREYWATCH_DATA_DIR", None)
    else:
        os.environ["GREYWATCH_DATA_DIR"] = old


def test_round2_groups_lead_the_nav(win):
    rows = []
    row = win._settings_index.get_first_child()
    while row is not None:
        rows.append(row._key)
        row = row.get_next_sibling()
    assert rows[:4] == ["look", "behavior", "assistant", "alerts"]
    # the operational groups that already had panes stay reachable
    assert {"firewall", "updates", "sites", "programs"} <= set(rows)


def test_settings_page_dock_has_the_search_group(win):
    win._show("settings")
    pump(10)
    assert "Search" in win.dock.group_titles()
    assert win.dock.group_titles()[0] == "Search"


def test_page_entry_map_greets_search_and_about():
    assert guided.PAGE_ENTRY["settings"] == "Search"
    assert guided.PAGE_ENTRY["help"] == "About"


def test_appearance_has_both_sliders(win):
    pane = win._settings_stack.get_child_by_name("look")
    scales = [w for w in _walk(pane) if isinstance(w, Gtk.Scale)]
    assert len(scales) == 2
    rail = scales[0]
    adj = rail.get_adjustment()
    assert adj.get_lower() == 5 and adj.get_upper() == 10


def _walk(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def test_rail_slider_saves_and_states_the_change(win, sealed_paths):
    scale = win._rail_scale
    scale.set_value(7)
    win._rail_apply(scale)
    pump(5)
    cfg = json.loads(sealed_paths.read_text())
    assert cfg["rail"] == 7
    assert "rail width = 7%" in win._rail_note.get_text()
    # the change lands live, not on the next tick
    assert win.rail_bar.get_size_request()[0] == shell.rail_size(
        win.get_allocated_width(), 7)


def test_dock_slider_saves_inside_the_clamp(win, sealed_paths):
    scale = win._dock_scale
    scale.set_value(300)
    win._dock_apply(scale)
    pump(5)
    cfg = json.loads(sealed_paths.read_text())
    assert cfg["dock_width"] == 300
    from ui.window import dock_width
    assert dock_width(1200, cfg["dock_width"]) == 300   # inside the clamp
    assert "dock width = 300px" in win._dock_note.get_text()


def test_rail_slider_survives_out_of_band_values(win, sealed_paths):
    """The slider's pick rides the same clamp the window's reading law
    keeps, so a hand-edited settings file never balloons the rail."""
    scale = win._rail_scale
    adj = scale.get_adjustment()
    adj.set_lower(1)                      # force an out-of-band value in
    scale.set_value(1)
    win._rail_apply(scale)
    pump(5)
    assert win.rail_bar.get_size_request()[0] >= 150   # the label floor


def test_auto_jump_switch_writes_the_toggle(win, sealed_paths):
    sw = win._auto_jump
    want = not bool(sw.get_active())
    sw.set_active(want)
    win._on_auto_jump(sw)
    pump(5)
    assert win._toggles["auto_jump"] is bool(want)
    cfg = json.loads(sealed_paths.read_text())
    assert cfg["auto_jump"] is bool(want)
    words = "on" if want else "off"
    assert words in win._auto_jump_note.get_text().lower()


def test_auto_jump_toggle_drives_the_router(win, sealed_paths):
    seen = []
    real = guided.navigate
    guided.navigate = lambda w, key: seen.append(key)
    try:
        win._toggles["auto_jump"] = False
        assert guided.handoff(win, "scans", "Schedule") is False
        win._toggles["auto_jump"] = True
        win._handoff_seen.clear()
        assert guided.handoff(win, "scans", "Schedule") is True
    finally:
        guided.navigate = real
        win._toggles["auto_jump"] = True
    assert seen == ["scans"]


def test_voice_radio_syncs_the_sun_moon(win, sealed_paths):
    win._radio_graphite.set_active(True)   # fires the radio's toggled seam
    pump(10)
    # the button shows the voice clicking it would bring
    assert win._voice_btn.get_label() == "☀"
    win._radio_paper.set_active(True)
    pump(10)
    assert win._voice_btn.get_label() == "☾"


def test_assistant_pane_states_the_brain_honestly(win):
    pane = win._settings_stack.get_child_by_name("assistant")
    texts = [l.get_text() for l in _walk(pane)
             if isinstance(l, Gtk.Label)]
    joined = " | ".join(texts)
    from assistant.model import MODEL_FILENAME
    assert MODEL_FILENAME in joined
    assert "CPU" in joined and "GPU model off" in joined
    assert "heuristics" in joined.lower() and "always on" in joined.lower()
    from tools.build_digests import DIGEST_TOOLS
    assert str(len(DIGEST_TOOLS)) in joined


def test_notifications_pane_still_lists_the_lanes(win):
    pane = win._settings_stack.get_child_by_name("alerts")
    switches = [w for w in _walk(pane) if isinstance(w, Gtk.Switch)]
    assert len(switches) == 3


def test_search_selects_the_best_match(win):
    win._show("settings")
    pump(10)
    entry = win._settings_search
    entry.set_text("rail width")
    win._on_settings_search(entry)
    pump(5)
    picked = win._settings_index.get_selected_row()
    assert picked is not None and picked._key == "look"
    # the non-matching groups hide while the query stands
    assert not win._settings_rows["alerts"].get_visible()


def test_search_finds_groups_by_their_controls(win):
    entry = win._settings_search
    entry.set_text("auto-jump")
    win._on_settings_search(entry)
    pump(5)
    picked = win._settings_index.get_selected_row()
    assert picked._key == "behavior"
    entry.set_text("")
    win._on_settings_search(entry)
    pump(5)
    assert win._settings_rows["alerts"].get_visible()   # empty = all back
