"""The Settings depth pass (GW-126): index sublines and related footers.

The approved mockup keeps the index-and-pane shape and puts the depth in
what each piece SAYS: a one-line what's-inside under every group name
(the two trust lists carry their real counts, never invented ones), and
a related-in-suite footer on every pane whose Open buttons hand off to
pages the app really has.
"""
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


def pump(n=20):
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


@pytest.fixture(scope="module")
def win():
    import tempfile
    from ui.window import MainWindow
    old = os.environ.get("GREYWATCH_DATA_DIR")
    os.environ["GREYWATCH_DATA_DIR"] = tempfile.mkdtemp(
        prefix="gw-settings-depth-")
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


PANES = ("look", "firewall", "alerts", "connections", "computer",
         "diagnostics", "updates", "sites", "programs")


def test_every_index_row_says_whats_inside(win):
    assert set(win._index_meta) == set(PANES)
    texts = {key: label.get_text() for key, label in win._index_meta.items()}
    assert texts["look"] == "the two looks · workspace · the pick is" \
                            " remembered"
    assert texts["firewall"] == "on/off · its modes · per-program decisions"
    assert texts["alerts"] == "snooze 30 minutes · per-lane switches ·" \
                            " master silence"
    for key, text in texts.items():
        assert text.strip(), key


def test_trust_list_counts_are_real_not_invented(win):
    trust = win.trust
    sites = len(trust.allow) + len(trust.block)
    programs = len(trust.apps_allow)
    assert win._index_meta_text("sites") == (
        f"{sites} on file · the firewall consults them first")
    assert win._index_meta_text("programs") == (
        f"{programs} on file · decided by a prompt you answered")


def test_counts_update_when_the_store_changes(win):
    before = win._index_meta_text("programs")
    win.trust.apps_allow.add("depth-test-sentinel/probe")
    win._refresh_apps()
    after = win._index_meta_text("programs")
    try:
        assert int(after.split()[0]) == int(before.split()[0]) + 1
    finally:
        win.trust.apps_allow.discard("depth-test-sentinel/probe")
        win._refresh_apps()


def test_every_pane_carries_a_related_footer(win):
    stack = win._settings_stack
    for key in PANES:
        pane = stack.get_child_by_name(key)
        footers = [c for c in pane.observe_children()
                   if "gw-related" in c.get_css_classes()]
        assert len(footers) == 1, key
        opens = []
        for child in footers[0].observe_children():
            for w in child.observe_children():
                if isinstance(w, Gtk.Button):
                    opens.append(w.get_label())
        assert "Open" in opens, key


def test_firewall_footer_says_the_approved_words(win):
    pane = win._settings_stack.get_child_by_name("firewall")
    wheres, whats = [], []
    for child in pane.observe_children():
        if "gw-related" not in child.get_css_classes():
            continue
        for row in child.observe_children():
            labels = list(row.observe_children())
            labels = [w for w in labels if isinstance(w, Gtk.Label)]
            for lab in labels:
                if "gw-rel-where" in lab.get_css_classes():
                    wheres.append(lab.get_text())
                elif "gw-rel-what" in lab.get_css_classes():
                    whats.append(lab.get_text())
    assert wheres == ["Connections", "Notifications", "Protections",
                      "Logs"]


def test_footer_open_moves_inside_settings(win):
    win._show("settings")
    pump()
    win._settings_open(None, "sites")
    pump()
    assert win._settings_stack.get_visible_child_name() == "sites"
    picked = win._settings_index.get_selected_row()._key
    assert picked == "sites"


def test_footer_open_moves_across_pages(win):
    win._settings_open(None, "logs")
    pump()
    assert win.stack.get_visible_child_name() == "logs"
    win._show("settings")
    pump()