"""Help = he1 (owner pick, rebuild round 2 task 12): the tour + digests.

The page leads with "Show me around": the Start-the-tour button walks
every rail page in RAIL order, pulsing each page's declared entry dock
group (guided's PAGE_ENTRY map), ~1.2 s a page, and it is skippable. It
auto-runs once on first launch (the settings file's "tour_done" flag,
default ON, written when the tour completes or stops). The doc digests
the assistant reads are listed with Read buttons, and the About card
names the version and the suite it carries.
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

from ui import guided  # noqa: E402
from tools.build_digests import DIGESTS, DIGEST_TOOLS  # noqa: E402


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
    os.environ["GREYWATCH_DATA_DIR"] = tempfile.mkdtemp(prefix="gw-he1-")
    w = MainWindow()
    w.present()
    pump(30)
    w._show("help")
    pump(10)
    yield w
    w.destroy()
    if old is None:
        os.environ.pop("GREYWATCH_DATA_DIR", None)
    else:
        os.environ["GREYWATCH_DATA_DIR"] = old


def _walk(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def test_show_me_around_is_the_first_card(win):
    pane = win._help_stack.get_child_by_name("start")
    buttons = [b for b in _walk(pane) if isinstance(b, Gtk.Button)]
    starts = [b for b in buttons if (b.get_label() or "") == "Start the tour"]
    assert starts and starts[0].get_sensitive()
    # the card leads the pane: the tour card is the pane's first card
    cards = [c for c in pane.observe_children()
             if "gw-card" in c.get_css_classes()]
    texts = [l.get_text() for l in _walk(cards[0])
             if isinstance(l, Gtk.Label) and l.get_text()]
    assert any("Show me around" in t for t in texts)


def test_tour_order_is_the_rail_order(win):
    pages = win.tour_pages()
    from ui import shell
    assert pages == ("overview",) + tuple(shell.RAIL_KEYS)


def test_the_tour_walks_every_page_and_pulses_its_entry(
        win, monkeypatch, tmp_path):
    sealed = tmp_path / "settings.json"
    monkeypatch.setattr(guided, "SETTINGS_PATH", sealed)
    visited, pulses = [], []
    real_nav, real_pulse = guided.navigate, guided.pulse

    def spy_nav(w, key):
        visited.append(key)
        real_nav(w, key)

    def spy_pulse(target, win=None):
        pulses.append(target.get_text() if hasattr(target, "get_text")
                      else str(target))
        return True        # record-only: the walk's own beat is enough

    guided.navigate = spy_nav
    guided.pulse = spy_pulse
    try:
        win._tour_start()
        assert win._tour is not None
        guard = 0
        while win._tour is not None and guard < 40:
            win._tour_step()
            guard += 1
            pump(10)
    finally:
        guided.navigate = real_nav
        guided.pulse = real_pulse
        if win._tour is not None:
            win._tour_end(False)
    assert tuple(visited) == win.tour_pages()
    # each walked page pulsed its declared dock entry group; a rail key
    # that folded into another page (logs -> auditlog) greets the entry
    # the resolved page declares
    from ui.window import _LEGACY_PAGE
    resolved = [_LEGACY_PAGE.get(p, p) for p in visited]
    entries = [guided.PAGE_ENTRY[k] for k in resolved
               if k in guided.PAGE_ENTRY]
    assert pulses == entries                     # in rail order
    # completion writes the one-time flag
    cfg = json.loads(sealed.read_text())
    assert cfg["tour_done"] is True
    assert win._tour is None
    # the stop control is gone when the tour is over
    assert win._tour_stop_btn is None


def test_the_tour_is_skippable(win, monkeypatch, tmp_path):
    sealed = tmp_path / "settings.json"
    monkeypatch.setattr(guided, "SETTINGS_PATH", sealed)
    real_nav = guided.navigate
    guided.navigate = lambda w, key: real_nav(w, key)
    try:
        win._tour_start()
        win._tour_step()
        pump(10)
        assert win.tour_position() >= 0
        win._tour_end(False)                     # the Stop button's path
        pump(10)
    finally:
        guided.navigate = real_nav
        if win._tour is not None:
            win._tour_end(False)
    assert win._tour is None
    cfg = json.loads(sealed.read_text())
    assert cfg["tour_done"] is True              # stopping also marks it


def test_the_tour_autoruns_on_first_launch(win, monkeypatch, tmp_path):
    sealed = tmp_path / "settings.json"
    monkeypatch.setattr(guided, "SETTINGS_PATH", sealed)
    monkeypatch.delenv("GREYWATCH_XVFB", raising=False)
    monkeypatch.delenv("GREYWATCH_TEST_DISPLAY", raising=False)
    real_nav = guided.navigate
    guided.navigate = lambda w, key: real_nav(w, key)
    try:
        assert sealed.exists() is False or "tour_done" not in \
            json.loads(sealed.read_text() or "{}")
        win._tour_autorun()
        assert win._tour is not None             # first boot: it walks
        win._tour_end(False)
        # a machine that already took it never gets walked again
        cfg = {"tour_done": True}
        sealed.write_text(json.dumps(cfg))
        win._tour_autorun()
        assert win._tour is None
    finally:
        guided.navigate = real_nav
        if win._tour is not None:
            win._tour_end(False)


def test_doc_digests_listed_with_read_buttons(win):
    pane = win._help_stack.get_child_by_name("docs")
    buttons = [b for b in _walk(pane) if isinstance(b, Gtk.Button)
               and (b.get_label() or "") == "Read"]
    names = [p.stem for p in sorted(DIGESTS.glob("*.md"))]
    assert "Read" in [b.get_label() for b in buttons]
    assert len(buttons) >= len(DIGEST_TOOLS)
    # every digest row names its file and says what it is
    texts = [l.get_text() for l in _walk(pane) if isinstance(l, Gtk.Label)]
    joined = " | ".join(texts)
    for name in names:
        assert name in joined, name


def test_read_opens_an_honest_in_app_viewer(win):
    path = DIGESTS / "psad.md"
    win._on_read_digest(None, path)
    pump(10)
    dlg = win._digest_viewer
    assert dlg is not None and dlg.get_visible()
    # the file's own words are in there, scrolling inside its own pane
    textview = [w for w in _walk(dlg) if isinstance(w, Gtk.TextView)]
    assert textview
    head = path.read_text(encoding="utf-8").splitlines()[0].lstrip("# ")
    buf = textview[0].get_buffer()
    assert head in buf.get_text(buf.get_start_iter(), buf.get_end_iter(),
                                False)
    dlg.destroy()
    win._digest_viewer = None


def test_about_card_names_the_version_and_the_suite(win):
    pane = win._help_stack.get_child_by_name("about")
    texts = [l.get_text() for l in _walk(pane) if isinstance(l, Gtk.Label)]
    joined = " | ".join(texts)
    assert win._version() in joined
    assert f"{len(win.by_name)} protections" in joined


def test_help_dock_carries_the_about_group(win):
    win._show("help")
    pump(10)
    assert "About" in win.dock.group_titles()
    # the brain state line is honest about what runs
    pane = win._help_stack.get_child_by_name("about")
    texts = [l.get_text() for l in _walk(pane) if isinstance(l, Gtk.Label)]
    assert any("heuristics on" in t.lower() and "GPU model off" in t
               for t in texts)
