"""Pins for the Tools page: one row per lane on the daemon's snapshot,
honest when the snapshot is stale, down or fresh."""

from __future__ import annotations

import json

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

import pytest

from tests.test_ui_v4 import _ShellStub, _all_texts
from tests.test_ui_network import _tree_rows


def _snap(tmp_path, stamp: str, tools: dict | None = None):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "status.json").write_text(json.dumps({
        "updated": stamp,
        "tools": tools or {
            "clamav": {"label": "Virus Scan", "state": "GREEN",
                       "last_event": "2026-11-15T08:20:03+00:00",
                       "unit_state": "active"},
            "tetragon": {"label": "Kernel Watch", "state": "YELLOW",
                         "last_event": None, "unit_state": "inactive"},
        },
        "defense": {"blocked": []}}))
    return d


def _build(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(tmp_path)))
    import ui.tools as tools
    page = tools.build(_ShellStub())
    return tools, page


@pytest.fixture
def tools_mod(monkeypatch, tmp_path):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(
        tmp_path, "2026-11-15T08:00:00+00:00")))
    import ui.tools as tools
    return tools


def test_fresh_snapshot_rows_in_daemon_order(tools_mod, monkeypatch,
                                             tmp_path):
    stamp = "2026-11-15T08:00:00+00:00"
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(tmp_path, stamp)))
    page = tools_mod.build(_ShellStub())
    rows = _tree_rows(page)
    assert [r[0] for r in rows] == ["Virus Scan", "Kernel Watch"]
    assert rows[0][1] == "Live"
    assert "active" in rows[0][2]
    assert rows[1][3] == "No notable event yet"


def test_stale_snapshot_says_the_service_may_be_paused(tools_mod,
                                                       monkeypatch,
                                                       tmp_path):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(tmp_path, stamp=(
        "2026-11-14T08:00:00+00:00"))))
    page = tools_mod.build(_ShellStub())
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page))).lower()
    assert "the service may be paused" in texts


def test_empty_snapshot_names_its_waiting_state(tools_mod, monkeypatch,
                                                tmp_path):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "status.json").write_text(json.dumps(
        {"updated": None, "tools": {}}))
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(d))
    page = tools_mod.build(_ShellStub())
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page))).lower()
    assert "waiting" in texts
    assert "no snapshot yet" in texts


def test_red_lane_drives_the_page_mark(tools_mod, monkeypatch, tmp_path):
    tools = {
        "responderd": {"label": "Auto-responder", "state": "RED",
                       "last_event": None, "unit_state": "failed"}}
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(
        tmp_path, "2026-11-15T08:00:00+00:00", tools)))
    page = tools_mod.build(_ShellStub())
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page))).lower()
    assert "a lane is down" in texts


def test_tool_states_print_words_not_tokens(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "status.json").write_text(json.dumps({
        "updated": "2026-11-19T12:00:00+00:00",
        "tools": {"psad": {"label": "Port Scan Watch", "state": "RED"}}}))
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(d))
    from ui import tools
    page = tools.build(_ShellStub())
    text = " ".join(" ".join(r) for r in _tree_rows(page))
    assert "Down" in text
    assert "RED" not in text


class _Path:
    def __init__(self, idx):
        self._idx = idx

    def get_indices(self):
        return [self._idx]


class _View:
    pass


class _DeskWindow(_ShellStub):
    def __init__(self):
        self.opened = None

    def open_tool_page(self, label, ids, digest):
        self.opened = (label, ids, digest)


def _treeview(w):
    if isinstance(w, Gtk.TreeView):
        return w
    child = w.get_first_child() if hasattr(w, "get_first_child") else None
    while child is not None:
        found = _treeview(child)
        if found is not None:
            return found
        child = child.get_next_sibling()
    return None


def test_row_activation_opens_the_desk(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(
        tmp_path, "2026-11-15T08:00:00+00:00")))
    from ui import tools
    window = _DeskWindow()
    page = tools.build(window)
    view = _treeview(getattr(page, "_gw_body", page))
    assert view is not None
    view.emit("row-activated", Gtk.TreePath.new_from_indices([0]), None)
    assert window.opened == ("Virus Scan", ("clamav", "freshclam"), "clamav")


def test_row_activation_with_an_unknown_tool_is_harmless(tmp_path,
                                                        monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(
        tmp_path, "2026-11-15T08:00:00+00:00")))
    from ui import tools
    window = _DeskWindow()
    tools._open_row(_View(), _Path(0), None, window, ["not-a-tool"])
    assert window.opened is None
    assert "no desk yet" in getattr(window, "last_note", "")


def test_lane_table_has_no_inner_vertical_scroller(tmp_path, monkeypatch):
    """The page scroller owns vertical movement; the lane table must not
    clip its last row inside a second scroller (seen live 2026-11-20)."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(
        tmp_path, "2026-11-15T08:00:00+00:00")))
    from ui import tools
    page = tools.build(_ShellStub())
    view = _treeview(getattr(page, "_gw_body", page))
    assert view is not None
    parent = view.get_parent()
    assert parent is not None
    _h, vertical = parent.get_policy()
    assert int(vertical) == int(Gtk.PolicyType.NEVER)
    model = view.get_model()
    assert model.iter_n_children(None) == 2


def test_built_scroller_fills_the_page(tmp_path, monkeypatch):
    """A lazily shown page must fill the window. The scroller and the
    body both expand, so the page never collapses to its minimum."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(
        tmp_path, "2026-11-15T08:00:00+00:00")))
    from ui import tools
    page = tools.build(_ShellStub())
    assert page.get_vexpand() is True
    assert page.get_hexpand() is True
    assert page._gw_body.get_vexpand() is True


def test_attention_pill_is_a_button_that_opens_the_yellow_desk(tmp_path,
                                                               monkeypatch):
    """GW-10: the Tools header pill navigates to the first YELLOW
    lane's desk instead of being paint that looks clickable."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap(
        tmp_path, "2026-11-15T08:00:00+00:00")))
    from ui import tools
    window = _DeskWindow()
    page = tools.build(window)
    body = getattr(page, "_gw_body", page)

    pills = []

    def walk(w):
        if isinstance(w, Gtk.Button) and w.has_css_class("gw-pill-link"):
            pills.append(w)
        child = w.get_first_child()
        while child is not None:
            walk(child)
            child = child.get_next_sibling()

    walk(body)
    assert pills, "no clickable pill on the Tools page"
    pills[0].emit("clicked")
    # the seeded snapshot's first YELLOW lane is tetragon -> Kernel Watch
    assert window.opened == ("Kernel Watch", ("tetragon",), "tetragon")


def test_all_green_page_has_no_navigation_pill(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(_snap_all_green(
        tmp_path, "2026-11-15T08:00:00+00:00")))
    from ui import tools
    page = tools.build(_DeskWindow())
    body = getattr(page, "_gw_body", page)
    pills = []

    def walk(w):
        if isinstance(w, Gtk.Button) and w.has_css_class("gw-pill-link"):
            pills.append(w)
        child = w.get_first_child()
        while child is not None:
            walk(child)
            child = child.get_next_sibling()

    walk(body)
    assert pills == []


def _snap_all_green(tmp_path, stamp):
    import json
    d = tmp_path / "state"
    d.mkdir(parents=True, exist_ok=True)
    (d / "status.json").write_text(json.dumps({
        "updated": stamp,
        "tools": {"clamav": {"label": "Virus & threat protection",
                             "state": "GREEN", "unit_state": "active",
                             "note": "ready", "last_event": None}}}))
    return d
