"""Rebuild Phase 3: the Overview and Services pages, two-lane-tested.

The amendment's hard line: a console page's feed never offers tool
lifecycle controls, and the services page never offers threat controls.
Both pages read the daemon's published digest and nothing else.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi_required = pytest.importorskip("gi")
gi_required.require_version("Gtk", "4.0")

from gi.repository import Gtk  # noqa: E402

import greywatch_daemon as dm  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "DATA_DIR", tmp_path)
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    return tmp_path


def _walk(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def _buttons(root):
    return [w for w in _walk(root) if isinstance(w, Gtk.Button)
            and w.get_sensitive()]


def _labels(root):
    return [str(b.get_label() or "") for b in _buttons(root)]


_SNAP = {
    "tools": {f"tool{i}": {"state": "GREEN" if i % 2 else "RED",
                           "installed": True} for i in range(10)},
    "defense": {"blocked": [{"ip": "203.0.113.9", "ts": ""}]},
    "pending_list": [
        {"id": "responderd:q", "source": "responderd", "kind": "question",
         "title": "quarantine ask", "detail": "", "ts": "",
         "options": [{"id": "keep", "helper": "keep-quarantine"}],
         "spec": {"id": "responderd:q", "question": "Keep it?",
                  "options": [{"id": "keep", "helper": "keep-quarantine"}]}},
        {"id": "hunter:adv", "source": "browser-watch", "kind": "advisory",
         "title": "scan finished with findings", "detail": "", "ts": "",
         "options": [{"id": "note", "label": "Noted"}],
         "spec": {"id": "hunter:adv", "subject": "scan finished",
                  "options": [{"id": "note", "label": "Noted"}]}},
    ],
    "recent": [
        {"ts": "2026-11-06T07:00:00+00:00", "from_tool": "responderd",
         "severity": "CRITICAL", "text": "quarantine: (sha256:aa) evil.bin",
         "interaction": {"id": "responderd:aa",
                         "question": "keep it?",
                         "options": [{"id": "keep",
                                      "helper": "keep-quarantine",
                                      "args": ["/tmp/x"]}]}},
        {"ts": "2026-11-06T07:01:00+00:00", "from_tool": "clamav",
         "severity": "INFO", "text": "check-in: idle"},  # tool lane
    ],
}


class _FakeWin:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.registry = [{"name": f"tool{i}", "unit": f"t{i}.service"}
                         for i in range(10)]
        self.by_name = {t["name"]: t for t in self.registry}
        self._snap = dict(_SNAP)
        self._snap["components"] = {
            "tool3": {"state": "tripped", "restarts": 2}}

    def _get_status(self):
        return dict(self._snap)

    def _get_recent(self):
        return list(self._snap["recent"])

    def _run_log_option(self, _btn, opt):
        self._routed = dict(opt)

    def _control_requested(self, name):
        self._controlled = name

    def _ask_assistant(self, *_a, **_k):
        pass

    def _assistant_intent(self, *_a, **_k):
        pass

    chat_llm = None

    def _show_folder(self, *_a, **_k):
        pass

    def _show(self, *_a, **_k):
        pass

    def _rescan_tool(self, *_a, **_k):
        pass

    def _tools_picked(self, *_a, **_k):
        pass

    def _details_selected(self, *_a, **_k):
        pass

    def refresh(self, *_a, **_k):
        pass

    def _show_filter(self, *_a, **_k):
        pass


# ---- Overview page --------------------------------------------------------
class TestOverview:
    def _page(self, store, monkeypatch):
        from ui.console import OverviewPage
        monkeypatch.setattr("ui.defense.cve_rows", lambda _dd: [1, 2])
        win = _FakeWin(store)
        page = OverviewPage(win=win)
        return page, win

    def test_ribbon_counts_the_published_digest(self, store, monkeypatch):
        page, _win = self._page(store, monkeypatch)
        page.refresh(page._win._get_status())
        values = {cap: card._value.get_text()
                  for cap, card in page._stats.items()}
        assert values == {"blocked": "1", "tools online": "5 / 10",
                          "CVE rules": "2", "pending decisions": "2"}

    def test_feed_splits_the_two_lanes(self, store, monkeypatch):
        page, _win = self._page(store, monkeypatch)
        page.refresh(page._win._get_status())
        assert len(list(page._feed["threat"]._rows)) == 1
        assert len(list(page._feed["tool"]._rows)) == 1

    def test_threat_row_click_paints_lane_truth_and_controls(
            self, store, monkeypatch):
        page, win = self._page(store, monkeypatch)
        page.refresh(page._win._get_status())
        row = list(page._feed["threat"]._rows)[0]
        row.emit("clicked")
        assert page._detail.get_visible()
        labels = _labels(page._detail)
        assert any("delete permanently" in t.lower() or "keep" in t.lower()
                   for t in labels)
        # tool rows never grow lifecycle controls
        page._feed["tool"].picked = None
        tool_row = list(page._feed["tool"]._rows)[0]
        tool_row.emit("clicked")
        labels = _labels(page._detail)
        assert labels == ["Copy details"], labels

    def test_tool_lane_row_never_carries_start_controls(
            self, store, monkeypatch):
        page, _win = self._page(store, monkeypatch)
        page.refresh(page._win._get_status())
        labels = _labels(page)
        assert not any(t.lower().startswith(("run ", "restart ", "stop "))
                       for t in labels)

    def test_advisory_strip_only_advisories(self, store, monkeypatch):
        page, _win = self._page(store, monkeypatch)
        page.refresh(page._win._get_status())
        # the strip renders the advisory's card; the question's helper
        # button must NOT live here (its route is the gate and the drawer)
        assert any("gw-card" in c.get_css_classes() for c in
                   _walk(page._advisories))
        assert "keep" not in [t.lower() for t in _labels(page._advisories)]

    def test_gate_rows_are_the_published_list(self, store, monkeypatch):
        page, _win = self._page(store, monkeypatch)
        (store / "status.json").write_text(json.dumps(_SNAP))
        page.refresh(page._win._get_status())
        labels = _labels(page._gate)
        assert any("keep" in t.lower() for t in labels)


# ---- Services page --------------------------------------------------------
class TestServices:
    def _page(self, store):
        from ui.toolhealth import ServicesPage
        return ServicesPage(win=_FakeWin(store))

    def test_scan_actions_lead_the_page(self, store):
        page = self._page(store)
        labels = [t.lower() for t in _labels(page)]
        assert any("run clamav" in t for t in labels)

    def test_healer_rows_appear_only_for_failed_components(self, store):
        page = self._page(store)
        page.refresh()
        labels = _labels(page._healer)
        assert any("restart tool3" in t.lower() for t in labels)

    def test_restart_suggestion_uses_helper_and_unit_order(self, store):
        page = self._page(store)
        page.refresh()
        out = {}
        page._win._routed = None
        page._win._run_log_option = lambda _b, opt: out.update(opt)
        page._restart_clicked(None, "tool3")
        assert out == {"id": "restart", "label": "Restart tool3",
                       "tone": "primary", "helper": "tool-control",
                       "args": ["restart", "t3.service"]}

    def test_no_threat_controls_ever_on_services(self, store):
        page = self._page(store)
        page.refresh()
        banned = ("quarantine", "lift", "delete perman", "keep block")
        text = " ".join(_labels(page)).lower()
        assert not any(b in text for b in banned), text
