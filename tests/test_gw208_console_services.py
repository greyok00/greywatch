"""Rebuild Phase 3: the Overview and Services pages, two-lane-tested.

The amendment's hard line (resolve-everything wording): a console
page's feed carries each row's own real actions - a tool row can run
its scan again and restart its service, but never a threat control -
and the services page never offers threat controls.
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


# ---- Overview page (rebuild round 2, task 5: variant-3 re-root) -----------
class TestOverview:
    def _page(self, store, monkeypatch):
        from ui.console import OverviewPage
        win = _FakeWin(store)
        page = OverviewPage(win=win)
        return page, win

    def test_verdict_counts_the_published_digest(self, store, monkeypatch):
        page, _win = self._page(store, monkeypatch)
        page.refresh(page._win._get_status())
        texts = [str(c.get_text() or "") for c in page._chips]
        assert any("tools 5 / 10" == t for t in texts)
        assert any(t.startswith("decisions 2") for t in texts)
        assert "blocked 1" in texts

    def test_needs_you_are_the_published_list(self, store, monkeypatch):
        page, _win = self._page(store, monkeypatch)
        (store / "status.json").write_text(json.dumps(_SNAP))
        page.refresh(page._win._get_status())
        labels = _labels(page.needs_you_card)
        assert any("keep" in t.lower() for t in labels)

    def test_needs_you_shows_only_the_question(self, store, monkeypatch):
        """The advisory carries no helper, so it is not an item with
        buttons: the needs-you section never renders it as one."""
        page, _win = self._page(store, monkeypatch)
        (store / "status.json").write_text(json.dumps(_SNAP))
        page.refresh(page._win._get_status())
        assert len(page.action_buttons()) == 1   # the quarantine keep only

    def test_needs_you_empty_hides_the_whole_section(self, store,
                                                     monkeypatch):
        """The bug-9 law on the variant-3 page: no rows, no section, no
        title; the empty-looking card never ships."""
        page, _win = self._page(store, monkeypatch)
        page.refresh(page._win._get_status())   # nothing published on disk
        assert not page.needs_you_box.get_visible()

    def test_group_cards_handoff_with_stable_row_keys(self, store,
                                                      monkeypatch):
        """The dedupe identity is the stable string key, never a widget;
        the fake window has no router, so the cards fall through to the
        window's own show (click-to-jump always works)."""
        page, _win = self._page(store, monkeypatch)
        shown = []
        page._win._show = lambda key: shown.append(key)
        for key in ("care", "defense", "system"):
            page.group_cards[key].emit("clicked")
        assert shown == ["tools", "defense", "logs"]


# ---- Services page --------------------------------------------------------
class TestServices:
    def _page(self, store):
        from ui.toolhealth import ServicesPage
        return ServicesPage(win=_FakeWin(store))

    def test_scan_actions_lead_the_scans_page(self, store):
        """Task 10 re-root: the scan actions are the Scans page's mode
        cards now; Services stays lifecycle-only (one subject per page)."""
        from ui.scanview import ScansPage
        page = ScansPage(win=_FakeWin(store))
        labels = [t.lower() for t in _labels(page)]
        assert any("run full suite" in t for t in labels)
        svc_labels = [t.lower() for t in _labels(self._page(store))]
        assert not any("run " in t and "restart" not in t
                       for t in svc_labels)
        assert "quarantine" not in " ".join(svc_labels)

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
