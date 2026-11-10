"""Protections = p1 (owner pick, rebuild round 2 task 10).

The page answers "between this box and threats, what is pending": the
strip with the Run-protections-now lane, PATCH ADVISORIES - the CVE wall
moved OFF the Firewall page into here, severity + affected tool per row
and the coverage line from the patch-the-planet machinery - and the
recent protection-run cards below. The dock carries the advisory filter
and the Runs facts. No tool grid, and the page never invents a patch
lane: disabled controls say why.
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


def _walk(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk(c))
        c = c.get_next_sibling()
    return out


def _buttons(root):
    return [w for w in _walk(root) if isinstance(w, Gtk.Button)]


def _texts(root):
    return [str(w.get_text() or "") for w in _walk(root)
            if isinstance(w, Gtk.Label)]


class _FakeWin:
    def __init__(self, data_dir):
        self.data_dir = pathlib.Path(data_dir)
        self.registry = [
            {"name": "clamav", "unit": "clamav-daemon.service",
             "label": "Antivirus"},
            {"name": "rkhunter", "unit": "", "label": "Rootkit scanner"}]
        self.ran = []
        self.asked = []

    def _run_protection(self, name):
        self.ran.append(name)

    def _ask_assistant(self, *_a, **_k):
        pass

    def _show(self, *_a, **_k):
        pass

    def _get_status(self):
        return {}


_CACHE = {
    "entries": [
        {"id": "CVE-2026-1001", "score": 8.5, "severity": "HIGH",
         "tool": "clamav", "summary": "a flaw in the updater",
         "modified": "2026-11-09"},
        {"id": "CVE-2026-1002", "score": 9.6, "severity": "CRITICAL",
         "tool": "psad", "summary": "a flaw in the chain",
         "modified": "2026-11-09"},
    ]}


@pytest.fixture
def page(tmp_path):
    from cverules import active_rules
    (tmp_path / "cve-cache.json").write_text(json.dumps(_CACHE))
    rules = active_rules(tmp_path / "cve-cache.json")
    assert len(rules) == 2
    from ui.protectdesk import ProtectionsPage
    win = _FakeWin(tmp_path)
    return ProtectionsPage(win=win), win


# ---- the strip ------------------------------------------------------------
def test_strip_names_the_lane_in_plain_words(page):
    p, _win = page
    joined = " ".join(_texts(p))
    assert "Between this box and threats" in joined


def test_run_protections_now_routes_the_existing_lane(page):
    p, win = page
    run = [b for b in _buttons(p) if b.get_sensitive()
           and "Run protections now" in str(b.get_label() or "")]
    assert run, "the strip carries the one protections run button"
    run[0].emit("clicked")
    assert win.ran == ["full"]      # the existing _run_protection lane


# ---- the advisory wall ------------------------------------------------------
def test_the_wall_renders_severity_and_tool_per_row(page):
    p, _win = page
    p.refresh()
    text = " ".join(_texts(p))
    assert "PATCH ADVISORIES" in text
    assert "CVE-2026-1001" in text and "CVE-2026-1002" in text
    assert "the antivirus" in text          # cverules' own tool label
    assert "CRITICAL" in text or "HIGH" in text


def test_patch_buttons_are_disabled_with_the_honest_reason(page):
    """No apt lane exists on this box: a row's Patch sits disabled and
    says so - never a button that pretends to patch."""
    p, _win = page
    p.refresh()
    patches = [b for b in _buttons(p)
               if str(b.get_label() or "") == "Patch"]
    assert len(patches) == 2
    assert all(not b.get_sensitive() for b in patches)
    tip = str(patches[0].get_tooltip_text() or "").lower()
    assert "no patch lane" in tip


def test_refresh_advisories_uses_the_update_lane(page):
    """The one update lane that exists (the CVE cache refresh) is the
    working button; the rows' honesty is untouched by it."""
    import inspect
    from ui import protectdesk
    buttons = [b for b in _buttons(page[0])
               if b.get_sensitive() and "Refresh advisories" in
               str(b.get_label() or "")]
    assert buttons
    src = inspect.getsource(protectdesk.ProtectionsPage)
    assert "refresh_cve" in src


def test_wall_is_honest_when_the_cache_is_missing(tmp_path):
    from ui.protectdesk import ProtectionsPage
    p = ProtectionsPage(win=_FakeWin(tmp_path))
    p.refresh()
    text = " ".join(_texts(p)).lower()
    assert "never been fetched" in text or "no advisory cache" in text


def test_wall_says_calm_when_nothing_is_active(tmp_path):
    (tmp_path / "cve-cache.json").write_text(json.dumps({"entries": []}))
    from ui.protectdesk import ProtectionsPage
    p = ProtectionsPage(win=_FakeWin(tmp_path))
    p.refresh()
    text = " ".join(_texts(p)).lower()
    assert "no active advisory" in text


# ---- the coverage line ------------------------------------------------------
def test_coverage_line_reads_the_watch_machinery(tmp_path, monkeypatch):
    (tmp_path / "cve-cache.json").write_text(json.dumps(
        {"entries": [{"id": "CVE-2026-2001", "score": 9.0, "severity":
                      "HIGH", "tool": "curl", "summary": "s"}]}))
    (tmp_path / "ptp-watch.json").write_text(json.dumps(
        {"ts": "2026-11-09T18:00:00+00:00",
         "projects": [{"project": "curl", "findings": 2, "high": 1,
                       "packages": ["curl"]}]}))
    from ui.protectdesk import ProtectionsPage
    p = ProtectionsPage(win=_FakeWin(tmp_path))
    p.refresh()
    text = " ".join(_texts(p))
    assert "Patch the Planet" in text
    assert "100%" in text
    assert "watchlist read" in text


def test_coverage_honest_when_the_watch_has_never_run(tmp_path):
    (tmp_path / "cve-cache.json").write_text(json.dumps(_CACHE))
    from ui.protectdesk import ProtectionsPage
    p = ProtectionsPage(win=_FakeWin(tmp_path))
    p.refresh()
    text = " ".join(_texts(p)).lower()
    assert "watchlist has never been read" in text


# ---- the recent protection-run cards ---------------------------------------
def test_recent_run_cards_render_the_run_documents(page):
    p, _win = page
    (p._win.data_dir / "scans").mkdir(exist_ok=True)
    (p._win.data_dir / "scans" / "20261109T120000-abcd.json").write_text(
        json.dumps({"scan_id": "20261109T120000-abcd", "key": "full",
                    "state": "done", "real_findings": 2,
                    "started_at": "2026-11-09T12:00:00+00:00",
                    "ended_at": "2026-11-09T12:06:00+00:00",
                    "scanners": {}}))
    p.refresh()
    text = " ".join(_texts(p))
    assert "RECENT RUNS" in text
    assert "Full scan" in text


def test_run_cards_admit_a_running_session(page):
    p, _win = page
    (p._win.data_dir / "scan-live.json").write_text(json.dumps(
        {"scan_id": "20261109T130000-beef", "key": "yara-tmp-scan",
         "state": "running", "update": "2026-11-09T13:00:00+00:00",
         "real_findings": 0, "scanners": {}}))
    p.refresh()
    text = " ".join(_texts(p))
    assert "scanning now" in text.lower()


# ---- the dock ---------------------------------------------------------------
def test_dock_groups_lead_with_the_advisory_filter(page):
    p, _win = page
    groups = p.dock_groups()
    assert groups[0][0] == "Advisories"
    names = [g[0] for g in groups]
    assert "Runs" in names


def test_advisory_filter_counts_and_filters(page):
    p, _win = page
    p.refresh()
    assert p.advisory_count() == 2
    p.set_severity_filter("CRITICAL")
    assert p.advisory_count() == 1
    p.set_severity_filter(None)
    p.set_tool_filter("clamav")
    assert p.advisory_count() == 1
    p.set_tool_filter(None)
    p.set_fixable_filter(True)
    # fixable = the tool the flaw touches is on the Patch the Planet map
    assert p.advisory_count() == 0
    (p._win.data_dir / "ptp-watch.json").write_text(json.dumps(
        {"ts": "2026-11-09T18:00:00+00:00",
         "projects": [{"project": "clamav", "packages": ["clamav"]}]}))
    assert p.advisory_count() == 1


def test_runs_group_names_the_real_units_and_stays_honest(page):
    p, _win = page
    groups = p.dock_groups()
    runs = dict(groups)["Runs"]
    widgets = [w for w in runs if isinstance(w, Gtk.Button)]
    disabled = [b for b in widgets if not b.get_sensitive()]
    tips = " ".join(str(b.get_tooltip_text() or "") for b in disabled)
    assert "greywatch-cve.timer" in tips


def test_guided_entry_is_advisories():
    from ui.guided import PAGE_ENTRY
    assert PAGE_ENTRY.get("protect") == "Advisories"


def test_no_tool_grid_on_protections(page):
    p, _win = page
    from ui.toolsdesk import ToolsDesk
    assert not any(isinstance(w, ToolsDesk) for w in _walk(p))


def test_window_refresh_feeds_the_protections_page():
    import inspect
    from ui import window
    src = inspect.getsource(window.MainWindow.refresh)
    assert 'shown == "protect"' in src
    assert "protect_page.refresh" in src


def test_builder_returns_the_page_no_whole_page_scroller():
    import inspect
    from ui import window
    src = inspect.getsource(window.MainWindow._protect_view)
    assert "ScrolledWindow" not in src
    assert "ProtectionsPage" in src
