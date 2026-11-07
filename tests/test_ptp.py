"""The Patch the Planet map as a GreyWatch watchlist (owner 2026-11-06).

The program's public dashboard is the critical vulnerability map. Pins:
the parser reads the real dashboard table shape, the map refresh falls
back to the shipped snapshot instead of vanishing, coverage matches
installed packages without inventing any, announcements fire once per
project across restarts, a missing watch file reads as "never fetched"
(never as safe), and the Defense page renders the watch rows it was
handed - and stays quiet when the map never arrived.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ptp  # noqa: E402
from ui import defense  # noqa: E402

# The dashboard embeds its findings as <tr data-project> rows; this
# fixture carries the real attribute order, two projects, four
# severities, and one junk row the parser must skip.
HTML = """
<table>
  <tr><td>project</td><td>sev</td><td>Issue</td></tr>
  <tr data-project="curl"><td>curl</td><td>high</td>
      <td>Tiny header lets a parser walk off </td><td>Issue</td></tr>
  <tr data-project="curl"><td>curl</td><td>medium</td>
      <td>Slow write keeps a socket half open</td><td>PR</td></tr>
  <tr data-project="sqlite"><td>sqlite</td><td>low</td>
      <td>A WAL checkpoint races a reader</td><td>Fix</td></tr>
  <tr data-project="zlib"><td>zlib</td><td>undetermined</td>
      <td>Two-byte CRLF split a header early</td><td>Issue</td></tr>
  <tr data-project=""><td></td><td>info</td><td>placeholder</td></tr>
</table>
"""


# ---- the parser -----------------------------------------------------------
def test_parse_dashboard_reads_the_real_row_shape():
    rows = ptp.parse_dashboard(HTML)
    assert len(rows) == 4            # the header and empty rows drop out
    assert rows[0] == {"project": "curl", "severity": "high",
                       "finding": "Tiny header lets a parser walk off",
                       "status": "Issue"}
    assert {r["project"] for r in rows} == {"curl", "sqlite", "zlib"}


def test_summarize_counts_pressure_per_project():
    cov = ptp.summarize(ptp.parse_dashboard(HTML))
    assert cov["curl"] == {"project": "curl", "findings": 2, "high": 1,
                           "medium": 1, "low": 0}
    assert cov["zlib"]["findings"] == 1 and cov["zlib"]["high"] == 0


# ---- the map: refresh, snapshot fallback, load ----------------------------
def test_refresh_writes_the_map_and_falls_back_quietly(tmp_path,
                                                        monkeypatch):
    def ok(_url, _timeout=0):
        return HTML
    monkeypatch.setattr(ptp, "fetch_dashboard", ok)
    assert ptp.refresh(tmp_path) == len(ptp.parse_dashboard(HTML))
    stored = json.loads((tmp_path / "ptp-map.json").read_text())
    assert stored["rows"][0]["project"] == "curl"

    def down(_url, _timeout=0):
        return None
    monkeypatch.setattr(ptp, "fetch_dashboard", down)
    # a failed fetch leaves the good map in place
    assert ptp.refresh(tmp_path) == 0
    assert ptp.load_map(tmp_path)[0]["project"] == "curl"

    # a machine with neither refresh nor snapshot reads as nothing...
    with pytest.MonkeyPatch.context() as ctx:
        ctx.setattr(ptp, "snapshot_path",
                    lambda: (tmp_path / "none") / "absent.json")
        assert ptp.load_map(tmp_path / "none") == []
    # ...and the shipped snapshot carries the real map for installs
    # that never reached the dashboard (a dir with no runtime map)
    fresh = tmp_path / "fresh"
    rows = ptp.load_map(fresh)
    assert len(rows) >= 400
    assert rows[0]["project"] in ("gpac", "curl", "aiohttp")


# ---- coverage: installed only, never invented ------------------------------
def make_runner(deb_lines=(), pip_lines=()):
    def run(line):
        if "dpkg-query" in line:
            return 0, "\n".join(deb_lines)
        if "pip list" in line:
            return 0, "\n".join(f"{p}==9.9" for p in pip_lines)
        return 1, ""
    return run


def test_coverage_matches_installed_deb_and_pip_only(tmp_path):
    rows = ptp.parse_dashboard(HTML)
    runner = make_runner(deb_lines=["curl", "zlib1g", "sqlite3"],
                         pip_lines=[])
    cov = ptp.coverage(rows, runner)
    names = {c["project"]: c for c in cov}
    # sqlite ships as sqlite3, zlib as zlib1g; both match through the
    # alias table with their deb channel named
    assert names["sqlite"]["packages"] == ["sqlite3"]
    assert names["sqlite"]["via"] == "deb"
    assert names["zlib"]["packages"] == ["zlib1g"]
    assert "curl" in names and names["curl"]["via"] == "deb"
    # a channel that answers nothing covers nothing: no invented rows,
    # and an empty machine is an empty list, not an error
    none = ptp.coverage(rows, make_runner())
    assert none == [] or all(isinstance(c, dict) for c in none) \
        and not none


def test_coverage_sees_pip_packages_and_sorts_high_first():
    html = HTML.replace('data-project="vllm"', 'data-project="vllm"') \
        + ('<tr data-project="vllm"><td>vllm</td><td>high</td>'
           "<td>SHM capability follows a gone worker</td></tr>"
           '<tr data-project="vllm"><td>vllm</td><td>high</td>'
           "<td>Prefix cache extracts another tenant tokens</td></tr>"
           '<tr data-project="vllm"><td>vllm</td><td>medium</td>'
           "<td>Thinking budget ignores a set cap</td></tr>")
    rows = ptp.parse_dashboard(html)
    runner = make_runner(pip_lines=["vllm", "pyzmq"])
    cov = ptp.coverage(rows, runner)
    top = {c["project"]: c for c in cov}["vllm"]
    assert top["via"] == "pip" and top["findings"] == 3
    assert top["high"] == 2 and top["packages"] == ["vllm"]
    highs = [c["project"] for c in cov if c["high"]]
    assert highs[0] == "vllm"      # highest-pressure project reads first


# ---- the announcements: once per project, across restarts ------------------
def test_evaluate_announces_each_new_project_once(tmp_path):
    rows = ptp.parse_dashboard(HTML)
    runner = make_runner(deb_lines=["curl", "zlib1g", "sqlite3"])
    first = ptp.evaluate(tmp_path, runner, rows=rows)
    assert sorted(spec[2] for spec in first) == ["curl", "sqlite", "zlib"]
    curl = next(spec for spec in first if spec[2] == "curl")
    assert "HIGH" in curl[0] or curl[0] == "HIGH"
    assert "verify the installed version" in curl[1]
    assert "keeper decides" in curl[1]   # never auto-fixes
    # the ledger lands on disk, so a restart does not re-announce
    again = ptp.evaluate(tmp_path, runner, rows=rows)
    assert again == []
    assert (tmp_path / "ptp-announced.jsonl").exists()


def test_evaluate_writes_nothing_when_the_ledger_cannot_persist(
        tmp_path, monkeypatch):
    rows = ptp.parse_dashboard(HTML)
    runner = make_runner(deb_lines=["curl"])
    locked = tmp_path / "ptp-announced.jsonl"
    locked.write_text("keep\n")
    locked.chmod(0o000)
    try:
        specs = ptp.evaluate(tmp_path, runner, rows=rows)
        assert specs == []       # cannot persist seen-state: say nothing
    finally:
        locked.chmod(0o644)


# ---- the pages: never-fetched reads as never-fetched ----------------------
def test_watch_rows_none_when_no_file(tmp_path):
    assert ptp.watch_rows(tmp_path) is None
    assert defense.ptp_rows(tmp_path) is None


def test_watch_rows_passes_the_daemons_projects_through(tmp_path):
    (tmp_path / "ptp-watch.json").write_text(json.dumps(
        {"ts": "2026-11-06T21:00:00+00:00",
         "projects": [{"project": "curl", "findings": 2, "high": 1,
                       "medium": 1, "low": 0, "via": "deb",
                       "packages": ["curl"]}]}))
    rows = defense.ptp_rows(tmp_path)
    assert rows and rows[0]["project"] == "curl"


# ---- the Defense page renders the watchlist -------------------------------
def _walk_labels(host):
    from gi.repository import Gtk
    out = []

    def walk(w):
        for k in list(w) if hasattr(w, "__iter__") else []:
            if getattr(k, "get_label", None):
                out.append(str(k.get_label()))
            walk(k)
    if hasattr(host, "__iter__"):
        walk(host)
    return out


@pytest.fixture
def defense_view(monkeypatch):
    import gi
    gi.require_version("Gtk", "4.0")
    v = defense.DefenseView()
    monkeypatch.setattr(defense, "cve_rows", lambda _dd: [])
    monkeypatch.setattr(defense, "psad_status", lambda: {})
    monkeypatch.setattr(defense, "arp_status", lambda: {})
    return v


def test_defense_page_renders_watch_rows(monkeypatch, defense_view):
    v = defense_view
    monkeypatch.setattr(defense, "ptp_rows", lambda _dd: [
        {"project": "curl", "findings": 2, "high": 1, "medium": 1,
         "low": 0, "via": "deb", "packages": ["curl"]}])
    v.refresh({"defense": {}})
    text = " ".join(_walk_labels(v._armor))
    assert "Patch the Planet watchlist" in text
    assert "curl (as curl)" in text and "1 HIGH" in text
    v.unparent()


def test_defense_page_names_the_never_fetched_watch(monkeypatch,
                                                    defense_view):
    v = defense_view
    monkeypatch.setattr(defense, "ptp_rows", lambda _dd: None)
    v.refresh({"defense": {}})
    text = " ".join(_walk_labels(v._armor))
    assert "has never been read" in text
    v.unparent()


def test_defense_page_stays_quiet_without_covered_software(
        monkeypatch, defense_view):
    v = defense_view
    monkeypatch.setattr(defense, "ptp_rows", lambda _dd: [])
    v.refresh({"defense": {}})
    text = " ".join(_walk_labels(v._armor))
    # the section keeps its head and refresh channel now, but it never
    # claims coverage: no per-project rows when nothing is covered
    assert "Patch the Planet watchlist" in text          # head remains
    assert "nothing this machine runs is inside the review map" in text
    assert "(as " not in text
    v.unparent()


# ---- the UI wave: drill-down, refresh channel, badge, tile -----------------
def test_ptp_high_count_sums_only_real_watch_rows(tmp_path):
    (tmp_path / "ptp-watch.json").write_text(json.dumps(
        {"ts": "2026-11-06T21:00:00+00:00",
         "projects": [{"project": "curl", "high": 3},
                      {"project": "vllm", "high": 2}]}))
    assert defense.ptp_high_count(tmp_path) == 5
    # never fetched reads as 0: the badge counts defense news
    assert defense.ptp_high_count(tmp_path / "none") == 0


def test_watch_stamp_formats_the_last_watch_run(tmp_path):
    (tmp_path / "ptp-watch.json").write_text(
        '{"ts": "2026-11-01T21:05:00+00:00"}')
    assert "Nov 01" in defense.ptp_watch_stamp(tmp_path)
    assert defense.ptp_watch_stamp(tmp_path / "none") == ""


def test_watch_rows_render_as_buttons_opening_the_drill_down(
        monkeypatch, defense_view):
    v = defense_view
    monkeypatch.setattr(defense, "ptp_rows", lambda _dd: [
        {"project": "curl", "findings": 2, "high": 1, "medium": 1,
         "low": 0, "via": "deb", "packages": ["curl"]}])
    v.refresh({"defense": {}})
    from gi.repository import Gtk
    btns = [w for w in _walk_widgets(v._armor) if isinstance(w, Gtk.Button)]
    assert any("Show the map rows for curl" ==
               (btn.get_tooltip_text() or "") for btn in btns)
    v.unparent()


def _walk_widgets(widget):
    out = []
    c = widget.get_first_child()
    while c is not None:
        out.append(c)
        out.extend(_walk_widgets(c))
        c = c.get_next_sibling()
    return out


def test_project_findings_filters_the_freshest_map(monkeypatch,
                                                   defense_view):
    v = defense_view
    monkeypatch.setattr(defense, "ptp_load_map", lambda _p: [
        {"project": "curl", "severity": "high", "finding": "one",
         "status": "Issue"},
        {"project": "sqlite", "severity": "low", "finding": "two"}])
    rows = v._project_findings(".", "curl")
    assert len(rows) == 1 and rows[0]["finding"] == "one"
    assert v._project_findings(".", "") == []


def test_refresh_channel_runs_the_child_process(monkeypatch):
    import ui.updates as updates
    seen = {}
    def fake_run(argv, **_k):
        seen["argv"] = argv
        seen["kw"] = _k
        class R:
            returncode = 0
        R.stdout = "map refreshed: 472 findings; 3 projects covered\n"
        R.stderr = ""
        return R
    monkeypatch.setattr(updates.subprocess, "run", fake_run)
    rc, msg = updates.refresh_ptp()
    assert rc == 0 and "3 projects covered" in msg
    assert seen["argv"][1].endswith("ptp.py")


def test_watch_info_reads_the_daemons_stamp(tmp_path, monkeypatch):
    import ui.updates as updates
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    assert updates.ptp_watch_info() is None
    (tmp_path / "ptp-watch.json").write_text(
        '{"ts": "2026-11-06T21:00:00+00:00", "projects": [{"a": 1}]}')
    info = updates.ptp_watch_info()
    assert info["count"] == 1 and info["ts"].startswith("2026-11-06")


# ---- the nightly delta: tonight's map vs yesterday's -----------------------
def test_map_delta_reads_tonights_additions_only():
    old = ptp.parse_dashboard(HTML)
    new = old + [{"project": "curl", "severity": "high",
                  "finding": "A brand new header overflow", "status": "New"}]
    delta = ptp.map_delta(old, new)
    assert list(delta) == ["curl"] and len(delta["curl"]) == 1
    assert delta["curl"][0]["finding"].startswith("A brand new header")
    # unchanged and removed findings are both silent: no re-reading, and
    # a shrinking map is not news
    assert ptp.map_delta(old, old) == {}
    assert ptp.map_delta(old, old[:1]) == {}


def test_evaluate_delta_announces_each_new_finding_once(tmp_path):
    old = ptp.parse_dashboard(HTML)
    new = old + [{"project": "sqlite", "severity": "high",
                  "finding": "A fresh WAL race", "status": "New"}]
    specs = ptp.evaluate_delta(tmp_path, old, new)
    assert len(specs) == 1 and specs[0] == ("HIGH", specs[0][1],
                                            specs[0][2])
    assert "sqlite" in specs[0][1] and "A fresh WAL race" in specs[0][1]
    assert "map update" in specs[0][1]
    # the ledger holds the key, so a restart never re-reads old news
    assert ptp.evaluate_delta(tmp_path, old, new) == []
    assert ptp.delta_path(tmp_path).exists()


def test_evaluate_delta_keeps_quiet_when_ledger_cannot_persist(
        tmp_path):
    old = ptp.parse_dashboard(HTML)
    new = old + [{"project": "zlib", "severity": "medium",
                  "finding": "A new slow write", "status": "New"}]
    locked = ptp.delta_path(tmp_path)
    locked.parent.mkdir(exist_ok=True)
    locked.mkdir()          # append into a directory -> OSError
    assert ptp.evaluate_delta(tmp_path, old, new) == []


def test_cross_join_matches_on_real_coverage_only(tmp_path):
    (tmp_path / "ptp-watch.json").write_text(json.dumps(
        {"ts": "t", "projects": [
            {"project": "curl", "findings": 12, "high": 3, "via": "deb",
             "packages": ["curl"]}]}))
    row = ptp.cross_join(tmp_path, "CURL")
    assert row["project"] == "curl"
    assert ptp.cross_join(tmp_path, "psad") is None
    assert ptp.cross_join(tmp_path, "") is None


# ---- the explain intent: Defense hands the chat a real question ------------
def test_explain_button_routes_a_real_question(defense_view):
    v = defense_view
    asked = {}
    v._win = type("W", (), {
        "_ask_assistant": (lambda self, q: asked.update(q=q))})()
    v.refresh({"defense": {}})
    from gi.repository import Gtk
    explains = [b for b in _walk_widgets(v._armor)
                if isinstance(b, Gtk.Button) and b.get_label() == "Explain"]
    assert explains
    explains[0].emit("clicked")
    assert "watchlist" in asked["q"]
    v.unparent()
