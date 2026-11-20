"""GW-158 pins: a protection whose service is green but whose LAST SCAN
did not finish reads under its own outcome banner ("Last scan did not
finish"), never under "Running clean" - the banner speaks about service
health and read as an all-clear over a row wearing a fail rail - and the
band's verdict words distinguish tool health from the scan's outcome."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from ui.protectdesk import ProtectDesk  # noqa: E402
from ui.toolsdesk import ToolsDesk  # noqa: E402

_REG = ("clamav", "rkhunter", "lynis", "aide")


def _registry():
    return [{"name": n, "unit": f"{n}.service", "logs": ()} for n in _REG]


def _fact(name, scan_state=None, quiet=False, live_state=None):
    return {"name": name, "state": "GREEN", "paused": False,
            "quiet": quiet, "unit": f"{name}.service",
            "installed": True, "label": name.upper(), "event": None,
            "last_scan": ({"state": scan_state, "detail": "stopped",
                           "exit_code": 137, "started_at":
                           "2026-11-04T07:00:00+00:00"}
                          if scan_state in ("failed", "interrupted")
                          else ({"state": scan_state, "count": 5,
                                 "detail": ""} if scan_state else {})),
            "live_scan": ({"state": live_state, "exit_code": 137}
                          if live_state in ("failed", "interrupted")
                          else None)}


def _labels(desk):
    return [w.get_text() for w in desk.feed._list.observe_children()
            if isinstance(w, Gtk.Label) and "gw-day" in str(
                list(w.get_css_classes()))]


def test_a_failed_last_scan_reads_under_its_own_banner():
    facts = {"clamav": _fact("clamav", scan_state="failed"),
             "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    labels = _labels(desk)
    assert labels[0] == "Last scan did not finish", labels
    assert "Running clean" in labels, ("the finished row keeps its own "
                                       "honest banner")
    assert labels.index("Last scan did not finish") \
        < labels.index("Running clean"), labels
    assert "clamav" in desk.feed.rows()
    assert "rkhunter" in desk.feed.rows()


def test_an_interrupted_last_scan_reads_under_the_outcome_banner_too():
    facts = {"clamav": _fact("clamav", scan_state="interrupted"),
             "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    assert "Last scan did not finish" in _labels(desk)


def test_a_finished_scan_still_reads_running_clean():
    facts = {"clamav": _fact("clamav", scan_state="done"),
             "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    labels = _labels(desk)
    assert "Running clean" in labels
    assert "Last scan did not finish" not in labels


def test_band_words_name_the_scan_when_tool_health_is_clean():
    facts = {"clamav": _fact("clamav", scan_state="failed"),
             "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    desk.band_paint(0, 0, 0, 0, 0, 2)
    val, sub = desk.band.tiles()["att"]
    assert val.get_text() == "0"          # tool health: nothing RED/YELLOW
    assert "1 last scan did not finish" in sub.get_text(), \
        "the tile must not read as an all-clear over a failed scan"


def test_band_all_clear_words_survive_when_no_scan_failed():
    facts = {"clamav": _fact("clamav", scan_state="done"),
             "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    desk.band_paint(2, 0, 0, 0, 0, 2)
    val, sub = desk.band.tiles()["att"]
    assert val.get_text() == "0"
    assert sub.get_text() == "nothing needs it right now"


def test_band_attention_dominance_keeps_its_dossier_pointer():
    facts = {"clamav": _fact("clamav"), "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    desk.band_paint(0, 2, 0, 0, 0, 2)
    val, sub = desk.band.tiles()["att"]
    assert val.get_text() == "2"
    assert sub.get_text() == "reasons in the dossier"


def test_tools_desk_bucketing_matches_the_protections_desk():
    facts = {"clamav": _fact("clamav", scan_state="failed"),
             "rkhunter": _fact("rkhunter", quiet=True),
             "lynis": _fact("lynis"),
             "aide": _fact("aide", scan_state="done")}
    desk = ToolsDesk(_registry())
    desk.paint(facts, [], "2026-11-04T10:00:00+00:00")
    labels = _labels(desk)
    assert "Last scan did not finish" in labels
    assert "Running clean, by activity" in labels


def test_tools_band_job_words_carry_the_scan_outcome():
    facts = {"clamav": _fact("clamav", scan_state="failed"),
             "rkhunter": _fact("rkhunter", quiet=True),
             "lynis": _fact("lynis"),
             "aide": _fact("aide")}
    desk = ToolsDesk(_registry())
    desk.paint(facts, [], "2026-11-04T10:00:00+00:00")
    desk.band_paint(4, 4, 0, 0, 0, 4, 120, 2, degraded=(), dropped=0)
    val, sub = desk.band.tiles()["job"]
    assert val.get_text() == "4/4"
    assert "1 last scan did not finish" in sub.get_text()


def test_tools_band_job_words_survive_when_no_scan_failed():
    facts = {n: _fact(n, quiet=True) for n in _REG}
    desk = ToolsDesk(_registry())
    desk.paint(facts, [], "2026-11-04T10:00:00+00:00")
    desk.band_paint(4, 0, 0, 0, 0, 4, 120, 2, degraded=(), dropped=0)
    val, sub = desk.band.tiles()["job"]
    assert val.get_text() == "0/4"
    assert sub.get_text() == "4 quiet, nothing needs it"


def test_the_live_run_outranks_stale_history_in_the_bucketing():
    # The scenario on this machine: history still holds an old finished
    # run while the live session's row says failed - the card's fail
    # rail must win the banner, or the page repeats the contradiction.
    facts = {"clamav": _fact("clamav", scan_state="done",
                             live_state="failed"),
             "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    labels = _labels(desk)
    assert labels[0] == "Last scan did not finish", labels
    desk.band_paint(0, 0, 0, 0, 0, 2)
    _val, sub = desk.band.tiles()["att"]
    assert "last scan did not finish" in sub.get_text()


def test_history_outranked_live_read_still_buckets_from_history():
    # No live row on file (live_scan None) but a failed last run in
    # history: the outcome banner still buckets the row.
    facts = {"clamav": _fact("clamav", scan_state="failed"),
             "rkhunter": _fact("rkhunter")}
    desk = ProtectDesk(_registry(), runset=set())
    desk.paint(facts, "2026-11-04T10:00:00+00:00",
               rows={n: Gtk.Box() for n in facts})
    assert "Last scan did not finish" in _labels(desk)
