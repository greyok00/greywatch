"""GW-122 and GW-124 closeout pins.

GW-122: pytest's own fixture drops (EICAR + a test trojan under
/tmp/pytest-of-grey/) were quarantined by every sweep that touches /tmp.
The shipped Quick-scan script already filters those paths from its yara
output; these tests pin the filter so it cannot regress. The live store's
18 contaminated rows and 9 stale asks stay owner-gated: cleanup writes to
/var/lib/greywatch, which belongs to the owner.

GW-124: the daemon's bounded queue (collectors.BoundedQueue) drops parsed
events while a tail stalls and counts them forever after (7,507,065 at
audit time). The count is per process, so it resets on each daemon start.
The Tools band now carries it as its own sentence instead of summing it
into the failure tally.
"""
import pathlib
import subprocess

import gi

gi.require_version("Gtk", "4.0")

ROOT = pathlib.Path(__file__).resolve().parents[1]
SWEEP = ROOT / "apply" / "yara-tmp-scan.sh"

_REG = ("clamav", "rkhunter", "lynis", "aide")


def _registry():
    return [{"name": n, "unit": f"{n}.service", "logs": ()} for n in _REG]


def _sweep_pattern() -> str:
    for line in SWEEP.read_text().splitlines():
        if "grep -vE" in line and "pytest-of-" in line:
            pat = line.split("grep -vE", 1)[1]
            pat = pat.strip().lstrip("'")
            return pat.rsplit("' \\")[0].rstrip("'\\ ")
    raise AssertionError(
        "yara-tmp-scan.sh lost its pytest exclusion grep")


def _kept(lines: list) -> list:
    """The sweep's exclusion grep, run exactly as the script runs it."""
    out = subprocess.run(["bash", "-c", "grep -vE -- \"$P\""],
                         capture_output=True, text=True,
                         env={"P": _sweep_pattern()},
                         input="\n".join(lines) + "\n")
    return out.stdout.splitlines()


def test_sweep_script_keeps_the_pytest_exclusion():
    text = SWEEP.read_text()
    assert "pytest-of-" in text
    assert "/(var/)?" in text


def test_sweep_exclusion_drops_only_pytest_fixture_paths():
    sample = [
        "RULE /tmp/pytest-of-grey/pytest-19/test_eicar0/EICAR: SUCCESS",
        "RULE /var/tmp/pytest-of-grey/pytest-3/t/x: SUCCESS",
        "RULE /tmp/notes.txt: SUCCESS",                       # ordinary tmp hit
        "RULE /home/alice/Downloads/wire: SUCCESS",            # real finding
        "RULE /tmp/yara-responder-test.txt: SUCCESS",         # fixture of ours
    ]
    kept = _kept(sample)
    assert kept == [sample[2], sample[3], sample[4]]
    for kept_line, expect in ((kept[0], "/tmp/notes.txt"),
                              (kept[1], "/home/alice/Downloads"),
                              (kept[2], "/tmp/yara-responder")):
        assert expect in kept_line


def test_band_paint_leaves_dropped_out_of_the_failure_tally():
    from ui.toolsdesk import ToolsDesk
    desk = ToolsDesk(_registry())
    desk.band_paint(4, 3, 1, 0, 0, 4, 120, 3,
                    degraded=("scan",), dropped=0)
    val, sub = desk.band.tiles()["fails"]
    assert val.get_text() == "3"
    assert "dropped" not in sub.get_text()


def test_band_paint_surfaces_a_big_dropped_count_in_its_own_sentence():
    from ui.toolsdesk import ToolsDesk
    desk = ToolsDesk(_registry())
    desk.band_paint(4, 4, 0, 0, 0, 4, 120, 2, degraded=(),
                    dropped=7_507_065)
    val, sub = desk.band.tiles()["fails"]
    assert val.get_text() == "2", "failures stay their own number"
    note = sub.get_text()
    assert "7,507,065 parsed events dropped, queue full" in note
    # The dropped sentence leads so the band's ellipsis cannot eat it.
    assert note.startswith("7,507,065 parsed events dropped, queue full ·")
    assert "reads only" in note


def test_band_paint_names_degraded_reads_alongside_the_drop_note():
    from ui.toolsdesk import ToolsDesk
    desk = ToolsDesk(_registry())
    desk.band_paint(4, 4, 0, 0, 0, 4, 120, 2,
                    degraded=("aide", "clamav"), dropped=12)
    val, sub = desk.band.tiles()["fails"]
    assert val.get_text() == "2"
    note = sub.get_text()
    assert note.startswith("12 parsed events dropped, queue full · ")
    assert "named by the reads: aide, clamav" in note


# --------------------------------------------------------------- GW-123

def _one_tool(tmp_path, db_path):
    return {"name": "aide", "label": "AIDE", "unit": "aide-check.timer",
            "scope": "root", "logs": [], "db": str(db_path)}


def _checker(unit_state):
    return lambda t: unit_state


def test_status_downgrades_a_baseline_less_tool(tmp_path):
    from status import snapshot
    snap = snapshot([_one_tool(tmp_path, tmp_path / "missing.db")],
                    _checker("active"))
    aide = snap["tools"]["aide"]
    assert aide["state"] == "YELLOW", "an active timer is not a working scan"
    assert aide["note"] == "no baseline built yet"
    assert aide["unit_state"] == "active", "the timer's own truth stays"


def test_status_keeps_a_real_baseline_green(tmp_path):
    from status import snapshot
    db = tmp_path / "aide.db"
    db.write_bytes(b"x" * 64)
    snap = snapshot([_one_tool(tmp_path, db)], _checker("active"))
    aide = snap["tools"]["aide"]
    assert aide["state"] == "GREEN"
    assert "note" not in aide


def test_status_note_never_hides_a_failed_service(tmp_path):
    from status import snapshot
    db = tmp_path / "missing.db"
    db_path = _one_tool(tmp_path, db)
    # a FAILED unit stays RED even though the db is gone
    snap = snapshot([db_path], _checker("failed"))
    aide = snap["tools"]["aide"]
    assert aide["state"] == "RED"
    assert aide["note"] == "no baseline built yet"


def test_scan_verdict_names_the_missing_baseline(tmp_path, monkeypatch):
    import scan_session as S
    monkeypatch.setattr(S, "AIDE_DB", tmp_path / "aide.db")
    assert S.exit_verdict("aide", 8) == (
        "failed", "no baseline: run 'sudo aideinit' once, then scan again")


def test_scan_verdict_keeps_rc_detail_when_a_baseline_exists(
        tmp_path, monkeypatch):
    import scan_session as S
    db = tmp_path / "aide.db"
    db.write_bytes(b"baseline")
    monkeypatch.setattr(S, "AIDE_DB", db)
    state, detail = S.exit_verdict("aide", 8)
    assert state == "failed"
    assert detail == "aide exited 8"