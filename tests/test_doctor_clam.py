"""The doctor names ClamAV trouble in plain words and offers control.

Owner 2026-11-14: ClamAV is the most troublesome program; it must be
throttled, controlled, and never allowed to hide a killed scan."""
import pathlib
import subprocess

import doctor


def _probe_fake(timer="active", enabled="enabled", defs="fresh"):
    """The probes row_clamav and the fix lane make against the ONE-SHOT
    lane (the resident engine is retired and masked)."""
    def fake(argv):
        if argv[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(argv, 0, timer, "")
        if argv[:2] == ["systemctl", "is-enabled"]:
            return subprocess.CompletedProcess(argv, 0, enabled, "")
        return subprocess.CompletedProcess(argv, 1, "", "")
    return fake


def test_killed_scan_is_named_not_hidden(tmp_path, monkeypatch):
    sec = tmp_path / "security-hardening"
    sec.mkdir()
    (sec / "clam-run.log").write_text(
        "2026-11-14T09:09:01-07:00 clamscan start\n"
        "2026-11-14T09:40:00-07:00 clamscan exit rc=137\n")
    monkeypatch.setattr(doctor, "_probe", _probe_fake())
    row = doctor.row_clamav(tmp_path / "data", home=tmp_path)
    assert row["verdict"] == "DEGRADED"
    assert "was killed" in row["text"]
    assert "09:40" in row["text"]


def test_one_shot_lane_armed_reads_ready(tmp_path, monkeypatch):
    # Superseded (owner 2026-11-17): the timer armed IS the antivirus
    # being healthy; the resident engine never runs again.
    monkeypatch.setattr(doctor, "_probe", _probe_fake(timer="active"))
    row = doctor.row_clamav(tmp_path / "data", home=tmp_path)
    assert row["verdict"] == "READY"
    assert "one-shot" in row["text"]


def test_disabled_timer_is_healthy_not_degraded(tmp_path, monkeypatch):
    """The automatic scan timers stay off (owner order 2026-11-19): a
    disabled timer is the intended state, never a fault."""
    monkeypatch.setattr(doctor, "_probe", _probe_fake(timer="inactive",
                                                      enabled="disabled"))
    row = doctor.row_clamav(tmp_path / "data", home=tmp_path)
    assert row["verdict"] == "READY"
    assert "timer is not armed" not in row["text"]
    assert "one-shot" in row["text"]
    assert "stays masked" in row["text"]


def test_clean_journal_reads_ready(tmp_path, monkeypatch):
    sec = tmp_path / "security-hardening"
    sec.mkdir()
    (sec / "clam-run.log").write_text(
        "2026-11-14T09:09:01-07:00 clamscan start\n"
        "2026-11-14T09:40:00-07:00 clamscan exit rc=0\n")
    monkeypatch.setattr(doctor, "_probe", _probe_fake())
    row = doctor.row_clamav(tmp_path / "data", home=tmp_path)
    assert row["verdict"] == "READY"
    assert "finished clean" in row["text"]


def test_fix_never_arms_the_scan_timer(tmp_path, monkeypatch):
    # The fix never arms a scan timer and never starts the masked
    # daemon; it only enables the definition updater.
    calls = []

    def fake(argv):
        calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-enabled"]:
            return subprocess.CompletedProcess(argv, 0, "disabled", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(doctor, "_probe", fake)
    monkeypatch.setattr(doctor, "_clam_control_helper",
                        lambda: pathlib.Path("/usr/bin/true"))
    lines = doctor.clamav_apply_fix()
    text = " ".join(lines)
    assert "definition updater was enabled" in text
    assert not any("greywatch-clam-scan.timer" in c for c in calls), calls
    assert not any("clamav-daemon.service" in c for c in calls), calls
    assert any("clamav-freshclam.service" in c for c in calls), calls


def test_fix_is_quiet_when_the_definitions_are_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_probe", _probe_fake(enabled="enabled"))
    lines = doctor.clamav_apply_fix()
    assert "nothing to do" in " ".join(lines)


def test_doctor_fix_never_arms_a_scan_timer(monkeypatch):
    """`doctor --fix` must never enable or start either automatic scan
    timer, even when the clam row is BROKEN and its unit is the timer."""
    import subprocess
    calls = []

    def fake(argv, **kwargs):
        calls.append(list(argv))
        out = ""
        if argv[:2] == ["systemctl", "is-enabled"]:
            out = "disabled\n"
        elif argv[:2] == ["systemctl", "is-active"]:
            out = "inactive\n"
        return subprocess.CompletedProcess(argv, 0, out, "")

    monkeypatch.setattr(doctor.subprocess, "run", fake)
    monkeypatch.setattr(doctor, "_registry",
                        lambda: [{"name": "clamav",
                                  "unit": "greywatch-clam-scan.timer"}])
    monkeypatch.setattr(doctor.setup_mod, "probe_tool",
                        lambda spec: {"verdict": "BROKEN"})
    monkeypatch.setattr(doctor, "health_snapshot", lambda *a, **k: [])
    monkeypatch.setattr(doctor, "hunter_service_row",
                        lambda fix: {"name": "hunter", "verdict": "READY",
                                     "stamp": "", "actions": []})
    monkeypatch.setattr(doctor, "clamav_apply_fix", lambda: [])
    doctor.doctor(fix=True, only="clamav")
    scan = {"greywatch-clam-scan.timer", "greywatch-boot-sweep.timer"}
    bad = [c for c in calls
           if ({"enable", "start"} & set(c)) and (scan & set(c))]
    assert bad == [], calls


def test_progress_pct_and_path(tmp_path):
    base = tmp_path / "security-hardening"
    base.mkdir()
    (base / "clam-progress.txt").write_text("12340\nScanning /home/grey/x\n")
    (base / "clam-run.log").write_text("x clamscan total=83000\n")
    import cli
    out = cli._clam_progress(str(base / "clam-scan.log"))
    assert "~14%" in out and "12,340 files" in out
    assert "/home/grey/x" in out


def test_progress_done(tmp_path):
    base = tmp_path / "security-hardening"
    base.mkdir()
    (base / "clam-progress.txt").write_text("83000\nDONE\n")
    import cli
    out = cli._clam_progress(str(base / "clam-scan.log"))
    assert "complete" in out




def test_session_exit_clears_the_stale_interrupt(tmp_path, monkeypatch):
    """The daemon session and the manual lane journal to ONE file; a
    finished session line after a killed one reads READY (the doctor's
    two-lane fix, owner 2026-11-15)."""
    sec = tmp_path / "security-hardening"
    sec.mkdir()
    (sec / "clam-run.log").write_text(
        "2026-11-14T18:35:28-07:00 clamscan exit rc=130\n"
        "2026-11-15T01:30:00+00:00 session 20261115T0125-a1 exit rc=0\n")
    monkeypatch.setattr(doctor, "_probe", _probe_fake())
    row = doctor.row_clamav(tmp_path / "data", home=tmp_path)
    assert row["verdict"] == "READY"
    assert "finished clean" in row["text"] and "01:30" in row["text"]
