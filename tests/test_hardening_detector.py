import os
from hardening.detector import scan, prod_runner


def C(**kw):
    return {"id": kw.get("id", "x"), "probe": kw.get("probe", "true"),
            "invert": kw.get("invert", False), "severity": "LOW",
            "group": "g"}


def test_pass_gap_cant():
    assert scan([C()], runner=lambda l: (0, ""))[0].state == "PASS"
    assert scan([C()], runner=lambda l: (1, "no"))[0].state == "GAP"

    def boom(_):
        raise OSError

    assert scan([C()], runner=boom)[0].state == "CANT-CHECK"


def test_invert_flag():
    assert scan([C(invert=True)], runner=lambda l: (1, ""))[0].state == "PASS"
    assert scan([C(invert=True)], runner=lambda l: (0, ""))[0].state == "GAP"


def test_fields_and_control_objects():
    f = scan([C(id="c1")], runner=lambda l: (1, "not set"))[0]
    assert f.control_id == "c1" and f.current == "not set"
    from hardening.controls import Control
    c = Control(id="c2", group="g", what="w", probe="true", probe_invert=True)
    assert scan([c], runner=lambda l: (1, ""))[0].state == "PASS"


def test_prod_runner_runs_user_context():
    rc, out = prod_runner("echo hello")
    assert rc == 0 and out.strip() == "hello"


def test_prod_runner_refuses_sudo():
    try:
        prod_runner("sudo ls")
    except RuntimeError:
        pass
    else:
        raise AssertionError("prod_runner must refuse sudo")


def test_prod_runner_bad_command_is_failure_not_crash():
    rc, out = prod_runner("")
    assert rc != 0


def test_prod_runner_repairs_the_desktop_path(tmp_path):
    # sysctl and nft live in /usr/sbin, which a desktop user session's
    # PATH does not include — a probe must still find them
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    stub = sbin / "kernctl"
    stub.write_text("#!/bin/sh\nprintf 'P=%s S=%s' \"$PATH\" \"$GWSECRET\"\n")
    stub.chmod(0o755)
    saved_path = os.environ.get("PATH")
    saved_secret = os.environ.get("GWSECRET")
    os.environ["PATH"] = f"{sbin}:/usr/bin:/bin"    # desktop-like: no sbin trees
    os.environ["GWSECRET"] = "never-leak-this"
    try:
        rc, out = prod_runner("kernctl -n kernel.unprivileged_bpf_disabled")
    finally:
        if saved_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved_path
        if saved_secret is None:
            os.environ.pop("GWSECRET", None)
        else:
            os.environ["GWSECRET"] = saved_secret
    assert rc == 0, out
    assert "/usr/sbin" in out and "/bin" in out    # sbin reached
    assert "never-leak-this" not in out            # env scrubbed
    assert "S=" in out and out.split("S=", 1)[1].strip() == ""


def test_prod_runner_runs_compound_probe_lines(tmp_path):
    # shipped probe lines may be compound (pipes/redirects) — they still run
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "tableprober"
    stub.write_text("#!/bin/sh\necho table inet greywatch\n")
    stub.chmod(0o755)
    probe = f"{stub} 2>/dev/null | grep -q greywatch && echo wired || echo dead"
    rc, out = prod_runner(probe)
    assert rc == 0 and "wired" in out


def test_probe_binaries_missing_name_the_tool():
    findings = scan([{"id": "needstool", "probe": "gw-absent-prober -n x",
                      "invert": False, "severity": "LOW", "group": "g"}],
                    runner=prod_runner)
    assert findings[0].state == "CANT-CHECK"
    assert "gw-absent-prober" in findings[0].note


def test_detail_supplies_the_current_line():
    calls = []

    def runner(line):
        calls.append(line)
        if line == "check":
            return 0, "ok"
        if line == "show value":
            return 0, "  0\n"
        raise AssertionError(line)

    controls = [{"id": "c", "group": "g", "what": "w", "severity": "LOW",
                 "probe": "check", "detail": "show value"}]
    got = scan(controls, runner=runner)
    assert got[0].state == "PASS"
    assert got[0].current == "0"
    assert calls == ["check", "show value"]


def test_detail_failure_falls_back_to_probe_text():
    def runner(line):
        if line == "check":
            return 1, "probe said no"
        raise RuntimeError("detail unavailable")

    controls = [{"id": "c", "group": "g", "what": "w", "severity": "LOW",
                 "probe": "check", "detail": "detail-cmd"}]
    got = scan(controls, runner=runner)
    assert got[0].state == "GAP"
    assert got[0].current == "probe said no"


def test_detail_never_changes_the_state():
    def runner(line):
        return (0, "good") if line == "check" else (1, "detail failed")

    controls = [{"id": "c", "group": "g", "what": "w", "severity": "LOW",
                 "probe": "check", "detail": "detail-cmd"}]
    assert scan(controls, runner=runner)[0].state == "PASS"
