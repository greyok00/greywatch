"""Tests for hardening.detector — injected runner, invert flag, CANT-CHECK."""
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
    # Finding carries control id + captured output; Control dataclass also works.
    f = scan([C(id="c1")], runner=lambda l: (1, "not set"))[0]
    assert f.control_id == "c1" and f.current == "not set"
    from hardening.controls import Control
    c = Control(id="c2", group="g", what="w", probe="true", probe_invert=True)
    assert scan([c], runner=lambda l: (1, ""))[0].state == "PASS"


def test_prod_runner_runs_user_context():
    rc, out = prod_runner("echo hello")
    assert rc == 0 and out.strip() == "hello"


def test_prod_runner_refuses_sudo():
    # sudo (or any root escalation) must never be attempted -> raised error,
    # which the detector maps to CANT-CHECK.
    try:
        prod_runner("sudo ls")
    except RuntimeError:
        pass
    else:
        raise AssertionError("prod_runner must refuse sudo")


def test_prod_runner_bad_command_is_failure_not_crash():
    rc, out = prod_runner("")
    assert rc != 0