"""One Full scan plus one uncapped run — and the legacy key still routes.

The "Scan everything" button became Full scan (throttled, the everyday
run) next to an explicit Max-speed run, and the hidden legacy ``scan-all``
key still resolves (chat phrasing, upgraded clients) to the same throttled
run. The GUI itself never escalates: it writes one request file; the root
daemon spawns ClamAV, rkhunter, Lynis, AIDE and YARA itself. These tests
pin the SCAN_MODES entries, that no-escalation fact, the daemon's command
table, and the shell helper's scan-all branch (still usable from a
terminal)."""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_full_scan_is_first_and_scan_all_still_routes():
    from ui.cards import SCAN_MODES, STRIP_MODES
    first = SCAN_MODES[0]
    # The everyday run is Full scan, throttled, and it is first.
    assert first["key"] == "full" and first["scope"] == "root"
    # The one uncapped run is explicit on the strip.
    assert "max-speed" in [m.get("key") for m in STRIP_MODES]
    # The legacy scan-all key stays resolvable (chat + upgrades) but is
    # never offered as a button again.
    legacy = [m for m in SCAN_MODES if m.get("key") == "scan-all"][0]
    assert legacy.get("hidden")
    assert "scan-all" not in [m.get("key") for m in STRIP_MODES]


def test_max_speed_entry_carries_the_uncapped_run_note():
    from ui.cards import SCAN_MODES
    fast = [m for m in SCAN_MODES if m.get("key") == "max-speed"][0]
    slow = [m for m in SCAN_MODES if m.get("key") == "full"][0]
    # The throttle note is the product, not decoration: each entry says
    # which run it is in the words a person sees while it runs.
    assert "full speed" in fast.get("run_note", "")
    assert "throttled" in slow.get("run_note", "")
    assert "hidden" not in fast and "hidden" not in slow


def _source(obj) -> str:
    """Source of a method, Cython-safe: falls back to the .py on disk when
    inspect.getsource raises TypeError (compiled cython_function_or_method)."""
    import inspect
    import pathlib
    try:
        return inspect.getsource(obj)
    except TypeError:
        mod = inspect.getmodule(obj)
        # mod.__file__ is e.g. ".../window.cpython-312-x86_64-linux-gnu.so"
        # — strip the FULL extension chain back to the .py sibling.
        py = pathlib.Path(mod.__file__)
        while py.suffix and py.suffix != ".py":
            py = py.with_suffix("")
        py = py.with_suffix(".py")
        return py.read_text(encoding="utf-8")


def test_the_gui_no_longer_escalates_to_run_scans():
    # The window never moves a protection except through a press of the
    # owner's hand. The old regression: automatic scan-all escalation,
    # a helper invocation with no ask, and polling loops left behind.
    # GW-194 (2026-11-05, owner finding "why can't i update from here?")
    # re-authorised ONE explicit path: a control button on the registry
    # record, which routes unit-less scanners through scan-now.sh and
    # everything else through the toggles.
    from ui import window
    src = (ROOT / "ui" / "toolctl.py").read_text(encoding="utf-8")
    shell = (ROOT / "ui" / "window.py").read_text(encoding="utf-8")
    assert "run_helper(\"tool-control\", [\"scan-all\"])" not in src
    assert "run_helper(\"tool-control\", [\"scan-all\"])" not in shell
    for gone in ("_run_scan", "_poll_scan", "_poll_process", "_scan_done",
                 "_finish_scan_watch"):
        assert not hasattr(window.MainWindow, gone), gone
    assert "_control_requested" in src          # the explicit press path


def test_scan_all_runs_the_same_five_scanners():
    from scan_session import SCAN_ALL, commands_for
    assert SCAN_ALL == ("clamav", "rkhunter", "lynis", "aide",
                        "yara-tmp-scan")
    binaries = {k: commands_for(k, "/home/alice", "grey")[0][0]
                for k in SCAN_ALL}
    assert [c[0] for c in commands_for("scan-all", "/home/alice", "grey")] \
        == list(binaries.values())
    assert binaries["clamav"] == "/usr/bin/clamscan"
    assert binaries["rkhunter"] == "/usr/bin/rkhunter"
    assert binaries["lynis"] == "/usr/sbin/lynis"
    assert binaries["aide"] == "/usr/bin/aide"
    assert binaries["yara-tmp-scan"] == "/usr/sbin/runuser"


def test_tool_control_scan_all_branch_runs_every_scanner():
    script = (ROOT / "apply" / "tool-control.sh").read_text(encoding="utf-8")
    assert '"scan-all"' in script
    for needle in ("clamscan", "rkhunter", "lynis", "yara-tmp-scan.service",
                   "aide-check.service"):
        assert needle in script, needle
    # scan-all is a one-arg branch, distinct from start-all/stop-all
    assert 'if [ $# -eq 1 ] && [ "$1" = "scan-all" ]; then' in script
    # rkhunter/lynis log where the daemon's registry.json points: /var/log.
    # (scan-now.sh's /var/log redirects work because the helper runs as
    # root via pkexec — same for scan-all. The defaults ride in the env-
    # overridable LOG variables so tests can redirect them to tmp.)
    assert 'RKHUNTER_LOG="${RKHUNTER_LOG:-/var/log/rkhunter.log}"' in script
    assert 'LYNIS_LOG="${LYNIS_LOG:-/var/log/lynis.log}"' in script
    # each scanner holds a lock for its whole run: scan-all clicked twice
    # never double-runs a scanner (the 2026-11-06 orphan-storm finding)
    for lock in ("clam-scan.lock", "rkhunter.lock", "lynis.lock"):
        assert lock in script, lock
    # clamav logs into the user-writable GH tree, matching scan-now.sh
    assert '--log="$GH/security-hardening/clam-scan.log"' in script


def test_tool_control_syntax_is_valid():
    r = subprocess.run(["bash", "-n", str(ROOT / "apply" / "tool-control.sh")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_polkit_allowlist_covers_tool_control():
    policy = (ROOT / "apply" / "polkit" / "greywatch.apply.policy") \
        .read_text(encoding="utf-8")
    assert 'id="com.greywatch.apply.tool-control"' in policy
    assert "__GW_LIB__/apply/tool-control.sh" in policy


def test_install_check_accepts_tool_control_action():
    # the install policy checker iterates every template action; tool-control
    # must be one of them so a staged install passes its own --check
    tpl = (ROOT / "apply" / "polkit" / "greywatch.apply.policy") \
        .read_text(encoding="utf-8")
    import re
    ids = re.findall(r'action id="(com\.greywatch\.apply\.[a-z-]+)"', tpl)
    assert "com.greywatch.apply.tool-control" in ids


def test_source_helper_strips_cpython_extension_chain():
    """The _source() fallback must turn
    '.../window.cpython-312-x86_64-linux-gnu.so' into '.../window.py'
    (CI compiles with Cython; mod.__file__ carries the full ABI tag)."""
    import pathlib
    ci_so = "/home/runner/work/greywatch/greywatch/ui/window.cpython-312-x86_64-linux-gnu.so"
    py = pathlib.Path(ci_so)
    while py.suffix and py.suffix != ".py":
        py = py.with_suffix("")
    py = py.with_suffix(".py")
    assert str(py) == "/home/runner/work/greywatch/greywatch/ui/window.py"
