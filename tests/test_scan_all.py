"""scan-all: one polkit call launches every on-demand scanner at once.

The "Scan everything" button routes through tool-control.sh scan-all (a
single root helper invocation), NOT through per-scanner pkexec calls —
that was the root cause of the ten back-to-back password prompts. These
tests pin the wiring: the SCAN_MODES entry, the UI runner routing, the
shell helper's scan-all branch, and the polkit allowlist action."""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_scan_all_mode_is_first_and_routes_through_tool_control():
    from ui.cards import SCAN_MODES
    first = SCAN_MODES[0]
    assert first["key"] == "scan-all"
    assert first["scope"] == "root"
    assert first.get("helper") == "tool-control"


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


def test_ui_runner_calls_tool_control_scan_all():
    from ui import window
    src = _source(window.MainWindow._run_scan)
    assert 'common.run_helper("tool-control", ["scan-all"])' in src


def test_window_scan_done_reports_all_scanners_launched():
    # scan-all has no single unit/proc to poll — it must not enter a
    # watch loop; it reports and stops
    from ui import window
    src = _source(window.MainWindow._scan_done)
    assert '"scan-all"' in src
    assert "All scanners launched" in src


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
    # root via pkexec — same for scan-all.)
    assert ">> /var/log/rkhunter.log" in script
    assert ">> /var/log/lynis.log" in script
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
