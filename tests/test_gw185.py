"""GW-185: the temp sweep's exit status is honest (owner 2026-11-05,
"one tool is giving exit 1 and i cant reenable it").

The wrapper used to end in `exit "$?"` at the tail of a
yara | grep | grep | grep pipeline, so "$?" was the last filter grep's
status - 1 ("no lines selected") on every clean scan, the good case
read as failure from the desk for four days. Now yara's own status is
captured and returned; the filters only decide what is printed."""
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apply" / "yara-tmp-scan.sh"

_NEEDLE = "GWGW185-NEEDLE"


def _run(*args):
    return subprocess.run(["/bin/bash", str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=120)


def test_the_script_returns_yaras_own_status_to_the_desk():
    """A source pin beside the behaviour tests: the exit reads yara's
    captured status, and no bare `$?` follows the filter pipeline."""
    code = "\n".join(l for l in SCRIPT.read_text().splitlines()
                     if not l.lstrip().startswith("#"))
    assert 'exit "$yara_rc"' in code, "the wrapper must exit on yara's rc"
    assert "yara_rc=$?" in code
    assert 'exit "$?"' not in code, (
        "$? at the tail is the last grep's status; that was GW-185")
    # GW-123's pytest exclusion survives the rewrite: the pattern line
    # still ends in a `' \` continuation where the closeout pin reads it.
    assert "pytest-of-" in code and "/(var/)?" in code


def test_usage_errors_exit_with_their_own_codes(tmp_path):
    assert _run().returncode == 64, "no rules and no roots"
    assert _run("/no/such/rules.yar", str(tmp_path)).returncode == 65, \
        "unreadable rules file"
    # Code 66 needs rules that ARE readable and every root unreadable,
    # because the rules check fires first.
    rules = tmp_path / "rules.yar"
    rules.write_text('rule empty { condition: false }\n')
    assert _run(str(rules), "/no/such/root").returncode == 66, \
        "no readable temp folder to sweep"
    # The 64s and 65s are the script's own checks; they never run yara.


@pytest.mark.skipif(shutil.which("yara") is None,
                    reason="yara is not installed on this box")
def test_a_clean_scan_succeeds_and_prints_only_progress(tmp_path):
    rules = tmp_path / "rules.yar"
    rules.write_text(f'rule gw185_needle {{ strings: $a = "{_NEEDLE}" '
                     'condition: $a }\n')
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "plain.txt").write_text("nothing to find here\n")
    out = _run(str(rules), str(clean))
    assert out.returncode == 0, (out.stdout, out.stderr)
    assert "@@DIRS" in out.stdout, "the folder walk is still reported"
    assert _NEEDLE not in out.stdout and "gw185_needle" not in out.stdout


@pytest.mark.skipif(shutil.which("yara") is None,
                    reason="yara is not installed on this box")
def test_a_hit_is_printed_and_still_exits_zero(tmp_path):
    import os

    rules = tmp_path / "rules.yar"
    rules.write_text(f'rule gw185_needle {{ strings: $a = "{_NEEDLE}" '
                     'condition: $a }\n')
    # Outside the pytest fixture tree the hit prints; under pytest tmp
    # the 2026-09-23 noise rule deliberately excludes it (so a test run
    # never reports itself), and both behaviours are pinned here.
    root = pathlib.Path("/dev/shm") / f"gw185-hit-{os.getpid()}"
    root.mkdir(exist_ok=True)
    try:
        (root / "needle.txt").write_text(f"{_NEEDLE}-marker\n")
        out = _run(str(rules), str(root))
        assert out.returncode == 0, (out.stdout, out.stderr)
        assert "gw185_needle" in out.stdout, "the hit names its rule"
        assert str(root) in out.stdout, "the hit names the file"
        fixture = tmp_path / "fixture"
        fixture.mkdir()
        (fixture / "needle.txt").write_text(f"{_NEEDLE}-marker\n")
        out2 = _run(str(rules), str(fixture))
        assert out2.returncode == 0
        assert "gw185_needle" not in out2.stdout, (
            "the pytest fixture exclusion still holds")
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.skipif(shutil.which("yara") is None,
                    reason="yara is not installed on this box")
def test_a_broken_rules_file_reads_as_a_failed_scan(tmp_path):
    rules = tmp_path / "bad.yar"
    rules.write_text("rule broken {{{ not yara\n")
    root = tmp_path / "sweep"
    root.mkdir()
    out = _run(str(rules), str(root))
    assert out.returncode != 0, (out.stdout, out.stderr)
    # And not one of the usage codes: the failure is yara's own.
    assert out.returncode not in (64, 65, 66)
