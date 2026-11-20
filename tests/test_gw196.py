"""GW-196 (owner live finding, 2026-11-05: "im getting exit 1s during
scans", "yara temp and others are doing the same").

Every 16k-folder temp sweep reported "exited 1" with zero findings: no
match, no noise story - the raw stderr said "input in flex scanner
failed". Temp files churn under the sweep (mktemp-style files vanished
between the failing scan and an inspection seconds later), and one
deleted-or-rewritten file kills YARA's whole pass. The wrapper now
sweeps each root on its own, gives a churning leg two attempts, and
exits on what was actually swept: one poison file's shadow no longer
marks findings or a healthy other leg as broken. A leg that dies twice
puts YARA's error line on stderr where the journal says why.
"""
import os
import pathlib
import shutil
import tempfile
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "apply" / "yara-tmp-scan.sh"


def _run(*args, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(["/bin/bash", str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=300,
                          env=env)


def test_transient_yara_death_is_retried(tmp_path):
    stub = tmp_path / "stub-yara.sh"
    counter = tmp_path / "runs"
    counter.write_text("0")
    # Attempt 1: the churn race kills the leg, exactly as on the owner's
    # box. Attempt 2: the file stopped moving; the leg completes.
    stub.write_text(
        '#!/bin/bash\n'
        f'n=$(cat "{counter}"); echo $((n+1)) > "{counter}"\n'
        'if [ "$n" -lt 1 ]; then\n'
        '    echo "error: input in flex scanner failed" >&2\n'
        '    exit 1\n'
        'fi\n'
        'echo 0\n')
    stub.chmod(0o755)
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x { condition: false }\n")   # only read-checked
    root = str(tmp_path / "sweep")
    os.mkdir(root)
    pathlib.Path(root, "plain.txt").write_text("nothing here\n")
    out = _run(str(rules), root, env_extra={"YARA_BIN": str(stub)})
    assert out.returncode == 0, (out.stdout, out.stderr)
    assert counter.read_text().strip() == "2", "the leg really retried"
    assert "flex" not in out.stderr


def test_one_poison_leg_does_not_fail_the_sweep(tmp_path):
    """The live shape: /tmp churns, the other legs are healthy. The
    sweep reports what was swept (exit 0) and the dead leg's reason
    lands on stderr, not in the row's exit code."""
    stub = tmp_path / "stub-yara.sh"
    # fail on any leg into a directory named "poison"; pass the rest
    stub.write_text('#!/bin/bash\n'
                    'for a in "$@"; do\n'
                    '    case "$(basename -- "$a")" in *poison*)\n'
                    '        echo "error: input in flex scanner failed" >&2\n'
                    '        exit 1;;\n'
                    '    esac\n'
                    'done\n'
                    'echo 0\n')
    stub.chmod(0o755)
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x { condition: false }\n")
    clean = tmp_path / "clean"
    clean.mkdir()
    poison = tmp_path / "poison-leg"
    poison.mkdir()
    out = _run(str(rules), str(clean), str(poison),
               env_extra={"YARA_BIN": str(stub)})
    assert out.returncode == 0, (out.stdout, out.stderr)
    assert "flex scanner" in out.stderr, "the dead leg says why, on stderr"


def test_nothing_swept_at_all_still_reads_as_failure(tmp_path):
    stub = tmp_path / "stub-yara.sh"
    stub.write_text('#!/bin/bash\n'
                    'echo "error: input in flex scanner failed" >&2\n'
                    'exit 1\n')
    stub.chmod(0o755)
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x { condition: false }\n")
    root = str(tmp_path / "sweep")
    os.mkdir(root)
    out = _run(str(rules), root, env_extra={"YARA_BIN": str(stub)})
    assert out.returncode == 1, out.stderr
    assert "flex scanner" in out.stderr


def test_matches_still_count_once_the_error_is_gone(tmp_path):
    # Real yara (skipped on boxes without it): a hit prints, the sweep
    # exits 0, and the pytest fixture exclusion still swallows its own
    # fixtures (the GW-185 contract).
    if shutil.which("yara") is None:
        pytest.skip("yara is not installed on this box")
    rules = tmp_path / "rules.yar"
    rules.write_text('rule gw196_needle { strings: $a = "GW196-STUB" '
                     'condition: $a }\n')
    # under pytest tmp the fixture exclusion strips every hit, so the
    # print-contract test scans /dev/shm (the same move GW-185 made)
    root = pathlib.Path(tempfile.mkdtemp(prefix="gw196-hit-"))
    (root / "needle.txt").write_text("GW196-STUB marker\n")
    out = _run(str(rules), str(root))
    shutil.rmtree(root, ignore_errors=True)
    assert out.returncode == 0, (out.stdout, out.stderr)
    assert "gw196_needle" in out.stdout
