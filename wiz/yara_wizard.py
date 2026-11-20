import pathlib
import subprocess
from rules import yara_source
from wiz import common

YARA_BIN = "/usr/bin/yara"
RULES_DIR = pathlib.Path.home() / "yara-rules"
_REPO = pathlib.Path(__file__).resolve().parents[1]
_PAYLOAD = _REPO / "tmp-payload.yar"


def compile_gate(source_lines: str) -> tuple:
    tmp = _REPO / "tmp-yara.yar"
    try:
        tmp.write_text(str(source_lines) + chr(10))
        out = subprocess.run([YARA_BIN, str(tmp), "/dev/null"],
                             capture_output=True, text=True, timeout=30)
        ok = out.returncode in (0, 1) and not out.stderr.strip()
        return ok, out.stderr.strip()
    except OSError:
        return False, "yara binary not available"
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def compile_and_test(source_lines: str, sample=None) -> tuple:
    tmp = _REPO / "tmp-yara.yar"
    try:
        tmp.write_text(source_lines + "\n")
        target = (str(sample) if sample and pathlib.Path(sample).exists()
                  else "/dev/null")
        out = subprocess.run([YARA_BIN, str(tmp), target],
                             capture_output=True, text=True, timeout=30)
        return (out.returncode in (0, 1)), out.stdout.strip() or out.stderr.strip()
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def build(rules: dict):
    lines = yara_source(rules)
    return {"rules": list(lines), "dir": str(RULES_DIR)}


def apply_rules(b, payload_path=_PAYLOAD):
    return None


def write_rule(name: str, source_lines, payload_path=_PAYLOAD):
    pathlib.Path(payload_path).write_text(source_lines + "\n")
    return common.run_helper("yara-write", [name])
