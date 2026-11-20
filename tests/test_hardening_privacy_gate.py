import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_GATE_ITSELF = pathlib.Path(__file__).name
_PATTERN = re.compile(
    r"serial|uuid|hwid|dmidecode|/sys/class/net|\bMAC\b", re.IGNORECASE)
_ALLOWED_PHRASES = (
    "MAC-address pattern",
    "runtime observation of MAC addresses",
    "mac-in-repo",
    "REDACTED-MAC",
)


def _feature_files():
    files = sorted((_ROOT / "hardening").glob("*.py"))
    # the old ui/harden.py left with the 2026-11-15 rebuild; the NEW
    # page re-enters this gate when it lands (the hardening page file)
    if (_ROOT / "ui" / "harden.py").exists():
        files += [_ROOT / "ui" / "harden.py"]
    files += [_ROOT / "apply" / "harden.sh"]
    files += [_ROOT / "data" / "hardening-controls.json"]
    files += sorted((_ROOT / "tests").glob("test_hardening_*.py"))
    files += [pathlib.Path(__file__)]
    return [f for f in files if f.name != _GATE_ITSELF]


def _allowed(line):
    return any(phrase in line for phrase in _ALLOWED_PHRASES)


def test_feature_files_have_no_identifier_probing():
    assert _feature_files(), "gate found no feature files to scan"
    bad = []
    for path in _feature_files():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            bad.append(f"{path}:UNREADABLE ({exc.__class__.__name__})")
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if _PATTERN.search(line) and not _allowed(line):
                bad.append(f"{path}:{lineno}")
    assert not bad, f"identifier patterns found: {bad}"
