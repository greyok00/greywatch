"""Global privacy grep gate over the whole hardening feature's files:
no hardware-identifier probing (serial numbers, UUIDs, MACs, /sys/class/net,
dmidecode) anywhere in the feature's source. Case-insensitive regex on
the tracked files themselves. This gate file is excluded from its own
scan — it necessarily contains the pattern text.

Rules:
- An unreadable/unscannable file is a recorded BAD entry, never a silent
  continue — a gate cannot honestly pass on files it never saw.
- The only allowed hits are the exact literal phrases below: they are
  the product's own privacy vocabulary (the controls.json policy texts,
  the mac-in-repo control ID used as an identifier in code/tests, and
  the REDACTED-MAC banlist token) — not identifier probing.
"""
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_GATE_ITSELF = pathlib.Path(__file__).name
_PATTERN = re.compile(
    r"serial|uuid|hwid|dmidecode|/sys/class/net|\bMAC\b", re.IGNORECASE)
_ALLOWED_PHRASES = (
    # controls.json policy texts (what the rule SAYS, not a probe):
    "MAC-address pattern",
    "runtime observation of MAC addresses",
    # the advisory control's ID, referenced as an identifier:
    "mac-in-repo",
    # the redaction banlist token in the content gate:
    "REDACTED-MAC",
)


def _feature_files():
    files = sorted((_ROOT / "hardening").glob("*.py"))
    files += [_ROOT / "ui" / "harden.py", _ROOT / "apply" / "harden.sh"]
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
            # Unreadable = unverifiable = recorded BAD, never a silent
            # continue: the gate must fail loudly, not pass blind.
            bad.append(f"{path}:UNREADABLE ({exc.__class__.__name__})")
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if _PATTERN.search(line) and not _allowed(line):
                bad.append(f"{path}:{lineno}")
    assert not bad, f"identifier patterns found: {bad}"
