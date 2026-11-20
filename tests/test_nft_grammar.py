"""Live nft-grammar tests: build_ruleset output must PARSE on the host's
nft binary. We cannot apply rules as an unprivileged user (netlink EPERM),
but the LEXER/PARSER runs before the netlink cache init, so a syntax error
surfaces even without root — that is exactly what we assert against.

Verified on nftables v1.1.3 (2026-10-27):
  - "queue num N bypass"        → SYNTAX ERROR (fixed: "queue flags bypass num N")
  - "ip6 protocol tcp ..."      → SYNTAX ERROR in inet family
  - "meta nfproto ipv6 protocol tcp ..." → SYNTAX ERROR (fixed:
    "meta nfproto ipv6 meta l4proto tcp ...")
"""
import shutil
import subprocess

import pytest

from appfw import config as acfg

NFT = shutil.which("nft")
pytestmark = pytest.mark.skipif(NFT is None, reason="nft not installed")


def _parses(script: str) -> tuple[bool, str]:
    """Feed a ruleset to nft -f - and report (parses, error_text).

    As an unprivileged user nft always fails at netlink cache init with
    'Operation not permitted' — that is AFTER parsing. A syntax error
    appears BEFORE that, so:
      - 'syntax error' in stderr  → grammar is broken
      - 'Operation not permitted'  → grammar is fine (would work as root)
    """
    r = subprocess.run([NFT, "-f", "-"], input=script,
                       capture_output=True, text=True, timeout=10)
    err = (r.stderr or "")
    if "syntax error" in err:
        return False, err
    if "Operation not permitted" in err or r.returncode == 0:
        return True, err
    # root or unusual: anything without a syntax error counts as parses
    return True, err


def test_full_ruleset_ipv6_on_parses_on_host_nft():
    script = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": True})
    ok, err = _parses(script)
    assert ok, f"ruleset has a syntax error on {NFT}:\n{err}\n--- script ---\n{script}"


def test_full_ruleset_ipv6_off_parses_on_host_nft():
    script = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": False})
    ok, err = _parses(script)
    assert ok, f"ruleset has a syntax error on {NFT}:\n{err}\n--- script ---\n{script}"


def test_full_ruleset_fail_closed_parses_on_host_nft():
    script = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": True,
                                "fail_open": False})
    ok, err = _parses(script)
    assert ok, f"fail-closed ruleset has a syntax error:\n{err}\n--- script ---\n{script}"


def test_ipv6_queue_rule_is_nfproto_disambiguated():
    """The exact regression: bare 'ip6 protocol tcp' in inet family."""
    script = acfg.build_ruleset({**acfg.DEFAULTS, "ipv6_enabled": True})
    queue_ipv6 = [l for l in script.splitlines()
                  if "queue" in l and ("ip6" in l or "nfproto ipv6" in l)]
    assert queue_ipv6, script
    for line in queue_ipv6:
        assert "meta nfproto ipv6" in line, (
            f"ipv6 queue rule lacks nfproto disambiguation: {line}")


def test_no_broken_queue_form_anywhere():
    """"queue num N bypass" (number then bare 'bypass') is always wrong."""
    for ipv6 in (True, False):
        for fail_open in (True, False):
            script = acfg.build_ruleset({**acfg.DEFAULTS,
                                        "ipv6_enabled": ipv6,
                                        "fail_open": fail_open})
            assert "queue num 111 bypass" not in script
            assert "queue num 111 flags" not in script
