"""Engine mode switch (review C2): one scheduling/verdict authority.

"nfqueue" (default, safe) keeps the shipped worker lane; "nft-scope"
retires the NFQUEUE worker, swaps the greywatch2 table, and routes the
catch path through decide(). Dual-table operation is forbidden on an
armed machine.
"""
from __future__ import annotations

import json

import pytest

import appfw.config as config


def test_mode_defaults_to_nfqueue(tmp_path):
    assert config.engine_mode(tmp_path) == "nfqueue"


def test_mode_reads_config(tmp_path):
    from appfw import atomicio
    p = config.config_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    atomicio.write_json_atomic(p, {"mode": "nft-scope"})
    assert config.engine_mode(tmp_path) == "nft-scope"


def test_mode_rejects_unknown_values(tmp_path):
    from appfw import atomicio
    p = config.config_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    atomicio.write_json_atomic(p, {"mode": "suricata"})
    assert config.engine_mode(tmp_path) == "nfqueue"   # refuse to guess
