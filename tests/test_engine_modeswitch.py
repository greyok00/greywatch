"""Engine arm respects the mode switch (review C2): nft-scope runs
worker-less (kernel lane + catch tailer); nfqueue keeps the shipped
worker. Dual-table operation is the forbidden state.
"""
from __future__ import annotations

import appfw.config as config
import appfw.engine as engine_mod


def _write_mode(tmp_path, mode):
    from appfw import atomicio
    cp = config.config_path(tmp_path)
    cp.parent.mkdir(parents=True, exist_ok=True)
    atomicio.write_json_atomic(cp, {"mode": mode})


def test_nft_scope_mode_reports_kernel_lane(tmp_path):
    _write_mode(tmp_path, "nft-scope")
    assert engine_mod._queue_lane_mode(tmp_path) == "nft-scope"


def test_default_mode_keeps_queue_lane(tmp_path):
    assert engine_mod._queue_lane_mode(tmp_path) == "nfqueue"


def test_unknown_mode_falls_back_to_queue_lane(tmp_path):
    _write_mode(tmp_path, "suricata")
    assert engine_mod._queue_lane_mode(tmp_path) == "nfqueue"
