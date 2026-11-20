"""The scan request seam, from the UI side (owner 2026-11-18).

The writer lives in scan_session (the service owns its channel and both
the CLI and the chat file requests through the same function); this thin
module keeps the UI's import path stable and gi-free.
"""

from __future__ import annotations

from scan_session import (control_path, new_request_id, request_path,
                          write_control, write_request)


def request_scan(data_dir, key: str) -> tuple[bool, str]:
    """File one scan request. Returns (ok, the honest human note)."""
    return write_request(data_dir, key)


def control_scan(data_dir, action: str,
                 scan_id: str | None = None) -> tuple[bool, str]:
    """Pause, resume or cancel the one scan through the daemon's channel."""
    return write_control(data_dir, action, scan_id)
