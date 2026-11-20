"""Bug-sweep sizing guards that need no display: the wizard's task-dialog
scale and the scanner's no-scan tolerance.

- wizard_size(): half the screen is gone (GW-171, owner): the task window
  takes 0.36 of the width / 0.62 of the height, inside the 640..760 x
  540..700 clamps, on a 1080p panel and a 4K one alike.
- inventory_lines(): a missing scan is an empty answer, never a crash
  (the preview step used to hit None.get and take the wizard down).
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.metrics import span, window_size, wizard_size  # noqa: E402
from wizard.inventory import inventory_lines  # noqa: E402


def test_wizard_size_is_task_dialog_scale():
    # Equal to span() of the real screen at the design fractions, so the
    # numbers move with the display and stay inside the clamps.
    from ui.metrics import screen_size
    sw, sh = screen_size()
    assert wizard_size() == (span(sw or 1920, 0.36, 640, 760),
                             span(sh or 1080, 0.62, 540, 700))


def test_wizard_size_bounds_hold_at_extremes():
    for sw, sh in ((800, 600), (1280, 720), (2560, 1440), (3840, 2400)):
        w, h = wizard_size()
        assert 640 <= w <= 760
        assert 540 <= h <= 700


def test_wizard_stays_below_the_dashboard_window():
    ww, wh = window_size()
    hw, hh = wizard_size()
    assert hw < ww and hh < wh


def test_span_clamps():
    assert span(1000, 0.5, 200, 900) == 500
    assert span(1000, 0.5, 200, 450) == 450


def test_inventory_lines_without_a_scan_is_empty():
    assert inventory_lines(None) == []
    assert inventory_lines("nope") == []
    assert inventory_lines(42) == []


def test_inventory_lines_with_a_scan_reports_packages():
    scan = {
        "packages": {"openssh-server": True},
        "ufw_status": "inactive",
        "ipv6_disable": None,
        "facts": {
            "listening_ports": None,
            "services_running": None,
            "disk_encrypted": None,
            "desktop": None,
            "laptop": None,
        },
    }
    lines = inventory_lines(scan)
    assert any("SSH server" in line and "installed" in line for line in lines)
    assert any("UFW firewall" in line for line in lines)