"""Tests for notifyd.py."""
from __future__ import annotations
import json, pathlib, tempfile, time, unittest
from unittest import mock

class TestNotifyd(unittest.TestCase):
    def _prefs(self, data_dir, prefs):
        (data_dir / "greywatch-ui-settings.json").write_text(json.dumps(prefs))

    def _alive(self, on):
        return lambda: on

    def test_off_prefs_no_call(self):
        with tempfile.TemporaryDirectory() as td:
            dd = pathlib.Path(td)
            self._prefs(dd, {"alerts": False})
            import notifyd
            notifyd._burst_at.clear(); notifyd._dedup_at.clear()
            with mock.patch("notifyd.subprocess.Popen") as mp:
                notifyd.notify("self-heal", "HIGH", "disk full", dd, "grey", self._alive(False))
                mp.assert_not_called()

    def test_snooze_no_call(self):
        with tempfile.TemporaryDirectory() as td:
            dd = pathlib.Path(td)
            self._prefs(dd, {"alerts": True, "alerts_snooze_until": time.time() + 3600})
            import notifyd
            notifyd._burst_at.clear(); notifyd._dedup_at.clear()
            with mock.patch("notifyd.subprocess.Popen") as mp:
                notifyd.notify("self-heal", "HIGH", "disk full", dd, "grey", self._alive(False))
                mp.assert_not_called()

    def test_medium_no_call(self):
        with tempfile.TemporaryDirectory() as td:
            dd = pathlib.Path(td)
            self._prefs(dd, {"alerts": True})
            import notifyd
            notifyd._burst_at.clear(); notifyd._dedup_at.clear()
            with mock.patch("notifyd.subprocess.Popen") as mp:
                notifyd.notify("self-heal", "MEDIUM", "event", dd, "grey", self._alive(False))
                mp.assert_not_called()

    def test_two_high_one_call(self):
        with tempfile.TemporaryDirectory() as td:
            dd = pathlib.Path(td)
            self._prefs(dd, {"alerts": True})
            import notifyd
            notifyd._burst_at.clear(); notifyd._dedup_at.clear()
            with mock.patch("notifyd.subprocess.Popen") as mp:
                mp.return_value = mock.Mock()
                notifyd.notify("self-heal", "HIGH", "event one", dd, "grey", self._alive(False))
                notifyd.notify("self-heal", "HIGH", "event two", dd, "grey", self._alive(False))
                self.assertEqual(mp.call_count, 1)

    def test_gui_alive_no_call(self):
        with tempfile.TemporaryDirectory() as td:
            dd = pathlib.Path(td)
            self._prefs(dd, {"alerts": True})
            import notifyd
            notifyd._burst_at.clear(); notifyd._dedup_at.clear()
            with mock.patch("notifyd.subprocess.Popen") as mp:
                notifyd.notify("self-heal", "HIGH", "event", dd, "grey", self._alive(True))
                mp.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)
