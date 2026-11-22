
def test_scan_finding_auto_quarantines(tmp_path):
    import importlib.util
    import pathlib
    spec = importlib.util.spec_from_file_location(
        "svcmod", str(pathlib.Path(__file__).resolve().parents[1]
                      / "scan_session.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    calls = []
    class FakeSvc:
        _EXEMPT_SEGMENTS = mod.ScanService._EXEMPT_SEGMENTS

        def log(self, msg):
            calls.append(("log", msg))

        def _run_file_action(self, action, target):
            calls.append(("action", action, target))
    svc = FakeSvc()
    real = "/tmp/fake-evil-file-that-exists.txt"
    pathlib.Path(real).write_text("x")
    mod.ScanService._auto_quarantine(
        svc, "clamav",
        {"severity": "HIGH", "text": real + ": Win.Trojan.X FOUND"})
    assert ("action", "quarantine", real) in calls, calls
    # exempt: the suite's own scratch path states itself, no action
    calls.clear()
    junk = "/tmp/pytest-of-grey/pytest-8/x: Eicar-Test-Signature FOUND"
    mod.ScanService._auto_quarantine(
        svc, "clamav", {"severity": "HIGH", "text": junk})
    assert calls and calls[-1][0] == "log", calls


def test_unicornscan_pentest_payloads_never_quarantined():
    """The owner's pentest tool ships its own payloads; a flag on that
    path reads and acts as the known-benign case (2026-11-11 verdict)."""
    import importlib.util
    import pathlib
    spec = importlib.util.spec_from_file_location(
        "s2", str(pathlib.Path(__file__).resolve().parents[1]
                  / "scan_session.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    calls = []

    class Svc:
        _EXEMPT_SEGMENTS = mod.ScanService._EXEMPT_SEGMENTS

        def log(self, msg):
            calls.append(("log", msg))

        def _run_file_action(self, action, target):
            calls.append(("action", action, target))
    Svc._auto_quarantine = mod.ScanService._auto_quarantine
    Svc()._auto_quarantine(
        "clamav",
        {"severity": "HIGH",
         "text": "/etc/unicornscan/payloads.conf: Py.Trojan.NecroBot FOUND"})
    assert "unicornscan" in calls[-1][1]
    assert not any(c[0] == "action" for c in calls)
