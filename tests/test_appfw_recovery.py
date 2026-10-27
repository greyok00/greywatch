"""App-firewall recovery: the engine must arm when the kernel queue
modules are available, and its failure notices must be deduplicated so a
persistently failing engine cannot flood the event feed."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _source(obj) -> str:
    """Source text of a function/method that works for BOTH pure-Python
    (inspect.getsource) and Cython-compiled (no __code__ → TypeError)
    modules. Falls back to reading the .py file from disk."""
    import inspect
    try:
        return inspect.getsource(obj)
    except TypeError:
        # Cython-compiled: inspect can't get the source. Read the .py.
        # mod.__file__ is e.g. ".../engine.cpython-312-x86_64-linux-gnu.so"
        # — strip the FULL extension chain back to the .py sibling.
        mod = inspect.getmodule(obj)
        if mod is None or not getattr(mod, "__file__", None):
            raise
        py = pathlib.Path(mod.__file__)
        # strip .cpython-312-x86_64-linux-gnu.so → .py
        while py.suffix and py.suffix != ".py":
            py = py.with_suffix("")
        py = py.with_suffix(".py")
        if py.exists():
            return py.read_text(encoding="utf-8")
        raise


def test_install_nft_loads_queue_modules_first():
    from appfw import engine
    src = _source(engine.Engine._install_nft)
    assert "_ensure_queue_module" in src
    # the queue modules the 'queue' statement needs are loaded explicitly
    mod_src = _source(engine.Engine._ensure_queue_module)
    assert "nfnetlink_queue" in mod_src
    assert "nft_queue" in mod_src


def test_install_nft_surfaces_the_real_error():
    from appfw import engine
    src = _source(engine.Engine._install_nft)
    # the raw nft stderr is surfaced, not swallowed as a bare "OFF"
    assert "nftables install failed" in src
    assert "detail" in src


def test_engine_start_does_not_emit_a_second_generic_failure():
    from appfw import engine
    src = _source(engine.Engine.start)
    # _install_nft already emitted the detailed reason; start() must not
    # add a vague duplicate that the deduper would then repeat
    assert "nftables install failed — OFF" not in src


def test_daemon_appfw_event_deduplicates_identical_notices(tmp_path):
    import greywatch_daemon as gd
    d = gd.Daemon(data_dir=tmp_path / "data", registry=[])
    d._appfw_event("appfw engine: nftables install failed — OFF")
    d._appfw_event("appfw engine: nftables install failed — OFF")
    d._appfw_event("appfw engine: nftables install failed — OFF")
    d.flush_outbox()
    evs = gd.read_events(d.events_path)
    fails = [e for e in evs if "nftables install failed" in e["text"]]
    assert len(fails) == 1, f"expected 1 deduped notice, got {len(fails)}"


def test_daemon_appfw_event_lets_distinct_notices_through(tmp_path):
    import greywatch_daemon as gd
    d = gd.Daemon(data_dir=tmp_path / "data", registry=[])
    d._appfw_event("appfw engine: reason A — OFF")
    d._appfw_event("appfw engine: reason B — OFF")
    d.flush_outbox()
    evs = gd.read_events(d.events_path)
    assert len(evs) == 2


def test_rulestore_survives_inaccessible_rules_dir(tmp_path, monkeypatch):
    """Regression: RuleStore must NOT crash when the rules dir is
    unreadable (e.g. root-owned 0700 dir probed by a non-root process).
    Before the fix, p.exists() raised PermissionError and took the
    whole Engine.__init__ down with it."""
    import os
    from appfw.rules import RuleStore
    rules_dir = tmp_path / "appfw" / "rules"
    rules_dir.mkdir(parents=True)
    # make the dir unreadable to us: remove all permissions
    # (simulates a root-only dir seen by grey; on CI we are the owner
    # so chmod 000 works)
    os.chmod(rules_dir, 0o000)
    try:
        store = RuleStore(rules_dir)     # must not raise
        assert store.load_errors          # errors recorded, not crashed
        assert len(store._allow) == 0
        assert len(store._deny) == 0
    finally:
        os.chmod(rules_dir, 0o755)      # let tmp_path cleanup work
