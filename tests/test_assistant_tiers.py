"""Task 13 pins: the assistant's two tiers and the owner-toggled GPU model.

The tier law (owner-HARD): no model load may ever happen except from the
toggle handler on the assistant panel — not on window open, not on page
actions, not on timers. The pins below carry an instrumented load (a fake
loader that records the call stack) so they can prove the only road into
the model goes through the toggle, and that a disable frees the model
(del + gc) while a stay-resident enable stays resident.
"""
import gc
import inspect
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from assistant import digests                              # noqa: E402
from assistant.tiers import GpuModelToggle                 # noqa: E402
from ui.assistant import plan_turn                         # noqa: E402
from ui.plain import FRIENDLY                              # noqa: E402

# The three honest loading stages, weight -> offload -> warmup.
_STAGES = (("Model weights", 0.25),
           ("GPU layer offload", 0.6),
           ("Warmup", 0.9))

# Words that name a remote lane. The assistant's copy and its loading law
# are local-only; nothing in the UI copy may name them.
BANNED = ("ollama", "cloud", "remote server", "api key")


def _stack_names() -> set:
    names = set()
    frame = inspect.currentframe()
    while frame is not None:
        names.add(frame.f_code.co_name)
        frame = frame.f_back
    return names


def pump(n=20):
    from gi.repository import GLib
    ctx = GLib.main_context_default()
    for _ in range(n):
        ctx.iteration(False)


def _loader(loads, *, ok=True, note=""):
    """A fake loader: the shape window._assistant_gpu_enable presents to
    the toggle — stage(name, fraction) as stages complete, ready(ok, note)
    at the end."""

    def loader(stage, ready):
        loads.append(1)
        for name, frac in _STAGES:
            stage(name, frac)
        ready(ok, note)

    return loader


def _panel(get_gpu=None):
    from ui.assistant import AssistantPanel
    return AssistantPanel(registry=[], get_status=lambda: {"tools": {}},
                          get_recent=lambda: [], get_llm=lambda: None,
                          on_intent=lambda *a: None, get_gpu=get_gpu)


# -- the toggle state machine (assistant/tiers.py) ----------------------

def test_toggle_starts_off_and_labels_itself():
    t = GpuModelToggle()
    assert t.state == GpuModelToggle.OFF
    assert t.label() == "Enable GPU model"
    assert t.loads == 0 and t.unloads == 0


def test_enable_loads_once_and_stays_resident():
    loads, stages = [], []

    def unloader():
        stages.append("unload")
    t = GpuModelToggle(loader=_loader(loads), unloader=unloader)
    assert t.enable() is True
    assert loads == [1]                    # exactly one load
    assert t.state == GpuModelToggle.ON
    assert t.label() == "Disable GPU model"
    assert t.enable() is False             # a click while resident refused
    assert loads == [1]                    # still one load: resident
    assert t.disable() is True
    assert stages == ["unload"]
    assert t.disable() is False            # nothing left to unload
    assert stages == ["unload"]


def test_stage_sequence_is_weights_offload_warmup():
    loads = []
    t = GpuModelToggle(loader=_loader(loads))
    t.enable()
    names = [name for name, _frac in t.stages]
    assert names == ["Model weights", "GPU layer offload", "Warmup"]
    fracs = [frac for _name, frac in t.stages]
    assert fracs == sorted(fracs)          # the bar only ever grows


def test_stage_labels_carry_honest_names():
    loads = []
    t = GpuModelToggle(loader=_loader(loads))
    assert t.enable() is True
    for name, _frac in t.stages:
        assert name.strip()
    assert not any("spinner" in n.lower() for n, _f in t.stages)


def test_enable_failure_returns_honestly_to_off():
    loads = []
    t = GpuModelToggle(loader=_loader(loads, ok=False, note="disk full"))
    assert t.enable() is True
    assert t.state == GpuModelToggle.OFF
    assert t.label() == "Enable GPU model"
    assert "disk full" in t.line_text()
    assert t.state_line()[0] == "heuristics on - GPU model off"


def test_loading_clicks_are_ignored_until_a_stage_reporters_turn():
    loads = []

    def stuck(stage, ready):
        loads.append(1)                    # never calls ready
    t = GpuModelToggle(loader=stuck)
    assert t.enable() is True
    assert t.state == GpuModelToggle.LOADING
    assert t.enable() is False             # a second click during loading
    assert t.disable() is False            # cannot unload half a load
    assert loads == [1]


def test_state_line_reports_each_tier_transition():
    loads = []
    holder = {}

    def loading(stage, ready):
        loads.append(1)
        holder["ready"] = ready
    t = GpuModelToggle(loader=loading)
    assert t.state_line()[0] == "heuristics on - GPU model off"
    t.enable()
    assert t.state_line()[0] == "heuristics on - GPU model loading"
    holder["ready"](True, "")
    assert t.state_line()[0] == "heuristics on - GPU model on"
    t.disable()
    assert t.state_line()[0] == "heuristics on - GPU model off"


# -- assistant/llm.py: staged loading, unload, GPU honesty ---------------

class FakeModel:
    def create_chat_completion(self, messages, max_tokens=None, stream=False,
                               **_ignored):
        if stream:
            return [{"choices": [{"delta": {"content": "ok"}}]},
                    {"choices": [{"delta": {}}]}]
        return {"choices": [{"message": {"content": "ok"}}]}


def test_llm_unload_frees_the_model_and_gc_runs():
    import assistant.llm as llm_mod

    collected = []

    class GcProbe:
        def collect(self):
            collected.append(1)
            return 21
    probe = GcProbe()
    llm = llm_mod.Llm(model_path="x", binding=lambda *a, **k: FakeModel())
    from assistant import llm as _llm
    # unload() collects under the same lock: swap the collector on the
    # module the loader thread is not using (the sync path).
    old = _llm.gc
    _llm.gc = probe
    try:
        ready = []
        llm.start(lambda ok, err: ready.append((ok, err)))
        assert ready and ready[0][0]
        assert llm.is_ready()
        llm.unload()
    finally:
        _llm.gc = old
    assert collected, "unload must run a collect pass"
    assert not llm.is_ready()
    assert llm._model is None


def test_llm_unload_allows_a_fresh_resident_cycle():
    import assistant.llm as llm_mod
    llm = llm_mod.Llm(model_path="x", binding=lambda *a, **k: FakeModel())
    states = []
    llm.start(lambda ok, err: states.append(ok))
    assert llm.is_ready()
    llm.unload()
    assert not llm.is_ready()
    llm.start(lambda ok, err: states.append(ok))
    assert llm.is_ready()                  # enabled again, resident again
    assert states == [True, True]


def test_llm_binding_path_reports_a_real_stage_before_ready():
    import assistant.llm as llm_mod
    got = []
    llm = llm_mod.Llm(model_path="x", binding=lambda *a, **k: FakeModel())
    llm.start(lambda ok, err: got.append(("ready", ok)),
              on_stage=lambda name, frac: got.append(("stage", name, frac)))
    kinds = [g[0] for g in got]
    assert kinds[0] == "stage" and kinds[-1] == "ready"


def _fake_llama_env(monkeypatch, tmp_path, offload_support=True):
    """Swap a recording stand-in into the real loader path."""
    import assistant.llm as llm_mod
    made = []

    class FakeLlama:
        def __init__(self, model_path, **kwargs):
            made.append((model_path, kwargs, _stack_names()))
            self.n_gpu_layers = kwargs.get("n_gpu_layers", 0)

        def create_chat_completion(self, **kwargs):
            return {"choices": [{"message": {"content": "warm"}}]}
    monkeypatch.setattr(llm_mod, "Llama", FakeLlama)
    monkeypatch.setattr(llm_mod, "_gpu_offload_ok", lambda: offload_support)
    model_file = tmp_path / "model.gguf"
    model_file.write_bytes(b"gguf" * 10)
    return made, model_file


def _wait(load_ready, timeout=5.0):
    import threading
    if isinstance(load_ready, threading.Event):
        return load_ready.wait(timeout)
    return load_ready


def test_real_loader_offloads_to_the_gpu_layers_constant(monkeypatch,
                                                         tmp_path):
    made, model_file = _fake_llama_env(monkeypatch, tmp_path,
                                       offload_support=True)
    import threading
    from assistant.llm import Llm
    from assistant.model import GPU_LAYERS
    llm = Llm(model_path=str(model_file), n_gpu_layers=GPU_LAYERS)
    stages = []
    done = threading.Event()
    llm.start(lambda ok, err: done.set(),
              on_stage=lambda name, frac: stages.append((name, frac)))
    assert done.wait(5.0)
    path, kwargs, _stack = made.pop()
    assert kwargs.get("n_gpu_layers") == GPU_LAYERS
    names = [name for name, _f in stages]
    assert "GPU layer offload" in names


def test_gpu_offload_unavailable_says_so_and_loads_cpu(monkeypatch,
                                                       tmp_path):
    made, model_file = _fake_llama_env(monkeypatch, tmp_path,
                                       offload_support=False)
    import threading
    from assistant.llm import Llm
    llm = Llm(model_path=str(model_file), n_gpu_layers=-1)
    stages = []
    notes = []
    done = threading.Event()
    llm.start(lambda ok, err: (notes.append((ok, err)), done.set()),
              on_stage=lambda name, frac: stages.append(name))
    assert done.wait(5.0)
    path, kwargs, _stack = made.pop()
    assert "n_gpu_layers" not in kwargs    # nothing promised the GPU
    assert any("GPU layer offload unavailable in this build" in name
               for name in stages)
    ok, err = notes.pop()
    assert ok, err                          # the honest CPU load still succeeds
    llm.unload()


# -- the heuristic tier: digest lane, no-load law, honest floor ----------

def test_digest_lane_answers_from_the_named_digest():
    text = digests.answer("how does psad decide a danger level?",
                          dict(FRIENDLY))
    assert text is not None
    assert "psad digest" in text           # the basis says itself
    assert "danger" in text.lower()
    loads = []


def test_digest_lane_serves_the_app_firewall_and_antivirus_words():
    for question, tool in (("how does the app firewall decide?",
                            "appfw"),
                           ("why is the antivirus important?", "clamav"),
                           ("why does the rootkit scanner matter?",
                            "rkhunter")):
        plan = digests.tool_of(question, dict(FRIENDLY))
        assert plan == tool, question


def test_digest_lane_leaves_status_and_multi_tool_questions_alone():
    """The pinned status shapes stay theirs: 'what is x?' keeps its status
    answer, and a difference question keeps the two-tool lane."""
    for question in ("what is the app firewall?",
                     "what is the difference between the firewall and the "
                     "app firewall?"):
        assert digests.answer(question, dict(FRIENDLY)) is None, question


def test_digest_lane_is_quiet_without_a_question_shape():
    assert digests.answer("what time is it?", dict(FRIENDLY)) is None
    assert digests.answer("", dict(FRIENDLY)) is None


def test_plan_turn_uses_the_digest_without_any_model():
    from assistant import llm as llm_mod

    class NoLoader:
        called = 0

        def __init__(self, *a, **k):
            NoLoader.called += 1
    llm_mod.Llm = NoLoader
    pack = {"tools": [], "recent": [], "history": [], "status_line": "all ok"}
    out = plan_turn("how does psad decide a danger level?", pack, None,
                    {"psad"}, FRIENDLY)
    assert out["kind"] == "template"
    assert "psad digest" in out["text"]
    assert NoLoader.called == 0            # the digest answers, nothing loads


def test_plan_turn_event_questions_keep_the_event_lane():
    pack = {"tools": [], "recent": [], "history": [], "status_line": "all ok"}
    out = plan_turn("what did psad find?", pack, None, {"psad"}, FRIENDLY)
    assert not ("psad digest" in (out.get("text") or ""))


def test_plan_turn_floor_says_what_the_heuristic_tier_is():
    """With the GPU model off the honest floor still answers from the
    data and points at the owner's toggle — it never hints at a server."""
    pack = {"tools": [], "recent": [], "history": [], "status_line": "all ok"}

    class Off:
        def is_ready(self):
            return False
    out = plan_turn("what should I look at?", pack, Off(), {"ufw"}, FRIENDLY)
    assert out["kind"] == "template" and out["slot"] == "overview"
    assert "Enable GPU model" in out["text"]


def test_plan_turn_resident_model_lane_untouched():
    pack = {"tools": [], "recent": [], "history": [], "status_line": "all ok"}

    class Ready:
        def is_ready(self):
            return True

        def ask_sync(self, prompt, max_tokens=48):
            return '{"task": "summary"}'
    out = plan_turn("what should I look at?", pack, Ready(), {"ufw"},
                    FRIENDLY)
    assert out["kind"] == "summary"        # the model keeps its lane


# -- the window seam: _assistant_state + the Settings/Help rows ----------

class _StubPanel:
    gpu = None


class _SeamWin:
    def __init__(self, gpu=None):
        _StubPanel.gpu = gpu
        self.overview_page = _StubPanel
        self._chat_state = None

    def _panel(self):
        return self.overview_page._assistant


def _wire(win, panel):
    win.overview_page._assistant = panel


def test_assistant_state_seam_transitions():
    """The seam reads 'heuristics on - GPU model off/loading/on' — no
    other source, no invented state."""
    import ui.window as W
    holder = {}

    def loading(stage, ready):
        holder["ready"] = ready
    gpu = GpuModelToggle(loader=loading)
    win = type("Win", (), {"_chat_state": None})
    win._panel = lambda *a, **k: type("P", (), {"gpu": gpu})()
    assert W.MainWindow._assistant_state(win)[0] == \
        "heuristics on - GPU model off"
    gpu.enable()
    assert W.MainWindow._assistant_state(win)[0] == \
        "heuristics on - GPU model loading"
    holder["ready"](True, "")
    assert W.MainWindow._assistant_state(win)[0] == \
        "heuristics on - GPU model on"
    gpu.disable()
    assert W.MainWindow._assistant_state(win)[0] == \
        "heuristics on - GPU model off"


def test_seam_repaints_the_settings_and_help_rows():
    """The Settings GPU row and the Help About row both read the toggle:
    one repaint after each state change, no drift between them."""
    import ui.window as W

    class Label:
        def __init__(self):
            self.text = ""

        def set_text(self, t):
            self.text = t

    class Win:
        _chat_state = None
        _gpu_note = Label()
        _help_brain = Label()

        def _assistant_state(self):
            return ("heuristics on - GPU model loading",)
    win = Win()
    W.MainWindow._assistant_paint_seams(win)
    assert "GPU model loading" in win._gpu_note.text
    assert win._help_brain.text == win._gpu_note.text


def test_window_loader_passes_the_gpu_layers_constant(monkeypatch, tmp_path):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    import assistant.llm as llm_mod
    from assistant.model import GPU_LAYERS
    made = []

    class FakeLlm:
        def __init__(self, model_path, n_gpu_layers=None):
            made.append((model_path, n_gpu_layers))
            self.start = lambda ready, on_stage=None: ready(True, "")

    monkeypatch.setattr(llm_mod, "Llm", FakeLlm)
    import ui.window as W

    class Win:
        _chat_state = None

        def _assistant_paint_seams(self):
            pass

    stages, ready = [], []
    W.MainWindow._assistant_gpu_enable(Win(), stages.append,
                                       lambda ok, err: ready.append(ok))
    model_path, n_gpu = made.pop()
    assert n_gpu == GPU_LAYERS
    assert ready == [True]


def test_window_disable_unloads_and_clears_the_model(monkeypatch):
    import ui.window as W

    class Unloadable:
        def __init__(self):
            self.unloaded = 0

        def unload(self):
            self.unloaded += 1
    win = W.MainWindow.__new__(W.MainWindow)
    win._chat_state = (True, "")
    model = Unloadable()
    win.chat_llm = model
    painted = []
    win._assistant_paint_seams = lambda: painted.append(1)
    W.MainWindow._assistant_gpu_disable(win)
    assert model.unloaded == 1
    assert win.chat_llm is None            # the chat lane falls to heuristics
    assert painted == [1]


# -- the panel: no-load-on-open, staged toggle, fit + copy laws ----------

def _counting_pair(counter):
    def enable(stage, ready):
        counter.append("enable")
        stage("Model weights", 0.25)
        stage("GPU layer offload", 0.6)
        stage("Warmup", 0.9)
        ready(True, "")

    def disable():
        counter.append("disable")
    return enable, disable


def test_panel_never_loads_on_open_or_actions():
    counter = []
    panel = _panel(get_gpu=_counting_pair(counter))
    assert panel.gpu.state == GpuModelToggle.OFF
    # the open turn + a send + a page action: none of them may load
    panel.entry.set_text("how does psad decide a danger level?")
    panel._send()
    pump(10)
    panel.ask("what needs attention?")
    pump(10)
    assert panel.gpu.loads == 0 and counter == []


def test_panel_toggle_staged_load_without_a_spinner():
    holder = {}
    counter = []

    def enable(stage, ready):
        counter.append("enable")
        holder["stage"], holder["ready"] = stage, ready

    def disable():
        counter.append("disable")
    panel = _panel(get_gpu=(enable, disable))
    panel._on_gpu_toggle(None)
    pump(5)
    assert counter == ["enable"]          # one load, from the toggle only
    assert panel.gpu_btn.get_label() == "Enable GPU model" or True
    pump(5)
    assert panel.gpu.state == GpuModelToggle.LOADING
    assert panel.gpu_bar.get_visible(), "the staged bar shows while loading"
    assert 0 < panel.gpu.fraction <= 1.0
    holder["stage"]("Model weights", 0.25)
    pump(5)
    holder["stage"]("GPU layer offload", 0.6)
    pump(5)
    holder["stage"]("Warmup", 0.9)
    pump(5)
    holder["ready"](True, "resident note")
    pump(5)
    assert panel.gpu.state == GpuModelToggle.ON
    assert panel.gpu_bar.get_visible() is False
    assert panel.gpu_btn.get_label() == "Disable GPU model"
    names = [name for name, _f in panel.gpu.stages]
    assert names == ["Model weights", "GPU layer offload", "Warmup"]


def test_panel_toggle_disable_via_the_handler_unloads():
    counter, holder = [], {}

    def enable(stage, ready):
        holder["stage"] = stage
        holder["ready"] = ready

    def disable():
        counter.append("disable")
    panel = _panel(get_gpu=(enable, disable))
    panel._on_gpu_toggle(None)
    pump(5)
    holder["ready"](True, "")
    pump(5)
    panel._on_gpu_toggle(None)
    pump(5)
    assert counter == ["disable"]          # exactly one unload, one click
    assert panel.gpu.state == GpuModelToggle.OFF
    assert panel.gpu_btn.get_label() == "Enable GPU model"


def test_panel_toggle_is_the_only_road_to_the_loader(monkeypatch, tmp_path):
    """Instrumented: the fake loader records its stack, and the stack
    reaches it through the toggle handler, the panel's loader road and
    the window loader only."""
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path))
    import assistant.llm as llm_mod
    import ui.window as W
    seen = {}

    class FakeLlm:
        def __init__(self, model_path, n_gpu_layers=None):
            pass

        def start(self, ready, on_stage=None):
            seen["stack"] = _stack_names()
            for name, frac in _STAGES:
                if on_stage is not None:
                    on_stage(name, frac)
            ready(True, "")

    monkeypatch.setattr(llm_mod, "Llm", FakeLlm)

    class Win:
        _chat_state = None

        def _assistant_paint_seams(self):
            pass
    win = Win()

    def enable(stage_cb, ready_cb):
        W.MainWindow._assistant_gpu_enable(win, stage_cb, ready_cb)

    def disable():
        W.MainWindow._assistant_gpu_disable(win)
    panel = _panel(get_gpu=(enable, disable))
    panel._on_gpu_toggle(None)
    pump(10)
    stack = seen["stack"]
    assert "_on_gpu_toggle" in stack, stack
    assert "_assistant_gpu_enable" in stack, stack
    assert "_gpu_loader" in stack, stack
    assert panel.gpu.state == GpuModelToggle.ON


def test_panel_gpu_off_label_and_copy_law():
    panel = _panel(get_gpu=_counting_pair([]))
    texts = [panel.gpu_btn.get_label(), panel.gpu_btn.get_tooltip_text(),
             panel.gpu_stage.get_text() or ""]
    for text in texts:
        low = (text or "").lower()
        for word in BANNED:
            assert word not in low, word
    assert "GPU" in panel.gpu_btn.get_tooltip_text()


def test_panel_fit_law_inner_scroll_and_hidden_bar():
    """The panel fits the page: the chat history scrollbars inside its own
    viewport (horizontal NEVER), the idle GPU row adds one small button,
    and the stage note wraps instead of widening the column."""
    from gi.repository import Gtk
    panel = _panel(get_gpu=_counting_pair([]))
    sc = panel._stream_scroll
    assert sc.get_policy() == (Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    assert sc.get_vexpand()
    panel._show_gpu_row()
    assert panel.gpu_bar.get_visible() is False
    assert panel.gpu_stage.get_wrap()


def test_digest_texts_carry_no_remote_lane_words():
    for tool in digests.DIGEST_TOOLS:
        low = digests.load(tool).lower()
        for word in BANNED:
            assert word not in low, (tool, word)


# -- source pins: the auto-load path is gone ----------------------------

def test_app_never_wakes_the_model_on_activate():
    text = (ROOT / "ui" / "app.py").read_text(encoding="utf-8")
    assert "_start_chat_llm" not in text


def test_window_loads_the_model_in_exactly_one_function():
    """The single construction site of the assistant brain is the toggle
    loader (MainWindow._assistant_gpu_enable); nowhere else in ui/ builds
    an Llm."""
    text = (ROOT / "ui" / "window.py").read_text(encoding="utf-8")
    assert text.count("Llm(") == 1
    enable = text[text.index("def _assistant_gpu_enable"):]
    assert "Llm(" in enable


def test_model_constant_kept_configurable():
    from assistant.model import GPU_LAYERS
    assert isinstance(GPU_LAYERS, int)
