from __future__ import annotations

from pathlib import Path

from core_utils import safety
from layers.layer0_observation import observe, observe_pipeline
from layers.layer2_risk_and_weakness_analysis import fusion
from layers.layer4_decision_logic_guardian.narrative import narrative_planner


def test_phase6_c10_observe_module_is_facade_to_pipeline() -> None:
    assert observe.observe_timing_batch is observe_pipeline.observe_timing_batch
    assert observe.observe_timing_batch.__module__ == "layers.layer0_observation.observe_pipeline"


def test_phase6_c13_observe_pipeline_uses_shared_safety_helpers() -> None:
    assert observe_pipeline._safe_str is safety.safe_str
    assert observe_pipeline._safe_float is safety.safe_float
    assert observe_pipeline._safe_int is safety.safe_int
    assert observe_pipeline._clamp01 is safety.clamp01


def test_phase6_c10_observe_facade_file_is_thin_wrapper() -> None:
    src = Path("layers/layer0_observation/observe.py").read_text(encoding="utf-8")
    assert "observe_pipeline" in src
    assert "import *" in src


def test_phase6_c13_selected_runtime_modules_use_shared_safety_helpers() -> None:
    assert fusion._safe_float is not None
    assert fusion._clamp01 is not None
    assert fusion._safe_float(0.5) == 0.5
    assert fusion._clamp01(1.5) == 1.0
    assert narrative_planner._safe_str("  ok  ") == "ok"
    assert narrative_planner._clamp01(2.0) == 1.0
