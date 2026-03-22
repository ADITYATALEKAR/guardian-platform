from __future__ import annotations

import json
from pathlib import Path

import pytest

from infrastructure.storage_manager.storage_manager import StorageManager
from layers.layer3_prediction_and_learning.layer3_engine import Layer3Engine
from layers.layer3_prediction_and_learning.learning_state_v2 import (
    MAX_CO_OCCURRENCE,
    MAX_KINDS,
    LearningState,
)


def _bundle(signals):
    return {
        "entity_id": "api.example.com:443",
        "session_id": "cycle_1",
        "ts_ms": 1000,
        "signals": signals,
    }


def test_phase5_layer3_static_boundary_no_forbidden_imports() -> None:
    root = Path("layers/layer3_prediction_and_learning")
    py_files = sorted(root.glob("*.py"))
    assert py_files

    forbidden = [
        "layers.layer4_",
        "simulator.",
        "infrastructure.operator_plane",
        "infrastructure.policy_integration",
    ]
    for path in py_files:
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"forbidden coupling '{token}' found in {path}"


def test_phase5_layer3_prediction_and_state_are_deterministic() -> None:
    engine = Layer3Engine()
    signals_a = [
        {"weakness_kind": "drift", "severity_01": 0.9, "confidence_01": 0.8, "metrics": {"drift_zscore": 0.7}},
        {"weakness_kind": "entropy", "severity_01": 0.7, "confidence_01": 0.6, "metrics": {"entropy_decay_rate": 0.5}},
        {"weakness_kind": "coherence", "severity_01": 0.8, "confidence_01": 0.7, "metrics": {"coherence_drop": 0.9}},
    ]
    signals_b = list(reversed(signals_a))

    pred_a, state_a = engine.predict(weakness_bundle=_bundle(signals_a), return_state=True)
    pred_b, state_b = engine.predict(weakness_bundle=_bundle(signals_b), return_state=True)

    assert pred_a.to_dict() == pred_b.to_dict()
    assert state_a.to_dict() == state_b.to_dict()


def test_phase5_layer3_snapshot_roundtrip_and_corruption_fail_loud(tmp_path: Path) -> None:
    engine = Layer3Engine()
    pred, state = engine.predict(
        weakness_bundle=_bundle(
            [{"weakness_kind": "drift", "severity_01": 0.9, "confidence_01": 0.8, "metrics": {"drift_zscore": 0.7}}]
        ),
        return_state=True,
    )
    assert pred.to_dict()["signals"]

    snapshot = LearningState.to_snapshot({"api.example.com:443": state}, tenant_id="tenant_a")
    roundtrip = LearningState.from_snapshot(snapshot, tenant_id="tenant_a")
    assert "api.example.com:443" in roundtrip

    corrupt = json.loads(json.dumps(snapshot))
    corrupt["version"] = 999
    with pytest.raises(RuntimeError, match="Corrupt layer3 snapshot"):
        LearningState.from_snapshot(corrupt, tenant_id="tenant_a")

    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    tenant_path = storage.get_tenant_path("tenant_a")
    bad_path = tenant_path / "layer3_state" / "layer3_state_snapshot.json"
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_text("{bad-json", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Corrupt layer3 snapshot"):
        storage.load_layer3_snapshot("tenant_a")


def test_phase5_layer3_state_growth_is_bounded() -> None:
    state = LearningState.empty("api.example.com:443")

    many_signals = []
    for i in range(MAX_KINDS + 20):
        many_signals.append(
            {
                "weakness_kind": f"k{i}",
                "severity_01": 0.9,
                "confidence_01": 0.8,
                "metrics": {"propagation_flag": 1.0},
            }
        )

    updated = state.update_from_signals(many_signals, ts_ms=1000, propagation_flag=1)
    assert len(updated.axis_state) <= MAX_KINDS
    assert len(updated.co_occurrence) <= MAX_CO_OCCURRENCE

