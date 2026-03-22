from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from infrastructure.storage_manager.storage_manager import StorageManager
from layers.layer4_decision_logic_guardian.core.guardian_core import GuardianCore
from layers.layer4_decision_logic_guardian.thresholds import GuardianThresholds
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.policy_response import (
    PolicyFinding as ContractPolicyFinding,
    PolicyResponse as ContractPolicyResponse,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.engine.policy_engine import (
    PolicyFinding as EnginePolicyFinding,
    PolicyResponse as EnginePolicyResponse,
)


def _prediction_signals() -> List[dict]:
    return [
        {
            "prediction_kind": "coherence_forecast",
            "severity_01": 0.91,
            "confidence_01": 0.88,
            "horizon_days": 3,
            "metrics": {
                "persistence": 14,
                "structural_reinforcement_score": 0.8,
                "volatility_ewma": 0.75,
                "coherence_drop": 0.9,
            },
            "evidence_refs": [{"kind": "handshake_fp_v1", "hash": "h1", "fingerprint_ids": ["fp_1"]}],
        },
        {
            "prediction_kind": "drift_forecast",
            "severity_01": 0.79,
            "confidence_01": 0.83,
            "horizon_days": 5,
            "metrics": {
                "persistence": 10,
                "structural_reinforcement_score": 0.7,
                "drift_zscore": 0.8,
            },
            "evidence_refs": [{"kind": "drift_fp_v1", "hash": "h2", "fingerprint_ids": ["fp_2"]}],
        },
        {
            "prediction_kind": "fallback_forecast",
            "severity_01": 0.72,
            "confidence_01": 0.81,
            "horizon_days": 7,
            "metrics": {
                "persistence": 12,
                "structural_reinforcement_score": 0.65,
                "fallback_frequency": 0.7,
                "correlation_strength": 0.7,
            },
            "evidence_refs": [{"kind": "fallback_path_fp_v1", "hash": "h3", "fingerprint_ids": ["fp_3"]}],
        },
    ]


def _prediction_bundle(signals: List[dict]) -> dict:
    return {
        "entity_id": "api.example.com:443",
        "session_id": "cycle_000001",
        "ts_ms": 123456,
        "signals": signals,
    }


def test_phase6_layer4_static_boundary_no_forbidden_imports() -> None:
    roots = [
        Path("layers/layer4_decision_logic_guardian/core"),
        Path("layers/layer4_decision_logic_guardian/contracts"),
        Path("layers/layer4_decision_logic_guardian/campaign"),
        Path("layers/layer4_decision_logic_guardian/narrative"),
        Path("layers/layer4_decision_logic_guardian/advisory"),
        Path("layers/layer4_decision_logic_guardian/guardian_core.py"),
        Path("layers/layer4_decision_logic_guardian/thresholds.py"),
    ]
    py_files: List[Path] = []
    for root in roots:
        if root.is_file():
            py_files.append(root)
        elif root.exists():
            py_files.extend(sorted(root.glob("*.py")))
    assert py_files

    forbidden = [
        "simulator.",
        "infrastructure.operator_plane",
        "infrastructure.policy_integration",
    ]
    for path in py_files:
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"forbidden coupling '{token}' found in {path}"


def test_phase6_layer4_deterministic_alert_output_for_fixed_input() -> None:
    guardian = GuardianCore(thresholds=GuardianThresholds())
    signals = _prediction_signals()

    r1 = guardian.evaluate(
        tenant_id="tenant_a",
        prediction_bundle=_prediction_bundle(signals),
        policy_mode="disabled",
    )
    r2 = guardian.evaluate(
        tenant_id="tenant_a",
        prediction_bundle=_prediction_bundle(list(reversed(signals))),
        policy_mode="disabled",
    )

    d1 = r1.to_dict()
    d2 = r2.to_dict()
    assert d1 == d2
    assert 0.0 <= float(d1["overall_severity_01"]) <= 1.0
    assert 0.0 <= float(d1["overall_confidence_01"]) <= 1.0
    for alert in d1["alerts"]:
        assert 0.0 <= float(alert["severity_01"]) <= 1.0
        assert 0.0 <= float(alert["confidence_01"]) <= 1.0


def test_phase6_layer4_missing_or_malformed_upstream_fields_do_not_crash() -> None:
    guardian = GuardianCore(thresholds=GuardianThresholds())
    response = guardian.evaluate(
        tenant_id="tenant_a",
        prediction_bundle={
            "entity_id": None,
            "session_id": object(),
            "ts_ms": "bad",
            "signals": [
                {"prediction_kind": "", "severity_01": "nan", "confidence_01": "inf"},
                {"prediction_kind": "x", "severity_01": -1, "confidence_01": 999, "metrics": "bad"},
                {"prediction_kind": "y", "severity_01": 0.1, "confidence_01": 0.1},  # below action thresholds
            ],
        },
        policy_mode="disabled",
    )
    payload = response.to_dict()
    assert isinstance(payload, dict)
    assert "alerts" in payload
    assert len(payload["alerts"]) == 0
    assert 0.0 <= float(payload["overall_severity_01"]) <= 1.0
    assert 0.0 <= float(payload["overall_confidence_01"]) <= 1.0


def test_phase6_layer4_alert_count_is_bounded_by_thresholds() -> None:
    guardian = GuardianCore(thresholds=GuardianThresholds(max_alerts=5))
    many = []
    for i in range(30):
        many.append(
            {
                "prediction_kind": f"k{i}",
                "severity_01": 0.8,
                "confidence_01": 0.8,
                "horizon_days": 3,
                "metrics": {"persistence": 10, "structural_reinforcement_score": 0.7},
                "evidence_refs": [{"kind": "handshake_fp_v1", "hash": f"h{i}", "fingerprint_ids": [f"fp_{i}"]}],
            }
        )
    response = guardian.evaluate(
        tenant_id="tenant_a",
        prediction_bundle=_prediction_bundle(many),
        policy_mode="disabled",
    )
    assert len(response.alerts or []) <= 5


def test_phase6_layer4_guardian_record_persistence_fail_loud_on_corruption(tmp_path: Path) -> None:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 123456,
            "entity_id": "api.example.com:443",
            "severity": 0.8,
            "confidence": 0.7,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
        },
    )
    records = storage.load_latest_guardian_records("tenant_a")
    assert len(records) == 1

    metadata_path = storage.get_tenant_path("tenant_a") / "guardian_records" / "metadata.jsonl"
    with open(metadata_path, "a", encoding="utf-8") as f:
        f.write("{bad-json\n")

    with pytest.raises(RuntimeError, match="Corrupt guardian records"):
        storage.load_latest_guardian_records("tenant_a")


def test_phase6_layer4_policy_engine_uses_contract_policy_response_types() -> None:
    assert EnginePolicyFinding is ContractPolicyFinding
    assert EnginePolicyResponse is ContractPolicyResponse


def test_phase6_layer4_alert_response_has_single_to_dict_definition() -> None:
    source = Path("layers/layer4_decision_logic_guardian/contracts/alert_response.py").read_text(
        encoding="utf-8"
    )
    assert source.count("def to_dict") == 1
