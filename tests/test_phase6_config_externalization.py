from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


def test_phase6_scenario_catalog_loaded_from_versioned_json() -> None:
    from simulator.scenarios.scenario_catalog import get_default_scenarios

    scenarios = get_default_scenarios()
    ids = [s.id for s in scenarios]
    assert ids == sorted(ids)
    assert "compromised_endpoint" in ids
    assert "certificate_compromise" in ids
    assert all(s.description for s in scenarios)


def test_phase6_scenario_catalog_override_fail_loud(tmp_path: Path, monkeypatch) -> None:
    bad_catalog = tmp_path / "bad_scenarios.json"
    bad_catalog.write_text("{bad-json", encoding="utf-8")
    monkeypatch.setenv("GUARDIAN_SCENARIO_CATALOG_PATH", str(bad_catalog))

    import simulator.scenarios.scenario_catalog as catalog

    importlib.reload(catalog)
    with pytest.raises(RuntimeError, match="valid JSON"):
        catalog.get_default_scenarios()

    monkeypatch.delenv("GUARDIAN_SCENARIO_CATALOG_PATH", raising=False)
    importlib.reload(catalog)


def test_phase6_technique_classifier_uses_externalized_rules() -> None:
    from layers.layer4_decision_logic_guardian.campaign.technique_classifier import classify_techniques

    labels = classify_techniques(
        [
            {
                "prediction_kind": "risk_forecast",
                "horizon_days": 2,
                "metrics": {"volatility_ewma": 0.9},
            },
            {
                "prediction_kind": "entropy_monitor",
                "metrics": {"entropy_decay_rate": 0.8, "entropy_zscore": 0.85},
            },
            {
                "prediction_kind": "transition_watch",
                "metrics": {"transition_score": 0.7, "drift_zscore": 0.75},
            },
        ]
    )
    names = [x.label for x in labels]
    assert "probe_exploit_attempt" in names
    assert "sustained_entropy_collection" in names
    assert "configuration_manipulation" in names


def test_phase6_legacy_layer4_package_explicitly_marked_deprecated() -> None:
    import layers.layer4_decision_logic_guardian.legacy as legacy_pkg

    assert getattr(legacy_pkg, "DEPRECATED", False) is True
