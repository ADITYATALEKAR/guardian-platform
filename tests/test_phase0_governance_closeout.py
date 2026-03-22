from __future__ import annotations

import json
from pathlib import Path

import pytest


REQUIRED_ADRS = [
    Path("docs/adr/policy_activation_contract.md"),
    Path("docs/adr/rate_control_contract.md"),
    Path("docs/adr/simulation_execution_contract.md"),
    Path("docs/adr/storage_migration_contract.md"),
]


def test_phase0_required_adrs_exist() -> None:
    missing = [str(p) for p in REQUIRED_ADRS if not p.exists()]
    assert not missing, f"Missing ADR files: {missing}"


@pytest.mark.performance
def test_phase0_baseline_snapshot_exists_and_has_required_sections() -> None:
    path = Path("docs/baselines/phase0_baseline.json")
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload.get("cycle_runtime"), dict)
    assert isinstance(payload.get("simulation_runtime"), dict)
    assert isinstance(payload.get("jsonl_storage"), dict)
    assert float(payload["cycle_runtime"].get("runtime_ms", 0.0)) >= 0.0
    assert float(payload["simulation_runtime"].get("runtime_ms", 0.0)) >= 0.0
    assert int(payload["jsonl_storage"].get("loaded_records", 0)) >= 1


def test_phase0_marker_groups_declared_and_mapped() -> None:
    pytest_ini = Path("pytest.ini").read_text(encoding="utf-8")
    for marker in ("security", "concurrency", "migration", "performance"):
        assert f"{marker}:" in pytest_ini

    indexed = Path("tests/test_phase1_security_and_concurrency.py").read_text(encoding="utf-8")
    assert "pytest.mark.security" in indexed
    assert "pytest.mark.concurrency" in indexed

    migration = Path("tests/test_phase5_rate_limit_and_artifact_migration.py").read_text(encoding="utf-8")
    assert "pytest.mark.migration" in migration

    performance = Path("tests/test_phase3_runtime_hardening.py").read_text(encoding="utf-8")
    assert "pytest.mark.performance" in performance
