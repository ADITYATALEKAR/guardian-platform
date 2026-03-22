from __future__ import annotations

from pathlib import Path

import pytest

from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.storage_manager.storage_manager import StorageManager
from simulator.storage.simulation_storage import SimulationStorage


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.create_tenant("tenant_b")
    return storage


def test_phase3_authz_is_enforced_in_runtime_and_aggregation(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    runtime = EngineRuntime(
        storage=storage,
        simulation_root=str(tmp_path / "sim_root"),
    )
    aggregation = AggregationEngine(
        storage=storage,
        simulation_root=str(tmp_path / "sim_root"),
    )
    scope_a = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])

    with pytest.raises(RuntimeError, match="unauthorized tenant access"):
        runtime.get_cycle_metadata("tenant_b", authz_scope=scope_a)

    with pytest.raises(RuntimeError, match="unauthorized tenant access"):
        aggregation.build_dashboard("tenant_b", authz_scope=scope_a)

    with pytest.raises(RuntimeError, match="unauthorized tenant access"):
        aggregation.build_dashboard("tenant_a")


def test_phase3_cycle_telemetry_filter_and_pagination_contract(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])

    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000001",
        {
            "sequence": 1,
            "timestamp_ms": 1,
            "entity_id": "a.example.com:443",
            "fingerprints": [{"kind": "tls"}],
            "posture_signals": [],
            "posture_findings": {"waf_findings": [], "tls_findings": []},
        },
    )
    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000001",
        {
            "sequence": 2,
            "timestamp_ms": 2,
            "entity_id": "b.example.com:443",
            "fingerprints": [],
            "posture_signals": [{"signal_type": "tls_profile"}],
            "posture_findings": {"waf_findings": [], "tls_findings": []},
        },
    )
    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000001",
        {
            "sequence": 3,
            "timestamp_ms": 3,
            "entity_id": "c.example.com:443",
            "fingerprints": [],
            "posture_signals": [],
            "posture_findings": {"waf_findings": [{"finding_id": "waf_1"}], "tls_findings": []},
        },
    )

    page_all = runtime.get_cycle_telemetry(
        "tenant_a",
        "cycle_000001",
        authz_scope=scope,
        record_type="all",
        page=1,
        page_size=2,
    )
    assert page_all["total"] == 3
    assert len(page_all["rows"]) == 2

    page_fp = runtime.get_cycle_telemetry(
        "tenant_a",
        "cycle_000001",
        authz_scope=scope,
        record_type="fingerprints",
        page=1,
        page_size=10,
    )
    assert page_fp["total"] == 1
    assert len(page_fp["rows"]) == 1

    page_signals = runtime.get_cycle_telemetry(
        "tenant_a",
        "cycle_000001",
        authz_scope=scope,
        record_type="posture_signals",
        page=1,
        page_size=10,
    )
    assert page_signals["total"] == 1
    assert len(page_signals["rows"]) == 1

    page_findings = runtime.get_cycle_telemetry(
        "tenant_a",
        "cycle_000001",
        authz_scope=scope,
        record_type="posture_findings",
        page=1,
        page_size=10,
    )
    assert page_findings["total"] == 1
    assert len(page_findings["rows"]) == 1


def test_phase3_cycle_bundle_stable_partial_cycle_keys(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])

    bundle = runtime.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope,
    )
    assert set(bundle.keys()) == {
        "tenant_id",
        "cycle_id",
        "snapshot",
        "cycle_metadata",
        "telemetry",
        "temporal_state",
        "trust_graph_snapshot",
        "layer3_state_snapshot",
        "guardian_records",
        "integrity_summary",
    }
    assert bundle["cycle_id"] is None
    assert bundle["snapshot"] is None
    assert bundle["cycle_metadata"] == []
    assert bundle["telemetry"] == []
    assert bundle["guardian_records"] == []


def test_phase3_simulation_listing_uses_payload_metadata(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    simulation_root = tmp_path / "sim_root"
    runtime = EngineRuntime(storage=storage, simulation_root=str(simulation_root))
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])

    sim_storage = SimulationStorage(str(simulation_root))
    sim_storage.persist(
        "tenant_a",
        "sim_good",
        {
            "simulation_id": "sim_good",
            "tenant_id": "tenant_a",
            "baseline_cycle_id": "cycle_000001",
            "scenario_id": "credential_theft",
        },
    )

    sim_dir = simulation_root / "tenants" / "tenant_a" / "simulations"
    sim_dir.mkdir(parents=True, exist_ok=True)
    (sim_dir / "sim_bad.json").write_text("{bad-json", encoding="utf-8")

    page = runtime.list_simulations(
        "tenant_a",
        authz_scope=scope,
        page=1,
        page_size=10,
    )
    assert page["tenant_id"] == "tenant_a"
    assert page["total"] == 2
    assert len(page["rows"]) == 2

    by_id = {row["simulation_id"]: row for row in page["rows"]}
    assert by_id["sim_good"]["scenario_id"] == "credential_theft"
    assert by_id["sim_good"]["baseline_cycle_id"] == "cycle_000001"
    assert by_id["sim_good"]["status"] == "completed"
    assert by_id["sim_bad"]["status"] == "corrupt"
