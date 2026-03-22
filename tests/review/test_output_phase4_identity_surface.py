from __future__ import annotations

from pathlib import Path

import pytest

from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.aggregation.global_identity import cycle_gid, endpoint_gid, tenant_gid
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.storage_manager.storage_manager import StorageManager


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.create_tenant("tenant_b")
    return storage


def _seed_cycle_artifacts(storage: StorageManager, tenant_id: str, cycle_id: str) -> None:
    storage.save_snapshot(
        tenant_id,
        {
            "schema_version": "v1",
            "cycle_id": cycle_id,
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "snapshot_hash_sha256": "abc123",
            "endpoint_count": 1,
            "endpoints": [
                {
                    "hostname": "api.bank.com",
                    "port": 443,
                    "tls_version": "TLSv1.3",
                    "entropy_score": 0.5,
                }
            ],
        },
    )
    storage.append_cycle_metadata(
        tenant_id,
        {
            "schema_version": "v1",
            "cycle_id": cycle_id,
            "cycle_number": 1,
            "status": "completed",
            "timestamp_unix_ms": 1_710_000_000_500,
        },
    )
    storage.persist_telemetry_record(
        tenant_id,
        cycle_id,
        {
            "sequence": 1,
            "timestamp_ms": 1_710_000_000_250,
            "entity_id": "api.bank.com:443",
            "fingerprints": [{"kind": "tls"}],
            "posture_signals": [{"signal_type": "tls_profile"}],
            "posture_findings": {"waf_findings": [], "tls_findings": []},
        },
    )
    storage.persist_guardian_record(
        tenant_id,
        {
            "timestamp_ms": 1_710_000_000_300,
            "entity_id": "api.bank.com:443",
            "severity": 6.0,
            "confidence": 0.8,
            "cycle_id": cycle_id,
            "cycle_number": 1,
            "alerts": [],
        },
    )
    storage.save_temporal_state(
        tenant_id,
        {
            "endpoints": {
                "api.bank.com:443": {
                    "volatility_score": 0.1,
                    "visibility_score": 0.9,
                    "consecutive_absence": 0,
                }
            }
        },
    )


def test_phase4_dashboard_surfaces_identity_overlay_fields(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("op_a", ["tenant_a"])
    _seed_cycle_artifacts(storage, "tenant_a", "cycle_000001")

    dashboard = runtime.build_dashboard("tenant_a", authz_scope=scope)
    assert dashboard["tenant_id"] == "tenant_a"
    assert dashboard["tenant_gid"] == tenant_gid("tenant_a")
    assert dashboard["cycle_id"] == "cycle_000001"
    assert dashboard["cycle_gid"] == cycle_gid("tenant_a", "cycle_000001")
    assert dashboard["endpoints"][0]["entity_id"] == "api.bank.com:443"
    assert dashboard["endpoints"][0]["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)


def test_phase4_cycle_bundle_surfaces_identity_overlay_fields(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("op_a", ["tenant_a"])
    _seed_cycle_artifacts(storage, "tenant_a", "cycle_000001")

    bundle = runtime.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope,
        cycle_id="cycle_000001",
        telemetry_record_type="all",
    )
    assert bundle["tenant_id"] == "tenant_a"
    assert bundle["cycle_id"] == "cycle_000001"
    assert bundle["snapshot"]["tenant_gid"] == tenant_gid("tenant_a")
    assert bundle["snapshot"]["cycle_gid"] == cycle_gid("tenant_a", "cycle_000001")
    assert bundle["snapshot"]["endpoints"][0]["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)
    assert bundle["telemetry"][0]["tenant_gid"] == tenant_gid("tenant_a")
    assert bundle["telemetry"][0]["cycle_gid"] == cycle_gid("tenant_a", "cycle_000001")
    assert bundle["telemetry"][0]["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)
    assert bundle["guardian_records"][0]["endpoint_gid"] == endpoint_gid("tenant_a", "api.bank.com", 443)


def test_phase4_cycle_bundle_authz_rejects_cross_tenant_access(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    runtime = EngineRuntime(storage=storage)
    _seed_cycle_artifacts(storage, "tenant_b", "cycle_000001")
    scope = AuthorizedTenantScope.from_iterable("op_a", ["tenant_a"])

    with pytest.raises(RuntimeError, match="unauthorized tenant access"):
        runtime.build_cycle_artifact_bundle("tenant_b", authz_scope=scope)
