from __future__ import annotations

from pathlib import Path

from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.storage_manager.storage_manager import StorageManager


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_tenant_config(
        "tenant_a",
        {
            "tenant_id": "tenant_a",
            "name": "Example Bank",
            "main_url": "https://app.example.com/",
            "seed_endpoints": ["app.example.com:443"],
            "onboarding_status": "COMPLETED",
        },
    )
    return storage


def test_phase9_dashboard_health_summary_counts_only_tenant_relevant_guardian_records(
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.save_snapshot(
        "tenant_a",
        {
            "schema_version": "v2",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "snapshot_hash_sha256": "abc123",
            "endpoint_count": 2,
            "endpoints": [
                {"hostname": "app.example.com", "port": 443, "confidence": 1.0, "discovered_by": ["protocol_observer"]},
                {"hostname": "cloudflare.com", "port": 443, "confidence": 1.0, "discovered_by": ["protocol_observer"]},
            ],
        },
    )
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_100,
            "duration_ms": 1234,
            "status": "completed",
            "endpoints_scanned": 2,
            "new_endpoints": 2,
            "removed_endpoints": 0,
            "snapshot_hash": "abc123",
            "rate_limited_events": 0,
            "error_messages": [],
        },
    )
    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 1_710_000_000_200,
            "entity_id": "app.example.com:443",
            "severity": 0.91,
            "confidence": 0.82,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "alerts": [{"id": "alert_1"}],
        },
    )
    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 1_710_000_000_201,
            "entity_id": "cloudflare.com:443",
            "severity": 0.93,
            "confidence": 0.81,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "alerts": [{"id": "alert_2"}],
        },
    )

    engine = AggregationEngine(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    payload = engine.build_dashboard("tenant_a", authz_scope=scope)

    health = payload["health_summary"]
    risk = payload["risk_distribution"]
    endpoints = payload["endpoints"]

    assert health["total_endpoints"] == 2
    assert health["critical_count"] == 2
    assert health["high_count"] == 0
    assert risk["critical"] == 2
    assert risk["high"] == 0
    assert {row["ownership_category"] for row in endpoints} == {"first_party", "third_party_dependency"}
