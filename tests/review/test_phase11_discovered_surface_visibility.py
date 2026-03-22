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
            "institution_name": "Demo Bank",
            "main_url": "https://www.bank.com",
            "seed_endpoints": ["www.bank.com:443"],
            "onboarding_status": "COMPLETED",
        },
    )
    return storage


def test_phase11_dashboard_and_endpoint_page_keep_discovered_surface_visible(
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.save_snapshot(
        "tenant_a",
        {
            "schema_version": "1.2",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "snapshot_hash_sha256": "abc123",
            "endpoint_count": 1,
            "endpoints": [
                {
                    "hostname": "www.bank.com",
                    "port": 443,
                    "confidence": 0.91,
                    "discovered_by": ["protocol_observer", "ct_log"],
                    "observation_state": "observed",
                    "last_observed_cycle": 1,
                    "last_observed_unix_ms": 1_710_000_000_000,
                }
            ],
            "discovered_surface": [
                {
                    "entity_id": "www.bank.com:443",
                    "hostname": "www.bank.com",
                    "port": 443,
                    "scheme": "https",
                    "discovery_source": "protocol_observer",
                    "discovery_sources": ["protocol_observer", "ct_log"],
                    "observation_status": "observed_successful",
                    "observation_attempted": True,
                    "recorded_in_snapshot": True,
                    "surface_tags": ["observed_successful", "seed"],
                },
                {
                    "entity_id": "smtp.bank.com:25",
                    "hostname": "smtp.bank.com",
                    "port": 25,
                    "scheme": "smtp",
                    "discovery_source": "ct_log",
                    "discovery_sources": ["ct_log"],
                    "observation_status": "historical_or_ct_only",
                    "observation_attempted": False,
                    "recorded_in_snapshot": False,
                    "surface_tags": ["historical_or_ct_only"],
                },
                {
                    "entity_id": "bank-com.mail.protection.outlook.com:443",
                    "hostname": "bank-com.mail.protection.outlook.com",
                    "port": 443,
                    "scheme": "https",
                    "discovery_source": "dns_mx",
                    "discovery_sources": ["dns_mx"],
                    "observation_status": "not_yet_observed",
                    "observation_attempted": False,
                    "recorded_in_snapshot": False,
                    "surface_tags": ["not_yet_observed"],
                },
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
            "endpoints_scanned": 1,
            "new_endpoints": 1,
            "removed_endpoints": 0,
            "snapshot_hash": "abc123",
            "rate_limited_events": 0,
            "error_messages": [],
            "build_stats": {
                "discovered_related_endpoints": 3,
                "observation_attempts": 1,
                "observation_successes": 1,
                "observation_failures": 0,
                "recorded_endpoints": 1,
                "unverified_historical_endpoints": 2,
                "total_discovered_domains": 3,
                "total_observations": 1,
                "successful_observations": 1,
                "failed_observations": 0,
                "endpoints_canonical": 1,
                "posture_summary": {},
            },
        },
    )
    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 1_710_000_000_200,
            "entity_id": "www.bank.com:443",
            "severity": 0.91,
            "confidence": 0.82,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "alerts": [{"id": "alert_1"}],
        },
    )

    engine = AggregationEngine(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])

    dashboard = engine.build_dashboard("tenant_a", authz_scope=scope)
    endpoint_page = engine.get_endpoint_page("tenant_a", authz_scope=scope, page=1, page_size=10)

    assert dashboard["health_summary"]["total_endpoints"] == 3
    assert dashboard["observation_summary"] == {
        "discovered_related": 3,
        "observation_attempts": 1,
        "observation_successes": 1,
        "observation_failures": 0,
        "recorded_endpoints": 1,
        "unverified_historical": 2,
        "tls_findings_count": 0,
        "waf_findings_count": 0,
    }
    assert endpoint_page["total"] == 3
    states = {
        row["entity_id"]: row["observation_status"]
        for row in endpoint_page["rows"]
    }
    assert states["www.bank.com:443"] == "observed_successful"
    assert states["smtp.bank.com:25"] == "historical_or_ct_only"
    assert states["bank-com.mail.protection.outlook.com:443"] == "not_yet_observed"
