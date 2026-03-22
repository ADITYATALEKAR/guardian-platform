from __future__ import annotations

from pathlib import Path

import pytest

from infrastructure.aggregation.artifact_version_matrix import ARTIFACT_VERSION_RULES
from infrastructure.aggregation.global_identity import (
    GLOBAL_IDENTITY_SCHEMA_VERSION,
    cycle_gid,
    endpoint_gid,
    endpoint_gid_from_endpoint_id,
    tenant_gid,
)
from infrastructure.posture.contracts_v1 import (
    FINDING_SCHEMA_VERSION,
    REPORTING_SCHEMA_VERSION,
    SIGNAL_SCHEMA_VERSION,
)
from infrastructure.storage_manager.storage_manager import StorageManager


def test_phase1_gid_deterministic_and_tenant_scoped() -> None:
    assert GLOBAL_IDENTITY_SCHEMA_VERSION == "gid_v1"

    a1 = tenant_gid("tenant_a")
    a2 = tenant_gid("tenant_a")
    b1 = tenant_gid("tenant_b")
    assert a1 == a2
    assert a1 != b1

    c1 = cycle_gid("tenant_a", "cycle_000001")
    c2 = cycle_gid("tenant_a", "cycle_000001")
    c3 = cycle_gid("tenant_b", "cycle_000001")
    assert c1 == c2
    assert c1 != c3

    e1 = endpoint_gid("tenant_a", "api.bank.com", 443)
    e2 = endpoint_gid("tenant_a", "api.bank.com", 443)
    e3 = endpoint_gid("tenant_b", "api.bank.com", 443)
    assert e1 == e2
    assert e1 != e3
    assert e1 == endpoint_gid_from_endpoint_id("tenant_a", "api.bank.com:443")


def test_phase1_cross_tenant_gid_collision_matrix_100k() -> None:
    seen = set()
    # 1000 tenants * 100 endpoints = 100k endpoint GIDs
    for t_idx in range(1000):
        tid = f"tenant_{t_idx:04d}"
        for e_idx in range(100):
            host = f"api{e_idx}.bank.example"
            gid = endpoint_gid(tid, host, 443)
            assert gid not in seen
            seen.add(gid)
    assert len(seen) == 100_000


def test_phase1_storage_reads_are_strict_and_do_not_create_tenant(tmp_path: Path) -> None:
    storage = StorageManager(str(tmp_path / "storage_root"))
    tenant_path = storage.tenants_dir / "tenant_missing"
    assert not tenant_path.exists()

    with pytest.raises(RuntimeError, match="Tenant does not exist"):
        storage.load_latest_snapshot("tenant_missing")
    with pytest.raises(RuntimeError, match="Tenant does not exist"):
        storage.load_telemetry_for_cycle("tenant_missing", "cycle_000001")
    with pytest.raises(RuntimeError, match="Tenant does not exist"):
        storage.load_cycle_metadata("tenant_missing")

    assert not tenant_path.exists()


def test_phase1_invalid_tenant_path_sequences_rejected(tmp_path: Path) -> None:
    storage = StorageManager(str(tmp_path / "storage_root"))

    with pytest.raises(ValueError, match="Invalid tenant_id path sequence"):
        storage.create_tenant("../escape")
    with pytest.raises(ValueError, match="Invalid tenant_id path sequence"):
        storage.ensure_tenant_exists("..\\escape")
    with pytest.raises(ValueError, match="Invalid tenant_id path sequence"):
        storage.tenant_exists("a/../../b")


def test_phase1_schema_version_coverage_matrix_and_docs_present() -> None:
    required = {
        "snapshot",
        "cycle_metadata",
        "trust_graph_snapshot",
        "reporting_metrics",
        "waf_posture_signal",
        "tls_posture_signal",
        "waf_finding",
        "tls_finding",
        "temporal_state",
        "layer0_baseline",
        "layer3_snapshot",
        "guardian_record",
        "telemetry_record",
    }
    assert required.issubset(set(ARTIFACT_VERSION_RULES.keys()))

    assert SIGNAL_SCHEMA_VERSION == "v1"
    assert FINDING_SCHEMA_VERSION == "v1"
    assert REPORTING_SCHEMA_VERSION == "v1"

    assert Path("docs/output_manifest_existing.md").exists()
    assert Path("docs/output_connector_contract.md").exists()
