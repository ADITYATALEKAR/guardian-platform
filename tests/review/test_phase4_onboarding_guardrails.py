from __future__ import annotations

from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager


def _build_lifecycle(tmp_path):
    storage = StorageManager(str(tmp_path / "storage"))
    identity = IdentityManager(storage)
    return TenantLifecycleManager(
        storage=storage,
        identity=identity,
        simulation_root=str(tmp_path / "simulation"),
    )


def test_phase4_dashboard_exposes_pending_workspace_state_without_snapshot(tmp_path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_pending_tenant(
        name="Phase4 Bank",
        password="internal-tenant-secret",
    )
    scope = AuthorizedTenantScope.from_iterable("op_test", [tenant_id])
    engine = AggregationEngine(lifecycle.storage)

    dashboard = engine.build_dashboard(tenant_id, authz_scope=scope)
    workspace = dashboard["workspace"]

    assert workspace["onboarding_status"] == "PENDING"
    assert workspace["institution_name"] == "Phase4 Bank"
    assert workspace["seed_count"] == 0
    assert dashboard["health_summary"] is None


def test_phase4_onboarding_completion_is_idempotent_for_timestamp(tmp_path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_pending_tenant(
        name="Phase4 Bank",
        password="internal-tenant-secret",
    )

    lifecycle.complete_tenant_onboarding(
        tenant_id=tenant_id,
        name="Phase4 Bank",
        main_url="https://www.phase4-bank.example",
        seed_endpoints=["www.phase4-bank.example:443"],
    )
    first = lifecycle.storage.load_tenant_config(tenant_id)
    first_ts = first.get("onboarded_at_unix_ms")

    lifecycle.complete_tenant_onboarding(
        tenant_id=tenant_id,
        name="Phase4 Bank",
        main_url="https://www.phase4-bank.example",
        seed_endpoints=["www.phase4-bank.example:443"],
    )
    second = lifecycle.storage.load_tenant_config(tenant_id)
    second_ts = second.get("onboarded_at_unix_ms")

    assert first["onboarding_status"] == "COMPLETED"
    assert second["onboarding_status"] == "COMPLETED"
    assert isinstance(first_ts, int)
    assert first_ts == second_ts
