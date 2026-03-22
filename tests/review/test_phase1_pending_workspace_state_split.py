from __future__ import annotations

import json
from pathlib import Path

from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager


def _build_lifecycle(tmp_path: Path) -> TenantLifecycleManager:
    storage = StorageManager(str(tmp_path / "storage"))
    identity = IdentityManager(storage)
    simulation_root = str(tmp_path / "simulation")
    return TenantLifecycleManager(storage, identity, simulation_root)


def test_phase1_pending_workspace_registers_with_pending_state(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)

    tenant_id = lifecycle.register_pending_tenant(
        name="Example Bank",
        password="tenant-internal-secret",
    )

    storage = lifecycle.storage
    assert storage.tenant_exists(tenant_id) is True
    assert lifecycle.identity.has_tenant(tenant_id) is True

    config_path = storage.get_tenant_path(tenant_id) / "tenant_config.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["tenant_id"] == tenant_id
    assert payload["name"] == "Example Bank"
    assert payload["main_url"] == ""
    assert payload["seed_endpoints"] == []
    assert payload["onboarding_status"] == TenantLifecycleManager.ONBOARDING_PENDING
    assert payload["onboarded_at_unix_ms"] is None


def test_phase1_complete_tenant_onboarding_updates_state_and_seeds(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)

    tenant_id = lifecycle.register_pending_tenant(
        name="Example Bank",
        password="tenant-internal-secret",
    )
    lifecycle.complete_tenant_onboarding(
        tenant_id=tenant_id,
        name="Example Bank PLC",
        main_url="https://www.examplebank.com",
        seed_endpoints=["WWW.ExampleBank.com", "api.examplebank.com:8443"],
    )

    storage = lifecycle.storage
    config_path = storage.get_tenant_path(tenant_id) / "tenant_config.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["name"] == "Example Bank PLC"
    assert payload["main_url"] == "https://www.examplebank.com"
    assert payload["seed_endpoints"] == ["api.examplebank.com:8443", "www.examplebank.com:443"]
    assert payload["onboarding_status"] == TenantLifecycleManager.ONBOARDING_COMPLETED
    assert isinstance(payload["onboarded_at_unix_ms"], int)


def test_phase1_seed_endpoint_updates_preserve_onboarding_fields(tmp_path: Path) -> None:
    lifecycle = _build_lifecycle(tmp_path)
    tenant_id = lifecycle.register_pending_tenant(
        name="Example Bank",
        password="tenant-internal-secret",
    )

    storage = lifecycle.storage
    storage.save_seed_endpoints(tenant_id, ["edge.examplebank.com:443"])

    config_path = storage.get_tenant_path(tenant_id) / "tenant_config.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["tenant_id"] == tenant_id
    assert payload["name"] == "Example Bank"
    assert payload["onboarding_status"] == TenantLifecycleManager.ONBOARDING_PENDING
    assert payload["seed_endpoints"] == ["edge.examplebank.com:443"]
