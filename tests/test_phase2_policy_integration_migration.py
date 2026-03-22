from __future__ import annotations

import json
from pathlib import Path

import pytest

from infrastructure.policy_integration.notifications import NotificationOutbox
from infrastructure.policy_integration.policies.policy_store import PolicyStore
from infrastructure.policy_integration.policies.sources import PolicySourceResolver
from infrastructure.storage_manager.storage_manager import StorageManager


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return storage


def test_phase2_policy_store_uses_canonical_tenant_storage(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    store = PolicyStore(storage_manager=storage, tenant_id="tenant_a")

    policy_id = store.save_proposed_policy(
        {
            "policy_id": "pol_001",
            "title": "TLS baseline",
            "jurisdiction": "EUROPE",
            "source": "manual",
            "tags": ["tls", "tls", "compliance"],
        }
    )
    assert policy_id == "pol_001"

    proposed = store.list_proposed_policies()
    assert len(proposed) == 1
    assert proposed[0]["status"] == "proposed"
    assert proposed[0]["tags"] == ["compliance", "tls"]

    tenant_root = storage.get_tenant_path("tenant_a")
    persisted = tenant_root / "policy_integration" / "proposed_policies" / "pol_001.json"
    assert persisted.exists()


def test_phase2_notification_outbox_is_fail_loud_on_corruption(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    outbox = NotificationOutbox(storage_manager=storage, tenant_id="tenant_a")
    event_id = outbox.enqueue(
        kind="policy_update",
        title="EU update",
        body="Policy changed",
        payload={"plan_id": "abc"},
    )
    assert event_id

    outbox_path = (
        storage.get_tenant_path("tenant_a")
        / "policy_integration"
        / "notifications"
        / "outbox.jsonl"
    )
    with open(outbox_path, "a", encoding="utf-8") as f:
        f.write("{bad-json\n")

    with pytest.raises(RuntimeError, match="corrupt notification outbox"):
        outbox.load_all()


def test_phase2_policy_source_resolver_none_mode_is_deterministic() -> None:
    resolver = PolicySourceResolver()
    result = resolver.resolve(["NONE", "INDIA", "EUROPE"])
    assert len(result.packs) == 1
    assert result.packs[0].jurisdiction_code == "NONE"
    assert result.unresolved_jurisdictions == ()


def test_phase2_no_forbidden_imports_in_policy_integration_package() -> None:
    package_root = Path("infrastructure/policy_integration")
    py_files = sorted(package_root.rglob("*.py"))
    assert py_files

    forbidden_fragments = [
        "integration.storage",
        "integration.tenants",
        "from integration.storage",
        "from integration.tenants",
    ]
    for path in py_files:
        source = path.read_text(encoding="utf-8")
        assert "while True" not in source, f"unexpected scheduler loop in {path}"
        for fragment in forbidden_fragments:
            assert fragment not in source, f"forbidden import fragment '{fragment}' in {path}"


def test_phase2_new_modules_are_json_serializable(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    store = PolicyStore(storage_manager=storage, tenant_id="tenant_a")
    store.save_approved_policy(
        {
            "policy_id": "approved_1",
            "title": "PCI baseline",
            "jurisdiction": "UNITED STATES",
            "source": "catalog",
            "tags": ["pci", "transport"],
        }
    )
    approved = store.list_approved_policies()
    assert len(approved) == 1
    json.dumps(approved[0], sort_keys=True)
