from __future__ import annotations

from pathlib import Path

import pytest

from infrastructure.storage_manager.storage_manager import StorageManager


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return storage


def test_load_telemetry_for_cycle_raises_on_corrupt_json_line(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_path = storage.get_tenant_path("tenant_a")
    telemetry_path = tenant_path / "telemetry" / "cycle_000001.jsonl"
    telemetry_path.write_text('{"sequence": 1, "timestamp_ms": 1}\n{bad-json}\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="Corrupt telemetry records"):
        storage.load_telemetry_for_cycle("tenant_a", "cycle_000001")


def test_load_telemetry_for_cycle_raises_on_non_object_json_line(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_path = storage.get_tenant_path("tenant_a")
    telemetry_path = tenant_path / "telemetry" / "cycle_000002.jsonl"
    telemetry_path.write_text('{"sequence": 1, "timestamp_ms": 1}\n[]\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="Corrupt telemetry records"):
        storage.load_telemetry_for_cycle("tenant_a", "cycle_000002")
