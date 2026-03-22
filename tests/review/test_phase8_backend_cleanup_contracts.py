from __future__ import annotations

from pathlib import Path

from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.storage_manager.storage_manager import StorageManager


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return storage


def _append_cycle_row(
    storage: StorageManager,
    *,
    cycle_id: str,
    cycle_number: int,
    status: str,
    timestamp_unix_ms: int,
) -> None:
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": cycle_id,
            "cycle_number": cycle_number,
            "timestamp_unix_ms": timestamp_unix_ms,
            "duration_ms": 0,
            "status": status,
            "endpoints_scanned": 0,
            "new_endpoints": 0,
            "removed_endpoints": 0,
            "snapshot_hash": "",
            "rate_limited_events": 0,
            "error_messages": [],
        },
    )


def test_phase8_storage_terminal_cycle_metadata_prefers_terminal_status(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    _append_cycle_row(
        storage,
        cycle_id="cycle_000001",
        cycle_number=1,
        status="running",
        timestamp_unix_ms=100,
    )
    _append_cycle_row(
        storage,
        cycle_id="cycle_000001",
        cycle_number=1,
        status="failed",
        timestamp_unix_ms=120,
    )
    _append_cycle_row(
        storage,
        cycle_id="cycle_000001",
        cycle_number=1,
        status="completed",
        timestamp_unix_ms=140,
    )

    terminal = storage.load_terminal_cycle_metadata("tenant_a", "cycle_000001")

    assert terminal is not None
    assert terminal["cycle_id"] == "cycle_000001"
    assert terminal["status"] == "completed"
    assert terminal["timestamp_unix_ms"] == 140


def test_phase8_list_cycles_uses_terminal_cycle_rows_only(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    _append_cycle_row(
        storage,
        cycle_id="cycle_000001",
        cycle_number=1,
        status="running",
        timestamp_unix_ms=100,
    )
    _append_cycle_row(
        storage,
        cycle_id="cycle_000001",
        cycle_number=1,
        status="completed",
        timestamp_unix_ms=200,
    )
    _append_cycle_row(
        storage,
        cycle_id="cycle_000002",
        cycle_number=2,
        status="running",
        timestamp_unix_ms=300,
    )

    terminal_rows = storage.list_terminal_cycle_metadata("tenant_a")
    engine = AggregationEngine(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    payload = engine.list_cycles("tenant_a", authz_scope=scope)

    assert len(terminal_rows) == 2
    assert [row["cycle_id"] for row in terminal_rows] == ["cycle_000002", "cycle_000001"]
    assert [row["cycle_id"] for row in payload["rows"]] == ["cycle_000002", "cycle_000001"]
    assert payload["rows"][0]["status"] == "running"
    assert payload["rows"][1]["status"] == "completed"
