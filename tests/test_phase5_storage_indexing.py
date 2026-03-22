from __future__ import annotations

from pathlib import Path

import pytest

from infrastructure.aggregation.telemetry_query import TelemetryQueryService
from infrastructure.storage_manager.storage_manager import StorageManager


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    return storage


def _seed_telemetry(storage: StorageManager, cycle_id: str = "cycle_000001", count: int = 6) -> None:
    for idx in range(count):
        storage.persist_telemetry_record(
            "tenant_a",
            cycle_id,
            {
                "sequence": idx,
                "timestamp_ms": 1_710_000_000_000 + idx,
                "entity_id": f"host{idx}.example.com:443",
                "fingerprints": [{"kind": "tls"}] if idx % 2 == 0 else [],
                "posture_signals": [],
                "posture_findings": (
                    {"waf_findings": [{"id": idx}], "tls_findings": []}
                    if idx % 2 == 1
                    else {"waf_findings": [], "tls_findings": []}
                ),
            },
        )


def test_phase5_c17_telemetry_writes_sidecar_index_and_cursor_pages(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    _seed_telemetry(storage, count=5)

    tenant_path = storage.get_tenant_path("tenant_a")
    index_path = tenant_path / "telemetry" / "cycle_000001.index"
    assert index_path.exists()
    assert len([ln for ln in index_path.read_text(encoding="utf-8").splitlines() if ln.strip()]) == 5

    page1 = storage.load_telemetry_for_cycle_cursor("tenant_a", "cycle_000001", cursor=0, limit=2)
    assert page1["total"] == 5
    assert len(page1["rows"]) == 2
    assert page1["next_cursor"] == 2
    assert page1["rows"][0]["sequence"] == 0
    assert page1["rows"][1]["sequence"] == 1

    page2 = storage.load_telemetry_for_cycle_cursor(
        "tenant_a",
        "cycle_000001",
        cursor=int(page1["next_cursor"]),
        limit=10,
    )
    assert len(page2["rows"]) == 3
    assert page2["next_cursor"] is None
    assert [row["sequence"] for row in page2["rows"]] == [2, 3, 4]


def test_phase5_c17_corrupt_index_rebuilds_from_jsonl(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    _seed_telemetry(storage, count=4)
    tenant_path = storage.get_tenant_path("tenant_a")
    index_path = tenant_path / "telemetry" / "cycle_000001.index"
    index_path.write_text("bad-offset\n", encoding="utf-8")

    page = storage.load_telemetry_for_cycle_cursor("tenant_a", "cycle_000001", cursor=0, limit=10)
    assert page["total"] == 4
    assert len(page["rows"]) == 4

    rebuilt = [ln for ln in index_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(rebuilt) == 4
    assert all(line.isdigit() for line in rebuilt)


def test_phase5_c17_query_all_uses_cursor_not_full_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    storage = _new_storage(tmp_path)
    _seed_telemetry(storage, count=6)
    svc = TelemetryQueryService(storage)

    def _should_not_call(*args, **kwargs):
        raise AssertionError("full-load telemetry path should not be used for record_type=all")

    monkeypatch.setattr(storage, "load_telemetry_for_cycle", _should_not_call)

    page = svc.query_cycle_telemetry(
        "tenant_a",
        "cycle_000001",
        record_type="all",
        page=2,
        page_size=2,
    )
    assert page.total == 6
    assert [row["sequence"] for row in page.rows] == [2, 3]


def test_phase5_c17_filtered_query_streams_and_paginates(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    _seed_telemetry(storage, count=10)
    svc = TelemetryQueryService(storage)

    page1 = svc.query_cycle_telemetry(
        "tenant_a",
        "cycle_000001",
        record_type="posture_findings",
        page=1,
        page_size=3,
    )
    assert page1.total == 5
    assert [row["sequence"] for row in page1.rows] == [1, 3, 5]

    page2 = svc.query_cycle_telemetry(
        "tenant_a",
        "cycle_000001",
        record_type="posture_findings",
        page=2,
        page_size=3,
    )
    assert [row["sequence"] for row in page2.rows] == [7, 9]
