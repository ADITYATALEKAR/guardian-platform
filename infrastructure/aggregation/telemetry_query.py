from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from infrastructure.aggregation.artifact_migration import ArtifactMigrationEngine
from infrastructure.storage_manager.storage_manager import StorageManager


_ALLOWED_RECORD_TYPES = {
    "all",
    "fingerprints",
    "posture_signals",
    "posture_findings",
}


@dataclass(frozen=True)
class TelemetryPage:
    tenant_id: str
    cycle_id: str
    record_type: str
    page: int
    page_size: int
    total: int
    rows: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "cycle_id": self.cycle_id,
            "record_type": self.record_type,
            "page": self.page,
            "page_size": self.page_size,
            "total": self.total,
            "rows": list(self.rows),
        }


class TelemetryQueryService:
    """
    Read-only telemetry projection service.

    Supports deterministic filtering and pagination over cycle telemetry.
    """

    def __init__(
        self,
        storage: StorageManager,
        *,
        migration_engine: Optional[ArtifactMigrationEngine] = None,
    ):
        self._storage = storage
        self._migrator = migration_engine or ArtifactMigrationEngine()

    def query_cycle_telemetry(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        record_type: str = "all",
        page: int = 1,
        page_size: int = 500,
    ) -> TelemetryPage:
        rtype = str(record_type or "all").strip().lower()
        if rtype not in _ALLOWED_RECORD_TYPES:
            raise ValueError("record_type")

        p = max(1, int(page))
        size = max(1, min(int(page_size), 10_000))
        start = (p - 1) * size

        if rtype == "all":
            cursor_payload = self._storage.load_telemetry_for_cycle_cursor(
                tenant_id,
                cycle_id,
                cursor=start,
                limit=size,
            )
            page_rows = self._migrator.migrate_telemetry_rows(
                list(cursor_payload.get("rows", []))
            )
            total = int(cursor_payload.get("total", 0))
        else:
            total, page_rows = self._query_filtered_rows_streaming(
                tenant_id=tenant_id,
                cycle_id=cycle_id,
                record_type=rtype,
                start=start,
                page_size=size,
            )

        return TelemetryPage(
            tenant_id=str(tenant_id),
            cycle_id=str(cycle_id),
            record_type=rtype,
            page=p,
            page_size=size,
            total=total,
            rows=page_rows,
        )

    def summarize_cycle_telemetry(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        preview_page_size: int = 50,
    ) -> Dict[str, Any]:
        size = max(1, min(int(preview_page_size), 500))
        total_records = 0
        counts = {
            "fingerprints": 0,
            "posture_signals": 0,
            "posture_findings": 0,
        }
        preview_rows: List[Dict[str, Any]] = []
        cursor = 0
        batch_size = max(500, size * 4)

        while True:
            payload = self._storage.load_telemetry_for_cycle_cursor(
                tenant_id,
                cycle_id,
                cursor=cursor,
                limit=batch_size,
            )
            raw_rows = list(payload.get("rows", []))
            rows = self._migrator.migrate_telemetry_rows(raw_rows)
            for row in rows:
                total_records += 1
                if len(preview_rows) < size:
                    preview_rows.append(row)
                if self._matches_record_type(row, "fingerprints"):
                    counts["fingerprints"] += 1
                if self._matches_record_type(row, "posture_signals"):
                    counts["posture_signals"] += 1
                if self._matches_record_type(row, "posture_findings"):
                    counts["posture_findings"] += 1

            next_cursor = payload.get("next_cursor")
            if next_cursor is None:
                break
            cursor = int(next_cursor)

        return {
            "total_records": total_records,
            "counts": counts,
            "preview_page": 1,
            "preview_page_size": size,
            "preview_rows": preview_rows,
        }

    def _query_filtered_rows_streaming(
        self,
        *,
        tenant_id: str,
        cycle_id: str,
        record_type: str,
        start: int,
        page_size: int,
    ) -> tuple[int, List[Dict[str, Any]]]:
        """
        Cursor-based filtered query that avoids loading full telemetry into memory.
        """
        filtered_total = 0
        page_rows: List[Dict[str, Any]] = []
        end = start + page_size
        cursor = 0
        batch_size = max(500, min(page_size * 2, 10_000))

        while True:
            payload = self._storage.load_telemetry_for_cycle_cursor(
                tenant_id,
                cycle_id,
                cursor=cursor,
                limit=batch_size,
            )
            raw_rows = list(payload.get("rows", []))
            rows = self._migrator.migrate_telemetry_rows(raw_rows)
            for row in rows:
                if not self._matches_record_type(row, record_type):
                    continue
                if start <= filtered_total < end:
                    page_rows.append(row)
                filtered_total += 1

            next_cursor = payload.get("next_cursor")
            if next_cursor is None:
                break
            cursor = int(next_cursor)

        return filtered_total, page_rows

    def _matches_record_type(self, row: Dict[str, Any], record_type: str) -> bool:
        if record_type == "fingerprints":
            values = row.get("fingerprints")
            return isinstance(values, list) and len(values) > 0

        if record_type == "posture_signals":
            values = row.get("posture_signals")
            return isinstance(values, list) and len(values) > 0

        if record_type == "posture_findings":
            findings = row.get("posture_findings")
            if not isinstance(findings, dict):
                return False
            waf = findings.get("waf_findings")
            tls = findings.get("tls_findings")
            return (
                (isinstance(waf, list) and len(waf) > 0)
                or (isinstance(tls, list) and len(tls) > 0)
            )

        return True
