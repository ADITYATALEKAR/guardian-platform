from __future__ import annotations

import json
import os
import random
import socket
import tempfile
import time
import shutil
import re
from pathlib import Path
from typing import Any, Dict, Optional, List

import threading
import logging
from collections import defaultdict

from infrastructure.aggregation.global_identity import (
    cycle_gid as build_cycle_gid,
    endpoint_gid as build_endpoint_gid,
    endpoint_gid_from_endpoint_id,
    tenant_gid as build_tenant_gid,
)


class StorageManager:
    """
    Durable, crash-safe storage layer.

    Responsibilities:
        - Tenant storage lifecycle
        - Atomic persistence
        - Snapshot persistence
        - Telemetry persistence
        - Temporal state persistence
        - Layer0 baseline persistence
        - Seed endpoint persistence
        - Cycle metadata persistence
        - Guardian record persistence (lazy directory creation)

    Does NOT:
        - Perform authentication
        - Validate endpoints
        - Mutate graph state
        - Trigger discovery
    """

    # ============================================================
    # INIT
    # ============================================================

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)

        self.identity_dir = self.base_path / "identity"
        self.identity_dir.mkdir(parents=True, exist_ok=True)

        self.tenants_dir = self.base_path / "tenant_data_storage" / "tenants"
        self.tenants_dir.mkdir(parents=True, exist_ok=True)

        self._append_locks = defaultdict(threading.Lock)

    # ============================================================
    # TENANT ID SAFETY
    # ============================================================

    def _validate_tenant_id(self, tenant_id: str) -> str:
        tid = str(tenant_id or "").strip()
        if not tid:
            raise ValueError("tenant_id cannot be empty")
        if any(sep in tid for sep in ("/", "\\", "..")):
            raise ValueError("Invalid tenant_id path sequence")
        return tid

    def require_tenant_exists(self, tenant_id: str) -> Path:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.tenants_dir / tid
        if not tenant_path.exists():
            raise RuntimeError(f"Tenant does not exist: {tid}")
        return tenant_path

    # ============================================================
    # TENANT LIFECYCLE
    # ============================================================

    def create_tenant(self, tenant_id: str) -> Path:
        """
        Create tenant storage structure.

        NOTE: create_tenant() is NOT idempotent.
        It will raise RuntimeError if tenant already exists.
        Use ensure_tenant_exists() for idempotent behavior.
        """
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.tenants_dir / tid
        if tenant_path.exists():
            # Backward-compatibility migration for legacy tenants missing dirs
            self._ensure_required_dirs(tenant_path)
            raise RuntimeError(f"Tenant already exists: {tid}")
        return self._initialize_tenant_dirs(tid)

    def ensure_tenant_exists(self, tenant_id: str) -> Path:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.tenants_dir / tid
        if not tenant_path.exists():
            return self._initialize_tenant_dirs(tid)
        return tenant_path

    def delete_tenant(self, tenant_id: str) -> None:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.tenants_dir / tid

        if not tenant_path.exists():
            raise RuntimeError(f"Tenant does not exist: {tid}")

        lock_path = tenant_path / ".cycle.lock"
        if lock_path.exists():
            if self._is_stale_cycle_lock(lock_path):
                lock_path.unlink()
            else:
                raise RuntimeError(
                    f"Cannot delete tenant {tenant_id}: active cycle lock present"
                )

        shutil.rmtree(tenant_path)

    def reset_tenant(self, tenant_id: str) -> Path:
        tid = self._validate_tenant_id(tenant_id)
        self.delete_tenant(tid)
        return self._initialize_tenant_dirs(tid)

    def tenant_exists(self, tenant_id: str) -> bool:
        tid = self._validate_tenant_id(tenant_id)
        return (self.tenants_dir / tid).exists()

    def get_tenant_path(self, tenant_id: str) -> Path:
        return self.require_tenant_exists(tenant_id)

    def list_tenant_ids(self) -> List[str]:
        tenant_ids: List[str] = []
        for child in sorted(self.tenants_dir.iterdir(), key=lambda item: item.name):
            if not child.is_dir():
                continue
            try:
                tenant_ids.append(self._validate_tenant_id(child.name))
            except Exception:
                continue
        return tenant_ids

    def _initialize_tenant_dirs(self, tenant_id: str) -> Path:
        tenant_path = self.tenants_dir / tenant_id

        (tenant_path / "snapshots").mkdir(parents=True, exist_ok=True)
        (tenant_path / "temporal_state").mkdir(parents=True, exist_ok=True)
        (tenant_path / "cycle_metadata").mkdir(parents=True, exist_ok=True)
        (tenant_path / "telemetry").mkdir(parents=True, exist_ok=True)
        (tenant_path / "layer3_state").mkdir(parents=True, exist_ok=True)
        (tenant_path / "trust_graph").mkdir(parents=True, exist_ok=True)
        (tenant_path / "guardian_records").mkdir(parents=True, exist_ok=True)

        return tenant_path

    def _ensure_required_dirs(self, tenant_path: Path) -> None:
        """
        Ensure required tenant subdirectories exist (migration helper).
        """
        (tenant_path / "snapshots").mkdir(parents=True, exist_ok=True)
        (tenant_path / "temporal_state").mkdir(parents=True, exist_ok=True)
        (tenant_path / "cycle_metadata").mkdir(parents=True, exist_ok=True)
        (tenant_path / "telemetry").mkdir(parents=True, exist_ok=True)
        (tenant_path / "layer3_state").mkdir(parents=True, exist_ok=True)
        (tenant_path / "trust_graph").mkdir(parents=True, exist_ok=True)
        (tenant_path / "guardian_records").mkdir(parents=True, exist_ok=True)

    # ============================================================
    # SEED ENDPOINTS
    # ============================================================

    def load_tenant_config(self, tenant_id: str) -> Dict[str, Any]:
        tenant_path = self.require_tenant_exists(tenant_id)
        config_path = tenant_path / "tenant_config.json"
        if not config_path.exists():
            return {}
        data = self._read_json(config_path)
        return data if isinstance(data, dict) else {}

    def save_tenant_config(self, tenant_id: str, config: Dict[str, Any]) -> None:
        tenant_path = self.ensure_tenant_exists(tenant_id)
        config_path = tenant_path / "tenant_config.json"
        payload = dict(config or {})
        payload["schema_version"] = str(payload.get("schema_version") or "v3")
        payload.setdefault("tenant_id", str(tenant_id))
        self._atomic_write(config_path, payload)

    def update_tenant_config_fields(self, tenant_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        existing = self.load_tenant_config(tenant_id)
        existing.update(dict(fields or {}))
        self.save_tenant_config(tenant_id, existing)
        return existing

    def save_seed_endpoints(self, tenant_id: str, endpoints: List[str]) -> None:
        tenant_path = self.ensure_tenant_exists(tenant_id)
        config_path = tenant_path / "tenant_config.json"

        payload: Dict[str, Any] = {}
        if config_path.exists():
            existing = self._read_json(config_path)
            if isinstance(existing, dict):
                payload.update(existing)

        payload["schema_version"] = str(payload.get("schema_version") or "v3")
        payload["seed_endpoints"] = sorted(set(endpoints))
        payload.setdefault("tenant_id", str(tenant_id))

        self._atomic_write(config_path, payload)

    def load_seed_endpoints(self, tenant_id: str) -> List[str]:
        tenant_path = self.require_tenant_exists(tenant_id)
        config_path = tenant_path / "tenant_config.json"

        if not config_path.exists():
            return []

        data = self._read_json(config_path)
        rows = data.get("seed_endpoints", [])
        if not isinstance(rows, list):
            return []
        return [str(x) for x in rows if str(x).strip()]

    def add_seed_endpoints(self, tenant_id: str, endpoints: List[str]) -> None:
        existing = self.load_seed_endpoints(tenant_id)
        updated = sorted(set(existing + endpoints))
        self.save_seed_endpoints(tenant_id, updated)

    def remove_seed_endpoint(self, tenant_id: str, endpoint: str) -> None:
        existing = self.load_seed_endpoints(tenant_id)
        if endpoint not in existing:
            return
        updated = [e for e in existing if e != endpoint]
        self.save_seed_endpoints(tenant_id, updated)

    # ============================================================
    # FINGERPRINT EXISTENCE
    # ============================================================

    def has_any_fingerprints(self, tenant_id: str) -> bool:
        tenant_path = self.require_tenant_exists(tenant_id)
        telemetry_dir = tenant_path / "telemetry"

        for file in telemetry_dir.glob("*.jsonl"):
            if file.stat().st_size > 0:
                return True
        return False

    # ============================================================
    # SNAPSHOTS
    # ============================================================

    def save_snapshot(self, tenant_id: str, snapshot: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.ensure_tenant_exists(tid)
        payload = self._overlay_snapshot_payload(tid, snapshot)
        path = tenant_path / "snapshots" / f"{payload['cycle_id']}.json"

        if path.exists():
            raise RuntimeError(f"Snapshot already exists: {payload['cycle_id']}")

        self._atomic_write(path, payload)

    def load_latest_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.require_tenant_exists(tid)
        files = sorted((tenant_path / "snapshots").glob("cycle_*.json"))
        if not files:
            return None
        record = self._read_json(files[-1])
        self._validate_snapshot_record(record)
        return self._overlay_snapshot_payload(tid, record)

    def load_previous_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.require_tenant_exists(tid)
        files = sorted((tenant_path / "snapshots").glob("cycle_*.json"))
        if len(files) < 2:
            return None
        record = self._read_json(files[-2])
        self._validate_snapshot_record(record)
        return self._overlay_snapshot_payload(tid, record)

    def load_snapshot_for_cycle(self, tenant_id: str, cycle_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        tenant_path = self.require_tenant_exists(tid)
        path = tenant_path / "snapshots" / f"{cid}.json"
        if not path.exists():
            return None
        record = self._read_json(path)
        self._validate_snapshot_record(record)
        return self._overlay_snapshot_payload(tid, record)

    # ============================================================
    # TEMPORAL STATE
    # ============================================================

    def save_temporal_state(
        self,
        tenant_id: str,
        state: Dict[str, Any],
        *,
        cycle_id: Optional[str] = None,
    ) -> None:
        tenant_path = self.ensure_tenant_exists(tenant_id)
        temporal_dir = tenant_path / "temporal_state"
        path = temporal_dir / "state.json"
        self._atomic_write(path, state)
        cid = str(cycle_id or "").strip()
        if cid:
            self._atomic_write(temporal_dir / f"{cid}.json", state)

    def load_temporal_state(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tenant_path = self.require_tenant_exists(tenant_id)
        path = tenant_path / "temporal_state" / "state.json"
        if not path.exists():
            return None
        return self._read_json(path)

    def load_temporal_state_for_cycle(
        self,
        tenant_id: str,
        cycle_id: str,
    ) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        tenant_path = self.require_tenant_exists(tid)
        path = tenant_path / "temporal_state" / f"{cid}.json"
        if not path.exists():
            return None
        return self._read_json(path)

    # ============================================================
    # LAYER 0 BASELINE
    # ============================================================

    def save_layer0_baseline(self, tenant_id: str, baseline_dict: Dict[str, Any]) -> None:
        tenant_path = self.ensure_tenant_exists(tenant_id)
        path = tenant_path / "layer0_baseline.json"
        self._atomic_write(path, baseline_dict)

    def load_layer0_baseline(self, tenant_id: str) -> Dict[str, Any]:
        tenant_path = self.require_tenant_exists(tenant_id)
        path = tenant_path / "layer0_baseline.json"
        if not path.exists():
            return {}
        return self._read_json(path)

    # ============================================================
    # TELEMETRY
    # ============================================================

    def persist_telemetry_record(
        self,
        tenant_id: str,
        cycle_id: str,
        record: Dict[str, Any],
    ) -> None:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        tenant_path = self.ensure_tenant_exists(tid)
        path = tenant_path / "telemetry" / f"{cid}.jsonl"
        index_path = tenant_path / "telemetry" / f"{cid}.index"

        payload = dict(record or {})
        payload.setdefault("timestamp_ms", self._now())
        payload.setdefault("sequence", 0)
        payload = self._overlay_telemetry_payload(tid, cid, payload)

        self._atomic_append_telemetry_with_index(path, index_path, payload)

    def load_telemetry_for_cycle(
        self,
        tenant_id: str,
        cycle_id: str,
    ) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        tenant_path = self.require_tenant_exists(tid)
        path = tenant_path / "telemetry" / f"{cid}.jsonl"

        if not path.exists():
            return []

        records: List[Dict[str, Any]] = []

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except Exception as exc:
                    raise RuntimeError("Corrupt telemetry records") from exc
                if not isinstance(parsed, dict):
                    raise RuntimeError("Corrupt telemetry records")
                records.append(self._overlay_telemetry_payload(tid, cid, parsed))

        records.sort(key=lambda r: (r.get("sequence", 0), r.get("timestamp_ms", 0)))
        return records

    def load_telemetry_for_cycle_cursor(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        cursor: int = 0,
        limit: int = 500,
    ) -> Dict[str, Any]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        tenant_path = self.require_tenant_exists(tid)
        telemetry_path = tenant_path / "telemetry" / f"{cid}.jsonl"
        index_path = tenant_path / "telemetry" / f"{cid}.index"

        if not telemetry_path.exists():
            return {
                "rows": [],
                "total": 0,
                "cursor": 0,
                "next_cursor": None,
            }

        offsets = self._load_or_rebuild_telemetry_offsets(telemetry_path, index_path)
        total = len(offsets)
        start = max(0, int(cursor))
        size = max(1, min(int(limit), 10_000))
        end = min(total, start + size)

        rows: List[Dict[str, Any]] = []
        with open(telemetry_path, "r", encoding="utf-8") as f:
            for offset in offsets[start:end]:
                f.seek(offset)
                line = f.readline().strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except Exception as exc:
                    raise RuntimeError("Corrupt telemetry records") from exc
                if not isinstance(parsed, dict):
                    raise RuntimeError("Corrupt telemetry records")
                rows.append(self._overlay_telemetry_payload(tid, cid, parsed))

        return {
            "rows": rows,
            "total": total,
            "cursor": start,
            "next_cursor": (end if end < total else None),
        }

    # ============================================================
    # CYCLE METADATA
    # ============================================================

    def append_cycle_metadata(self, tenant_id: str, metadata: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.ensure_tenant_exists(tid)
        metadata_path = tenant_path / "cycle_metadata" / "metadata.jsonl"
        payload = self._overlay_cycle_metadata_payload(tid, metadata)
        self._atomic_append_jsonl(metadata_path, payload)

    def load_cycle_metadata(self, tenant_id: str) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.require_tenant_exists(tid)
        metadata_path = tenant_path / "cycle_metadata" / "metadata.jsonl"

        if not metadata_path.exists():
            return []

        records: List[Dict[str, Any]] = []
        with open(metadata_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    self._validate_cycle_metadata_record(record)
                    records.append(self._overlay_cycle_metadata_payload(tid, record))
                except Exception as exc:
                    raise RuntimeError(
                        "Corrupt cycle metadata"
                    ) from exc

        return records

    def _validate_cycle_metadata_record(self, record: Dict[str, Any]) -> None:
        if not isinstance(record, dict):
            raise RuntimeError("Corrupt cycle metadata")

        required = {
            "schema_version": str,
            "cycle_number": int,
            "status": str,
            "timestamp_unix_ms": int,
        }

        for key, expected in required.items():
            if key not in record:
                raise RuntimeError("Corrupt cycle metadata")
            if not isinstance(record[key], expected):
                raise RuntimeError("Corrupt cycle metadata")

    # ============================================================
    # TRUST GRAPH SNAPSHOTS (Layer 1)
    # ============================================================

    MAX_SNAPSHOT_FILES: Optional[int] = None

    def persist_graph_snapshot(
        self,
        tenant_id: str,
        snapshot: Dict[str, Any],
        *,
        snapshot_id: str,
        cycle_id: Optional[str] = None,
    ) -> None:
        """
        Persist deterministic TrustGraph snapshot.
        """
        tenant_path = self.ensure_tenant_exists(tenant_id)
        graph_dir = tenant_path / "trust_graph"
        if not graph_dir.exists():
            raise RuntimeError("Storage not initialized: trust_graph directory missing")
        payload = dict(snapshot or {})
        cid = str(cycle_id or "").strip()
        if cid:
            payload.setdefault("cycle_id", cid)
        per_cycle_path = graph_dir / f"{snapshot_id}.json"
        latest_path = graph_dir / "latest.json"
        self._atomic_write_json(per_cycle_path, payload)
        if cid:
            self._atomic_write_json(graph_dir / f"{cid}.json", payload)
        self._atomic_write_json(latest_path, payload)

    def load_graph_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tenant_path = self.require_tenant_exists(tenant_id)
        path = tenant_path / "trust_graph" / "latest.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                record = json.load(f)
                self._validate_graph_snapshot(record)
                return record
        except Exception as exc:
            logging.getLogger(__name__).error(
                "trust_graph.snapshot_corrupt",
                extra={"tenant_id": tenant_id, "path": str(path), "error": str(exc)},
            )
            raise

    def load_graph_snapshot_for_cycle(
        self,
        tenant_id: str,
        cycle_id: str,
    ) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        tenant_path = self.require_tenant_exists(tid)
        graph_dir = tenant_path / "trust_graph"
        path = graph_dir / f"{cid}.json"
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    record = json.load(f)
                    self._validate_graph_snapshot(record)
                    return record
            except Exception as exc:
                logging.getLogger(__name__).error(
                    "trust_graph.snapshot_corrupt",
                    extra={"tenant_id": tid, "path": str(path), "error": str(exc)},
                )
                raise

        cycle_rows = self.load_cycle_metadata_for_cycle(tid, cid)
        for row in reversed(cycle_rows):
            try:
                timestamp = int(row.get("timestamp_unix_ms", 0) or 0)
            except Exception:
                timestamp = 0
            if timestamp <= 0:
                continue
            legacy_path = graph_dir / f"{timestamp}.json"
            if legacy_path.exists():
                try:
                    with open(legacy_path, "r", encoding="utf-8") as f:
                        record = json.load(f)
                        self._validate_graph_snapshot(record)
                        return record
                except Exception as exc:
                    logging.getLogger(__name__).error(
                        "trust_graph.snapshot_corrupt",
                        extra={"tenant_id": tid, "path": str(legacy_path), "error": str(exc)},
                    )
                    raise
        return None

    def load_latest_cycle_metadata(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        records = self.load_cycle_metadata(tenant_id)
        if not records:
            return None
        return records[-1]

    def load_terminal_cycle_metadata(
        self,
        tenant_id: str,
        cycle_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        rows = self.load_cycle_metadata(tenant_id)
        if not rows:
            return None
        cid = str(cycle_id or "").strip()
        if cid:
            rows = [
                row for row in rows
                if str(row.get("cycle_id", "")).strip() == cid
            ]
            if not rows:
                return None
        ordered = sorted(
            rows,
            key=self._cycle_metadata_rank_key,
        )
        return dict(ordered[-1]) if ordered else None

    def list_terminal_cycle_metadata(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = self.load_cycle_metadata(tenant_id)
        if not rows:
            return []
        by_cycle: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            cycle_id = str(row.get("cycle_id", "")).strip()
            if not cycle_id:
                continue
            existing = by_cycle.get(cycle_id)
            if existing is None:
                by_cycle[cycle_id] = row
                continue
            existing_key = self._cycle_metadata_rank_key(existing)
            candidate_key = self._cycle_metadata_rank_key(row)
            if candidate_key >= existing_key:
                by_cycle[cycle_id] = row
        return sorted(
            by_cycle.values(),
            key=lambda row: (
                -int(row.get("cycle_number", 0) or 0),
                -int(row.get("timestamp_unix_ms", 0) or 0),
            ),
        )

    @staticmethod
    def _cycle_metadata_rank_key(row: Dict[str, Any]) -> tuple[int, int, int]:
        status_rank = {"running": 0, "failed": 1, "completed": 2}
        return (
            int(row.get("cycle_number", 0) or 0),
            status_rank.get(str(row.get("status", "")).strip().lower(), -1),
            int(row.get("timestamp_unix_ms", 0) or 0),
        )

    def load_cycle_metadata_for_cycle(self, tenant_id: str, cycle_id: str) -> List[Dict[str, Any]]:
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        records = self.load_cycle_metadata(tenant_id)
        return [record for record in records if str(record.get("cycle_id", "")).strip() == cid]

    # ============================================================
    # GUARDIAN RECORDS (LAZY DIR CREATION)
    # ============================================================

    def persist_guardian_record(self, tenant_id: str, record: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.ensure_tenant_exists(tid)
        guardian_dir = tenant_path / "guardian_records"
        if not guardian_dir.exists():
            raise RuntimeError("Storage not initialized: guardian_records directory missing")

        path = guardian_dir / "metadata.jsonl"
        payload = self._overlay_guardian_payload(tid, record)
        self._atomic_append_jsonl(path, payload)

    def load_latest_guardian_records(
        self,
        tenant_id: str,
        *,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        tenant_path = self.require_tenant_exists(tid)
        guardian_dir = tenant_path / "guardian_records"
        if not guardian_dir.exists():
            return []

        path = guardian_dir / "metadata.jsonl"
        if not path.exists():
            return []

        records: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    self._validate_guardian_record(record)
                    records.append(self._overlay_guardian_payload(tid, record))
                except Exception as exc:
                    raise RuntimeError("Corrupt guardian records") from exc

        if limit is not None:
            try:
                lim = int(limit)
                if lim > 0:
                    records = records[-lim:]
            except Exception:
                pass

        return records

    def load_guardian_records_for_cycle(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        records = self.load_latest_guardian_records(tenant_id, limit=limit)
        return [record for record in records if str(record.get("cycle_id", "")).strip() == cid]

    def _validate_snapshot_record(self, record: Dict[str, Any]) -> None:
        if not isinstance(record, dict):
            raise RuntimeError("Corrupt snapshot")
        required = {
            "schema_version": str,
            "cycle_id": str,
            "cycle_number": int,
            "timestamp_unix_ms": int,
            "snapshot_hash_sha256": str,
            "endpoint_count": int,
            "endpoints": list,
        }
        for key, expected in required.items():
            if key not in record:
                raise RuntimeError("Corrupt snapshot")
            if not isinstance(record[key], expected):
                raise RuntimeError("Corrupt snapshot")

    def _validate_graph_snapshot(self, record: Dict[str, Any]) -> None:
        if not isinstance(record, dict):
            raise RuntimeError("Corrupt trust graph snapshot")
        required = {
            "version": int,
            "created_at_ms": int,
            "nodes": list,
            "edges": list,
        }
        for key, expected in required.items():
            if key not in record:
                raise RuntimeError("Corrupt trust graph snapshot")
            if not isinstance(record[key], expected):
                raise RuntimeError("Corrupt trust graph snapshot")

    def _validate_guardian_record(self, record: Dict[str, Any]) -> None:
        if not isinstance(record, dict):
            raise RuntimeError("Corrupt guardian records")
        required = {
            "timestamp_ms": (int, float),
            "entity_id": str,
            "severity": (int, float),
            "confidence": (int, float),
            "cycle_id": str,
            "cycle_number": int,
        }
        for key, expected in required.items():
            if key not in record:
                raise RuntimeError("Corrupt guardian records")
            if not isinstance(record[key], expected):
                raise RuntimeError("Corrupt guardian records")

    def _overlay_snapshot_payload(self, tenant_id: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(snapshot or {})
        payload.setdefault("tenant_id", tenant_id)
        payload.setdefault("tenant_gid", build_tenant_gid(tenant_id))

        cycle_id = str(payload.get("cycle_id", "")).strip()
        if cycle_id:
            payload.setdefault("cycle_gid", build_cycle_gid(tenant_id, cycle_id))

        endpoints = payload.get("endpoints", [])
        if isinstance(endpoints, list):
            out = []
            for endpoint in endpoints:
                if not isinstance(endpoint, dict):
                    out.append(endpoint)
                    continue
                ep = dict(endpoint)
                host = str(ep.get("hostname", "")).strip().lower().rstrip(".")
                port = ep.get("port")
                if host and isinstance(port, int):
                    try:
                        ep.setdefault("endpoint_gid", build_endpoint_gid(tenant_id, host, port))
                    except Exception:
                        pass
                out.append(ep)
            payload["endpoints"] = out
        return payload

    def _overlay_cycle_metadata_payload(self, tenant_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(metadata or {})
        payload.setdefault("tenant_id", tenant_id)
        payload.setdefault("tenant_gid", build_tenant_gid(tenant_id))
        cycle_id = str(payload.get("cycle_id", "")).strip()
        if cycle_id:
            payload.setdefault("cycle_gid", build_cycle_gid(tenant_id, cycle_id))
        return payload

    def _overlay_telemetry_payload(self, tenant_id: str, cycle_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(record or {})
        payload.setdefault("tenant_id", tenant_id)
        payload.setdefault("cycle_id", cycle_id)
        payload.setdefault("tenant_gid", build_tenant_gid(tenant_id))
        payload.setdefault("cycle_gid", build_cycle_gid(tenant_id, cycle_id))

        entity_id = str(payload.get("entity_id", "")).strip()
        if entity_id:
            try:
                payload.setdefault("endpoint_gid", endpoint_gid_from_endpoint_id(tenant_id, entity_id))
            except Exception:
                pass

        findings = payload.get("posture_findings")
        if isinstance(findings, dict):
            for bucket in ("waf_findings", "tls_findings"):
                rows = findings.get(bucket)
                if not isinstance(rows, list):
                    continue
                out_rows = []
                for item in rows:
                    if not isinstance(item, dict):
                        out_rows.append(item)
                        continue
                    row = dict(item)
                    row.setdefault("tenant_id", tenant_id)
                    row.setdefault("cycle_id", cycle_id)
                    endpoint_id = str(row.get("endpoint_id", "")).strip()
                    if endpoint_id:
                        try:
                            row.setdefault("endpoint_gid", endpoint_gid_from_endpoint_id(tenant_id, endpoint_id))
                        except Exception:
                            pass
                    out_rows.append(row)
                findings[bucket] = out_rows
            payload["posture_findings"] = findings

        return payload

    def _overlay_guardian_payload(self, tenant_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(record or {})
        payload.setdefault("tenant_id", tenant_id)
        payload.setdefault("tenant_gid", build_tenant_gid(tenant_id))
        cycle_id = str(payload.get("cycle_id", "")).strip()
        if cycle_id:
            payload.setdefault("cycle_gid", build_cycle_gid(tenant_id, cycle_id))
        entity_id = str(payload.get("entity_id", "")).strip()
        if entity_id:
            try:
                payload.setdefault("endpoint_gid", endpoint_gid_from_endpoint_id(tenant_id, entity_id))
            except Exception:
                pass
        return payload

    # ============================================================
    # LAYER 3 STATE (per-entity)
    # ============================================================

    def _safe_entity_filename(self, entity_id: str) -> str:
        s = str(entity_id or "").strip()
        if not s:
            return "unknown"
        s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
        return s[:128] if s else "unknown"

    def load_layer3_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tenant_path = self.require_tenant_exists(tenant_id)
        state_dir = tenant_path / "layer3_state"
        if not state_dir.exists():
            return None
        path = state_dir / "layer3_state_snapshot.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as exc:
            logging.getLogger(__name__).error(
                "layer3.snapshot_corrupt",
                extra={"tenant_id": tenant_id, "path": str(path), "error": str(exc)},
            )
            raise RuntimeError("Corrupt layer3 snapshot") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Corrupt layer3 snapshot")
        return payload

    def load_layer3_snapshot_for_cycle(
        self,
        tenant_id: str,
        cycle_id: str,
    ) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        tenant_path = self.require_tenant_exists(tid)
        state_dir = tenant_path / "layer3_state"
        if not state_dir.exists():
            return None
        path = state_dir / f"{cid}.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as exc:
            logging.getLogger(__name__).error(
                "layer3.snapshot_corrupt",
                extra={"tenant_id": tid, "path": str(path), "error": str(exc)},
            )
            raise RuntimeError("Corrupt layer3 snapshot") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Corrupt layer3 snapshot")
        return payload

    def persist_layer3_snapshot(
        self,
        tenant_id: str,
        snapshot: Dict[str, Any],
        *,
        cycle_id: Optional[str] = None,
    ) -> bool:
        tenant_path = self.ensure_tenant_exists(tenant_id)
        state_dir = tenant_path / "layer3_state"
        state_dir.mkdir(parents=True, exist_ok=True)
        path = state_dir / "layer3_state_snapshot.json"
        try:
            self._atomic_write_sorted(path, snapshot)
            cid = str(cycle_id or "").strip()
            if cid:
                self._atomic_write_sorted(state_dir / f"{cid}.json", snapshot)
            return True
        except Exception as exc:
            logging.getLogger(__name__).error(
                "layer3.snapshot_persist_failed",
                extra={"tenant_id": tenant_id, "path": str(path), "error": str(exc)},
            )
            return False

    # ============================================================
    # LOCK MANAGEMENT
    # ============================================================

    STALE_CYCLE_LOCK_THRESHOLD_MS = 6 * 60 * 60 * 1000  # 6 hours
    TERMINAL_CYCLE_LOCK_GRACE_MS = 30 * 1000
    _CYCLE_LOCK_WRITE_RETRY_DELAYS_SECONDS = (0.025, 0.05, 0.1, 0.2)
    _CYCLE_LOCK_READ_RETRY_DELAYS_SECONDS = (0.01, 0.025, 0.05, 0.1)
    _CYCLE_LOCK_UNLINK_RETRY_DELAYS_SECONDS = (0.025, 0.05, 0.1, 0.2)

    def reserve_cycle_launch(
        self,
        tenant_id: str,
        cycle_id: str,
        cycle_number: int,
    ) -> None:
        tenant_path = self.require_tenant_exists(tenant_id)
        lock_path = tenant_path / ".cycle.lock"

        if lock_path.exists():
            if self._is_stale_cycle_lock(lock_path):
                try:
                    lock_path.unlink()
                except Exception as exc:
                    raise RuntimeError("Stale cycle lock removal failed") from exc
            else:
                raise RuntimeError("Active cycle already running")

        now_ms = self._now()
        payload = {
            "cycle_id": cycle_id,
            "cycle_number": cycle_number,
            "started_at_unix_ms": now_ms,
            "updated_at_unix_ms": now_ms,
            "stage": "launching",
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
        }

        self._write_cycle_lock(lock_path, payload)

    def acquire_cycle_lock(
        self,
        tenant_id: str,
        cycle_id: str,
        cycle_number: int,
    ) -> None:
        tenant_path = self.require_tenant_exists(tenant_id)
        lock_path = tenant_path / ".cycle.lock"

        if lock_path.exists():
            if self._is_stale_cycle_lock(lock_path):
                try:
                    lock_path.unlink()
                except Exception as exc:
                    raise RuntimeError("Stale cycle lock removal failed") from exc
            else:
                existing = self._read_cycle_lock_json(lock_path)
                existing_stage = str(existing.get("stage", "")).strip().lower()
                existing_cycle_id = str(existing.get("cycle_id", "")).strip()
                try:
                    existing_cycle_number = int(existing.get("cycle_number", 0) or 0)
                except Exception:
                    existing_cycle_number = 0
                if not (
                    existing_stage == "launching"
                    and existing_cycle_id == str(cycle_id or "").strip()
                    and existing_cycle_number == int(cycle_number)
                ):
                    raise RuntimeError("Active cycle already running")

        now_ms = self._now()
        payload = {
            "cycle_id": cycle_id,
            "cycle_number": cycle_number,
            "started_at_unix_ms": now_ms,
            "updated_at_unix_ms": now_ms,
            "stage": "initializing",
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
        }

        self._write_cycle_lock(lock_path, payload)

    def release_cycle_lock(self, tenant_id: str) -> None:
        tenant_path = self.require_tenant_exists(tenant_id)
        lock_path = tenant_path / ".cycle.lock"
        if not lock_path.exists():
            return
        last_error: Optional[Exception] = None
        for index, delay in enumerate((0.0, *self._CYCLE_LOCK_UNLINK_RETRY_DELAYS_SECONDS)):
            if delay > 0:
                time.sleep(delay + random.uniform(0.0, 0.01))
            try:
                lock_path.unlink(missing_ok=True)
                return
            except FileNotFoundError:
                return
            except PermissionError as exc:
                last_error = exc
                if index + 1 == len(self._CYCLE_LOCK_UNLINK_RETRY_DELAYS_SECONDS) + 1:
                    break
            except OSError as exc:
                last_error = exc
                if not self._is_retryable_cycle_lock_error(exc):
                    raise
        payload = self._read_cycle_lock_json(lock_path, default={})
        now_ms = self._now()
        if not isinstance(payload, dict):
            payload = {}
        payload.update(
            {
                "terminal": True,
                "released": False,
                "release_failed_at_unix_ms": now_ms,
                "updated_at_unix_ms": now_ms,
            }
        )
        if not str(payload.get("stage", "")).strip():
            payload["stage"] = "failed"
        try:
            self._write_cycle_lock(lock_path, payload)
        except Exception:
            logging.getLogger(__name__).warning(
                "cycle_lock_release_tombstone_failed path=%s",
                str(lock_path),
                exc_info=True,
            )
        if last_error is not None:
            logging.getLogger(__name__).warning(
                "cycle_lock_release_retry_exhausted path=%s error=%s",
                str(lock_path),
                str(last_error),
            )

    def load_cycle_lock(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tenant_path = self.require_tenant_exists(tenant_id)
        lock_path = tenant_path / ".cycle.lock"
        if not lock_path.exists():
            return None
        payload = self._read_cycle_lock_json(lock_path, default=None)
        if payload is None:
            if self._is_stale_cycle_lock(lock_path):
                try:
                    self.release_cycle_lock(tenant_id)
                except Exception:
                    pass
                return None
            return None
        if self._is_terminal_cycle_lock_payload(payload):
            if self._terminal_cycle_lock_expired(payload):
                try:
                    self.release_cycle_lock(tenant_id)
                except Exception:
                    pass
            return None
        if self._is_stale_cycle_lock(lock_path, payload=payload):
            try:
                self.release_cycle_lock(tenant_id)
            except OSError:
                pass
            return None
        return payload

    def load_scheduler_state(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tenant_path = self.require_tenant_exists(tenant_id)
        state_path = tenant_path / "scheduler_state.json"
        if not state_path.exists():
            return None
        payload = self._read_json(state_path)
        return payload if isinstance(payload, dict) else None

    def save_scheduler_state(self, tenant_id: str, state: Dict[str, Any]) -> None:
        tenant_path = self.require_tenant_exists(tenant_id)
        state_path = tenant_path / "scheduler_state.json"
        self._atomic_write_sorted(state_path, dict(state or {}))

    def update_cycle_lock(self, tenant_id: str, updates: Dict[str, Any]) -> None:
        tenant_path = self.require_tenant_exists(tenant_id)
        lock_path = tenant_path / ".cycle.lock"
        if not lock_path.exists():
            raise RuntimeError("Active cycle lock not found")

        payload = self._read_cycle_lock_json(lock_path)
        payload.update(dict(updates or {}))
        payload["updated_at_unix_ms"] = self._now()
        self._write_cycle_lock(lock_path, payload)

    def _is_stale_cycle_lock(
        self,
        lock_path: Path,
        *,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if payload is None:
            payload = self._read_cycle_lock_json(lock_path, default=None)
        if not isinstance(payload, dict):
            try:
                stat = lock_path.stat()
            except OSError:
                return True
            return (self._now() - int(stat.st_mtime * 1000)) > self.STALE_CYCLE_LOCK_THRESHOLD_MS

        started = payload.get("started_at_unix_ms")
        if not isinstance(started, int):
            return True

        if self._is_terminal_cycle_lock_payload(payload):
            return self._terminal_cycle_lock_expired(payload)

        lock_hostname = str(payload.get("hostname", "")).strip()
        pid = payload.get("pid")
        if (
            lock_hostname
            and lock_hostname == socket.gethostname()
            and isinstance(pid, int)
            and pid > 0
            and not self._is_process_alive(pid)
        ):
            return True

        now = self._now()
        return (now - started) > self.STALE_CYCLE_LOCK_THRESHOLD_MS

    def _is_terminal_cycle_lock_payload(self, payload: Dict[str, Any]) -> bool:
        stage = str(payload.get("stage", "")).strip().lower()
        return bool(payload.get("terminal")) or stage in {"completed", "failed"}

    def _terminal_cycle_lock_expired(self, payload: Dict[str, Any]) -> bool:
        updated_at = payload.get("updated_at_unix_ms")
        started_at = payload.get("started_at_unix_ms")
        try:
            timestamp_ms = int(updated_at or started_at or 0)
        except Exception:
            timestamp_ms = 0
        if timestamp_ms <= 0:
            return True
        return (self._now() - timestamp_ms) > self.TERMINAL_CYCLE_LOCK_GRACE_MS

    def _is_retryable_cycle_lock_error(self, exc: BaseException) -> bool:
        if isinstance(exc, PermissionError):
            return True
        if isinstance(exc, OSError):
            if getattr(exc, "winerror", None) in {5, 32}:
                return True
            if getattr(exc, "errno", None) in {13, 16}:
                return True
        text = str(exc or "").lower()
        return "access is denied" in text or "permission denied" in text or "used by another process" in text

    def _read_cycle_lock_json(
        self,
        lock_path: Path,
        *,
        default: Any = ...,
    ) -> Any:
        last_error: Optional[Exception] = None
        for delay in (0.0, *self._CYCLE_LOCK_READ_RETRY_DELAYS_SECONDS):
            if delay > 0:
                time.sleep(delay)
            try:
                return self._read_json(lock_path)
            except FileNotFoundError as exc:
                last_error = exc
                break
            except json.JSONDecodeError as exc:
                last_error = exc
            except PermissionError as exc:
                last_error = exc
            except OSError as exc:
                last_error = exc
                if not self._is_retryable_cycle_lock_error(exc):
                    break
        if default is not ...:
            return default
        if last_error is not None:
            raise last_error
        raise FileNotFoundError(str(lock_path))

    def _write_cycle_lock(self, lock_path: Path, data: Dict[str, Any]) -> None:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(data or {})
        serialized = json.dumps(payload, indent=2, ensure_ascii=True)
        last_error: Optional[Exception] = None

        for delay in (0.0, *self._CYCLE_LOCK_WRITE_RETRY_DELAYS_SECONDS):
            if delay > 0:
                time.sleep(delay + random.uniform(0.0, 0.01))
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    delete=False,
                    dir=lock_path.parent,
                    encoding="utf-8",
                ) as tmp_file:
                    tmp_file.write(serialized)
                    tmp_file.flush()
                    os.fsync(tmp_file.fileno())
                    tmp_path = Path(tmp_file.name)
                try:
                    os.replace(tmp_path, lock_path)
                except Exception:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    raise
                return
            except Exception as exc:
                last_error = exc
                if not self._is_retryable_cycle_lock_error(exc):
                    raise

        self._write_cycle_lock_inplace(lock_path, serialized, last_error)

    def _write_cycle_lock_inplace(
        self,
        lock_path: Path,
        serialized: str,
        last_error: Optional[Exception] = None,
    ) -> None:
        try:
            with open(lock_path, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception as exc:
            if last_error is not None and self._is_retryable_cycle_lock_error(exc):
                raise last_error
            raise

    @staticmethod
    def _is_process_alive(pid: int) -> bool:
        if os.name == "nt":
            try:
                import ctypes

                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                handle = ctypes.windll.kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    int(pid),
                )
                if handle:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True
                error_code = ctypes.GetLastError()
                if error_code == 5:
                    return True
                return False
            except Exception:
                return False
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except (OSError, SystemError):
            return False
        return True

    # ============================================================
    # INTERNAL HELPERS
    # ============================================================

    def _atomic_write(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=path.parent,
            encoding="utf-8",
        ) as tmp_file:
            json.dump(data, tmp_file, indent=2)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = Path(tmp_file.name)

        os.replace(tmp_path, path)

    def _atomic_append_jsonl(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        json_line = json.dumps(data, separators=(",",":"), ensure_ascii=False) + "\n"
        lock = self._append_locks[str(path)]

        with lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json_line)
                f.flush()
                os.fsync(f.fileno())

    def _atomic_append_telemetry_with_index(
        self,
        telemetry_path: Path,
        index_path: Path,
        data: Dict[str, Any],
    ) -> None:
        telemetry_path.parent.mkdir(parents=True, exist_ok=True)
        json_line = json.dumps(data, separators=(",", ":"), ensure_ascii=False) + "\n"
        lock = self._append_locks[str(telemetry_path)]
        with lock:
            with open(telemetry_path, "a+", encoding="utf-8") as tf:
                tf.seek(0, os.SEEK_END)
                offset = tf.tell()
                tf.write(json_line)
                tf.flush()
                os.fsync(tf.fileno())
            with open(index_path, "a", encoding="utf-8") as ix:
                ix.write(f"{offset}\n")
                ix.flush()
                os.fsync(ix.fileno())

    def _load_or_rebuild_telemetry_offsets(
        self,
        telemetry_path: Path,
        index_path: Path,
    ) -> List[int]:
        def _parse_index_lines(text: str) -> List[int]:
            offsets: List[int] = []
            for raw in text.splitlines():
                line = raw.strip()
                if not line:
                    continue
                offsets.append(int(line))
            return offsets

        lock = self._append_locks[str(telemetry_path)]
        with lock:
            if index_path.exists():
                try:
                    offsets = _parse_index_lines(index_path.read_text(encoding="utf-8"))
                    if offsets:
                        return offsets
                except Exception:
                    # Rebuild from telemetry file below.
                    pass

            offsets: List[int] = []
            with open(telemetry_path, "r", encoding="utf-8") as f:
                while True:
                    offset = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if line.strip():
                        offsets.append(offset)

            tmp = index_path.with_suffix(index_path.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as out:
                for offset in offsets:
                    out.write(f"{offset}\n")
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, index_path)
            return offsets

    def _read_json(self, path: Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _atomic_write_sorted(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=path.parent,
            encoding="utf-8",
        ) as tmp_file:
            json.dump(data, tmp_file, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = Path(tmp_file.name)

        os.replace(tmp_path, path)

    def _atomic_write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """
        Atomic JSON writer with deterministic encoding.
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=path.parent,
            encoding="utf-8",
        ) as tmp_file:
            json.dump(data, tmp_file, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = Path(tmp_file.name)

        os.replace(tmp_path, path)

    def _now(self) -> int:
        return int(time.time() * 1000)
