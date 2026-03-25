"""
Postgres-backed StorageManager.

Implements the same public interface as StorageManager so it can be used as a
drop-in replacement when GUARDIAN_DATABASE_URL is set.

The __init__ still accepts base_path for compatibility (filesystem paths are
used for the write-probe in bootstrap.py and as a fallback sentinel).
"""
from __future__ import annotations

import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2.extras

from infrastructure.aggregation.global_identity import (
    cycle_gid as build_cycle_gid,
    endpoint_gid as build_endpoint_gid,
    endpoint_gid_from_endpoint_id,
    tenant_gid as build_tenant_gid,
)
from infrastructure.db.connection import get_conn, put_conn

logger = logging.getLogger(__name__)

STALE_CYCLE_LOCK_THRESHOLD_MS = 6 * 60 * 60 * 1000  # 6 hours
TERMINAL_CYCLE_LOCK_GRACE_MS = 30 * 1000


class PgStorageManager:
    """
    Postgres-backed implementation of the StorageManager interface.
    """

    def __init__(self, base_path: str) -> None:
        self.base_path = Path(base_path)
        # Maintain these for any code that accesses them directly.
        self.identity_dir = self.base_path / "identity"
        self.tenants_dir = self.base_path / "tenant_data_storage" / "tenants"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def _validate_tenant_id(tenant_id: str) -> str:
        tid = str(tenant_id or "").strip()
        if not tid:
            raise ValueError("tenant_id cannot be empty")
        if any(sep in tid for sep in ("/", "\\", "..")):
            raise ValueError("Invalid tenant_id path sequence")
        return tid

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

    # ------------------------------------------------------------------
    # Tenant lifecycle
    # ------------------------------------------------------------------

    def create_tenant(self, tenant_id: str) -> Path:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM tenants WHERE tenant_id = %s", (tid,)
                )
                if cur.fetchone() is not None:
                    raise RuntimeError(f"Tenant already exists: {tid}")
                cur.execute(
                    "INSERT INTO tenants (tenant_id) VALUES (%s)", (tid,)
                )
            conn.commit()
        finally:
            put_conn(conn)
        return self.base_path / "tenant_data_storage" / "tenants" / tid

    def ensure_tenant_exists(self, tenant_id: str) -> Path:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id) VALUES (%s) ON CONFLICT DO NOTHING",
                    (tid,),
                )
            conn.commit()
        finally:
            put_conn(conn)
        return self.base_path / "tenant_data_storage" / "tenants" / tid

    def tenant_exists(self, tenant_id: str) -> bool:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM tenants WHERE tenant_id = %s", (tid,)
                )
                return cur.fetchone() is not None
        finally:
            put_conn(conn)

    def delete_tenant(self, tenant_id: str) -> None:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status FROM cycle_locks WHERE tenant_id = %s", (tid,)
                )
                lock_row = cur.fetchone()
                if lock_row is not None and lock_row[0] == "active":
                    raise RuntimeError(
                        f"Cannot delete tenant {tid}: active cycle lock present"
                    )
                cur.execute(
                    "DELETE FROM tenants WHERE tenant_id = %s RETURNING tenant_id",
                    (tid,),
                )
                if cur.rowcount == 0:
                    raise RuntimeError(f"Tenant does not exist: {tid}")
            conn.commit()
        finally:
            put_conn(conn)

    def reset_tenant(self, tenant_id: str) -> Path:
        self.delete_tenant(tenant_id)
        return self.create_tenant(tenant_id)

    def require_tenant_exists(self, tenant_id: str) -> Path:
        tid = self._validate_tenant_id(tenant_id)
        if not self.tenant_exists(tid):
            raise RuntimeError(f"Tenant does not exist: {tid}")
        return self.base_path / "tenant_data_storage" / "tenants" / tid

    def get_tenant_path(self, tenant_id: str) -> Path:
        return self.require_tenant_exists(tenant_id)

    def list_tenant_ids(self) -> List[str]:
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT tenant_id FROM tenants ORDER BY tenant_id")
                return [row[0] for row in cur.fetchall()]
        finally:
            put_conn(conn)

    # Alias used by some callers
    def list_all_tenants(self) -> List[str]:
        return self.list_tenant_ids()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def save_tenant_config(self, tenant_id: str, config: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        payload = dict(config or {})
        payload["schema_version"] = str(payload.get("schema_version") or "v3")
        payload.setdefault("tenant_id", tid)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tenant_configs (tenant_id, config, updated_at)
                    VALUES (%s, %s::jsonb, now())
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        config     = EXCLUDED.config,
                        updated_at = now()
                    """,
                    (tid, json.dumps(payload)),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def load_tenant_config(self, tenant_id: str) -> Dict[str, Any]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT config FROM tenant_configs WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
            if row is None:
                return {}
            cfg = row["config"]
            return cfg if isinstance(cfg, dict) else {}
        finally:
            put_conn(conn)

    def update_tenant_config_fields(self, tenant_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        existing = self.load_tenant_config(tenant_id)
        existing.update(dict(fields or {}))
        self.save_tenant_config(tenant_id, existing)
        return existing

    def save_seed_endpoints(self, tenant_id: str, endpoints: List[str]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        cleaned = sorted(set(str(e) for e in (endpoints or []) if str(e).strip()))
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM seed_endpoints WHERE tenant_id = %s", (tid,)
                )
                for ep in cleaned:
                    cur.execute(
                        "INSERT INTO seed_endpoints (tenant_id, endpoint) VALUES (%s, %s) "
                        "ON CONFLICT DO NOTHING",
                        (tid, ep),
                    )
                # Mirror the tenant_config.json layout — store in tenant_configs too.
                cur.execute(
                    "SELECT config FROM tenant_configs WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
                existing_cfg: Dict[str, Any] = {}
                if row and isinstance(row[0], dict):
                    existing_cfg = row[0]
                existing_cfg["seed_endpoints"] = cleaned
                existing_cfg.setdefault("schema_version", "v3")
                existing_cfg.setdefault("tenant_id", tid)
                cur.execute(
                    """
                    INSERT INTO tenant_configs (tenant_id, config, updated_at)
                    VALUES (%s, %s::jsonb, now())
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        config     = EXCLUDED.config,
                        updated_at = now()
                    """,
                    (tid, json.dumps(existing_cfg)),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def load_seed_endpoints(self, tenant_id: str) -> List[str]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT endpoint FROM seed_endpoints WHERE tenant_id = %s ORDER BY endpoint",
                    (tid,),
                )
                return [row[0] for row in cur.fetchall()]
        finally:
            put_conn(conn)

    def add_seed_endpoints(self, tenant_id: str, endpoints: List[str]) -> None:
        existing = self.load_seed_endpoints(tenant_id)
        updated = sorted(set(existing + list(endpoints)))
        self.save_seed_endpoints(tenant_id, updated)

    def remove_seed_endpoint(self, tenant_id: str, endpoint: str) -> None:
        existing = self.load_seed_endpoints(tenant_id)
        if endpoint not in existing:
            return
        self.save_seed_endpoints(tenant_id, [e for e in existing if e != endpoint])

    # ------------------------------------------------------------------
    # Fingerprints
    # ------------------------------------------------------------------

    def has_any_fingerprints(self, tenant_id: str) -> bool:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT EXISTS(SELECT 1 FROM fingerprints WHERE tenant_id = %s)",
                    (tid,),
                )
                return bool(cur.fetchone()[0])
        finally:
            put_conn(conn)

    def save_fingerprints(self, tenant_id: str, fingerprints: List[Dict[str, Any]]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                for fp in fingerprints:
                    entity_id = str(fp.get("entity_id", "")).strip()
                    if not entity_id:
                        continue
                    cur.execute(
                        """
                        INSERT INTO fingerprints (tenant_id, entity_id, payload, updated_at)
                        VALUES (%s, %s, %s::jsonb, now())
                        ON CONFLICT (tenant_id, entity_id) DO UPDATE SET
                            payload    = EXCLUDED.payload,
                            updated_at = now()
                        """,
                        (tid, entity_id, json.dumps(fp)),
                    )
            conn.commit()
        finally:
            put_conn(conn)

    def load_fingerprints(self, tenant_id: str) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM fingerprints WHERE tenant_id = %s ORDER BY entity_id",
                    (tid,),
                )
                rows = cur.fetchall()
            return [row["payload"] for row in rows]
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def save_snapshot(self, tenant_id: str, snapshot: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        payload = self._overlay_snapshot_payload(tid, snapshot)
        cycle_id = str(payload.get("cycle_id", "")).strip()
        if not cycle_id:
            raise ValueError("snapshot must contain a cycle_id")
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM snapshots WHERE tenant_id = %s AND cycle_id = %s",
                    (tid, cycle_id),
                )
                if cur.fetchone() is not None:
                    raise RuntimeError(f"Snapshot already exists: {cycle_id}")
                cur.execute(
                    "INSERT INTO snapshots (tenant_id, cycle_id, payload) VALUES (%s, %s, %s::jsonb)",
                    (tid, cycle_id, json.dumps(payload)),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def load_latest_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM snapshots WHERE tenant_id = %s "
                    "ORDER BY cycle_id DESC LIMIT 1",
                    (tid,),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return self._overlay_snapshot_payload(tid, row["payload"])
        finally:
            put_conn(conn)

    def load_previous_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM snapshots WHERE tenant_id = %s "
                    "ORDER BY cycle_id DESC LIMIT 1 OFFSET 1",
                    (tid,),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return self._overlay_snapshot_payload(tid, row["payload"])
        finally:
            put_conn(conn)

    def load_snapshot_for_cycle(self, tenant_id: str, cycle_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM snapshots WHERE tenant_id = %s AND cycle_id = %s",
                    (tid, cid),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return self._overlay_snapshot_payload(tid, row["payload"])
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Temporal state
    # ------------------------------------------------------------------

    def save_temporal_state(
        self,
        tenant_id: str,
        state: Dict[str, Any],
        *,
        cycle_id: Optional[str] = None,
    ) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO temporal_states (tenant_id, cycle_id, payload, updated_at)
                    VALUES (%s, 'current', %s::jsonb, now())
                    ON CONFLICT (tenant_id, cycle_id) DO UPDATE SET
                        payload    = EXCLUDED.payload,
                        updated_at = now()
                    """,
                    (tid, json.dumps(state)),
                )
                cid = str(cycle_id or "").strip()
                if cid:
                    cur.execute(
                        """
                        INSERT INTO temporal_states (tenant_id, cycle_id, payload, updated_at)
                        VALUES (%s, %s, %s::jsonb, now())
                        ON CONFLICT (tenant_id, cycle_id) DO UPDATE SET
                            payload    = EXCLUDED.payload,
                            updated_at = now()
                        """,
                        (tid, cid, json.dumps(state)),
                    )
            conn.commit()
        finally:
            put_conn(conn)

    def load_temporal_state(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM temporal_states WHERE tenant_id = %s AND cycle_id = 'current'",
                    (tid,),
                )
                row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    def load_temporal_state_for_cycle(self, tenant_id: str, cycle_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM temporal_states WHERE tenant_id = %s AND cycle_id = %s",
                    (tid, cid),
                )
                row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Layer 0 baseline
    # ------------------------------------------------------------------

    def save_layer0_baseline(self, tenant_id: str, baseline_dict: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO layer0_baselines (tenant_id, payload, updated_at)
                    VALUES (%s, %s::jsonb, now())
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        payload    = EXCLUDED.payload,
                        updated_at = now()
                    """,
                    (tid, json.dumps(baseline_dict)),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def load_layer0_baseline(self, tenant_id: str) -> Dict[str, Any]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM layer0_baselines WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
            return row["payload"] if row else {}
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------

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
        self.ensure_tenant_exists(tid)
        payload = dict(record or {})
        payload.setdefault("timestamp_ms", self._now())
        payload.setdefault("sequence", 0)
        payload = self._overlay_telemetry_payload(tid, cid, payload)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO telemetry
                        (tenant_id, cycle_id, sequence, record_type, timestamp_ms, payload)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        tid,
                        cid,
                        int(payload.get("sequence", 0) or 0),
                        str(payload.get("record_type", "") or ""),
                        int(payload.get("timestamp_ms", 0) or 0),
                        json.dumps(payload),
                    ),
                )
            conn.commit()
        finally:
            put_conn(conn)

    # Alias used by some callers
    def append_telemetry(
        self,
        tenant_id: str,
        cycle_id: str,
        record: Dict[str, Any],
        record_type: Optional[str] = None,
    ) -> None:
        if record_type is not None:
            record = dict(record)
            record.setdefault("record_type", record_type)
        self.persist_telemetry_record(tenant_id, cycle_id, record)

    def load_telemetry_for_cycle(
        self,
        tenant_id: str,
        cycle_id: str,
        record_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if record_type:
                    cur.execute(
                        "SELECT payload FROM telemetry "
                        "WHERE tenant_id = %s AND cycle_id = %s AND record_type = %s "
                        "ORDER BY sequence, timestamp_ms",
                        (tid, cid, record_type),
                    )
                else:
                    cur.execute(
                        "SELECT payload FROM telemetry "
                        "WHERE tenant_id = %s AND cycle_id = %s "
                        "ORDER BY sequence, timestamp_ms",
                        (tid, cid),
                    )
                rows = cur.fetchall()
            return [self._overlay_telemetry_payload(tid, cid, row["payload"]) for row in rows]
        finally:
            put_conn(conn)

    def load_telemetry_for_cycle_cursor(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        cursor: int = 0,
        limit: int = 500,
    ) -> Dict[str, Any]:
        return self.load_telemetry_page(
            tenant_id, cycle_id, cursor=cursor, page_size=limit
        )

    def load_telemetry_page(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        cursor: int = 0,
        page_size: int = 500,
        record_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        offset = max(0, int(cursor))
        size = max(1, min(int(page_size), 10_000))
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if record_type:
                    cur.execute(
                        "SELECT COUNT(*) FROM telemetry "
                        "WHERE tenant_id = %s AND cycle_id = %s AND record_type = %s",
                        (tid, cid, record_type),
                    )
                else:
                    cur.execute(
                        "SELECT COUNT(*) FROM telemetry WHERE tenant_id = %s AND cycle_id = %s",
                        (tid, cid),
                    )
                total = cur.fetchone()["count"]

                if record_type:
                    cur.execute(
                        "SELECT payload FROM telemetry "
                        "WHERE tenant_id = %s AND cycle_id = %s AND record_type = %s "
                        "ORDER BY sequence, timestamp_ms "
                        "LIMIT %s OFFSET %s",
                        (tid, cid, record_type, size, offset),
                    )
                else:
                    cur.execute(
                        "SELECT payload FROM telemetry "
                        "WHERE tenant_id = %s AND cycle_id = %s "
                        "ORDER BY sequence, timestamp_ms "
                        "LIMIT %s OFFSET %s",
                        (tid, cid, size, offset),
                    )
                rows = cur.fetchall()
            result_rows = [self._overlay_telemetry_payload(tid, cid, r["payload"]) for r in rows]
            end = offset + len(result_rows)
            return {
                "rows": result_rows,
                "total": total,
                "cursor": offset,
                "next_cursor": (end if end < total else None),
            }
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Cycle metadata
    # ------------------------------------------------------------------

    def append_cycle_metadata(self, tenant_id: str, metadata: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        payload = self._overlay_cycle_metadata_payload(tid, metadata)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cycle_metadata
                        (tenant_id, cycle_id, cycle_number, status, schema_version,
                         timestamp_unix_ms, payload)
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        tid,
                        str(payload.get("cycle_id", "") or ""),
                        int(payload.get("cycle_number", 0) or 0),
                        str(payload.get("status", "") or ""),
                        str(payload.get("schema_version", "") or ""),
                        int(payload.get("timestamp_unix_ms", 0) or 0),
                        json.dumps(payload),
                    ),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def load_cycle_metadata(self, tenant_id: str, *, limit: int = 20) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM cycle_metadata WHERE tenant_id = %s ORDER BY id DESC LIMIT %s",
                    (tid, int(limit)),
                )
                rows = cur.fetchall()
            # Reverse so callers that expect ascending order still work.
            return [self._overlay_cycle_metadata_payload(tid, row["payload"]) for row in reversed(rows)]
        finally:
            put_conn(conn)

    def load_cycle_metadata_for_cycle(self, tenant_id: str, cycle_id: str) -> List[Dict[str, Any]]:
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        records = self.load_cycle_metadata(tenant_id)
        return [r for r in records if str(r.get("cycle_id", "")).strip() == cid]

    def load_latest_cycle_metadata(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        records = self.load_cycle_metadata(tenant_id)
        return records[-1] if records else None

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
            rows = [r for r in rows if str(r.get("cycle_id", "")).strip() == cid]
            if not rows:
                return None
        ordered = sorted(rows, key=self._cycle_metadata_rank_key)
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
            if self._cycle_metadata_rank_key(row) >= self._cycle_metadata_rank_key(existing):
                by_cycle[cycle_id] = row
        return sorted(
            by_cycle.values(),
            key=lambda r: (
                -int(r.get("cycle_number", 0) or 0),
                -int(r.get("timestamp_unix_ms", 0) or 0),
            ),
        )

    @staticmethod
    def _cycle_metadata_rank_key(row: Dict[str, Any]) -> tuple:
        status_rank = {"running": 0, "failed": 1, "completed": 2}
        return (
            int(row.get("cycle_number", 0) or 0),
            status_rank.get(str(row.get("status", "")).strip().lower(), -1),
            int(row.get("timestamp_unix_ms", 0) or 0),
        )

    # ------------------------------------------------------------------
    # Trust graph snapshots
    # ------------------------------------------------------------------

    def persist_graph_snapshot(
        self,
        tenant_id: str,
        snapshot: Dict[str, Any],
        *,
        snapshot_id: str,
        cycle_id: Optional[str] = None,
    ) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        payload = dict(snapshot or {})
        cid = str(cycle_id or "").strip()
        if cid:
            payload.setdefault("cycle_id", cid)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO trust_graph_snapshots
                        (tenant_id, snapshot_id, cycle_id, payload, created_at)
                    VALUES (%s, %s, %s, %s::jsonb, now())
                    ON CONFLICT (tenant_id, snapshot_id) DO UPDATE SET
                        cycle_id   = EXCLUDED.cycle_id,
                        payload    = EXCLUDED.payload,
                        created_at = now()
                    """,
                    (tid, snapshot_id, cid or None, json.dumps(payload)),
                )
                # Always update "latest" alias.
                cur.execute(
                    """
                    INSERT INTO trust_graph_snapshots
                        (tenant_id, snapshot_id, cycle_id, payload, created_at)
                    VALUES (%s, 'latest', %s, %s::jsonb, now())
                    ON CONFLICT (tenant_id, snapshot_id) DO UPDATE SET
                        cycle_id   = EXCLUDED.cycle_id,
                        payload    = EXCLUDED.payload,
                        created_at = now()
                    """,
                    (tid, cid or None, json.dumps(payload)),
                )
                # Store a per-cycle alias so load_graph_snapshot_for_cycle works.
                if cid:
                    cur.execute(
                        """
                        INSERT INTO trust_graph_snapshots
                            (tenant_id, snapshot_id, cycle_id, payload, created_at)
                        VALUES (%s, %s, %s, %s::jsonb, now())
                        ON CONFLICT (tenant_id, snapshot_id) DO UPDATE SET
                            cycle_id   = EXCLUDED.cycle_id,
                            payload    = EXCLUDED.payload,
                            created_at = now()
                        """,
                        (tid, f"cycle_{cid}", cid, json.dumps(payload)),
                    )
            conn.commit()
        finally:
            put_conn(conn)

    def load_graph_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM trust_graph_snapshots "
                    "WHERE tenant_id = %s AND snapshot_id = 'latest'",
                    (tid,),
                )
                row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    def load_graph_snapshot_for_cycle(self, tenant_id: str, cycle_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM trust_graph_snapshots "
                    "WHERE tenant_id = %s AND snapshot_id = %s",
                    (tid, f"cycle_{cid}"),
                )
                row = cur.fetchone()
                if row is None:
                    # Fallback: find by cycle_id column.
                    cur.execute(
                        "SELECT payload FROM trust_graph_snapshots "
                        "WHERE tenant_id = %s AND cycle_id = %s "
                        "ORDER BY created_at DESC LIMIT 1",
                        (tid, cid),
                    )
                    row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    def load_graph_snapshot_by_id(self, tenant_id: str, snapshot_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM trust_graph_snapshots "
                    "WHERE tenant_id = %s AND snapshot_id = %s",
                    (tid, snapshot_id),
                )
                row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Layer 3 snapshots
    # ------------------------------------------------------------------

    def persist_layer3_snapshot(
        self,
        tenant_id: str,
        snapshot: Dict[str, Any],
        *,
        cycle_id: Optional[str] = None,
    ) -> bool:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO layer3_snapshots (tenant_id, cycle_id, payload, updated_at)
                    VALUES (%s, 'current', %s::jsonb, now())
                    ON CONFLICT (tenant_id, cycle_id) DO UPDATE SET
                        payload    = EXCLUDED.payload,
                        updated_at = now()
                    """,
                    (tid, json.dumps(snapshot)),
                )
                cid = str(cycle_id or "").strip()
                if cid:
                    cur.execute(
                        """
                        INSERT INTO layer3_snapshots (tenant_id, cycle_id, payload, updated_at)
                        VALUES (%s, %s, %s::jsonb, now())
                        ON CONFLICT (tenant_id, cycle_id) DO UPDATE SET
                            payload    = EXCLUDED.payload,
                            updated_at = now()
                        """,
                        (tid, cid, json.dumps(snapshot)),
                    )
            conn.commit()
            return True
        except Exception as exc:
            logger.error("layer3.snapshot_persist_failed tenant=%s error=%s", tid, exc)
            return False
        finally:
            put_conn(conn)

    def load_layer3_snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM layer3_snapshots "
                    "WHERE tenant_id = %s AND cycle_id = 'current'",
                    (tid,),
                )
                row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    def load_layer3_snapshot_for_cycle(self, tenant_id: str, cycle_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM layer3_snapshots WHERE tenant_id = %s AND cycle_id = %s",
                    (tid, cid),
                )
                row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Guardian records
    # ------------------------------------------------------------------

    def persist_guardian_record(self, tenant_id: str, record: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        payload = self._overlay_guardian_payload(tid, record)
        cycle_id = str(payload.get("cycle_id", "") or "")
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO guardian_records (tenant_id, cycle_id, payload) "
                    "VALUES (%s, %s, %s::jsonb)",
                    (tid, cycle_id or None, json.dumps(payload)),
                )
            conn.commit()
        finally:
            put_conn(conn)

    # Alias names used by orchestrator/pipeline code
    def append_guardian_record(self, tenant_id: str, record: Dict[str, Any]) -> None:
        self.persist_guardian_record(tenant_id, record)

    def load_latest_guardian_records(
        self,
        tenant_id: str,
        *,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                effective_limit = int(limit) if limit is not None else 200
                # Fetch latest records (DESC) so we get current-cycle records
                # first, then reverse for ascending order compatibility.
                cur.execute(
                    "SELECT payload FROM guardian_records WHERE tenant_id = %s "
                    "ORDER BY id DESC LIMIT %s",
                    (tid, effective_limit),
                )
                rows = cur.fetchall()
            return [self._overlay_guardian_payload(tid, row["payload"]) for row in reversed(rows)]
        finally:
            put_conn(conn)

    def load_all_guardian_records(
        self,
        tenant_id: str,
        *,
        limit: int = 50000,
    ) -> List[Dict[str, Any]]:
        return self.load_latest_guardian_records(tenant_id, limit=limit)

    def load_guardian_records_for_cycle(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        cid = str(cycle_id or "").strip()
        if not cid:
            raise ValueError("cycle_id")
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if limit is not None:
                    cur.execute(
                        "SELECT payload FROM guardian_records "
                        "WHERE tenant_id = %s AND cycle_id = %s ORDER BY id LIMIT %s",
                        (tid, cid, int(limit)),
                    )
                else:
                    cur.execute(
                        "SELECT payload FROM guardian_records "
                        "WHERE tenant_id = %s AND cycle_id = %s ORDER BY id",
                        (tid, cid),
                    )
                rows = cur.fetchall()
            return [self._overlay_guardian_payload(tid, row["payload"]) for row in rows]
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Cycle lock
    # ------------------------------------------------------------------

    def reserve_cycle_launch(
        self,
        tenant_id: str,
        cycle_id: str,
        cycle_number: int,
    ) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        now_ms = self._now()
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM cycle_locks WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
                if row and row["status"] == "active":
                    if not self._is_stale_lock_row(row):
                        raise RuntimeError("Active cycle already running")
                    # Stale — overwrite below.
                cur.execute(
                    """
                    INSERT INTO cycle_locks
                        (tenant_id, cycle_id, cycle_number, started_at_unix_ms,
                         updated_at_unix_ms, stage, pid, hostname, status)
                    VALUES (%s, %s, %s, %s, %s, 'launching', %s, %s, 'active')
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        cycle_id           = EXCLUDED.cycle_id,
                        cycle_number       = EXCLUDED.cycle_number,
                        started_at_unix_ms = EXCLUDED.started_at_unix_ms,
                        updated_at_unix_ms = EXCLUDED.updated_at_unix_ms,
                        stage              = EXCLUDED.stage,
                        pid                = EXCLUDED.pid,
                        hostname           = EXCLUDED.hostname,
                        status             = EXCLUDED.status
                    """,
                    (
                        tid, cycle_id, int(cycle_number), now_ms, now_ms,
                        os.getpid(), socket.gethostname(),
                    ),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def acquire_cycle_lock(
        self,
        tenant_id: str,
        cycle_id: str,
        cycle_number: int,
    ) -> None:
        tid = self._validate_tenant_id(tenant_id)
        self.ensure_tenant_exists(tid)
        now_ms = self._now()
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM cycle_locks WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
                if row and row["status"] == "active":
                    existing_stage = str(row.get("stage", "") or "").strip().lower()
                    existing_cid = str(row.get("cycle_id", "") or "").strip()
                    try:
                        existing_cn = int(row.get("cycle_number", 0) or 0)
                    except Exception:
                        existing_cn = 0
                    if not (
                        existing_stage == "launching"
                        and existing_cid == str(cycle_id or "").strip()
                        and existing_cn == int(cycle_number)
                    ):
                        if not self._is_stale_lock_row(row):
                            raise RuntimeError("Active cycle already running")
                cur.execute(
                    """
                    INSERT INTO cycle_locks
                        (tenant_id, cycle_id, cycle_number, started_at_unix_ms,
                         updated_at_unix_ms, stage, pid, hostname, status)
                    VALUES (%s, %s, %s, %s, %s, 'initializing', %s, %s, 'active')
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        cycle_id           = EXCLUDED.cycle_id,
                        cycle_number       = EXCLUDED.cycle_number,
                        started_at_unix_ms = EXCLUDED.started_at_unix_ms,
                        updated_at_unix_ms = EXCLUDED.updated_at_unix_ms,
                        stage              = EXCLUDED.stage,
                        pid                = EXCLUDED.pid,
                        hostname           = EXCLUDED.hostname,
                        status             = EXCLUDED.status
                    """,
                    (
                        tid, cycle_id, int(cycle_number), now_ms, now_ms,
                        os.getpid(), socket.gethostname(),
                    ),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def release_cycle_lock(self, tenant_id: str) -> None:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE cycle_locks SET status = 'completed', updated_at_unix_ms = %s "
                    "WHERE tenant_id = %s",
                    (self._now(), tid),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def load_cycle_lock(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM cycle_locks WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
            if row is None:
                return None
            row_dict = dict(row)
            if row_dict.get("status") != "active":
                return None
            if self._is_stale_lock_row(row_dict):
                self.release_cycle_lock(tid)
                return None
            # Merge stored progress payload so all live detail fields are returned.
            progress = dict(row_dict.get("progress") or {})
            progress.update({
                "cycle_id": row_dict.get("cycle_id"),
                "cycle_number": row_dict.get("cycle_number"),
                "started_at_unix_ms": row_dict.get("started_at_unix_ms"),
                "updated_at_unix_ms": row_dict.get("updated_at_unix_ms"),
                "stage": row_dict.get("stage"),
                "pid": row_dict.get("pid"),
                "hostname": row_dict.get("hostname"),
            })
            return progress
        finally:
            put_conn(conn)

    def update_cycle_lock(self, tenant_id: str, updates: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        from infrastructure.db.connection import try_get_conn
        conn = try_get_conn()
        if conn is None:
            # Pool exhausted — skip this progress write rather than raising.
            # The orchestrator will retry on the next tick.
            return
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT stage, progress FROM cycle_locks WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
                if row is None:
                    raise RuntimeError("Active cycle lock not found")
                upd = dict(updates or {})
                new_stage = str(upd.get("stage") or row["stage"] or "")
                existing_progress = dict(row["progress"] or {})
                existing_progress.update(upd)
                cur.execute(
                    "UPDATE cycle_locks SET stage = %s, updated_at_unix_ms = %s, progress = %s::jsonb "
                    "WHERE tenant_id = %s",
                    (
                        new_stage,
                        self._now(),
                        json.dumps(existing_progress),
                        tid,
                    ),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def _is_stale_lock_row(self, row: Dict[str, Any]) -> bool:
        started = row.get("started_at_unix_ms")
        if not isinstance(started, int):
            return True
        return (self._now() - started) > STALE_CYCLE_LOCK_THRESHOLD_MS

    # ------------------------------------------------------------------
    # Scheduler state
    # ------------------------------------------------------------------

    def seed_scheduler_state(self, tenant_id: str, state: Dict[str, Any]) -> None:
        self.save_scheduler_state(tenant_id, state)

    def save_scheduler_state(self, tenant_id: str, state: Dict[str, Any]) -> None:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scheduler_states (tenant_id, payload, updated_at)
                    VALUES (%s, %s::jsonb, now())
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        payload    = EXCLUDED.payload,
                        updated_at = now()
                    """,
                    (tid, json.dumps(dict(state or {}))),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def load_scheduler_state(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT payload FROM scheduler_states WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
            return row["payload"] if row else None
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Identity helpers (embedded so PgIdentityManager can delegate here)
    # ------------------------------------------------------------------

    def set_identity_credentials(self, tenant_id: str, password_hash: str) -> None:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM tenant_identities WHERE tenant_id = %s", (tid,)
                )
                if cur.fetchone() is not None:
                    raise RuntimeError("Tenant already exists in identity store")
                cur.execute(
                    "INSERT INTO tenant_identities (tenant_id, password_hash) VALUES (%s, %s)",
                    (tid, password_hash),
                )
            conn.commit()
        finally:
            put_conn(conn)

    def get_identity_credentials(self, tenant_id: str) -> Optional[str]:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT password_hash FROM tenant_identities WHERE tenant_id = %s", (tid,)
                )
                row = cur.fetchone()
            return row[0] if row else None
        finally:
            put_conn(conn)

    def delete_identity_credentials(self, tenant_id: str) -> None:
        tid = self._validate_tenant_id(tenant_id)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tenant_identities WHERE tenant_id = %s", (tid,)
                )
            conn.commit()
        finally:
            put_conn(conn)

    # ------------------------------------------------------------------
    # Validation helpers (mirrors StorageManager for compatibility)
    # ------------------------------------------------------------------

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
            if key not in record or not isinstance(record[key], expected):
                raise RuntimeError("Corrupt snapshot")
