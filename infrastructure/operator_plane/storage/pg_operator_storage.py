"""
Postgres-backed operator storage.

Each public function mirrors the corresponding function in operator_storage.py.
When use_postgres() is False, all calls delegate to the filesystem backend.
When use_postgres() is True, they use the Postgres connection pool.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import psycopg2.extras

from infrastructure.db.connection import get_conn, put_conn, use_postgres
from infrastructure.db.schema import ensure_schema
from infrastructure.operator_plane.storage import operator_storage as _fs


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def ensure_operator_storage(
    root: str | Path,
    created_at_unix_ms: Optional[int] = None,
) -> Path:
    if not use_postgres():
        return _fs.ensure_operator_storage(root, created_at_unix_ms)
    # For Postgres mode we still need a writable root for compat; just ensure it exists.
    ensure_schema()
    root_path = Path(root)
    root_path.mkdir(parents=True, exist_ok=True)
    return root_path


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

def read_operators(root: str | Path) -> Dict[str, Any]:
    if not use_postgres():
        return _fs.read_operators(root)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT operator_id, email, password_hash, created_at_unix_ms, status, role "
                "FROM operators"
            )
            rows = cur.fetchall()
        result: Dict[str, Any] = {}
        for row in rows:
            rec = dict(row)
            result[rec["operator_id"]] = rec
        return result
    finally:
        put_conn(conn)


def write_operators(root: str | Path, payload: Dict[str, Any]) -> None:
    """
    Upsert operators present in payload. Operators absent from payload are
    deleted only if they were explicitly in the previous read — we use
    targeted per-operator_id operations to avoid wiping concurrent users.
    """
    if not use_postgres():
        _fs.write_operators(root, payload)
        return
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Upsert every operator in payload.
            for op in payload.values():
                cur.execute(
                    """
                    INSERT INTO operators
                        (operator_id, email, password_hash, created_at_unix_ms, status, role)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (operator_id) DO UPDATE SET
                        email               = EXCLUDED.email,
                        password_hash       = EXCLUDED.password_hash,
                        created_at_unix_ms  = EXCLUDED.created_at_unix_ms,
                        status              = EXCLUDED.status,
                        role                = EXCLUDED.role
                    """,
                    (
                        op["operator_id"],
                        op["email"],
                        op["password_hash"],
                        int(op.get("created_at_unix_ms", 0) or 0),
                        op.get("status", "ACTIVE"),
                        op.get("role", "OWNER"),
                    ),
                )
        conn.commit()
    finally:
        put_conn(conn)


def delete_operator_pg(root: str | Path, operator_id: str) -> None:
    """Targeted single-operator delete for Postgres mode."""
    if not use_postgres():
        return  # filesystem path handles it via write_operators
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM operators WHERE operator_id = %s", (operator_id,))
            cur.execute(
                "DELETE FROM operator_tenant_links WHERE operator_id = %s", (operator_id,)
            )
            cur.execute(
                "DELETE FROM operator_sessions WHERE operator_id = %s", (operator_id,)
            )
        conn.commit()
    finally:
        put_conn(conn)


# ---------------------------------------------------------------------------
# Operator–Tenant links
# ---------------------------------------------------------------------------

def read_operator_links(root: str | Path) -> Dict[str, Any]:
    """Returns {operator_id: [tenant_id, ...]}"""
    if not use_postgres():
        return _fs.read_operator_links(root)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT operator_id, tenant_id FROM operator_tenant_links ORDER BY operator_id"
            )
            rows = cur.fetchall()
        result: Dict[str, Any] = {}
        for row in rows:
            oid = row["operator_id"]
            tid = row["tenant_id"]
            result.setdefault(oid, [])
            result[oid].append(tid)
        return result
    finally:
        put_conn(conn)


def write_operator_links(root: str | Path, payload: Dict[str, Any]) -> None:
    """payload = {operator_id: [tenant_id, ...]}
    Only touches rows for operator_ids present in payload — never deletes
    other operators' links (prevents cross-tenant data corruption).
    """
    if not use_postgres():
        _fs.write_operator_links(root, payload)
        return
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            for operator_id, tenant_ids in payload.items():
                # Replace only this operator's links.
                cur.execute(
                    "DELETE FROM operator_tenant_links WHERE operator_id = %s",
                    (operator_id,),
                )
                for tenant_id in tenant_ids:
                    cur.execute(
                        "INSERT INTO operator_tenant_links (operator_id, tenant_id) "
                        "VALUES (%s, %s) ON CONFLICT DO NOTHING",
                        (operator_id, tenant_id),
                    )
        conn.commit()
    finally:
        put_conn(conn)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def read_session(root: str | Path, token: str) -> Dict[str, Any]:
    if not use_postgres():
        return _fs.read_session(root, token)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT token, operator_id, issued_at_unix_ms, expires_at_unix_ms, "
                "       client_ip, user_agent "
                "FROM operator_sessions WHERE token = %s",
                (token,),
            )
            row = cur.fetchone()
        if row is None:
            raise RuntimeError("session not found")
        return dict(row)
    finally:
        put_conn(conn)


def write_session(root: str | Path, token: str, payload: Dict[str, Any]) -> None:
    if not use_postgres():
        _fs.write_session(root, token, payload)
        return
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO operator_sessions
                    (token, operator_id, issued_at_unix_ms, expires_at_unix_ms,
                     client_ip, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (token) DO UPDATE SET
                    operator_id        = EXCLUDED.operator_id,
                    issued_at_unix_ms  = EXCLUDED.issued_at_unix_ms,
                    expires_at_unix_ms = EXCLUDED.expires_at_unix_ms,
                    client_ip          = EXCLUDED.client_ip,
                    user_agent         = EXCLUDED.user_agent
                """,
                (
                    payload["token"],
                    payload["operator_id"],
                    int(payload["issued_at_unix_ms"]),
                    int(payload["expires_at_unix_ms"]),
                    payload.get("client_ip"),
                    payload.get("user_agent"),
                ),
            )
        conn.commit()
    finally:
        put_conn(conn)


def revoke_all_sessions(root: str | Path, operator_id: str) -> None:
    """Delete all sessions for a given operator_id."""
    if not use_postgres():
        # Delegate to filesystem implementation inline.
        from pathlib import Path as _Path
        sessions_dir = _Path(root) / "sessions"
        if not sessions_dir.exists():
            return
        for path in sessions_dir.glob("*.json"):
            try:
                payload = _fs.read_session(root, path.stem)
                if payload.get("operator_id") == operator_id:
                    _fs.delete_session(root, path.stem)
            except Exception:
                pass
        return
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM operator_sessions WHERE operator_id = %s",
                (operator_id,),
            )
        conn.commit()
    finally:
        put_conn(conn)


def delete_session(root: str | Path, token: str) -> None:
    if not use_postgres():
        _fs.delete_session(root, token)
        return
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM operator_sessions WHERE token = %s",
                (token,),
            )
            if cur.rowcount == 0:
                raise RuntimeError("session not found")
        conn.commit()
    finally:
        put_conn(conn)
