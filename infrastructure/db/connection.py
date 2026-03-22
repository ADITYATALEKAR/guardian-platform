from __future__ import annotations

import os
import threading

import psycopg2
import psycopg2.extras
import psycopg2.pool

_pool = None
_pool_lock = threading.Lock()


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                dsn = os.environ["GUARDIAN_DATABASE_URL"]
                _pool = psycopg2.pool.ThreadedConnectionPool(1, 10, dsn)
    return _pool


def get_conn():
    return _get_pool().getconn()


def put_conn(conn) -> None:
    _get_pool().putconn(conn)


def use_postgres() -> bool:
    return bool(os.environ.get("GUARDIAN_DATABASE_URL", "").strip())


def get_setting(key: str) -> str | None:
    """Read a guardian_settings value. Returns None if not found."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM guardian_settings WHERE key = %s", (key,))
            row = cur.fetchone()
        return row[0] if row else None
    finally:
        put_conn(conn)


def set_setting(key: str, value: str) -> None:
    """Upsert a guardian_settings key-value pair."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO guardian_settings (key, value, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                """,
                (key, value),
            )
        conn.commit()
    finally:
        put_conn(conn)
