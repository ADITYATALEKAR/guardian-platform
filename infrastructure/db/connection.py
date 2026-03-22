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
