from __future__ import annotations

import hashlib
from typing import Tuple


GLOBAL_IDENTITY_SCHEMA_VERSION = "gid_v1"


def tenant_gid(tenant_id: str) -> str:
    tid = _safe_tenant_id(tenant_id)
    return _gid("tenant", tid)


def cycle_gid(tenant_id: str, cycle_id: str) -> str:
    tid = _safe_tenant_id(tenant_id)
    cid = _safe_token(cycle_id, "cycle_id")
    return _gid("cycle", tid, cid)


def endpoint_gid(tenant_id: str, hostname: str, port: int) -> str:
    tid = _safe_tenant_id(tenant_id)
    host = _safe_hostname(hostname)
    p = _safe_port(port)
    return _gid("endpoint", tid, host, str(p))


def endpoint_gid_from_endpoint_id(tenant_id: str, endpoint_id: str) -> str:
    host, port = _split_endpoint_id(endpoint_id)
    return endpoint_gid(tenant_id, host, port)


def _split_endpoint_id(endpoint_id: str) -> Tuple[str, int]:
    token = _safe_token(endpoint_id, "endpoint_id")
    if ":" not in token:
        raise ValueError("endpoint_id")
    host, raw_port = token.rsplit(":", 1)
    if not host:
        raise ValueError("endpoint_id")
    try:
        port = int(raw_port)
    except Exception as exc:
        raise ValueError("endpoint_id") from exc
    return host, port


def _gid(kind: str, *parts: str) -> str:
    payload = f"{GLOBAL_IDENTITY_SCHEMA_VERSION}|{kind}|{'|'.join(parts)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _safe_tenant_id(tenant_id: str) -> str:
    tid = _safe_token(tenant_id, "tenant_id")
    if any(sep in tid for sep in ("/", "\\", "..")):
        raise ValueError("tenant_id")
    return tid


def _safe_hostname(hostname: str) -> str:
    host = _safe_token(hostname, "hostname").strip().lower().rstrip(".")
    if not host:
        raise ValueError("hostname")
    return host


def _safe_port(port: int) -> int:
    try:
        p = int(port)
    except Exception as exc:
        raise ValueError("port") from exc
    if p < 1 or p > 65535:
        raise ValueError("port")
    return p


def _safe_token(value: str, field: str) -> str:
    token = str(value or "").strip()
    if not token:
        raise ValueError(field)
    return token
