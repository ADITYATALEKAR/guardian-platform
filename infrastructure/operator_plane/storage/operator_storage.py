from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional


META_SCHEMA_VERSION = "v1"


def ensure_operator_storage(
    root: str | Path, created_at_unix_ms: Optional[int] = None
) -> Path:
    root_path = Path(root)
    root_path.mkdir(parents=True, exist_ok=True)

    sessions_dir = root_path / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    meta_path = root_path / "meta.json"
    if not meta_path.exists():
        meta = {
            "schema_version": META_SCHEMA_VERSION,
            "created_at_unix_ms": 0
            if created_at_unix_ms is None
            else int(created_at_unix_ms),
        }
        write_meta(root_path, meta)
    else:
        read_meta(root_path)

    return root_path


def read_meta(root: str | Path) -> Dict[str, Any]:
    path = Path(root) / "meta.json"
    payload = _read_json(path)
    _validate_meta(payload)
    return payload


def write_meta(root: str | Path, payload: Dict[str, Any]) -> None:
    _validate_meta(payload)
    path = Path(root) / "meta.json"
    _atomic_write_json(path, payload)


def read_operators(root: str | Path) -> Dict[str, Any]:
    path = Path(root) / "operators.json"
    if not path.exists():
        return {}
    payload = _read_json(path)
    _validate_operators(payload)
    return payload


def write_operators(root: str | Path, payload: Dict[str, Any]) -> None:
    _validate_operators(payload)
    path = Path(root) / "operators.json"
    _atomic_write_json(path, payload)


def read_operator_links(root: str | Path) -> Dict[str, Any]:
    path = Path(root) / "operator_tenant_links.json"
    if not path.exists():
        return {}
    payload = _read_json(path)
    _validate_operator_links(payload)
    return payload


def write_operator_links(root: str | Path, payload: Dict[str, Any]) -> None:
    _validate_operator_links(payload)
    path = Path(root) / "operator_tenant_links.json"
    _atomic_write_json(path, payload)


def read_session(root: str | Path, token: str) -> Dict[str, Any]:
    path = Path(root) / "sessions" / f"{token}.json"
    if not path.exists():
        raise RuntimeError("session not found")
    payload = _read_json(path)
    _validate_session(payload)
    return payload


def write_session(root: str | Path, token: str, payload: Dict[str, Any]) -> None:
    _validate_session(payload)
    path = Path(root) / "sessions" / f"{token}.json"
    _atomic_write_json(path, payload)


def delete_session(root: str | Path, token: str) -> None:
    path = Path(root) / "sessions" / f"{token}.json"
    if not path.exists():
        raise RuntimeError("session not found")
    path.unlink()


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
    ) as tmp_file:
        json.dump(payload, tmp_file, sort_keys=True, separators=(",", ":"))
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
        tmp_path = Path(tmp_file.name)
    os.replace(tmp_path, path)


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Corrupt operator storage: {path.name}") from exc
    except OSError as exc:
        raise RuntimeError(f"Failed to read operator storage: {path.name}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Corrupt operator storage: {path.name}")
    return payload


def _validate_meta(payload: Dict[str, Any]) -> None:
    if payload.get("schema_version") != META_SCHEMA_VERSION:
        raise RuntimeError("Corrupt operator storage: meta.json")
    created_at = payload.get("created_at_unix_ms")
    if not isinstance(created_at, int) or created_at < 0:
        raise RuntimeError("Corrupt operator storage: meta.json")


def _validate_operators(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise RuntimeError("Corrupt operator storage: operators.json")
    for key, value in payload.items():
        if not isinstance(key, str) or not key:
            raise RuntimeError("Corrupt operator storage: operators.json")
        if not isinstance(value, dict):
            raise RuntimeError("Corrupt operator storage: operators.json")


def _validate_operator_links(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise RuntimeError("Corrupt operator storage: operator_tenant_links.json")
    for key, value in payload.items():
        if not isinstance(key, str) or not key:
            raise RuntimeError("Corrupt operator storage: operator_tenant_links.json")
        if not isinstance(value, list):
            raise RuntimeError("Corrupt operator storage: operator_tenant_links.json")
        for tenant_id in value:
            if not isinstance(tenant_id, str) or not tenant_id:
                raise RuntimeError(
                    "Corrupt operator storage: operator_tenant_links.json"
                )


def _validate_session(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise RuntimeError("Corrupt operator storage: sessions")
    required = ("token", "operator_id", "issued_at_unix_ms", "expires_at_unix_ms")
    for key in required:
        if key not in payload:
            raise RuntimeError("Corrupt operator storage: sessions")
    for key in ("client_ip", "user_agent"):
        value = payload.get(key)
        if value is not None and not isinstance(value, str):
            raise RuntimeError("Corrupt operator storage: sessions")
