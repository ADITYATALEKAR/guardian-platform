from __future__ import annotations

import json
import os
import socket
import tempfile
import time
import threading
from contextlib import contextmanager
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

from infrastructure.storage_manager.storage_manager import StorageManager


_PROCESS_LOCKS = defaultdict(threading.Lock)


def _safe_tenant_id(tenant_id: str) -> str:
    tid = str(tenant_id or "").strip()
    if not tid:
        raise RuntimeError("invalid tenant_id")
    return tid


def require_tenant_path(storage_manager: StorageManager, tenant_id: str) -> Path:
    tid = _safe_tenant_id(tenant_id)
    if not storage_manager.tenant_exists(tid):
        raise RuntimeError("tenant not found")
    return storage_manager.get_tenant_path(tid)


def policy_root(storage_manager: StorageManager, tenant_id: str) -> Path:
    root = require_tenant_path(storage_manager, tenant_id) / "policy_integration"
    root.mkdir(parents=True, exist_ok=True)
    return root


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        dir=path.parent,
        encoding="utf-8",
    ) as tmp:
        json.dump(payload, tmp, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        dir=path.parent,
        encoding="utf-8",
    ) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def read_json_fail_loud(path: Path, *, context: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise RuntimeError(f"corrupt {context}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"corrupt {context}")
    return data


def read_jsonl_fail_loud(path: Path, *, context: str) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception as exc:
                raise RuntimeError(f"corrupt {context}") from exc
            if not isinstance(record, dict):
                raise RuntimeError(f"corrupt {context}")
            out.append(record)
    return out


def list_json_files_sorted(directory: Path, *, limit: int = 2048) -> List[Path]:
    if not directory.exists():
        return []
    files = sorted(directory.glob("*.json"))
    return files[: max(0, int(limit))]


def stable_dedupe_sorted(values: Iterable[str]) -> List[str]:
    return sorted({str(v).strip() for v in values if str(v or "").strip()})


def _lock_payload() -> Dict[str, Any]:
    return {
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "locked_at_unix_ms": int(time.time() * 1000),
    }


def _read_lock_payload(lock_path: Path) -> Dict[str, Any] | None:
    try:
        with open(lock_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


@contextmanager
def file_lock(
    lock_path: Path,
    *,
    timeout_seconds: float = 5.0,
    poll_interval_seconds: float = 0.05,
    stale_after_seconds: float = 300.0,
):
    """
    Cross-process lock using atomic lock-file creation.
    Fails loud on timeout and attempts stale lock cleanup.
    """
    deadline = time.time() + max(0.1, float(timeout_seconds))
    stale_after_ms = int(max(1.0, float(stale_after_seconds)) * 1000)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    acquired = False
    lock_fd: int | None = None

    process_lock = _PROCESS_LOCKS[str(lock_path)]
    with process_lock:
        while time.time() < deadline:
            try:
                lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                payload = json.dumps(
                    _lock_payload(),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                os.write(lock_fd, payload)
                os.fsync(lock_fd)
                acquired = True
                break
            except FileExistsError:
                payload = _read_lock_payload(lock_path)
                locked_at = payload.get("locked_at_unix_ms") if isinstance(payload, dict) else None
                now_ms = int(time.time() * 1000)
                is_stale = isinstance(locked_at, int) and (now_ms - locked_at) > stale_after_ms
                if is_stale:
                    try:
                        lock_path.unlink()
                        continue
                    except FileNotFoundError:
                        continue
                    except Exception:
                        pass
                time.sleep(max(0.01, float(poll_interval_seconds)))

    if not acquired:
        raise RuntimeError(f"lock timeout: {lock_path}")

    try:
        yield
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except Exception:
                pass
        released = False
        for _ in range(50):
            try:
                lock_path.unlink()
                released = True
                break
            except FileNotFoundError:
                released = True
                break
            except PermissionError:
                time.sleep(0.02)
        if not released:
            raise RuntimeError(f"lock release failed: {lock_path}")
