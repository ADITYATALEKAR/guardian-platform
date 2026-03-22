from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
import hashlib
import json

from infrastructure.storage_manager.storage_manager import StorageManager

from ..io import (
    append_jsonl,
    file_lock,
    policy_root,
    read_jsonl_fail_loud,
)


def _safe_str(value: Any, default: str = "") -> str:
    try:
        token = str(value).strip()
    except Exception:
        return default
    return token if token else default


def _stable_event_id(kind: str, title: str, body: str, payload: Dict[str, Any]) -> str:
    raw = json.dumps(
        {"kind": kind, "title": title, "body": body, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


@dataclass(frozen=True)
class NotificationOutbox:
    storage_manager: StorageManager
    tenant_id: str

    def _path(self) -> Path:
        root = policy_root(self.storage_manager, self.tenant_id)
        target = root / "notifications"
        target.mkdir(parents=True, exist_ok=True)
        return target / "outbox.jsonl"

    def _lock_path(self) -> Path:
        return self._path().with_suffix(".lock")

    def _sent_path(self) -> Path:
        return self._path().with_suffix(".sent.jsonl")

    def enqueue(self, *, kind: str, title: str, body: str, payload: Dict[str, Any]) -> str:
        kind_s = _safe_str(kind, "unknown")
        title_s = _safe_str(title, "notification")
        body_s = _safe_str(body, "")
        payload_obj = payload if isinstance(payload, dict) else {}
        event_id = _stable_event_id(kind_s, title_s, body_s, payload_obj)

        with file_lock(self._lock_path()):
            append_jsonl(
                self._path(),
                {
                    "event_id": event_id,
                    "kind": kind_s,
                    "title": title_s,
                    "body": body_s,
                    "payload": payload_obj,
                    "sent": False,
                },
            )
        return event_id

    def load_all(self) -> List[Dict[str, Any]]:
        items = read_jsonl_fail_loud(self._path(), context="notification outbox")
        sent_ids = self._load_sent_ids()
        if not sent_ids:
            return items
        merged: List[Dict[str, Any]] = []
        for item in items:
            row = dict(item)
            if _safe_str(row.get("event_id")) in sent_ids:
                row["sent"] = True
            merged.append(row)
        return merged

    def list_pending(self) -> List[Dict[str, Any]]:
        return [item for item in self.load_all() if not bool(item.get("sent"))]

    def mark_sent(self, event_id: str) -> None:
        eid = _safe_str(event_id)
        if not eid:
            raise RuntimeError("invalid event_id")

        with file_lock(self._lock_path()):
            items = read_jsonl_fail_loud(self._path(), context="notification outbox")
            found = any(_safe_str(item.get("event_id")) == eid for item in items)
            if not found:
                raise RuntimeError("event not found")
            sent_ids = self._load_sent_ids()
            if eid in sent_ids:
                return
            append_jsonl(self._sent_path(), {"event_id": eid, "sent": True})

    def _load_sent_ids(self) -> set[str]:
        sent_path = self._sent_path()
        if not sent_path.exists():
            return set()
        rows = read_jsonl_fail_loud(sent_path, context="notification sent ledger")
        sent_ids = set()
        for row in rows:
            eid = _safe_str(row.get("event_id"))
            if eid:
                sent_ids.add(eid)
        return sent_ids
