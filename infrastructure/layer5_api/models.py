from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional


def _normalize_method(method: str) -> str:
    m = str(method or "").strip().upper()
    if not m:
        raise ValueError("method")
    return m


def _normalize_path(path: str) -> str:
    p = str(path or "").strip()
    if not p or not p.startswith("/"):
        raise ValueError("path")
    return p


@dataclass(frozen=True)
class APIRequest:
    method: str
    path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    query: Mapping[str, str] = field(default_factory=dict)
    json_body: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", _normalize_method(self.method))
        object.__setattr__(self, "path", _normalize_path(self.path))

        normalized_headers = {
            str(k or "").strip().lower(): str(v or "").strip()
            for k, v in dict(self.headers or {}).items()
            if str(k or "").strip()
        }
        object.__setattr__(self, "headers", normalized_headers)

        normalized_query = {
            str(k or "").strip(): str(v or "").strip()
            for k, v in dict(self.query or {}).items()
            if str(k or "").strip()
        }
        object.__setattr__(self, "query", normalized_query)

        body = self.json_body
        if body is not None and not isinstance(body, dict):
            raise ValueError("json_body")


@dataclass(frozen=True)
class APIResponse:
    status_code: int
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": int(self.status_code),
            "payload": dict(self.payload or {}),
        }
