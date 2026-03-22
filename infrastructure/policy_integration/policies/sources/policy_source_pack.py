from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
import hashlib
import json


def _safe_str(value: Any, default: str = "") -> str:
    try:
        s = str(value).strip()
    except Exception:
        return default
    return s if s else default


@dataclass(frozen=True)
class PolicySourcePack:
    jurisdiction_code: str
    name: str
    version: str
    sources: List[Dict[str, Any]] = field(default_factory=list)

    def stable_hash(self) -> str:
        payload = {
            "jurisdiction_code": _safe_str(self.jurisdiction_code, "UNKNOWN"),
            "name": _safe_str(self.name, "unknown"),
            "version": _safe_str(self.version, "v0"),
            "sources": self.sources,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
