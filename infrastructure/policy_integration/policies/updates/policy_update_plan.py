from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def _safe_str(value: object, default: str = "") -> str:
    token = str(value or "").strip()
    return token if token else default


def _bound(value: str, max_len: int) -> str:
    token = _safe_str(value)
    return token[:max_len] if len(token) > max_len else token


def _stable_hash(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class PolicyUpdatePlan:
    plan_id: str
    tenant_id: str
    jurisdiction_id: str
    source_pack_id: str
    source_id: str
    source_url: str
    old_fingerprint: str
    new_fingerprint: str
    effective_date_utc: str
    summary: str
    created_ts_ms: int = 0
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _bound(self.tenant_id, 96))
        object.__setattr__(self, "jurisdiction_id", _bound(self.jurisdiction_id, 32))
        object.__setattr__(self, "source_pack_id", _bound(self.source_pack_id, 96))
        object.__setattr__(self, "source_id", _bound(self.source_id, 96))
        object.__setattr__(self, "source_url", _bound(self.source_url, 512))
        object.__setattr__(self, "old_fingerprint", _bound(self.old_fingerprint, 128))
        object.__setattr__(self, "new_fingerprint", _bound(self.new_fingerprint, 128))
        object.__setattr__(self, "effective_date_utc", _bound(self.effective_date_utc, 16))
        object.__setattr__(self, "summary", _bound(self.summary, 280))
        object.__setattr__(self, "created_ts_ms", max(0, int(self.created_ts_ms)))

        bounded_meta: Dict[str, Any] = {}
        for i, (k, v) in enumerate(sorted(self.raw_metadata.items(), key=lambda kv: str(kv[0]))):
            if i >= 64:
                break
            key = _bound(str(k), 64)
            if not key:
                continue
            if isinstance(v, (dict, list, tuple)):
                bounded_meta[key] = _bound(json.dumps(v, sort_keys=True), 1000)
            else:
                bounded_meta[key] = _bound(str(v), 256)
        object.__setattr__(self, "raw_metadata", bounded_meta)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "tenant_id": self.tenant_id,
            "jurisdiction_id": self.jurisdiction_id,
            "source_pack_id": self.source_pack_id,
            "source_id": self.source_id,
            "source_url": self.source_url,
            "old_fingerprint": self.old_fingerprint,
            "new_fingerprint": self.new_fingerprint,
            "effective_date_utc": self.effective_date_utc,
            "summary": self.summary,
            "created_ts_ms": self.created_ts_ms,
            "raw_metadata": dict(self.raw_metadata),
        }

    @staticmethod
    def build(
        *,
        tenant_id: str,
        jurisdiction_id: str,
        source_pack_id: str,
        source_id: str,
        source_url: str,
        old_fingerprint: str,
        new_fingerprint: str,
        effective_date_utc: str,
        summary: str,
        created_ts_ms: int = 0,
        raw_metadata: Optional[Dict[str, Any]] = None,
    ) -> "PolicyUpdatePlan":
        core = {
            "tenant_id": _safe_str(tenant_id, "unknown"),
            "jurisdiction_id": _safe_str(jurisdiction_id, "GLOBAL"),
            "source_pack_id": _safe_str(source_pack_id, "unknown_pack"),
            "source_id": _safe_str(source_id, "unknown_source"),
            "source_url": _safe_str(source_url),
            "old_fingerprint": _safe_str(old_fingerprint),
            "new_fingerprint": _safe_str(new_fingerprint),
            "effective_date_utc": _safe_str(effective_date_utc),
        }
        plan_id = _stable_hash(core)
        return PolicyUpdatePlan(
            plan_id=plan_id,
            tenant_id=core["tenant_id"],
            jurisdiction_id=core["jurisdiction_id"],
            source_pack_id=core["source_pack_id"],
            source_id=core["source_id"],
            source_url=core["source_url"],
            old_fingerprint=core["old_fingerprint"],
            new_fingerprint=core["new_fingerprint"],
            effective_date_utc=core["effective_date_utc"],
            summary=summary,
            created_ts_ms=created_ts_ms,
            raw_metadata=raw_metadata or {},
        )
