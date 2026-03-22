from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


def _safe_str(value: Any, default: str = "") -> str:
    try:
        token = str(value) if value is not None else ""
    except Exception:
        token = ""
    token = token.strip()
    return token if token else default


def _bound(value: str, max_len: int) -> str:
    token = _safe_str(value, "")
    return token[:max_len] if len(token) > max_len else token


@dataclass(frozen=True, kw_only=True)
class PolicyUpdateSchedulePlan:
    tenant_id: str
    jurisdiction_id: str
    policy_name: str
    source_url: str
    old_sha256: str
    new_sha256: str
    effective_from_ymd: str
    requires_approval: bool = True
    auto_activate_on_effective_date: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _bound(self.tenant_id, 64))
        object.__setattr__(self, "jurisdiction_id", _bound(self.jurisdiction_id, 64))
        object.__setattr__(self, "policy_name", _bound(self.policy_name, 140))
        object.__setattr__(self, "source_url", _bound(self.source_url, 400))
        object.__setattr__(self, "old_sha256", _bound(self.old_sha256, 64))
        object.__setattr__(self, "new_sha256", _bound(self.new_sha256, 64))
        object.__setattr__(self, "effective_from_ymd", _bound(self.effective_from_ymd, 16))
        object.__setattr__(self, "requires_approval", bool(self.requires_approval))
        object.__setattr__(self, "auto_activate_on_effective_date", bool(self.auto_activate_on_effective_date))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "jurisdiction_id": self.jurisdiction_id,
            "policy_name": self.policy_name,
            "source_url": self.source_url,
            "old_sha256": self.old_sha256,
            "new_sha256": self.new_sha256,
            "effective_from_ymd": self.effective_from_ymd,
            "requires_approval": self.requires_approval,
            "auto_activate_on_effective_date": self.auto_activate_on_effective_date,
        }
