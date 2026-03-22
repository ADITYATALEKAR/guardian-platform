from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional


_ALIASES = {
    "NONE": "NONE",
    "DISABLED": "NONE",
    "NO POLICY": "NONE",
    "NO_POLICIES": "NONE",
    "POLICY_DISABLED": "NONE",
    "IN": "INDIA",
    "IND": "INDIA",
    "EU": "EUROPE",
    "EUR": "EUROPE",
    "DE": "GERMANY",
    "GER": "GERMANY",
    "UK": "UNITED KINGDOM",
    "GB": "UNITED KINGDOM",
    "US": "UNITED STATES",
    "USA": "UNITED STATES",
    "UAE": "UNITED ARAB EMIRATES",
    "AE": "UNITED ARAB EMIRATES",
    "SA": "SAUDI ARABIA",
    "SG": "SINGAPORE",
    "JP": "JAPAN",
    "CN": "CHINA",
    "BR": "BRAZIL",
    "ZA": "SOUTH AFRICA",
}


def _normalize(value: object) -> str:
    if value is None:
        return ""
    token = " ".join(str(value).strip().upper().split())
    if not token:
        return ""
    return _ALIASES.get(token, token)


@dataclass(frozen=True)
class ComplianceSelection:
    jurisdictions: List[str] = field(default_factory=list)
    policy_enabled: bool = True

    @staticmethod
    def from_user_input(jurisdictions: Optional[Iterable[object]]) -> "ComplianceSelection":
        items = [_normalize(j) for j in (jurisdictions or [])]
        items = [j for j in items if j]
        items = sorted(set(items[:32]))
        if "NONE" in items:
            return ComplianceSelection(jurisdictions=["NONE"], policy_enabled=False)
        return ComplianceSelection(jurisdictions=items, policy_enabled=True)

    def to_dict(self) -> dict:
        return {
            "jurisdictions": list(self.jurisdictions),
            "policy_enabled": bool(self.policy_enabled),
        }

    def is_policy_disabled(self) -> bool:
        return not bool(self.policy_enabled)

    def canonical_jurisdictions(self) -> List[str]:
        if self.is_policy_disabled():
            return ["NONE"]
        return list(self.jurisdictions)
