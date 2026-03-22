from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .policy_source_pack import PolicySourcePack


@dataclass
class PolicySourceRegistry:
    packs: Dict[str, PolicySourcePack]
    fallback_pack: PolicySourcePack

    @staticmethod
    def _placeholder(code: str, label: str) -> PolicySourcePack:
        return PolicySourcePack(
            jurisdiction_code=code,
            name=f"{label} Policy Pack (placeholder)",
            version="v1",
            sources=[],
        )

    @staticmethod
    def default() -> "PolicySourceRegistry":
        packs: Dict[str, PolicySourcePack] = {
            "NONE": PolicySourcePack(
                jurisdiction_code="NONE",
                name="No Policy Pack (disabled)",
                version="v1",
                sources=[],
            ),
            "GLOBAL": PolicySourcePack(
                jurisdiction_code="GLOBAL",
                name="Global Policy Pack (fallback placeholder)",
                version="v1",
                sources=[],
            ),
        }

        major = [
            "EUROPE",
            "UNITED STATES",
            "CHINA",
            "GERMANY",
            "JAPAN",
            "INDIA",
            "UNITED KINGDOM",
            "FRANCE",
            "ITALY",
            "CANADA",
            "BRAZIL",
            "RUSSIA",
            "SOUTH KOREA",
            "AUSTRALIA",
            "SPAIN",
            "MEXICO",
            "INDONESIA",
            "NETHERLANDS",
            "SAUDI ARABIA",
            "TURKEY",
            "SWITZERLAND",
            "POLAND",
            "SWEDEN",
            "BELGIUM",
            "ARGENTINA",
            "SINGAPORE",
            "UNITED ARAB EMIRATES",
            "SOUTH AFRICA",
        ]

        for code in major:
            packs[code] = PolicySourceRegistry._placeholder(code, code.title())

        return PolicySourceRegistry(packs=packs, fallback_pack=packs["GLOBAL"])

    @staticmethod
    def _canonical_key(jurisdiction: str) -> str:
        raw = (jurisdiction or "").strip().upper()
        aliases = {
            "EU": "EUROPE",
            "IN": "INDIA",
            "US": "UNITED STATES",
            "USA": "UNITED STATES",
            "UK": "UNITED KINGDOM",
            "DE": "GERMANY",
            "JP": "JAPAN",
            "CN": "CHINA",
            "BR": "BRAZIL",
            "ZA": "SOUTH AFRICA",
            "AE": "UNITED ARAB EMIRATES",
            "SG": "SINGAPORE",
        }
        return aliases.get(raw, raw)

    def resolve(self, jurisdiction: str) -> PolicySourcePack:
        key = self._canonical_key(jurisdiction)
        if not key:
            return self.fallback_pack
        if key == "NONE":
            return self.packs.get("NONE", self.fallback_pack)
        return self.packs.get(key, self.fallback_pack)

    def resolve_many(self, jurisdictions: Iterable[str], *, max_items: int = 64) -> List[PolicySourcePack]:
        cap = min(max(1, int(max_items)), 256)
        unique: Dict[str, PolicySourcePack] = {}
        for jurisdiction in jurisdictions:
            key = self._canonical_key(jurisdiction)
            if not key or key in unique:
                continue
            unique[key] = self.resolve(key)
            if len(unique) >= cap:
                break
        return sorted(unique.values(), key=lambda p: (p.jurisdiction_code, p.name, p.version))

    def maybe_get(self, jurisdiction: str) -> Optional[PolicySourcePack]:
        key = self._canonical_key(jurisdiction)
        if not key:
            return None
        return self.packs.get(key)
