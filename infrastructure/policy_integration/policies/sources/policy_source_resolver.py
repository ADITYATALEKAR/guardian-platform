from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from ...compliance.jurisdiction_catalog import JurisdictionCatalog
from .policy_source_pack import PolicySourcePack
from .policy_source_registry import PolicySourceRegistry


@dataclass(frozen=True)
class ResolvePolicySourcesResult:
    packs: Tuple[PolicySourcePack, ...]
    unresolved_jurisdictions: Tuple[str, ...] = ()


class PolicySourceResolver:
    def __init__(self, registry: Optional[PolicySourceRegistry] = None):
        self.registry = registry or PolicySourceRegistry.default()

    def resolve(
        self,
        jurisdictions: Iterable[str],
        *,
        include_supersets: bool = True,
        max_packs: int = 64,
    ) -> ResolvePolicySourcesResult:
        cap = min(max(1, int(max_packs)), 128)
        selected = JurisdictionCatalog.normalize_selection(jurisdictions)
        if "NONE" in selected:
            none_pack = self.registry.resolve("NONE")
            return ResolvePolicySourcesResult(packs=(none_pack,), unresolved_jurisdictions=())

        expanded = (
            JurisdictionCatalog.expand_with_supersets(selected)
            if include_supersets
            else selected
        )
        packs: List[PolicySourcePack] = []
        unresolved: List[str] = []

        for jurisdiction in expanded:
            pack = self.registry.resolve(jurisdiction)
            if pack.jurisdiction_code == "GLOBAL" and jurisdiction not in ("GLOBAL", "EUROPE"):
                unresolved.append(jurisdiction)
            packs.append(pack)

        unique: dict[str, PolicySourcePack] = {}
        for pack in packs:
            unique[pack.jurisdiction_code] = pack

        final = sorted(unique.values(), key=lambda p: (p.jurisdiction_code, p.name, p.version))[:cap]
        return ResolvePolicySourcesResult(
            packs=tuple(final),
            unresolved_jurisdictions=tuple(sorted(set(unresolved))[:64]),
        )
