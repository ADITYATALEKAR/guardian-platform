from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class ImpactedAsset:
    asset_id: str
    asset_type: str              # endpoint | service | identity | cert
    confidence: float            # confidence of impact linkage

@dataclass(frozen=True)
class ImpactResponse:
    """
    Structural impact estimation (no severity changes).
    """
    estimated_scope: str         # LOW | MEDIUM | HIGH
    impacted_assets: List[ImpactedAsset]
    notes: str
