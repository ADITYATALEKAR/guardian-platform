from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class AdvisoryResponse:
    """
    Canonical advisory summary contract.

    Tests require:
      - trend
      - pattern_priority
      - uncertainty_notes
      - business_interpretation
    """

    trend: str
    pattern_priority: List[str]
    uncertainty_notes: List[str]
    business_interpretation: str

    # optional extra fields (production)
    observation_window: Optional[str] = None
    dominant_patterns: Optional[List[str]] = None
