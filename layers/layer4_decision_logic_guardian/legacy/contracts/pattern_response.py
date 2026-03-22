from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PatternResponse:
    """
    Canonical pattern label response.

    Tests require:
      - label
      - description
      - confidence (optional, default-safe)
    """
    label: str
    description: str
    confidence: float = 0.0
