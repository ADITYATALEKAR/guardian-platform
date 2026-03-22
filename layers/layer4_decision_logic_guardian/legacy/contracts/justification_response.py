from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class JustificationResponse:
    """
    Canonical justification contract.

    Canonical field:
      - summary: str

    Compatibility alias supported:
      - explanation: str  (older tests/contracts)

    This model stays immutable and stable for production.
    """
    summary: str
    contributing_predictors: List[str] = field(default_factory=list)
    reasoning_steps: List[str] = field(default_factory=list)

    def __init__(
        self,
        summary: Optional[str] = None,
        contributing_predictors: Optional[List[str]] = None,
        reasoning_steps: Optional[List[str]] = None,
        explanation: Optional[str] = None,
    ):
        if summary is None and explanation is not None:
            summary = explanation

        if summary is None:
            summary = ""

        object.__setattr__(self, "summary", str(summary))
        object.__setattr__(self, "contributing_predictors", list(contributing_predictors or []))
        object.__setattr__(self, "reasoning_steps", list(reasoning_steps or []))
