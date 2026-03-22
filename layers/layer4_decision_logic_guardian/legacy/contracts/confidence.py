from dataclasses import dataclass

@dataclass(frozen=True)
class ConfidenceStatement:
    """
    Explicit confidence with ceiling and rationale.
    """
    observed: float              # e.g. 0.78
    ceiling: float               # e.g. 0.85 (external-only limit)
    rationale: str               # why the ceiling exists
