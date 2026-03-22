from dataclasses import dataclass


@dataclass(frozen=True)
class ConfidenceStatement:
    """
    Explicit confidence representation.

    This separates:
    - observed confidence (what the system computed)
    - confidence ceiling (structural limit of certainty)
    - rationale (why certainty is capped)

    This object is REQUIRED for:
    - auditability
    - regulator explanation
    - honest uncertainty communication

    This object MUST NOT:
    - imply correctness
    - imply enforcement
    - imply action
    """

    observed: float          # e.g. 0.78
    ceiling: float           # e.g. 0.85 (external-only limit)
    rationale: str           # human explanation

    def __post_init__(self):
        if not (0.0 <= self.observed <= 1.0):
            raise ValueError("observed confidence must be between 0.0 and 1.0")

        if not (0.0 <= self.ceiling <= 1.0):
            raise ValueError("confidence ceiling must be between 0.0 and 1.0")

        if self.observed > self.ceiling:
            raise ValueError(
                "observed confidence cannot exceed confidence ceiling"
            )
