from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CycleStatus(str, Enum):
    INITIALIZING = "initializing"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class CycleState:
    """
    Immutable discovery cycle state.

    Used for:
    - Crash recovery
    - Operational audit trail
    - Deterministic cycle tracking
    """

    cycle_id: str
    timestamp_ms: int
    status: CycleStatus
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cycle_id": self.cycle_id,
            "timestamp_ms": self.timestamp_ms,
            "status": self.status.value,
            "error": self.error,
        }

    @staticmethod
    def from_dict(data: dict) -> "CycleState":
        return CycleState(
            cycle_id=data["cycle_id"],
            timestamp_ms=data["timestamp_ms"],
            status=CycleStatus(data["status"]),
            error=data.get("error"),
        )