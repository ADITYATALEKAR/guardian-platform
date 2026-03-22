from dataclasses import dataclass, field
from typing import Any, Dict, List

from enum import Enum


class AlertLevel(Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    ORANGE = "ORANGE"
    RED = "RED"

    def __str__(self) -> str:
        return self.value



@dataclass(frozen=True)
class AlertResponse:
    # ------------------------------------------------------------------
    # CANONICAL LAYER-4 CONTRACT
    # ------------------------------------------------------------------
    entity_id: str
    session_id: str
    alert_kind: str
    severity_01: float
    confidence_01: float
    title: str
    body: str

    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # LEGACY ACCESSORS (READ-ONLY)
    # ------------------------------------------------------------------
    @property
    def evidence_ids(self) -> List[str]:
        ids: List[str] = []
        for ref in self.evidence_refs:
            ids.extend(ref.get("fingerprint_ids", []))
        return ids

    @property
    def confidence(self) -> float:
        return float(self.confidence_01)

    @property
    def level(self) -> str:
        return self.alert_kind

    @property
    def alert_level(self) -> str:
        return self.alert_kind
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AlertResponse":
        return cls(**d)

    # ------------------------------------------------------------------
    # SERIALIZATION
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "session_id": self.session_id,
            "alert_kind": self.alert_kind,
            "severity_01": float(self.severity_01),
            "confidence_01": float(self.confidence_01),
            "title": self.title,
            "body": self.body,
            "evidence_refs": self.evidence_refs,
            "metrics": self.metrics,
        }

    # ------------------------------------------------------------------
    # LEGACY FACTORY (SAFE, EXPLICIT)
    # ------------------------------------------------------------------
    @classmethod
    def from_legacy_alert(cls, alert: Any) -> "AlertResponse":
        """
        Adapter for old Alert objects used in tests / integrations.
        """

        raw_level = getattr(alert, "alert_level", None) or getattr(alert, "level", "UNKNOWN")
        if hasattr(raw_level, "name"):
            alert_kind = raw_level.name
        else:
            alert_kind = str(raw_level)

        return cls(
            entity_id=getattr(alert, "entity_id", "UNKNOWN"),
            session_id=getattr(alert, "session_id", ""),
            alert_kind=str(alert_kind),
            severity_01=float(getattr(alert, "severity_01", 0.5)),
            confidence_01=float(getattr(alert, "confidence", 0.5)),
            title="Security alert detected",
            body="Automated detection triggered",
            evidence_refs=[
                {"fingerprint_ids": getattr(alert, "evidence_ids", [])}
            ],
            metrics={
                "policy_version": getattr(alert, "policy_version", None),
                "generated_at_utc": getattr(alert, "generated_at_utc", None),
            },
        )
