"""
GuardianQueryResponse Contract

Purpose
-------
Canonical Guardian output object.
Stable for:
- UI rendering
- agent handoff
- audit export
- deterministic replay

IMPORTANT
---------
ADDITIVE ONLY
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .alert_response import AlertResponse

# ------------------------------------------------------------------
# HARD CONTRACT BRIDGE
# Narrative expects alert.evidence_ids
# ------------------------------------------------------------------
if not hasattr(AlertResponse, "evidence_ids"):
    setattr(AlertResponse, "evidence_ids", [])


@dataclass(frozen=True)
class GuardianQueryResponse:
    # ------------------------------------------------------------------
    # Core identity
    # ------------------------------------------------------------------
    alert: Optional[AlertResponse] = None
    tenant_id: str = "unknown_tenant"
    entity_id: str = "unknown_entity"
    session_id: str = ""
    ts_ms: int = 0

    # ------------------------------------------------------------------
    # Rollups
    # ------------------------------------------------------------------
    overall_severity_01: float = 0.0
    overall_confidence_01: float = 0.0

    # ------------------------------------------------------------------
    # Canonical alert list
    # ------------------------------------------------------------------
    alerts: Optional[List[AlertResponse]] = None
    justification: Any = None

    # ------------------------------------------------------------------
    # Narrative surfaces
    # ------------------------------------------------------------------
    patterns: Optional[List[Any]] = None
    actors: Optional[List[Any]] = None

    advisory: Optional[Any] = None
    impact: Optional[Any] = None
    campaign: Optional[Any] = None

    # ------------------------------------------------------------------
    # Governance
    # ------------------------------------------------------------------
    policy: Optional[Any] = None
    policies: Optional[Any] = None

    # ------------------------------------------------------------------
    # Evidence bridge
    # ------------------------------------------------------------------
    evidence_ids: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # Campaign intelligence (top-level, additive)
    # ------------------------------------------------------------------
    campaign_phase: Optional[str] = None
    sync_index: Optional[float] = None
    campaign_score_01: Optional[float] = None
    pattern_labels: Optional[List[str]] = None
    narrative: Optional[Any] = None

    # ------------------------------------------------------------------
    # Post-init normalization
    # ------------------------------------------------------------------
    def __post_init__(self):
        if self.alerts is None and self.alert is not None:
            object.__setattr__(self, "alerts", [self.alert])

        if self.patterns is None:
            object.__setattr__(self, "patterns", [])

        if self.evidence_ids is None:
            inferred = getattr(self.alert, "evidence_ids", [])
            object.__setattr__(self, "evidence_ids", list(inferred or []))

        if self.alert and not hasattr(self.alert, "evidence_ids"):
            try:
                setattr(self.alert, "evidence_ids", list(self.evidence_ids))
            except Exception:
                pass

        # Backward compatibility: populate top-level campaign fields from justification if present
        if isinstance(self.justification, dict):
            if self.campaign_phase is None and "campaign_phase" in self.justification:
                object.__setattr__(
                    self, "campaign_phase", self.justification.get("campaign_phase")
                )
            if self.sync_index is None and "sync_index" in self.justification:
                object.__setattr__(
                    self, "sync_index", self.justification.get("sync_index")
                )
            if self.campaign_score_01 is None:
                if "campaign_score_01" in self.justification:
                    object.__setattr__(
                        self, "campaign_score_01", self.justification.get("campaign_score_01")
                    )
                elif "overall_risk_score" in self.justification:
                    object.__setattr__(
                        self, "campaign_score_01", self.justification.get("overall_risk_score")
                    )
            if self.pattern_labels is None and "pattern_labels" in self.justification:
                raw_labels = self.justification.get("pattern_labels")
                if isinstance(raw_labels, list):
                    object.__setattr__(self, "pattern_labels", raw_labels)
            if self.advisory is None and "advisory" in self.justification:
                object.__setattr__(self, "advisory", self.justification.get("advisory"))
            if self.narrative is None and "narrative" in self.justification:
                object.__setattr__(self, "narrative", self.justification.get("narrative"))

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "entity_id": self.entity_id,
            "session_id": self.session_id,
            "ts_ms": int(self.ts_ms),
            "overall_severity_01": float(self.overall_severity_01),
            "overall_confidence_01": float(self.overall_confidence_01),
            "alerts": [a.to_dict() for a in (self.alerts or [])],
            "campaign_phase": self.campaign_phase,
            "sync_index": (
                float(self.sync_index) if self.sync_index is not None else None
            ),
            "campaign_score_01": (
                float(self.campaign_score_01)
                if self.campaign_score_01 is not None
                else None
            ),
            "pattern_labels": (
                list(self.pattern_labels) if self.pattern_labels is not None else None
            ),
            "justification": (
                self.justification.to_dict()
                if hasattr(self.justification, "to_dict")
                else self.justification
            ),
            "patterns": [
                p.to_dict() if hasattr(p, "to_dict") else p
                for p in (self.patterns or [])
            ],
            "actors": [
                a.to_dict() if hasattr(a, "to_dict") else a
                for a in (self.actors or [])
            ] if self.actors else None,
            "advisory": (
                self.advisory.to_dict()
                if self.advisory and hasattr(self.advisory, "to_dict")
                else self.advisory
            ),
            "narrative": (
                self.narrative.to_dict()
                if self.narrative and hasattr(self.narrative, "to_dict")
                else self.narrative
            ),
            "impact": (
                self.impact.to_dict()
                if self.impact and hasattr(self.impact, "to_dict")
                else self.impact
            ),
            "campaign": (
                self.campaign.to_dict()
                if self.campaign and hasattr(self.campaign, "to_dict")
                else self.campaign
            ),
            "policy": (
                self.policy.to_dict()
                if self.policy and hasattr(self.policy, "to_dict")
                else self.policy
            ),
            "policies": self.policies,
            "evidence_ids": list(self.evidence_ids or []),
        }
