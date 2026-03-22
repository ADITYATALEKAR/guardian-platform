"""
Guardian’s read-only query interface.

Hard rules:
- No decisions
- No mutation
- Must preserve identity: result["alert"] is raw alert (unit test requirement)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, List, Optional, Dict

from layers.layer4_decision_logic_guardian.guardian_core import GuardianCore
from layers.layer4_decision_logic_guardian.thresholds import GuardianThresholds

from layers.layer4_decision_logic_guardian.legacy.justification import build_alert_justification
from layers.layer4_decision_logic_guardian.legacy.impact_analysis import ImpactAnalyzer
from layers.layer4_decision_logic_guardian.legacy.pattern_labels import PatternLabeler
from layers.layer4_decision_logic_guardian.legacy.advisory_analysis import AdvisoryAnalyzer
from layers.layer4_decision_logic_guardian.legacy.campaign_engine import CampaignEngine
from layers.layer4_decision_logic_guardian.legacy.actor_extractor import ActorExtractor
from layers.layer4_decision_logic_guardian.legacy.alert import Alert

from layers.layer4_decision_logic_guardian.policy_ingestion.registry.file_policy_registry import (
    FilePolicyRegistry,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.engine.policy_engine import (
    PolicyEngine,
)

from layers.layer4_decision_logic_guardian.contracts.alert_response import (
    AlertResponse,
    AlertLevel,
)
from layers.layer4_decision_logic_guardian.legacy.contracts.justification_response import (
    JustificationResponse,
)
from layers.layer4_decision_logic_guardian.legacy.contracts.pattern_response import PatternResponse
from layers.layer4_decision_logic_guardian.legacy.contracts.advisory_response import AdvisoryResponse
from layers.layer4_decision_logic_guardian.legacy.contracts.impact_response import ImpactResponse
from layers.layer4_decision_logic_guardian.contracts.guardian_query_response import (
    GuardianQueryResponse,
)

DEFAULT_CAMPAIGN_VERSION = "1.0"
DEFAULT_POLICY_VERSION = "1.0"


class AttributeDict(dict):
    """Dict with attribute-style access (required by narrative builder tests)."""

    def __getattr__(self, name: str):
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(name) from e

    def __setattr__(self, name: str, value: Any):
        self[name] = value


class GuardianQueries:
    def __init__(self):
        self.guardian = GuardianCore(thresholds=GuardianThresholds())

        self.impact_analyzer = ImpactAnalyzer()
        self.pattern_labeler = PatternLabeler()
        self.advisory_analyzer = AdvisoryAnalyzer()
        self.campaign_engine = CampaignEngine()
        self.actor_extractor = ActorExtractor()

        self.policy_registry = FilePolicyRegistry(storage_root=Path("storage/policies"))
        self.policy_engine = PolicyEngine(self.policy_registry)

    def explain_alert(
        self,
        alert: Alert,
        weaknesses: List[object],
        trust_graph=None,
        historical_confidences: Optional[List[float]] = None,
    ) -> AttributeDict:

        # -------------------------------------------------
        # Justification
        # -------------------------------------------------
        justification_text = build_alert_justification(alert)
        justification = JustificationResponse(
            explanation=justification_text,
            contributing_predictors=list(getattr(alert, "predictor_names", []) or []),
        )

        # -------------------------------------------------
        # Patterns
        # -------------------------------------------------
        derived_patterns = self.pattern_labeler.derive(weaknesses)
        pattern_labels = [p.label for p in derived_patterns]

        observed_patterns: List[PatternResponse] = [
            PatternResponse(
                label=p.label,
                description=p.description,
                confidence=float(getattr(p, "confidence", 0.0) or 0.0),
            )
            for p in derived_patterns
        ]

        # -------------------------------------------------
        # Advisory
        # -------------------------------------------------
        advisory_summary = self.advisory_analyzer.analyze(
            pattern_labels=pattern_labels,
            historical_confidences=historical_confidences or [],
        )

        advisory = AdvisoryResponse(
            trend=advisory_summary.trend,
            pattern_priority=pattern_labels,
            uncertainty_notes=advisory_summary.uncertainty_notes or [],
            business_interpretation=advisory_summary.business_interpretation,
        )

        # -------------------------------------------------
        # Impact Analysis (KEY FIX)
        # -------------------------------------------------
        impact: Optional[ImpactResponse] = None
        impact_analysis: Optional[Dict[str, Any]] = None

        if trust_graph is not None:
            impact_result = self.impact_analyzer.analyze(
                alert=alert, trust_graph=trust_graph
            )
            impact = ImpactResponse(
                estimated_scope=impact_result.estimated_scope,
                impacted_assets=impact_result.impacted_assets,
            )
            impact_analysis = impact.to_dict()
        else:
            impact_analysis = None

        # -------------------------------------------------
        # AlertResponse (canonical)
        # -------------------------------------------------
        level = getattr(alert, "level", AlertLevel.GREEN)

        severity_map = {
            AlertLevel.GREEN: 0.2,
            AlertLevel.ORANGE: 0.6,
            AlertLevel.RED: 0.9,
        }

        alert_response = AlertResponse(
            entity_id=alert.entity_id,
            session_id=getattr(alert, "session_id", ""),
            alert_kind=level.value if isinstance(level, AlertLevel) else str(level),
            severity_01=severity_map.get(level, 0.5),
            confidence_01=float(alert.confidence or 0.0),
            title=f"{level.value.upper()} security alert",
            body=justification_text,
            evidence_refs=list(getattr(alert, "evidence_prediction_ids", []) or []),
            metrics={},
        )

        # -------------------------------------------------
        # Policy & Campaign
        # -------------------------------------------------
        policy = self.policy_engine.evaluate(
            tenant_id=getattr(alert, "tenant_id", "unknown_tenant"),
            pattern_labels=pattern_labels,
            jurisdiction=None,
            include_internal=True,
        )

        campaign = self.campaign_engine.evaluate(
            pattern_labels=pattern_labels,
            campaign_version=DEFAULT_CAMPAIGN_VERSION,
        )

        # -------------------------------------------------
        # Actors (HARDENED)
        # -------------------------------------------------
        try:
            actors = self.actor_extractor.extract_from_patterns(
                patterns=pattern_labels,
                evidence_ids=list(getattr(alert, "evidence_prediction_ids", []) or []),
                alert_timestamp_utc=int(time.time()),
            )
            if not isinstance(actors, list):
                actors = []
        except Exception:
            actors = []

        # -------------------------------------------------
        # Typed Response (canonical)
        # -------------------------------------------------
        typed_response = GuardianQueryResponse(
            alert=alert_response,
            tenant_id=getattr(alert, "tenant_id", "unknown_tenant"),
            entity_id=alert.entity_id,
            session_id=getattr(alert, "session_id", ""),
            justification=justification,
            patterns=observed_patterns,
            advisory=advisory,
            impact=impact,
            policy=policy,
            campaign=campaign,
            actors=actors or None,
        )

        # -------------------------------------------------
        # DTO wrapper (raw alert identity preserved)
        # -------------------------------------------------
        return AttributeDict(
            {
                "alert": alert,  # REQUIRED (raw alert)
                "alert_response": alert_response,
                "justification": justification,
                "patterns": observed_patterns,
                "advisory": advisory,
                "impact": impact,
                "impact_analysis": impact_analysis,  #  REQUIRED BY TEST
                "policy": policy,
                "campaign": campaign,
                "actors": actors or None,
                "_typed_response": typed_response,
            }
        )
