"""
Layer 4 / Guardian Core

Purpose
-------
GuardianCore converts Layer3 PredictionBundle-like data into a bank-grade,
auditable decision object for:
- alerts
- advisory narrative
- stable severity/confidence summary
- compliance/policy enforcement (optional)

Who depends on this file?
-------------------------
- guardian_queries.py (likely)
- campaign_engine.py (likely)
- Layer 4 tests (direct)
- Integration / UI / Agents (via outputs)

Bank-grade requirements
-----------------------
- Deterministic output ordering
- JSON safe output (no NaN / inf / objects)
- Bounded sizes
- Robust to missing / malformed fields
- policy_mode="disabled" must still work
"""

from dataclasses import dataclass
import math
from typing import Any, Dict, List, Optional

from ..thresholds import GuardianThresholds
from ..contracts.alert_response import AlertResponse
from ..contracts.guardian_query_response import GuardianQueryResponse
from .risk_aggregation import aggregate_risk
from ..campaign.sync_index import compute_sync_index
from ..campaign.phase_machine import infer_phase
from ..campaign.risk_projection import project_risk
from ..campaign.technique_classifier import classify_techniques
from ..narrative.narrative_planner import build_narrative
from ..advisory.advisory_engine import build_advisory


def _sanitize_scalar(x: Any) -> Any:
    """
    Ensures scalar is JSON-safe.
    - removes NaN/Inf -> 0.0
    - converts objects -> str(...)
    """
    if x is None:
        return None

    if isinstance(x, (bool, int, str)):
        return x

    if isinstance(x, float):
        if not math.isfinite(x):
            return 0.0
        return float(x)

    # numeric strings, decimals, etc.
    try:
        v = float(x)
        if math.isfinite(v):
            return float(v)
        return 0.0
    except Exception:
        return str(x)


def _sanitize_metrics(metrics: Any, max_items: int = 32) -> Dict[str, Any]:
    """
    Metrics must be JSON-safe and bounded.
    """
    if not isinstance(metrics, dict):
        return {}

    out: Dict[str, Any] = {}
    for k in sorted(metrics.keys())[:max_items]:
        key = str(k)[:64]
        out[key] = _sanitize_scalar(metrics.get(k))
    return out


def _sanitize_evidence_refs(evidence_refs: Any, max_refs: int = 16, max_fp_ids: int = 32) -> List[Dict[str, Any]]:
    """
    Evidence refs must be bounded and deterministic.
    """
    if not isinstance(evidence_refs, list):
        return []

    out: List[Dict[str, Any]] = []
    for ref in evidence_refs[:max_refs]:
        if not isinstance(ref, dict):
            continue

        fp_ids = ref.get("fingerprint_ids", [])
        if not isinstance(fp_ids, list):
            fp_ids = []

        out.append(
            {
                "kind": str(ref.get("kind", ""))[:64],
                "hash": str(ref.get("hash", ""))[:96],
                "fingerprint_ids": [str(x)[:96] for x in fp_ids[:max_fp_ids]],
            }
        )
    return out


@dataclass(frozen=True)
class GuardianCore:
    """
    GuardianCore is intentionally small + deterministic.

    It is the "bank-grade finalizer":
    - consumes Layer3 forecast signals
    - emits bounded decision response for UI + enforcement
    """

    thresholds: GuardianThresholds

    def evaluate(
        self,
        tenant_id: str,
        prediction_bundle: Dict[str, Any],
        policy_mode: str = "disabled",
    ) -> GuardianQueryResponse:
        """
        Evaluate a Layer3 PredictionBundle-like payload.

        policy_mode:
          - "disabled": Guardian runs without policy enforcement data
          - future: "enabled" (will wire to Layer4 policy_ingestion engine)
        """

        entity_id = str(prediction_bundle.get("entity_id") or "")[:128]
        session_id = str(prediction_bundle.get("session_id") or "")[:128]

        ts_raw = prediction_bundle.get("ts_ms")
        try:
            ts_ms = int(ts_raw)
        except Exception:
            ts_ms = 0

        signals = prediction_bundle.get("signals", [])
        if not isinstance(signals, list):
            signals = []

        # Normalize + filter signals deterministically
        norm_signals: List[Dict[str, Any]] = []
        for s in signals:
            if not isinstance(s, dict):
                continue

            pk = str(s.get("prediction_kind") or "").strip()
            if not pk:
                continue

            sev = _sanitize_scalar(s.get("severity_01"))
            conf = _sanitize_scalar(s.get("confidence_01"))

            try:
                sev_f = float(sev)
            except Exception:
                sev_f = 0.0
            try:
                conf_f = float(conf)
            except Exception:
                conf_f = 0.0

            sev_f = self.thresholds.clamp01(sev_f)
            conf_f = self.thresholds.clamp01(conf_f)

            # actions only if meaningful
            if conf_f < self.thresholds.min_signal_confidence_for_action:
                continue
            if sev_f < self.thresholds.min_signal_severity_for_action:
                continue

            try:
                horizon_days = int(s.get("horizon_days", 0))
            except Exception:
                horizon_days = 0
            if horizon_days < 0:
                horizon_days = 0
            if horizon_days > 90:
                horizon_days = 90

            metrics = _sanitize_metrics(s.get("metrics"))
            evidence_refs = _sanitize_evidence_refs(s.get("evidence_refs"))

            norm_signals.append(
                {
                    "prediction_kind": pk,
                    "severity_01": sev_f,
                    "confidence_01": conf_f,
                    "horizon_days": horizon_days,
                    "metrics": metrics,
                    "evidence_refs": evidence_refs,
                }
            )

        # deterministic ordering (severity desc, confidence desc, kind)
        norm_signals.sort(
            key=lambda x: (
                -float(x["severity_01"]),
                -float(x["confidence_01"]),
                str(x["prediction_kind"]),
            )
        )

        # -------------------------------------------------
        # Phase 9 integration: campaign inference pipeline
        # -------------------------------------------------
        overall_risk_score, scored_signals = aggregate_risk(
            norm_signals,
            weight_severity=self.thresholds.weight_severity,
            weight_confidence=self.thresholds.weight_confidence,
        )
        sync_index = compute_sync_index(norm_signals)
        phase_result = infer_phase(norm_signals, sync_index=sync_index)
        risk_proj = project_risk(norm_signals, sync_index=sync_index)
        technique_labels = classify_techniques(norm_signals)

        narrative = build_narrative(
            campaign_phase=phase_result.phase.value,
            risk_class=risk_proj.risk_class,
            sync_index=sync_index,
            overall_risk_score=overall_risk_score,
            pattern_labels=[lbl.label for lbl in technique_labels],
        )

        advisory = build_advisory(
            campaign_phase=phase_result.phase.value,
            risk_class=risk_proj.risk_class,
            pattern_labels=[lbl.label for lbl in technique_labels],
        )

        # Aggregate severity/confidence
        if not norm_signals:
            overall_sev = 0.0
            overall_conf = 0.0
        else:
            # top-signal base
            base = norm_signals[0]
            base_score = (
                self.thresholds.weight_severity * float(base["severity_01"])
                + self.thresholds.weight_confidence * float(base["confidence_01"])
            )

            # convergence boost
            extra = max(0, len(norm_signals) - 1)
            boost = min(self.thresholds.cross_axis_boost_cap, extra * self.thresholds.cross_axis_boost_per_extra_signal)

            overall_sev = self.thresholds.clamp01(float(base["severity_01"]) + boost)
            overall_conf = self.thresholds.clamp01(float(base["confidence_01"]) + boost)

            # slight influence from base_score (keeps monotonic)
            overall_sev = self.thresholds.clamp01((overall_sev + base_score) / 2.0)
            overall_conf = self.thresholds.clamp01((overall_conf + base_score) / 2.0)

        # Convert to alerts (bounded)
        alerts: List[AlertResponse] = []
        for s in norm_signals[: self.thresholds.max_alerts]:
            title = f"Predicted risk: {s['prediction_kind']}"
            body = (
                f"Forecast indicates {int(round(s['confidence_01'] * 100))}% confidence "
                f"and {int(round(s['severity_01'] * 100))}% severity within {s['horizon_days']} days."
            )

            alerts.append(
                AlertResponse(
                    entity_id=entity_id,
                    session_id=session_id,
                    alert_kind=str(s["prediction_kind"]),
                    severity_01=float(s["severity_01"]),
                    confidence_01=float(s["confidence_01"]),
                    title=title[:200],
                    body=body[:600],
                    evidence_refs=s["evidence_refs"],
                    metrics=s["metrics"],
                )
            )

        # Justification must contain percent + evidence mention (auditable)
        # We extract a bounded set of fingerprint_ids from evidence_refs.
        fp_ids: List[str] = []
        for s in norm_signals:
            for ref in s.get("evidence_refs", []):
                for fp in ref.get("fingerprint_ids", []):
                    if isinstance(fp, str) and fp.strip():
                        fp_ids.append(fp.strip())

        # Deduplicate deterministically + bound
        fp_ids = sorted(set(fp_ids))[:12]

        if fp_ids:
            fp_text = "fingerprint refs: " + ", ".join(fp_ids)
        else:
            fp_text = "fingerprint refs: none"

        justification = (
            f"Guardian assessed overall risk at {int(round(overall_sev * 100))}% severity "
            f"with {int(round(overall_conf * 100))}% confidence based on convergent forecast evidence; "
            f"{fp_text}."
        )
        justification = justification[: self.thresholds.max_justification_chars]


        # policy disabled => policies omitted
        policies: Optional[Any] = None
        if str(policy_mode).strip().lower() != "disabled":
            # future hook
            policies = []

        return GuardianQueryResponse(
            tenant_id=str(tenant_id)[:128],
            entity_id=entity_id,
            session_id=session_id,
            ts_ms=ts_ms,
            overall_severity_01=float(overall_sev),
            overall_confidence_01=float(overall_conf),
            campaign_phase=phase_result.phase.value,
            sync_index=float(sync_index),
            campaign_score_01=float(overall_risk_score),
            pattern_labels=[lbl.label for lbl in technique_labels],
            advisory=advisory,
            narrative=narrative,
            alerts=alerts,
            justification={
                "summary": justification,
                "campaign_phase": phase_result.phase.value,
                "phase_confidence": float(phase_result.confidence),
                "sync_index": float(sync_index),
                "overall_risk_score": float(overall_risk_score),
                "structural_risk_potential": float(risk_proj.structural_risk_potential),
                "propagation_potential": float(risk_proj.propagation_potential),
                "risk_class": risk_proj.risk_class,
                "pattern_labels": [lbl.label for lbl in technique_labels],
                "narrative": narrative,
                "advisory": advisory,
            },
            policies=policies,
        )
