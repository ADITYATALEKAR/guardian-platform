"""
layer3_engine.py

Layer 3 — Prediction & Learning Engine (stateful, deterministic)

Responsibilities:
- Accept WeaknessBundle-like dict (Layer2 output)
- Update bounded per-entity LearningState
- Produce PredictionBundle with deterministic ordering

Constraints:
- No wall clock usage
- No randomness
- No Layer0/Layer1 recomputation
- Bounded memory and time per entity
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .prediction_contracts import (
    PredictionBundle,
    PredictionSignal,
    _clamp01,
    _json_safe_metrics,
    _safe_int,
    _safe_str,
    _stable_round,
)
from .learning_state_v2 import LearningState, AxisState, MAX_PERSISTENCE
from .temporal_features import (
    clamp01,
    compute_prediction_severity,
    compute_prediction_confidence,
    compute_horizon_days,
)


@dataclass(frozen=True)
class Layer3EngineConfig:
    max_signals: int = 24
    max_horizon_days: int = 90
    min_severity_emit: float = 0.20
    min_confidence_emit: float = 0.30


PREDICTION_KIND_MAP: Dict[str, str] = {
    "coherence": "coherence_instability",
    "drift": "drift_escalation",
    "entropy": "entropy_degradation",
    "fallback": "fallback_escalation",
    "correlation": "multi_axis_instability",
    "transition": "transition_shift",
    "fusion": "trajectory_deterioration_risk",
    "crypto_posture": "crypto_posture_risk",
    "protection_posture": "protection_posture_risk",
    "harvest_now_decrypt_later": "harvest_now_decrypt_later_risk",
}

ALLOWED_PREDICTION_KINDS = {
    'coherence_instability',
    'crypto_posture_risk',
    'drift_escalation',
    'entropy_degradation',
    'fallback_escalation',
    'harvest_now_decrypt_later_risk',
    'multi_axis_instability',
    'protection_posture_risk',
    'trajectory_deterioration_risk',
    'transition_shift',
}

AXIS_METRIC_WEIGHT = {
    'drift': 1.0,
    'entropy': 1.0,
    'coherence': 0.9,
    'fallback': 1.0,
    'correlation': 0.8,
    'transition': 0.9,
}


def _canonicalize_weakness_signals(signals: Any) -> List[Dict[str, Any]]:
    if not isinstance(signals, list):
        return []

    out: List[Dict[str, Any]] = []
    for item in signals:
        if not isinstance(item, dict):
            continue

        kind = _safe_str(item.get("weakness_kind"), "unknown").lower()
        sev = _stable_round(_clamp01(item.get("severity_01")))
        conf = _stable_round(_clamp01(item.get("confidence_01")))

        metrics_clean = _json_safe_metrics(item.get("metrics", {}), max_items=32)

        ev = item.get("evidence_refs", [])
        if not isinstance(ev, list):
            ev = []

        out.append(
            {
                "weakness_kind": kind,
                "severity_01": float(sev),
                "confidence_01": float(conf),
                "metrics": metrics_clean,
                "evidence_refs": ev,
            }
        )

    out.sort(
        key=lambda s: (
            str(s.get("weakness_kind", "")),
            -float(s.get("severity_01", 0.0)),
            -float(s.get("confidence_01", 0.0)),
        )
    )
    return out


def _axis_inputs(signals: List[Dict[str, Any]]) -> Tuple[Dict[str, Tuple[float, float]], Dict[str, List[Dict[str, Any]]], Dict[str, float], int]:
    axis_vals: Dict[str, Tuple[float, float]] = {}
    axis_evidence: Dict[str, List[Dict[str, Any]]] = {}
    axis_metric_intensity: Dict[str, float] = {}
    propagation_flag = 0

    metric_keys = [
        "correlation_strength",
        "drift_zscore",
        "coherence_drop",
        "fallback_rate",
        "structural_score",
        "entropy_value",
        "entropy_decay_rate",
        "momentum_value",
        "transition_rate",
        "oscillation_energy",
    ]

    for s in signals:
        k = _safe_str(s.get("weakness_kind", "")).lower()
        if not k or k == "unknown":
            continue

        sev = clamp01(s.get("severity_01", 0.0))
        conf = clamp01(s.get("confidence_01", 0.0))

        prev = axis_vals.get(k)
        if prev is None or sev > prev[0] or (sev == prev[0] and conf > prev[1]):
            axis_vals[k] = (sev, conf)
            ev = s.get("evidence_refs", [])
            axis_evidence[k] = ev if isinstance(ev, list) else []
            metrics = s.get("metrics", {})
            if isinstance(metrics, dict):
                mval = 0.0
                for mk in metric_keys:
                    mval = max(mval, clamp01(metrics.get(mk, 0.0)))
                axis_metric_intensity[k] = clamp01(mval)
            else:
                axis_metric_intensity[k] = 0.0

        metrics = s.get("metrics", {})
        if isinstance(metrics, dict) and float(metrics.get("propagation_flag", 0.0)) >= 1.0:
            propagation_flag = 1

    return axis_vals, axis_evidence, axis_metric_intensity, propagation_flag


def _prediction_kind(kind: str) -> str:
    k = _safe_str(kind, "unknown").lower()
    return PREDICTION_KIND_MAP.get(k, f"{k}_forecast")


class Layer3Engine:
    """
    Deterministic Layer3 prediction engine.

    - Does not mutate Layer2 output
    - State passed in, updated deterministically
    - Outputs PredictionBundle only
    """

    def __init__(self, config: Optional[Layer3EngineConfig] = None) -> None:
        self.config = config or Layer3EngineConfig()

    def _assert_01(self, name: str, v: float) -> None:
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError(f"{name} not finite")
        if v < 0.0 or v > 1.0:
            raise ValueError(f"{name} out of [0,1]")

    def predict(
        self,
        *,
        weakness_bundle: Optional[Dict[str, Any]] = None,
        bundle: Optional[Dict[str, Any]] = None,
        state: Optional[LearningState] = None,
        return_state: bool = False,
    ):
        wb = weakness_bundle if weakness_bundle is not None else bundle
        if not isinstance(wb, dict):
            wb = {}

        entity_id = _safe_str(wb.get("entity_id"), "unknown")
        session_id = _safe_str(wb.get("session_id"), "unknown")
        ts_ms = max(0, _safe_int(wb.get("ts_ms", 0), 0))

        weakness_signals = _canonicalize_weakness_signals(wb.get("signals", []))
        axis_vals, axis_evidence, axis_metric_intensity, propagation_flag = _axis_inputs(weakness_signals)

        prev_state = state if isinstance(state, LearningState) else LearningState.empty(entity_id)
        updated_state = prev_state.update_from_signals(
            weakness_signals,
            ts_ms=ts_ms,
            propagation_flag=propagation_flag,
        )

        preds: List[PredictionSignal] = []
        reinforcement = updated_state.structural_reinforcement_score

        # Predictions may continue after an axis disappears due to EWMA decay.
        # This is intentional to model residual risk; outputs decay to zero via ABSENCE_DECAY.
        # deterministic axis order
        for kind in sorted(updated_state.axis_state.keys()):
            st = updated_state.axis_state.get(kind)
            if not isinstance(st, AxisState):
                continue

            # No-emission guard for fully neutral state
            if st.ewma_severity == 0.0 and st.persistence == 0 and reinforcement == 0.0:
                continue

            # Inertia dampener for tiny decays
            if st.ewma_severity < 0.25 and st.persistence == 0 and reinforcement < 0.2:
                continue

            p_norm = float(st.persistence) / float(MAX_PERSISTENCE)
            metric_w = AXIS_METRIC_WEIGHT.get(kind, 1.0)
            metric_intensity = clamp01(axis_metric_intensity.get(kind, 0.0) * float(metric_w))
            sev = compute_prediction_severity(
                st.ewma_severity,
                st.peak_severity_recent,
                st.velocity,
                p_norm,
                reinforcement,
                metric_intensity,
            )
            rel_score = clamp01(1.0 - st.reliability_ewma)
            conf = compute_prediction_confidence(
                st.ewma_confidence,
                st.velocity,
                st.volatility_ewma,
                p_norm,
                reinforcement,
                rel_score,
            )

            self._assert_01("prediction_severity", sev)
            self._assert_01("prediction_confidence", conf)

            if sev < float(self.config.min_severity_emit) or conf < float(self.config.min_confidence_emit):
                continue

            prop_norm = float(updated_state.propagation_persistence) / float(MAX_PERSISTENCE)
            horizon_days = compute_horizon_days(
                st.velocity,
                p_norm,
                reinforcement,
                st.volatility_ewma,
                prop_norm,
                int(self.config.max_horizon_days),
            )
            horizon_days = min(int(self.config.max_horizon_days), max(0, int(horizon_days)))

            metrics = {
                "ewma_severity": float(_stable_round(st.ewma_severity)),
                "ewma_confidence": float(_stable_round(st.ewma_confidence)),
                "reliability_score": float(_stable_round(rel_score)),
                "volatility_ewma": float(_stable_round(st.volatility_ewma)),
                "velocity": float(_stable_round(st.velocity)),
                "persistence": float(st.persistence),
                "structural_reinforcement": float(_stable_round(reinforcement)),
                "structural_reinforcement_score": float(_stable_round(reinforcement)),
            }

            pred_kind = _prediction_kind(kind)
            if pred_kind not in ALLOWED_PREDICTION_KINDS:
                raise ValueError('prediction_kind not allowed')

            preds.append(
                PredictionSignal(
                    entity_id=entity_id,
                    session_id=session_id,
                    ts_ms=ts_ms,
                    prediction_kind=pred_kind,
                    severity_01=float(_stable_round(sev)),
                    confidence_01=float(_stable_round(conf)),
                    horizon_days=int(horizon_days),
                    metrics=metrics,
                    evidence_refs=axis_evidence.get(kind, []),
                )
            )

        preds = preds[: max(0, int(self.config.max_signals))]

        bundle_out = PredictionBundle(
            entity_id=entity_id,
            session_id=session_id,
            ts_ms=int(ts_ms),
            signals=preds,
        )

        if return_state:
            return bundle_out, updated_state
        return bundle_out
