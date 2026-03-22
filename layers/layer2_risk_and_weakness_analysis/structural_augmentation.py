from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

from .weakness_contracts import WeaknessSignal
from .graph_signals import GraphStructuralSignals


def _safe_float(x: object, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


@dataclass(frozen=True, slots=True)
class StructuralAugmentationConfig:
    # Severity amplification cap
    a_max: float = 0.35

    # Confidence boost cap
    b_max: float = 0.25

    # Per-kind alpha (severity)
    alpha_by_kind: Dict[str, float] = None

    # Per-kind beta (confidence)
    beta_by_kind: Dict[str, float] = None

    # Propagation thresholds
    propagation_identity_threshold: float = 0.6
    propagation_material_threshold: float = 0.6

    def __post_init__(self) -> None:
        object.__setattr__(self, "alpha_by_kind", dict(self.alpha_by_kind or {
            "coherence": 0.6,
            "drift": 0.6,
            "entropy": 0.5,
            "fallback": 0.5,
            "correlation": 0.7,
            "transition": 0.5,
            "fusion": 0.4,
        }))
        object.__setattr__(self, "beta_by_kind", dict(self.beta_by_kind or {
            "coherence": 0.4,
            "drift": 0.4,
            "entropy": 0.3,
            "fallback": 0.3,
            "correlation": 0.5,
            "transition": 0.3,
            "fusion": 0.3,
        }))


class StructuralAugmentationEngine:
    """
    Apply bounded structural amplification to existing WeaknessSignals.
    """

    def __init__(self, config: StructuralAugmentationConfig) -> None:
        self._cfg = config

    def _structural_strength(self, kind: str, s: GraphStructuralSignals) -> float:
        k = str(kind or "").strip().lower()
        if k == "coherence":
            return _clamp01(max(s.identity_reuse_density, s.similarity_cluster_score))
        if k == "drift":
            return _clamp01(max(s.temporal_escalation_score, s.vector_stability_score))
        if k == "entropy":
            return _clamp01(max(s.similarity_cluster_score, s.cross_endpoint_correlation_score))
        if k == "fallback":
            return _clamp01(s.material_dependency_fanout)
        if k == "correlation":
            return _clamp01(s.cross_endpoint_correlation_score)
        if k == "transition":
            return _clamp01(s.temporal_escalation_score)
        if k == "fusion":
            return _clamp01(s.evidence_quality_weight)
        return 0.0

    def _amplify(self, s: WeaknessSignal, structural: GraphStructuralSignals) -> WeaknessSignal:
        if s.severity_01 <= 0.0:
            return s

        kind = str(s.weakness_kind or "").strip().lower()
        G = _clamp01(self._structural_strength(kind, structural))

        alpha = _clamp01(_safe_float(self._cfg.alpha_by_kind.get(kind, 0.0), 0.0))
        beta = _clamp01(_safe_float(self._cfg.beta_by_kind.get(kind, 0.0), 0.0))

        A = min(alpha * G, _clamp01(self._cfg.a_max))
        B = min(beta * G, _clamp01(self._cfg.b_max))

        s_local = _clamp01(_safe_float(s.severity_01, 0.0))
        c_local = _clamp01(_safe_float(s.confidence_01, 0.0))

        s_final = min(1.0, s_local * (1.0 + A))
        c_final = min(1.0, c_local + B * (1.0 - c_local))

        # Propagation flag (independent of severity)
        propagation_flag = 1.0 if (
            structural.identity_reuse_density >= self._cfg.propagation_identity_threshold
            or structural.material_dependency_fanout >= self._cfg.propagation_material_threshold
        ) else 0.0

        metrics = dict(s.metrics or {})
        if propagation_flag > 0.0:
            metrics["propagation_flag"] = 1.0
        metrics.setdefault("structural_strength", float(G))

        return WeaknessSignal(
            entity_id=s.entity_id,
            session_id=s.session_id,
            ts_ms=s.ts_ms,
            weakness_id=s.weakness_id,
            weakness_kind=s.weakness_kind,
            severity_01=float(s_final),
            confidence_01=float(c_final),
            evidence_refs=list(s.evidence_refs or []),
            metrics=metrics,
        )

    def augment_signals(
        self,
        signals: Sequence[WeaknessSignal],
        structural: GraphStructuralSignals,
    ) -> List[WeaknessSignal]:
        return [self._amplify(s, structural) for s in (signals or [])]
