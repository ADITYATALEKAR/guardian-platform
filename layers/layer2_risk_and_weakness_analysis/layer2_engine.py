"""
layer2_engine.py

Layer 2 deterministic orchestrator.

Fixes applied:
1) Layer2EngineConfig uses dataclass default_factory (no broken defaults).
2) Evidence kind selection is robust (substring matching) via evidence_refs.py.
3) Correlation coherence_drop is clamped to [0..1].
4) Transition is always emitted (contract), but:
   - correlation ignores transition unless transition_detected=1
   - fusion ignores transition unless transition_detected=1
5) Evidence refs cap aligned to 8 across contracts, thresholds, and selection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core_utils.safety import clamp01 as _clamp01
from core_utils.safety import safe_float as _safe_float
from core_utils.safety import safe_str as _safe_str
from .weakness_contracts import WeaknessBundle, WeaknessSignal
from .evidence_refs import EvidencePolicy, build_evidence_refs_from_fingerprints, select_evidence_refs_for_axes
from .thresholds import Layer2Thresholds, correlation_badness_thresholds, default_thresholds
from .fusion import fuse_signals

from .coherence_weakness import CoherenceWeaknessDetector
from .drift_weakness import DriftWeaknessDetector
from .entropy_weakness import EntropyWeaknessDetector
from .fallback_weakness import FallbackWeaknessDetector
from .correlation_weakness import CorrelationWeaknessDetector
from .transition_weakness import TransitionWeaknessDetector
from .graph_slice import GraphSlice
from .graph_signals import GraphSignalExtractor, GraphStructuralSignals
from .structural_augmentation import StructuralAugmentationConfig, StructuralAugmentationEngine


@dataclass(frozen=True)
class Layer2EngineConfig:
    thresholds: Layer2Thresholds = field(default_factory=default_thresholds)
    evidence_policy: EvidencePolicy = field(
        default_factory=lambda: EvidencePolicy(
            max_refs=12,
            max_fp_ids_per_ref=8,
            prefer_handshake_anchor=True,
        )
    )
    structural_config: StructuralAugmentationConfig = field(
        default_factory=StructuralAugmentationConfig
    )


class Layer2Engine:
    """
    Bank-grade Layer 2 engine.

    Inputs:
      - entity_id, session_id, ts_ms
      - fingerprints: Layer0 evidence objects
      - physics_signals: scalar physics values
      - baseline: baseline statistics

    Output:
      - WeaknessBundle (deterministic, bounded, Layer4-safe)
    """

    def __init__(self, config: Optional[Layer2EngineConfig] = None):
        self._cfg = config or Layer2EngineConfig()

        self._coherence = CoherenceWeaknessDetector()
        self._drift = DriftWeaknessDetector()
        self._entropy = EntropyWeaknessDetector()
        self._fallback = FallbackWeaknessDetector()
        self._correlation = CorrelationWeaknessDetector()
        self._transition = TransitionWeaknessDetector()
        self._graph_signals = GraphSignalExtractor()
        self._augmenter = StructuralAugmentationEngine(self._cfg.structural_config)

    def evaluate(
        self,
        *,
        entity_id: str,
        session_id: str,
        ts_ms: int,
        fingerprints: Sequence[Any],
        physics_signals: Dict[str, Any],
        baseline: Dict[str, Any],
        graph_slice: Optional[GraphSlice] = None,
    ) -> WeaknessBundle:
        eid = _safe_str(entity_id, "unknown")
        sid = _safe_str(session_id, "unknown")
        try:
            t = int(ts_ms)
        except Exception:
            t = 0
        if t < 0:
            t = 0

        ps = dict(physics_signals or {})
        bl = dict(baseline or {})

        evidence_universe = build_evidence_refs_from_fingerprints(
            fingerprints,
            policy=self._cfg.evidence_policy,
        )

        max_refs = int(self._cfg.thresholds.max_evidence_refs_per_signal)

        signals: List[WeaknessSignal] = []

        structural: Optional[GraphStructuralSignals] = None
        if graph_slice is not None:
            structural = self._graph_signals.extract(graph_slice)

        # ----------------------------
        # Coherence
        # ----------------------------
        coherence_score = _clamp01(ps.get("coherence_score", ps.get("coherence", 1.0)))
        baseline_coh = _clamp01(bl.get("baseline_coherence", bl.get("coherence_mean", coherence_score)))
        baseline_coh_std = bl.get("coherence_std", None)

        coh = self._coherence.evaluate(
            eid,
            coherence_score,
            baseline_coh,
            baseline_std=baseline_coh_std,
        )
        if coh is not None:
            ev = select_evidence_refs_for_axes(
                evidence_universe,
                include_kinds=["coherence_fp", "handshake_fp"],
                max_refs=max_refs,
            )
            signals.append(
                WeaknessSignal(
                    entity_id=eid,
                    session_id=sid,
                    ts_ms=t,
                    weakness_id=coh.weakness_id,
                    weakness_kind="coherence",
                    severity_01=coh.severity,
                    confidence_01=coh.confidence,
                    evidence_refs=ev,
                    metrics={
                        "coherence_drop": float(getattr(coh, "coherence_drop", 0.0)),
                        "persistent": 1.0 if bool(getattr(coh, "persistent", False)) else 0.0,
                    },
                )
            )

        # ----------------------------
        # Drift
        # ----------------------------
        drift_rate = _safe_float(ps.get("drift_rate", ps.get("drift_strength", 0.0)), 0.0)
        momentum = _safe_float(ps.get("momentum", ps.get("momentum_strength", 0.0)), 0.0)

        b_mu = _safe_float(bl.get("baseline_drift_mean", bl.get("drift_mean", 0.0)), 0.0)
        b_sd = _safe_float(bl.get("baseline_drift_std", bl.get("drift_std", 0.0)), 0.0)

        dr = self._drift.evaluate(
            eid,
            drift_rate,
            momentum,
            coherence_score,
            b_mu,
            b_sd,
            baseline_coherence=baseline_coh,
        )
        if dr is not None:
            ev = select_evidence_refs_for_axes(
                evidence_universe,
                include_kinds=["drift_fp", "momentum_fp", "coherence_fp", "handshake_fp"],
                max_refs=max_refs,
            )
            signals.append(
                WeaknessSignal(
                    entity_id=eid,
                    session_id=sid,
                    ts_ms=t,
                    weakness_id=dr.weakness_id,
                    weakness_kind="drift",
                    severity_01=dr.severity,
                    confidence_01=dr.confidence,
                    evidence_refs=ev,
                    metrics={
                        "drift_zscore": float(getattr(dr, "drift_zscore", 0.0)),
                        "momentum_anomaly": 1.0 if bool(getattr(dr, "momentum_anomaly", False)) else 0.0,
                        "coherence_drop": float(getattr(dr, "coherence_drop", 0.0)),
                    },
                )
            )

        # ----------------------------
        # Entropy
        # ----------------------------
        entropy_value = _safe_float(ps.get("entropy_value", ps.get("entropy_level", ps.get("entropy_strength", 0.0))), 0.0)
        entropy_decay = _safe_float(ps.get("entropy_decay_rate", ps.get("decay_rate", 0.0)), 0.0)

        ent_mu = _safe_float(bl.get("baseline_entropy_mean", bl.get("entropy_mean", entropy_value)), entropy_value)
        ent_sd = _safe_float(bl.get("baseline_entropy_std", bl.get("entropy_std", 0.0)), 0.0)
        ent_floor = _safe_float(bl.get("entropy_floor", 0.0), 0.0)

        en = self._entropy.evaluate(
            eid,
            entropy_value,
            entropy_decay,
            ent_mu,
            ent_sd,
            ent_floor,
        )
        if en is not None:
            ev = select_evidence_refs_for_axes(
                evidence_universe,
                include_kinds=["entropy_histogram_fp", "handshake_fp"],
                max_refs=max_refs,
            )
            signals.append(
                WeaknessSignal(
                    entity_id=eid,
                    session_id=sid,
                    ts_ms=t,
                    weakness_id=en.weakness_id,
                    weakness_kind="entropy",
                    severity_01=en.severity,
                    confidence_01=en.confidence,
                    evidence_refs=ev,
                    metrics={
                        "entropy_zscore": float(getattr(en, "entropy_zscore", 0.0)),
                        "entropy_drop": float(getattr(en, "entropy_drop", 0.0)),
                        "entropy_decay_rate": float(getattr(en, "entropy_decay_rate", 0.0)),
                    },
                )
            )

        # ----------------------------
        # Fallback
        # ----------------------------
        fallback_rate = _safe_float(ps.get("fallback_rate", ps.get("fallback_frequency", 0.0)), 0.0)
        baseline_fallback_rate = _safe_float(bl.get("baseline_fallback_rate", bl.get("fallback_mean", 0.0)), 0.0)

        fb = self._fallback.evaluate(eid, fallback_rate, baseline_fallback_rate)
        if fb is not None:
            ev = select_evidence_refs_for_axes(
                evidence_universe,
                include_kinds=["fallback_path_fp", "handshake_fp"],
                max_refs=max_refs,
            )
            signals.append(
                WeaknessSignal(
                    entity_id=eid,
                    session_id=sid,
                    ts_ms=t,
                    weakness_id=fb.weakness_id,
                    weakness_kind="fallback",
                    severity_01=fb.severity,
                    confidence_01=fb.confidence,
                    evidence_refs=ev,
                    metrics={
                        "fallback_frequency": float(getattr(fb, "fallback_frequency", 0.0)),
                        "recent_spike": 1.0 if bool(getattr(fb, "recent_spike", False)) else 0.0,
                    },
                )
            )

        # ----------------------------
        # Transition (always emitted by contract)
        # ----------------------------
        prev_val = _safe_float(ps.get("transition_prev", 0.0), 0.0)
        curr_val = _safe_float(ps.get("transition_curr", ps.get("transition_score", 0.0)), 0.0)
        tw = self._transition.detect("transition_score", prev_val, curr_val, entity_id=eid)

        ev = select_evidence_refs_for_axes(
            evidence_universe,
            include_kinds=["transition_fp", "handshake_fp"],
            max_refs=max_refs,
        )
        transition_detected_f = 1.0 if bool(getattr(tw, "transition_detected", False)) else 0.0

        signals.append(
            WeaknessSignal(
                entity_id=eid,
                session_id=sid,
                ts_ms=t,
                weakness_id=tw.weakness_id,
                weakness_kind="transition",
                severity_01=tw.severity,
                confidence_01=tw.confidence,
                evidence_refs=ev,
                metrics={
                    "delta": float(getattr(tw, "delta", 0.0)),
                    "transition_score": float(getattr(tw, "transition_score", 0.0)),
                    "transition_detected": transition_detected_f,
                },
            )
        )

        # ----------------------------
        # Correlation (badness-only, ignore non-detected transition)
        # ----------------------------
        corr_thresholds = correlation_badness_thresholds()
        axis_badness: Dict[str, float] = {}

        for s in signals:
            # ignore transition unless detected
            if s.weakness_kind == "transition" and float(s.metrics.get("transition_detected", 0.0)) < 0.5:
                continue

            if s.weakness_kind in ("drift", "entropy", "fallback", "transition"):
                axis_badness[s.weakness_kind] = float(s.severity_01)

            if s.weakness_kind == "coherence":
                # ensure clamped badness input
                coh_drop = _clamp01(s.metrics.get("coherence_drop", s.severity_01))
                axis_badness["coherence_drop"] = float(coh_drop)

        corr = self._correlation.evaluate(eid, axis_badness, corr_thresholds)
        if corr is not None:
            ev = select_evidence_refs_for_axes(
                evidence_universe,
                include_kinds=[
                    "drift_fp",
                    "coherence_fp",
                    "entropy_histogram_fp",
                    "fallback_path_fp",
                    "transition_fp",
                    "handshake_fp",
                ],
                max_refs=max_refs,
            )
            signals.append(
                WeaknessSignal(
                    entity_id=eid,
                    session_id=sid,
                    ts_ms=t,
                    weakness_id=corr.weakness_id,
                    weakness_kind="correlation",
                    severity_01=corr.severity,
                    confidence_01=corr.confidence,
                    evidence_refs=ev,
                    metrics={
                        "correlation_strength": float(getattr(corr, "correlation_strength", 0.0)),
                        "persistent": 1.0 if bool(getattr(corr, "persistent", False)) else 0.0,
                        "weak_axes_count": float(len(getattr(corr, "weak_signals", []) or [])),
                    },
                )
            )

        # ----------------------------
        # Fusion (transition gating handled inside fusion.py)
        # ----------------------------
        fused = fuse_signals(
            entity_id=eid,
            session_id=sid,
            ts_ms=t,
            signals=signals,
            min_axes=self._cfg.thresholds.fusion_min_axes,
            axis_severity_min=self._cfg.thresholds.fusion_axis_severity_min,
            bundle_severity_min=self._cfg.thresholds.fusion_bundle_severity_min,
        )
        all_signals = list(signals) + list(fused)

        # Single structural augmentation phase (if available)
        if structural is not None:
            all_signals = self._augmenter.augment_signals(all_signals, structural)

        return WeaknessBundle(
            entity_id=eid,
            session_id=sid,
            ts_ms=t,
            signals=all_signals[: int(self._cfg.thresholds.max_signals_per_bundle)],
        )
