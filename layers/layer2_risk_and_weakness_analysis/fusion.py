"""
fusion.py

Layer 2 — cross-axis fusion (non-narrative).

Fix:
- Transition is always emitted by contract, but fusion must only treat it
  as an active axis if transition_detected=1.0 (or >=0.5).

This prevents "always-present transition artifact" from polluting fusion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from core_utils.safety import clamp01, safe_float
from .weakness_contracts import WeaknessSignal
from .base_weakness import BaseWeakness


def _safe_float(x: object, default: float = 0.0) -> float:
    value = safe_float(x, default)
    return float(default if value is None else value)


def _clamp01(x: object) -> float:
    return clamp01(x)


def _round_stable(x: object, ndigits: int = 6) -> float:
    return float(round(_safe_float(x, 0.0), ndigits))


@dataclass(frozen=True)
class FusionRule:
    name: str
    axes: Tuple[str, ...]


DEFAULT_FUSION_RULES: Tuple[FusionRule, ...] = (
    FusionRule(name="instability_cluster", axes=("drift", "coherence", "entropy")),
    FusionRule(name="negotiation_disruption_cluster", axes=("fallback", "transition", "coherence")),
    FusionRule(name="cross_axis_degradation_cluster", axes=("correlation", "drift", "entropy")),
)


def _is_transition_active(s: WeaknessSignal) -> bool:
    """
    Transition is always emitted as a fact artifact.
    Only treat it as active axis when detected.
    """
    if s.weakness_kind != "transition":
        return True
    return float(s.metrics.get("transition_detected", 0.0)) >= 0.5


def fuse_signals(
    *,
    entity_id: str,
    session_id: str,
    ts_ms: int,
    signals: Sequence[WeaknessSignal],
    min_axes: int = 2,
    axis_severity_min: float = 0.45,
    bundle_severity_min: float = 0.55,
) -> List[WeaknessSignal]:
    if not signals:
        return []

    # best per kind, but only for active transition
    best_by_kind: Dict[str, WeaknessSignal] = {}
    for s in signals:
        k = str(s.weakness_kind or "").strip()
        if not k:
            continue

        # transition gating for fusion participation
        if k == "transition" and not _is_transition_active(s):
            continue

        prev = best_by_kind.get(k)
        if prev is None or s.severity_01 > prev.severity_01:
            best_by_kind[k] = s

    fused: List[WeaknessSignal] = []

    for rule in DEFAULT_FUSION_RULES:
        present: List[WeaknessSignal] = []
        for ax in rule.axes:
            if ax in best_by_kind:
                present.append(best_by_kind[ax])

        strong = [s for s in present if s.severity_01 >= axis_severity_min]
        if len(strong) < max(1, int(min_axes)):
            continue

        sev_vals = [s.severity_01 for s in strong]
        mean_sev = sum(sev_vals) / max(1, len(sev_vals))
        max_sev = max(sev_vals) if sev_vals else 0.0
        fused_sev = _clamp01(0.55 * max_sev + 0.45 * mean_sev)

        if fused_sev < bundle_severity_min:
            continue

        conf_vals = [s.confidence_01 for s in strong]
        base_conf = min(conf_vals) if conf_vals else 0.0
        fused_conf = _clamp01(base_conf * 0.75 + fused_sev * 0.25)

        # bounded unique evidence refs (by anchor)
        ev: List = []
        for s in strong:
            ev.extend(list(s.evidence_refs or []))

        seen = set()
        unique_ev = []
        for r in ev:
            key = (r.anchor.kind, r.anchor.hash)
            if key in seen:
                continue
            seen.add(key)
            unique_ev.append(r)
            if len(unique_ev) >= 8:
                break

        fused.append(
            WeaknessSignal(
                entity_id=entity_id,
                session_id=session_id,
                ts_ms=int(ts_ms),
                weakness_id=BaseWeakness.stable_kind_id(f"fusion_{rule.name}", 1),
                weakness_kind="fusion",
                severity_01=_round_stable(fused_sev),
                confidence_01=_round_stable(fused_conf),
                evidence_refs=unique_ev,
                metrics={
                    "axes_present_count": float(len(present)),
                    "axes_strong_count": float(len(strong)),
                    "mean_axis_severity": float(mean_sev),
                    "max_axis_severity": float(max_sev),
                },
            )
        )

    fused.sort(key=lambda s: (-s.severity_01, -s.confidence_01, s.weakness_id))
    return fused[:8]
