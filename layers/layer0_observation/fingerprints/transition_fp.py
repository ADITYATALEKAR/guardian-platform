"""
transition_fp.py

Transition fingerprint generator for Layer 0.

This produces an observational signature of "change dynamics":
- jumpiness vs stability
- sudden large deltas vs gradual drift
- frequency of transitions across thresholds

This fingerprint supports:
- Layer 2 TransitionWeakness
- Layer 3 narratives / audits
- long-term endpoint identity + behavior persistence

NOT risk, NOT policy, NOT attacker claims.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint


def _is_finite(x: float) -> bool:
    return isinstance(x, (int, float)) and (x == x) and math.isfinite(x)


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        fx = float(x)
        if not _is_finite(fx):
            return default
        return fx
    except Exception:
        return default


def _clamp(x: float, lo: float, hi: float) -> float:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _quantize(x: float, step: float, max_v: float) -> float:
    if step <= 0.0:
        return 0.0
    x = max(0.0, min(float(x), float(max_v)))
    return float(round(x / step) * step)


def _compute_transition_metrics(values: Sequence[float]) -> Dict[str, float]:
    """
    Computes transition metrics on a numeric signal sequence.
    Values should already be normalized (Layer 0 normalization/physics).

    Returns:
      - count
      - mean_abs_delta
      - max_abs_delta
      - transition_rate (fraction of steps crossing a delta threshold)
      - jumpiness_score (0..1)
    """
    clean = [float(v) for v in values if _is_finite(v)]
    n = len(clean)
    if n < 2:
        return {
            "count": float(n),
            "mean_abs_delta": 0.0,
            "max_abs_delta": 0.0,
            "transition_rate": 0.0,
            "jumpiness_score": 0.0,
        }

    deltas = [abs(clean[i] - clean[i - 1]) for i in range(1, n)]
    mean_abs_delta = sum(deltas) / len(deltas)
    max_abs_delta = max(deltas) if deltas else 0.0

    # jumpiness score: normalized max delta + normalized mean delta
    # stable heuristic, NOT cliff logic
    jumpiness_score = _clamp((0.65 * (max_abs_delta / 1.0) + 0.35 * (mean_abs_delta / 0.5)), 0.0, 1.0)

    # transition rate threshold (soft) based on mean delta
    # We use a small fixed threshold to avoid data-dependent oscillations
    transition_threshold = 0.25
    transitions = sum(1 for d in deltas if d >= transition_threshold)
    transition_rate = transitions / float(len(deltas))

    return {
        "count": float(n),
        "mean_abs_delta": float(mean_abs_delta),
        "max_abs_delta": float(max_abs_delta),
        "transition_rate": float(transition_rate),
        "jumpiness_score": float(jumpiness_score),
    }


def _quality_from_count(n: int, min_samples: int, max_samples: int) -> float:
    if n <= 0:
        return 0.0
    if n < min_samples:
        return Fingerprint.safe_quality(n / float(min_samples))
    if n >= max_samples:
        return 1.0
    span = max(1, max_samples - min_samples)
    return Fingerprint.safe_quality(0.7 + 0.3 * ((n - min_samples) / float(span)))


def build_transition_fingerprint(
    *,
    entity_id: str,
    signal_name: str,
    signal_values: Optional[Sequence[float]] = None,
    window_ms: Optional[int] = None,
    kind: str = "transition_fp_v1",
    version: int = 1,
    min_samples: int = 10,
    max_samples: int = 200,
) -> Fingerprint:
    """
    Build a transition fingerprint over a sequence of normalized signal values.

    Typical signal_name inputs:
      - "drift_rate"
      - "entropy_decay"
      - "coherence_score"
      - "fallback_rate"

    The fingerprint identity is derived from quantized transition metrics,
    NOT from timestamps or entity metadata.
    """
    signal_values = signal_values or []
    values = [_safe_float(v, 0.0) for v in signal_values]

    metrics = _compute_transition_metrics(values)
    n = int(metrics["count"])

    window_ms = int(window_ms) if isinstance(window_ms, int) and window_ms > 0 else 0

    # Quantize metrics for stability
    mean_d_q = _quantize(metrics["mean_abs_delta"], step=0.05, max_v=5.0)
    max_d_q = _quantize(metrics["max_abs_delta"], step=0.05, max_v=5.0)
    rate_q = _quantize(metrics["transition_rate"], step=0.05, max_v=1.0)
    jump_q = _quantize(metrics["jumpiness_score"], step=0.05, max_v=1.0)

    quality = _quality_from_count(n, min_samples=min_samples, max_samples=max_samples)

    payload = {
        "kind": kind,
        "version": version,
        "signal_name": str(signal_name or ""),
        "mean_abs_delta": mean_d_q,
        "max_abs_delta": max_d_q,
        "transition_rate": rate_q,
        "jumpiness_score": jump_q,
        "sample_count": int(n),
        "window_ms": int(window_ms),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(payload)

    vec = Fingerprint.make_vector(
        [
            mean_d_q,
            max_d_q,
            rate_q,
            jump_q,
            float(int(n)),
            float(window_ms),
        ],
        quantize_decimals=3,
    )

    return Fingerprint(
        entity_id=str(entity_id or ""),
        kind=kind,
        version=version,
        hash=fp_hash,
        vector=vec,
        quality=Fingerprint.safe_quality(quality),
        source_fields={
            "signal_name": str(signal_name or ""),
            "sample_count": n,
            "window_ms": window_ms,
            "quantization": {
                "delta_step": 0.05,
                "rate_step": 0.05,
                "jumpiness_step": 0.05,
            },
            "metrics": {
                "mean_abs_delta": metrics["mean_abs_delta"],
                "max_abs_delta": metrics["max_abs_delta"],
                "transition_rate": metrics["transition_rate"],
                "jumpiness_score": metrics["jumpiness_score"],
            },
        },
    )


def compute_transition_fingerprint(*args, **kwargs):
    """
    Canonical Layer-0 public function.

    Delegates to build_transition_fingerprint for compatibility.
    """
    impl = globals().get("build_transition_fingerprint")
    if callable(impl):
        return impl(*args, **kwargs)
    raise ImportError("transition_fp.py must define build_transition_fingerprint(...)")
