"""
jitter_fp.py

Micro-jitter fingerprint generator for Layer 0.

Purpose:
- produce a stable identity-like signature from timing jitter behavior
- help detect "same endpoint, different stack" or "different endpoint, similar stack"
- enable similarity comparisons across time windows

This fingerprint is NOT a risk output.
It is an observational signature.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

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


def _robust_stats(values: Sequence[float]) -> Dict[str, float]:
    """
    Robust summary stats for jitter values (ms).
    We avoid heavy math to keep it stable and safe.

    Returns:
      mean, std, p50, p90, iqr, count
    """
    clean = [float(v) for v in values if _is_finite(v)]
    n = len(clean)
    if n == 0:
        return {"mean": 0.0, "std": 0.0, "p50": 0.0, "p90": 0.0, "iqr": 0.0, "count": 0.0}

    clean.sort()

    def percentile(p: float) -> float:
        if n == 1:
            return clean[0]
        idx = p * (n - 1)
        lo = int(math.floor(idx))
        hi = int(math.ceil(idx))
        if lo == hi:
            return clean[lo]
        frac = idx - lo
        return clean[lo] * (1.0 - frac) + clean[hi] * frac

    mean = sum(clean) / n
    var = sum((x - mean) ** 2 for x in clean) / max(1, n - 1)
    std = math.sqrt(max(0.0, var))

    p25 = percentile(0.25)
    p50 = percentile(0.50)
    p75 = percentile(0.75)
    p90 = percentile(0.90)
    iqr = max(0.0, p75 - p25)

    return {
        "mean": float(mean),
        "std": float(std),
        "p50": float(p50),
        "p90": float(p90),
        "iqr": float(iqr),
        "count": float(n),
    }


def _compute_quality(n: int, *, min_samples: int, max_samples: int) -> float:
    """
    Quality is about sample sufficiency and stability.
    Not about threat/risk.
    """
    if n <= 0:
        return 0.0

    # ramp up quality after min_samples, saturate near max_samples
    if n < min_samples:
        return Fingerprint.safe_quality(n / float(min_samples))

    if n >= max_samples:
        return 1.0

    # Between min and max: smooth progression
    span = max(1, max_samples - min_samples)
    return Fingerprint.safe_quality(0.7 + 0.3 * ((n - min_samples) / float(span)))


def _quantize_bucket(x: float, *, step: float, max_bucket: float) -> float:
    """
    Quantize continuous values into stable buckets.
    This reduces fingerprint instability from tiny jitter changes.
    """
    if step <= 0:
        return 0.0
    x = max(0.0, min(float(x), float(max_bucket)))
    bucket = round(x / step) * step
    return float(bucket)


def build_jitter_fingerprint(
    *,
    entity_id: str,
    jitter_samples_ms: Optional[Sequence[float]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
    kind: str = "jitter_fp_v1",
    version: int = 1,
    min_samples: int = 20,
    max_samples: int = 200,
) -> Fingerprint:
    """
    Build a micro-jitter fingerprint.

    Inputs can be:
      - raw jitter samples (ms)
      - optional already-computed physics signals:
          jitter_score, jitter_std, etc.

    We intentionally make this tolerant:
      - missing samples -> vector still generated using available fields
      - quality reflects completeness

    Returns Fingerprint with:
      - stable hash from quantized stats + window metadata
      - comparable vector
    """
    jitter_samples_ms = jitter_samples_ms or []
    physics_signals = physics_signals or {}

    # Extract robust statistics from raw samples if present
    stats = _robust_stats([_safe_float(v, 0.0) for v in jitter_samples_ms])
    n = int(stats["count"])

    # Prefer physics-provided jitter_score if available, else estimate from std/mean
    jitter_score = _safe_float(physics_signals.get("jitter_score"), default=-1.0)
    if jitter_score < 0.0:
        # heuristic: more std relative to mean implies more jitter energy
        mean = stats["mean"]
        std = stats["std"]
        denom = max(1e-6, mean)
        ratio = std / denom
        jitter_score = _clamp(ratio, 0.0, 3.0) / 3.0  # normalize into 0..1

    # Normalize and quantize for stability
    mean_q = _quantize_bucket(stats["mean"], step=0.5, max_bucket=500.0)   # 0.5ms buckets
    std_q = _quantize_bucket(stats["std"], step=0.5, max_bucket=500.0)
    p50_q = _quantize_bucket(stats["p50"], step=0.5, max_bucket=500.0)
    p90_q = _quantize_bucket(stats["p90"], step=1.0, max_bucket=500.0)    # coarser for tail
    iqr_q = _quantize_bucket(stats["iqr"], step=0.5, max_bucket=500.0)

    # window contributes to comparability (optional)
    window_ms = int(window_ms) if isinstance(window_ms, int) and window_ms > 0 else 0

    # Quality: mainly sample sufficiency
    quality = _compute_quality(n, min_samples=min_samples, max_samples=max_samples)

    # Stable payload (no timestamps, no collector ids)
    payload = {
        "kind": kind,
        "version": version,
        "mean_ms": mean_q,
        "std_ms": std_q,
        "p50_ms": p50_q,
        "p90_ms": p90_q,
        "iqr_ms": iqr_q,
        "jitter_score": round(float(_clamp(jitter_score, 0.0, 1.0)), 3),
        "sample_count": int(n),
        "window_ms": int(window_ms),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(payload)

    # Comparable vector (low dimensional, quantized)
    vec = Fingerprint.make_vector(
        [
            mean_q,
            std_q,
            p50_q,
            p90_q,
            iqr_q,
            float(int(n)),
            float(window_ms),
            float(_clamp(jitter_score, 0.0, 1.0)),
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
            "sample_count": n,
            "window_ms": window_ms,
            "quantization": {
                "mean_step_ms": 0.5,
                "std_step_ms": 0.5,
                "p50_step_ms": 0.5,
                "p90_step_ms": 1.0,
                "iqr_step_ms": 0.5,
            },
            "stats": {
                "mean_ms": stats["mean"],
                "std_ms": stats["std"],
                "p50_ms": stats["p50"],
                "p90_ms": stats["p90"],
                "iqr_ms": stats["iqr"],
            },
        },
    )


def compute_jitter_fingerprint(*args, **kwargs):
    """
    Canonical Layer-0 public function.

    Delegates to build_jitter_fingerprint for compatibility.
    """
    impl = globals().get("build_jitter_fingerprint")
    if callable(impl):
        return impl(*args, **kwargs)
    raise ImportError("jitter_fp.py must define build_jitter_fingerprint(...)")
