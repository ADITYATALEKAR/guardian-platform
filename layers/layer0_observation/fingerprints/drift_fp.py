"""
drift_fp.py

Layer 0 Fingerprint: Drift Fingerprint

Purpose:
- Create a deterministic, external-safe fingerprint summarizing drift behavior
  for an entity over a time window.
- No risk interpretation. No policy. No alerting.
- Output is stable across sessions and comparable over time.
"""

from __future__ import annotations

import json
import math
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

from .fingerprint_types import Fingerprint


DRIFT_FP_KIND = "drift_fp_v1"
DRIFT_FP_VERSION = 1


# ----------------------------
# Safety / Determinism helpers
# ----------------------------
def _now_ms() -> int:
    # NOTE: We keep created_ms in the Fingerprint, but NEVER in hash material.
    import time

    return int(time.time() * 1000)


def _is_finite_number(x: Any) -> bool:
    try:
        v = float(x)
    except Exception:
        return False
    return math.isfinite(v)


def _safe_float(x: Any, default: float = 0.0) -> float:
    if not _is_finite_number(x):
        return float(default)
    return float(x)


def _safe_str(x: Any, default: str = "") -> str:
    if x is None:
        return default
    try:
        s = str(x)
    except Exception:
        return default
    return s


def _clamp01(x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    return float(x)


def _quantize(x: float, decimals: int = 6) -> float:
    """
    Deterministic rounding to avoid float noise.
    6 decimals is safe + stable for fingerprint vectors.
    """
    try:
        return float(round(float(x), decimals))
    except Exception:
        return 0.0


def _stable_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _bounded_tanh(x: float) -> float:
    """
    Stable normalization into [-1, 1] while preserving sign.
    """
    return float(math.tanh(float(x)))


def _normalize_positive_unbounded(x: float) -> float:
    """
    Maps [0, +inf) -> [0, 1).
    Smooth and monotonic; avoids hard cliffs.
    """
    x = max(0.0, float(x))
    return float(1.0 - math.exp(-x))


# ----------------------------
# Input model (optional)
# ----------------------------
@dataclass(frozen=True, kw_only=True)
class DriftFingerprintInput:
    """
    Optional typed input to support clean integration.
    You may also pass a dict directly.
    """

    entity_id: str = ""

    drift_rate: Optional[float] = None
    drift_zscore: Optional[float] = None

    baseline_drift_mean: Optional[float] = None
    baseline_drift_std: Optional[float] = None

    # optional companion signals
    coherence_drop: Optional[float] = None
    window_size: Optional[int] = None


def build_drift_fingerprint(
    *,
    entity_id: str,
    physics_signals: Optional[Dict[str, Any]] = None,
    inp: Optional[Union[DriftFingerprintInput, Dict[str, Any]]] = None,
    created_ms: Optional[int] = None,
) -> Fingerprint:
    """
    Build a drift fingerprint from physics outputs.

    Accepts:
      - physics_signals dict (preferred)
      - inp: DriftFingerprintInput OR dict with compatible keys
    """

    raw: Dict[str, Any] = {}
    if physics_signals:
        raw.update(dict(physics_signals))

    if inp is not None:
        if isinstance(inp, DriftFingerprintInput):
            raw.update(
                {
                    "entity_id": inp.entity_id,
                    "drift_rate": inp.drift_rate,
                    "drift_zscore": inp.drift_zscore,
                    "baseline_drift_mean": inp.baseline_drift_mean,
                    "baseline_drift_std": inp.baseline_drift_std,
                    "coherence_drop": inp.coherence_drop,
                    "window_size": inp.window_size,
                }
            )
        elif isinstance(inp, dict):
            raw.update(dict(inp))

    entity_id = _safe_str(entity_id) or _safe_str(raw.get("entity_id"))

    # ----------------------------
    # Extract signals
    # ----------------------------
    drift_rate = _safe_float(raw.get("drift_rate", 0.0), 0.0)
    drift_zscore = _safe_float(raw.get("drift_zscore", 0.0), 0.0)

    baseline_mean = _safe_float(raw.get("baseline_drift_mean", 0.0), 0.0)
    baseline_std = _safe_float(raw.get("baseline_drift_std", 0.0), 0.0)

    coherence_drop = _safe_float(raw.get("coherence_drop", 0.0), 0.0)
    window_size = raw.get("window_size", None)

    # ----------------------------
    # Normalizations (stable)
    # ----------------------------
    # drift_rate can be unbounded: normalize into [0,1)
    drift_rate_norm = _normalize_positive_unbounded(drift_rate)

    # drift_zscore is signed-ish but typically positive: normalize bounded
    drift_zscore_norm = 0.5 * (_bounded_tanh(drift_zscore / 3.0) + 1.0)  # -> [0,1]

    # baseline std: positive unbounded
    baseline_std_norm = _normalize_positive_unbounded(max(0.0, baseline_std))

    # coherence_drop is already 0..1 (clamp)
    coherence_drop_norm = _clamp01(coherence_drop)

    # Fingerprint vector (quantized)
    vector: Tuple[float, ...] = (
        _quantize(drift_rate_norm, 6),
        _quantize(drift_zscore_norm, 6),
        _quantize(baseline_std_norm, 6),
        _quantize(coherence_drop_norm, 6),
    )

    # ----------------------------
    # Quality scoring = completeness, not risk
    # ----------------------------
    quality = 1.0

    # If we don't have any drift info, quality is low.
    if not _is_finite_number(raw.get("drift_rate", None)) and not _is_finite_number(
        raw.get("drift_zscore", None)
    ):
        quality = min(quality, 0.50)

    # Missing baseline makes normalization less meaningful
    if baseline_std <= 0.0:
        quality = min(quality, 0.75)

    # Optional window size helps confidence of the fingerprint
    if window_size is not None:
        try:
            ws = int(window_size)
            if ws < 3:
                quality = min(quality, 0.70)
        except Exception:
            quality = min(quality, 0.85)
    else:
        quality = min(quality, 0.90)

    quality = _clamp01(quality)

    # ----------------------------
    # Hash material (entity-bound identity)
    # ----------------------------
    hash_material = {
        "kind": DRIFT_FP_KIND,
        "version": DRIFT_FP_VERSION,
        "entity_id": entity_id,
        "vector": vector,
    }

    fp_hash = _sha256_hex(_stable_json(hash_material))

    # created_ms is observational metadata only
    created_ms = int(created_ms) if created_ms is not None else _now_ms()

    # Minimal explainability without affecting identity stability
    source_fields = {
        "drift_rate": _quantize(drift_rate, 6),
        "drift_zscore": _quantize(drift_zscore, 6),
        "baseline_drift_std": _quantize(baseline_std, 6),
        "coherence_drop": _quantize(coherence_drop, 6),
        "window_size": window_size,
    }

    return Fingerprint(
        fingerprint_id=f"{DRIFT_FP_KIND}_{fp_hash[:12]}",
        entity_id=entity_id,
        kind=DRIFT_FP_KIND,
        version=DRIFT_FP_VERSION,
        created_ms=created_ms,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )


def compute_drift_fingerprint(*args, **kwargs):
    """
    Canonical Layer-0 public function.

    Delegates to build_drift_fingerprint for compatibility.
    """
    impl = globals().get("build_drift_fingerprint")
    if callable(impl):
        return impl(*args, **kwargs)
    raise ImportError("drift_fp.py must define build_drift_fingerprint(...)")
