"""
meta_fp.py

Layer 0 Fingerprint: meta-physics summary (meta_fp_v1)

Meaning
-------
Third-order structure:
- persistence (trend memory)
- divergence (branching / instability)
- jerk (third derivative; sudden changes)
- stability (overall controlled behavior)
- sample_count_norm (reliability)
- window_bucket (temporal context)

Rules
-----
- MUST NOT recompute meta physics.
- Hash is bucketized (stable identity).
- Vector is bounded and quantized.
- Safe for bank-grade environments (no raw data).

Expected physics producer
-------------------------
layers.layer0_observation.physics.meta.compute_meta_physics()
"""

from __future__ import annotations

from typing import Any, Dict, Sequence

from .fingerprint_types import Fingerprint


# ----------------------------
# Helpers
# ----------------------------
def _require_entity_id(entity_id: Any) -> str:
    eid = str(entity_id or "").strip()
    if not eid:
        raise ValueError("entity_id must be non-empty")
    return eid


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        f = float(x)
        if f != f or f in (float("inf"), float("-inf")):
            return default
        return f
    except Exception:
        return default


def _clamp01(x: Any) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def _bucketize01(x01: float, edges: Sequence[float]) -> int:
    x = _clamp01(x01)
    for i, e in enumerate(edges):
        if x <= e:
            return i
    return len(edges)


def _clamp_window_bucket(x: Any) -> int:
    """
    window_bucket is intended to be a small stable int.
    Enforce: 0..6
    """
    try:
        v = int(float(x))
    except Exception:
        return 0
    if v < 0:
        return 0
    if v > 6:
        return 6
    return v


# ----------------------------
# Main API
# ----------------------------
def compute_meta_fingerprint(
    *,
    entity_id: str,
    physics_signals: Dict[str, float],
) -> Fingerprint:
    """
    Produce meta_fp_v1 from physics outputs only.

    Expected keys:
      - persistence_index      (0..1)
      - divergence_index       (0..1)
      - jerk_index             (0..1)
      - stability_index        (0..1)
      - sample_count_norm      (0..1)
      - window_bucket          (int bucket)
    """
    eid = _require_entity_id(entity_id)
    ps = dict(physics_signals or {})

    persistence_index = _clamp01(ps.get("persistence_index", 0.0))
    divergence_index = _clamp01(ps.get("divergence_index", 0.0))
    jerk_index = _clamp01(ps.get("jerk_index", 0.0))
    stability_index = _clamp01(ps.get("stability_index", 0.0))
    sample_count_norm = _clamp01(ps.get("sample_count_norm", 0.0))
    window_bucket = _clamp_window_bucket(ps.get("window_bucket", 0))

    # Identity buckets (stable)
    edges = [0.12, 0.25, 0.40, 0.55, 0.70, 0.85]
    pers_b = _bucketize01(persistence_index, edges)
    div_b = _bucketize01(divergence_index, edges)
    jerk_b = _bucketize01(jerk_index, edges)
    stab_b = _bucketize01(stability_index, edges)
    sample_b = _bucketize01(sample_count_norm, [0.20, 0.40, 0.60, 0.80])

    # Derived meta modes (stable, helps stealth attribution)
    # - "quiet_persistent": high persistence + high stability + low jerk
    # - "stealthy_divergent": high divergence but without large jerk (under-bounds drift)
    quiet_persistent = 1 if (persistence_index >= 0.70 and stability_index >= 0.70 and jerk_index <= 0.35) else 0
    stealthy_divergent = 1 if (divergence_index >= 0.65 and jerk_index <= 0.45 and stability_index <= 0.65) else 0

    hash_payload = {
        "entity_id": eid,
        "pers_b": int(pers_b),
        "div_b": int(div_b),
        "jerk_b": int(jerk_b),
        "stab_b": int(stab_b),
        "sample_b": int(sample_b),
        "window_b": int(window_bucket),
        "quiet_persistent": int(quiet_persistent),
        "stealthy_divergent": int(stealthy_divergent),
    }
    identity_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # Vector
    vector = Fingerprint.make_vector(
        [
            persistence_index,
            divergence_index,
            jerk_index,
            stability_index,
            sample_count_norm,
            float(window_bucket) / 6.0,
            float(quiet_persistent),
            float(stealthy_divergent),
        ],
        quantize_decimals=4,
    )

    # Quality:
    # stable meta values require samples, but also stability itself matters.
    base = 0.92
    sample_factor = 0.35 + 0.65 * sample_count_norm
    stability_factor = 0.50 + 0.50 * stability_index
    quality = Fingerprint.safe_quality(base * sample_factor * stability_factor)

    source_fields = {
        "persistence_index": float(persistence_index),
        "divergence_index": float(divergence_index),
        "jerk_index": float(jerk_index),
        "stability_index": float(stability_index),
        "sample_count_norm": float(sample_count_norm),
        "window_bucket": float(window_bucket),
        "modes": {
            "quiet_persistent": int(quiet_persistent),
            "stealthy_divergent": int(stealthy_divergent),
        },
        "buckets": {
            "pers_b": int(pers_b),
            "div_b": int(div_b),
            "jerk_b": int(jerk_b),
            "stab_b": int(stab_b),
            "sample_b": int(sample_b),
        },
    }

    return Fingerprint(
        entity_id=eid,
        kind="meta_fp_v1",
        version=1,
        hash=identity_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
