"""
coupling_fp.py

Layer 0 Fingerprint: coupling physics summary (coupling_fp_v1)

Meaning
-------
Second-order timing structure:
- how two derived signals "move together"
- how consistent direction is over time
- whether coupling is lagged
- whether shock alignment exists

Rules
-----
- MUST NOT recompute coupling physics.
- MUST be deterministic.
- Hash payload must be bucketized to avoid float churn.
- Vector is bounded & quantized.

Expected physics producer
-------------------------
layers.layer0_observation.physics.coupling.compute_coupling_signals()

Preferred physics_signals keys:
- coupling_strength               (0..1)
- coupling_direction_agreement    (0..1)
- coupling_best_lag               (0..1)  # normalized lag position
- coupling_lag_strength           (0..1)
- coupling_shock_alignment        (0..1)
- sample_count_norm               (0..1)

This FP is bank-grade safe: no raw sequences, no PII.
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


def _get(ps: Dict[str, Any], key: str, default: float) -> float:
    return _safe_float(ps.get(key, default), default)


# ----------------------------
# Main API
# ----------------------------
def compute_coupling_fingerprint(
    *,
    entity_id: str,
    physics_signals: Dict[str, float],
) -> Fingerprint:
    """
    Produce coupling_fp_v1 from physics outputs only.
    """
    eid = _require_entity_id(entity_id)
    ps = dict(physics_signals or {})

    # canonical extractions (with safe defaults)
    coupling_strength = _clamp01(_get(ps, "coupling_strength", 0.0))
    coupling_direction_agreement = _clamp01(_get(ps, "coupling_direction_agreement", 0.0))
    coupling_best_lag = _clamp01(_get(ps, "coupling_best_lag", 0.5))
    coupling_lag_strength = _clamp01(_get(ps, "coupling_lag_strength", 0.0))
    coupling_shock_alignment = _clamp01(_get(ps, "coupling_shock_alignment", 0.0))
    sample_count_norm = _clamp01(_get(ps, "sample_count_norm", 0.0))

    # Stable identity buckets
    strength_b = _bucketize01(coupling_strength, [0.08, 0.20, 0.40, 0.65, 0.85])
    direction_b = _bucketize01(coupling_direction_agreement, [0.15, 0.30, 0.50, 0.70, 0.85])
    lagpos_b = _bucketize01(coupling_best_lag, [0.18, 0.35, 0.50, 0.65, 0.82])
    lagstr_b = _bucketize01(coupling_lag_strength, [0.08, 0.20, 0.40, 0.65, 0.85])
    shock_b = _bucketize01(coupling_shock_alignment, [0.15, 0.35, 0.60, 0.82])
    sample_b = _bucketize01(sample_count_norm, [0.20, 0.40, 0.60, 0.80])

    # Derived qualitative mode buckets (stable)
    # These help stealth attribution without magnitudes.
    # mode_high_direction: consistent direction agreement
    # mode_shocky: coupling occurs in burst shocks
    mode_high_direction = 1 if coupling_direction_agreement >= 0.75 else 0
    mode_shocky = 1 if coupling_shock_alignment >= 0.75 and coupling_strength >= 0.40 else 0

    hash_payload = {
        "entity_id": eid,
        "strength_b": int(strength_b),
        "direction_b": int(direction_b),
        "lagpos_b": int(lagpos_b),
        "lagstr_b": int(lagstr_b),
        "shock_b": int(shock_b),
        "sample_b": int(sample_b),
        "mode_high_direction": int(mode_high_direction),
        "mode_shocky": int(mode_shocky),
    }
    identity_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # Vector (continuous + bounded) for similarity clustering
    vector = Fingerprint.make_vector(
        [
            coupling_strength,
            coupling_direction_agreement,
            coupling_best_lag,
            coupling_lag_strength,
            coupling_shock_alignment,
            sample_count_norm,
            float(mode_high_direction),
            float(mode_shocky),
        ],
        quantize_decimals=4,
    )

    # Quality modeling:
    # - sample_count_norm is the core reliability scalar
    # - very weak coupling signals should not appear "high confidence"
    base = 0.92
    sample_factor = 0.35 + 0.65 * sample_count_norm
    strength_factor = 0.50 + 0.50 * coupling_strength
    quality = Fingerprint.safe_quality(base * sample_factor * strength_factor)

    source_fields = {
        "coupling_strength": float(coupling_strength),
        "coupling_direction_agreement": float(coupling_direction_agreement),
        "coupling_best_lag": float(coupling_best_lag),
        "coupling_lag_strength": float(coupling_lag_strength),
        "coupling_shock_alignment": float(coupling_shock_alignment),
        "sample_count_norm": float(sample_count_norm),
        "modes": {
            "mode_high_direction": int(mode_high_direction),
            "mode_shocky": int(mode_shocky),
        },
        "buckets": {
            "strength_b": int(strength_b),
            "direction_b": int(direction_b),
            "lagpos_b": int(lagpos_b),
            "lagstr_b": int(lagstr_b),
            "shock_b": int(shock_b),
            "sample_b": int(sample_b),
        },
    }

    return Fingerprint(
        entity_id=eid,
        kind="coupling_fp_v1",
        version=1,
        hash=identity_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
