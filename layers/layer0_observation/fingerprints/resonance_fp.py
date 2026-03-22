"""
resonance_fp.py

Layer 0 Fingerprint: resonance_fp_v1

Consumes resonance physics outputs and emits a stable fingerprint.
No semantics. No policy.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .fingerprint_types import Fingerprint


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v:
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


def build_resonance_fingerprint(
    *,
    entity_id: str,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    """
    Build resonance_fp_v1 from physics signals.
    Expected keys:
      - resonance_score
      - active_signals
    """
    ps = dict(physics_signals or {})
    score = _clamp01(_safe_float(ps.get("resonance_score", 0.0), 0.0))
    active = int(_safe_float(ps.get("active_signals", 0.0), 0.0))

    payload = {
        "entity_id": str(entity_id or "").strip(),
        "kind": "resonance_fp_v1",
        "score_bucket": round(score, 3),
        "active_bucket": min(active, 16),
    }
    fp_hash = Fingerprint.stable_hash_from_payload(payload)

    vector = Fingerprint.make_vector(
        [score, float(min(active, 16)), float(window_ms or 0)],
        quantize_decimals=3,
    )

    quality = Fingerprint.safe_quality(0.9 if score > 0 else 0.5)

    return Fingerprint(
        entity_id=payload["entity_id"],
        kind="resonance_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields={
            "resonance_score": float(score),
            "active_signals": int(active),
            "window_ms": int(window_ms) if window_ms is not None else None,
        },
    )


def compute_resonance_fingerprint(*args, **kwargs):
    """
    Canonical Layer-0 public function.
    Delegates to build_resonance_fingerprint for compatibility.
    """
    impl = globals().get("build_resonance_fingerprint")
    if callable(impl):
        return impl(*args, **kwargs)
    raise ImportError("resonance_fp.py must define build_resonance_fingerprint(...)")
