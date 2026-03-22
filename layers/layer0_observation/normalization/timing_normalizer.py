"""
timing_normalizer.py (Layer 0)

Normalizes raw TimingObservation into stable, bounded features for Layer 1+ usage.

Goals:
- Deterministic normalization (no randomness)
- Works even with partial baselines
- Prevents extreme values from exploding downstream physics
- Produces NormalizedTiming contract

Normalization philosophy:
- Use robust stats when possible (center/scale)
- Clamp to [0,1] for normalized fields
- Provide z-like outputs for diagnostics
"""

from __future__ import annotations

from dataclasses import replace
from typing import Dict, Optional

from layers.layer0_observation.schemas.timing_schema import (
    NormalizedTiming,
    TimingBaseline,
    TimingCalibrationResult,
    TimingObservation,
)


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _robust_z(x: float, center: float, scale: float) -> float:
    # safe z, scale never zero due to schema constraints
    return (x - center) / scale


def _sigmoid01(z: float) -> float:
    """
    Stable map of z-score -> [0,1].

    z ~ 0 => 0.5
    z positive => closer to 1
    z negative => closer to 0

    We clamp z to avoid extreme exp behavior.
    """
    zc = _clamp(z, -12.0, 12.0)
    # logistic
    import math

    return 1.0 / (1.0 + math.exp(-zc))


class TimingNormalizer:
    """
    Normalizes TimingObservation using calibration baselines.

    This class is stateless and safe for multi-tenant use.
    """

    SUPPORTED_FEATURES = (
        "rtt_ms",
        "handshake_ms",
        "request_latency_ms",
        "response_latency_ms",
    )

    def normalize(
        self,
        obs: TimingObservation,
        calibration: Optional[TimingCalibrationResult] = None,
    ) -> NormalizedTiming:
        """
        Normalize a TimingObservation.

        If calibration is missing, returns NormalizedTiming with raw fields only.

        Returns:
            NormalizedTiming (immutable)
        """
        baselines: Dict[str, TimingBaseline] = {}
        if calibration is not None:
            baselines = calibration.baselines or {}

        # Raw values
        rtt = obs.rtt_ms
        hs = obs.handshake_ms
        req = obs.request_latency_ms
        resp = obs.response_latency_ms

        # If no baselines exist, output raw-only
        if not baselines:
            return NormalizedTiming(
                entity_id=obs.entity_id,
                event_time_ms=obs.event_time_ms,
                rtt_ms=rtt,
                handshake_ms=hs,
                request_latency_ms=req,
                response_latency_ms=resp,
            )

        # Compute normalized values if baselines exist for those features
        def _norm(feature_name: str, raw_value: Optional[float]) -> tuple[Optional[float], Optional[float]]:
            if raw_value is None:
                return None, None
            b = baselines.get(feature_name)
            if b is None:
                return None, None
            z = _robust_z(float(raw_value), center=b.robust_center, scale=b.robust_scale)
            score = _sigmoid01(z)
            return float(_clamp(score, 0.0, 1.0)), float(z)

        rtt_norm, rtt_z = _norm("rtt_ms", rtt)
        hs_norm, hs_z = _norm("handshake_ms", hs)
        req_norm, _ = _norm("request_latency_ms", req)
        resp_norm, _ = _norm("response_latency_ms", resp)

        return NormalizedTiming(
            entity_id=obs.entity_id,
            event_time_ms=obs.event_time_ms,
            rtt_norm=rtt_norm,
            handshake_norm=hs_norm,
            req_latency_norm=req_norm,
            resp_latency_norm=resp_norm,
            rtt_z=rtt_z,
            handshake_z=hs_z,
            rtt_ms=rtt,
            handshake_ms=hs,
            request_latency_ms=req,
            response_latency_ms=resp,
        )
