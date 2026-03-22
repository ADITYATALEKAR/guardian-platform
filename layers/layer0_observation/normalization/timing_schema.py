"""
timing_schema.py (Layer 0)

Canonical timing schema for Layer 0 observation signals.

Design goals:
- Immutable, validated contracts
- Safe defaults (production + unit tests)
- No filesystem writes
- Timestamp normalization support (ms/us/ns -> ms)
- Supports partial fields (collector variability) while preserving invariants

This is a schema module: it does NOT perform inference or detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional
import time


# ----------------------------
# Exceptions
# ----------------------------
class TimingSchemaError(ValueError):
    """Raised when timing schema invariants are violated."""


# ----------------------------
# Helpers
# ----------------------------
def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def _safe_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        x = float(v)
        if x != x:  # NaN check
            return None
        return x
    except Exception:
        return None


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


# ----------------------------
# Canonical Schema Objects
# ----------------------------
@dataclass(frozen=True, slots=True, kw_only=True)
class TimingObservation:
    """
    Canonical Layer 0 timing observation.

    This is the smallest stable unit that Layer 0 can emit upstream.

    Important:
    - Not all timing fields are mandatory (collectors may be partial).
    - Invariants must still hold:
        * durations >= 0
        * timestamps monotonic within the same record when present
        * units explicitly tracked
    """

    # identity / routing
    entity_id: str
    observation_id: str = ""
    source: str = "unknown"

    # timestamps (epoch)
    # NOTE: upstream prefers ms, but collectors may send raw.
    event_time_ms: int = field(default_factory=_now_ms)
    received_time_ms: int = field(default_factory=_now_ms)

    # durations (ms)
    # These are "measured durations" and should be non-negative.
    rtt_ms: Optional[float] = None
    handshake_ms: Optional[float] = None
    request_latency_ms: Optional[float] = None
    response_latency_ms: Optional[float] = None

    # payload size hints (optional, helps normalization)
    request_bytes: Optional[int] = None
    response_bytes: Optional[int] = None

    # metadata
    protocol: str = "unknown"
    transport: str = "unknown"
    source_ip: Optional[str] = None

    # freeform but immutable dictionary
    tags: Mapping[str, str] = field(default_factory=dict)
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.entity_id, str) or not self.entity_id.strip():
            raise TimingSchemaError("TimingObservation.entity_id must be a non-empty string")

        if self.event_time_ms <= 0 or self.received_time_ms <= 0:
            raise TimingSchemaError("TimingObservation timestamps must be positive epoch ms")

        # Allow minor skew; but received_time_ms should not be earlier than event_time_ms by large gaps
        # (We do NOT assume perfect clock sync. Just guard obvious corruption.)
        if self.received_time_ms + 60_000 < self.event_time_ms:
            raise TimingSchemaError(
                "TimingObservation.received_time_ms is implausibly earlier than event_time_ms"
            )

        # Duration invariants
        for name in ("rtt_ms", "handshake_ms", "request_latency_ms", "response_latency_ms"):
            val = getattr(self, name)
            if val is None:
                continue
            if not isinstance(val, (float, int)):
                raise TimingSchemaError(f"{name} must be float-compatible when present")
            if float(val) < 0.0:
                raise TimingSchemaError(f"{name} must be >= 0 when present")

        if self.request_bytes is not None and self.request_bytes < 0:
            raise TimingSchemaError("request_bytes must be >= 0 when present")
        if self.response_bytes is not None and self.response_bytes < 0:
            raise TimingSchemaError("response_bytes must be >= 0 when present")


@dataclass(frozen=True, slots=True, kw_only=True)
class TimingWindow:
    """
    A bounded collection window for observations.

    Layer 0 is primarily streaming, but windows are needed for:
    - calibration
    - baseline updates
    - stable normalization across a short horizon
    """

    entity_id: str
    window_start_ms: int
    window_end_ms: int
    observation_count: int

    def __post_init__(self) -> None:
        if not self.entity_id.strip():
            raise TimingSchemaError("TimingWindow.entity_id must be non-empty")
        if self.window_start_ms <= 0 or self.window_end_ms <= 0:
            raise TimingSchemaError("TimingWindow timestamps must be positive epoch ms")
        if self.window_end_ms < self.window_start_ms:
            raise TimingSchemaError("TimingWindow.window_end_ms must be >= window_start_ms")
        if self.observation_count < 0:
            raise TimingSchemaError("TimingWindow.observation_count must be >= 0")


@dataclass(frozen=True, slots=True, kw_only=True)
class NormalizedTiming:
    """
    Output of Layer 0 normalization.

    The philosophy:
    - Normalize to stable numeric ranges
    - Provide both raw_ms and normalized forms (when possible)
    - Avoid leaking units ambiguity upstream
    """

    entity_id: str
    event_time_ms: int

    # normalized features in [0, 1]
    rtt_norm: Optional[float] = None
    handshake_norm: Optional[float] = None
    req_latency_norm: Optional[float] = None
    resp_latency_norm: Optional[float] = None

    # scaled stability helpers
    # zscore-like terms are allowed but should be robust.
    rtt_z: Optional[float] = None
    handshake_z: Optional[float] = None

    # keep raw originals for traceability (ms)
    rtt_ms: Optional[float] = None
    handshake_ms: Optional[float] = None
    request_latency_ms: Optional[float] = None
    response_latency_ms: Optional[float] = None

    def __post_init__(self) -> None:
        if not self.entity_id.strip():
            raise TimingSchemaError("NormalizedTiming.entity_id must be non-empty")

        if self.event_time_ms <= 0:
            raise TimingSchemaError("NormalizedTiming.event_time_ms must be epoch ms")

        for name in ("rtt_norm", "handshake_norm", "req_latency_norm", "resp_latency_norm"):
            v = getattr(self, name)
            if v is None:
                continue
            if not (0.0 <= float(v) <= 1.0):
                raise TimingSchemaError(f"{name} must be in [0, 1] when present")


@dataclass(frozen=True, slots=True, kw_only=True)
class TimingBaseline:
    """
    Baseline statistics for a timing feature.

    Notes:
    - mean/std stored for z-score compatibility
    - robust_center/robust_scale for heavy tails
    """

    feature_name: str
    mean: float
    std: float

    robust_center: float
    robust_scale: float

    last_updated_ms: int = field(default_factory=_now_ms)

    def __post_init__(self) -> None:
        if not self.feature_name.strip():
            raise TimingSchemaError("TimingBaseline.feature_name must be non-empty")

        # std/scale must be positive (or extremely small epsilon)
        eps = 1e-9
        if self.std < eps:
            raise TimingSchemaError("TimingBaseline.std must be > 0")
        if self.robust_scale < eps:
            raise TimingSchemaError("TimingBaseline.robust_scale must be > 0")


@dataclass(frozen=True, slots=True, kw_only=True)
class TimingCalibrationResult:
    """
    Calibration bundle returned by the Calibrator.

    This is used by the Normalizer and validators.
    """

    entity_id: str
    baselines: Dict[str, TimingBaseline]
    window: TimingWindow

    # How aggressive the calibration is (for audit)
    method: str = "ewma_robust"
    alpha: float = 0.15

    def __post_init__(self) -> None:
        if not self.entity_id.strip():
            raise TimingSchemaError("TimingCalibrationResult.entity_id must be non-empty")
        if not self.baselines:
            raise TimingSchemaError("TimingCalibrationResult.baselines must not be empty")
        if not (0.0 < float(self.alpha) <= 1.0):
            raise TimingSchemaError("TimingCalibrationResult.alpha must be in (0,1]")


# ----------------------------
# Construction helpers (DTO -> Schema)
# ----------------------------
def timing_observation_from_dict(data: Mapping[str, Any]) -> TimingObservation:
    """
    Parse raw dict (collector output) into TimingObservation.

    This is defensive and tolerant:
    - Missing optional fields are allowed
    - Unknown fields are preserved in `raw`
    """
    entity_id = str(data.get("entity_id", "")).strip()
    if not entity_id:
        raise TimingSchemaError("Missing entity_id")

    event_time_ms = _safe_int(data.get("event_time_ms")) or _safe_int(data.get("event_time")) or _now_ms()
    received_time_ms = _safe_int(data.get("received_time_ms")) or _now_ms()

    return TimingObservation(
        entity_id=entity_id,
        observation_id=str(data.get("observation_id", "") or ""),
        source=str(data.get("source", "unknown") or "unknown"),
        event_time_ms=event_time_ms,
        received_time_ms=received_time_ms,
        rtt_ms=_safe_float(data.get("rtt_ms")),
        handshake_ms=_safe_float(data.get("handshake_ms")),
        request_latency_ms=_safe_float(data.get("request_latency_ms")),
        response_latency_ms=_safe_float(data.get("response_latency_ms")),
        request_bytes=_safe_int(data.get("request_bytes")),
        response_bytes=_safe_int(data.get("response_bytes")),
        protocol=str(data.get("protocol", "unknown") or "unknown"),
        transport=str(data.get("transport", "unknown") or "unknown"),
        source_ip=str(data.get("source_ip")) if data.get("source_ip") is not None else None,
        tags=dict(data.get("tags", {}) or {}),
        raw=dict(data),
    )
