"""
timing_validation.py (Layer 0)

Validation + invariants enforcement for timing observations.

This layer exists to prevent garbage signals from contaminating
physics primitives (drift/jitter/coherence/etc).

Validation Philosophy:
- Reject structurally invalid records
- Clamp/repair only when safe and explicit
- Do NOT infer intent
- Do NOT mutate objects: return validated copies or raise

Layer 0 validation should be deterministic and side-effect free.


Importance:  Sanity firewall

What it does

Rejects malformed or dangerous input

Enforces bounds

What’s special

Validation is separate from normalization

This separation is rare and correct

Metaphor

Lab contamination prevention.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Optional

from layers.layer0_observation.schemas.timing_schema import (
    TimingObservation,
    TimingSchemaError,
)


class TimingValidationError(TimingSchemaError):
    """Raised when timing validation fails."""


def validate_timing_observation(obs: TimingObservation) -> TimingObservation:
    """
    Strict validation for a single observation.

    Returns:
        The same observation (or a safe corrected copy).

    Raises:
        TimingValidationError if record is unsafe or inconsistent.
    """

    # entity_id already validated in schema, but keep guard
    if not obs.entity_id.strip():
        raise TimingValidationError("entity_id missing")

    # Basic timestamp sanity
    if obs.event_time_ms <= 0 or obs.received_time_ms <= 0:
        raise TimingValidationError("timestamps must be positive epoch ms")

    # Durations must be >= 0
    for field_name in ("rtt_ms", "handshake_ms", "request_latency_ms", "response_latency_ms"):
        v = getattr(obs, field_name)
        if v is None:
            continue
        if float(v) < 0.0:
            raise TimingValidationError(f"{field_name} must be >= 0")

    # If request/response latency exist but RTT is missing,
    # it’s not invalid; but RTT should not be less than individual latencies.
    if obs.rtt_ms is not None:
        for field_name in ("request_latency_ms", "response_latency_ms", "handshake_ms"):
            v = getattr(obs, field_name)
            if v is None:
                continue
            # RTT should generally cover total observed time; allow slight inconsistencies
            if float(v) > float(obs.rtt_ms) * 10.0:
                raise TimingValidationError(
                    f"{field_name} is implausibly larger than rtt_ms (possible unit mismatch)"
                )

    # Size invariants
    if obs.request_bytes is not None and obs.request_bytes < 0:
        raise TimingValidationError("request_bytes must be >= 0")
    if obs.response_bytes is not None and obs.response_bytes < 0:
        raise TimingValidationError("response_bytes must be >= 0")

    return obs


def validate_batch(observations: Iterable[TimingObservation]) -> list[TimingObservation]:
    """
    Validate a batch of observations.
    Hard-fails on the first invalid record (strict mode).
    """
    validated: list[TimingObservation] = []
    for obs in observations:
        validated.append(validate_timing_observation(obs))
    return validated


def repair_unit_mismatch_if_obvious(obs: TimingObservation) -> TimingObservation:
    """
    VERY conservative repair:
    attempts to fix common collector mistakes where durations are sent in microseconds.

    Rule:
    - If a duration is huge (e.g. > 60,000 ms = 60s) but looks like microseconds
      (e.g. 120_000 => 120ms if /1000), repair it.
    - We apply repair ONLY when it reduces to a plausible range.

    Returns:
        new TimingObservation (copy) if repaired, else original.
    """
    repaired_fields = {}

    def _maybe_fix(x: Optional[float]) -> Optional[float]:
        if x is None:
            return None
        val = float(x)
        # more than 60s for a single latency is almost always wrong at Layer 0 timing collection
        if val > 60_000.0:
            fixed = val / 1000.0
            if 0.0 <= fixed <= 60_000.0:
                return fixed
        return None

    for name in ("rtt_ms", "handshake_ms", "request_latency_ms", "response_latency_ms"):
        fixed = _maybe_fix(getattr(obs, name))
        if fixed is not None:
            repaired_fields[name] = fixed

    if not repaired_fields:
        return obs

    return replace(obs, **repaired_fields)
