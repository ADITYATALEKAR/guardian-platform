"""
handshake_collector.py

Layer 0 collector for handshake-style observations.

This collector does NOT attempt to "understand" TLS, crypto, or risk.
It simply maps raw event dictionaries into a canonical HandshakeObservation.

Collector responsibilities:
- accept raw payload(s) from the ingest surface
- canonicalize into schema objects
- keep things bounded and safe
- do NOT compute physics here
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from ..schemas.handshake_schema import HandshakeObservation


def collect_handshake_observations(
    raw_events: Iterable[Dict[str, Any]],
) -> List[HandshakeObservation]:
    """
    Convert raw event dicts into HandshakeObservation objects.

    Any event that fails schema requirements is skipped ONLY if it is malformed.
    We keep strictness: entity_id is mandatory.
    """
    out: List[HandshakeObservation] = []
    for ev in raw_events or []:
        if not isinstance(ev, dict):
            continue
        try:
            out.append(HandshakeObservation.from_raw(ev))
        except Exception:
            # Layer-0 collector should be resilient to partial garbage inputs.
            # Validation layer will enforce stricter correctness later.
            continue
    return out


def collect_single_handshake_observation(
    raw_event: Dict[str, Any],
) -> HandshakeObservation:
    """
    Convenience wrapper when upstream deals in single events.
    """
    if not isinstance(raw_event, dict):
        raise ValueError("raw_event must be a dict")
    return HandshakeObservation.from_raw(raw_event)
