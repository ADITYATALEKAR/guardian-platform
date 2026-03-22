"""
handshake_fp.py

Handshake/protocol fingerprint generator for Layer 0.

This module consumes raw handshake-like observables and emits a Fingerprint:
- stable across noise
- deterministic
- comparable (via vector)
- external-safe

IMPORTANT:
- No attacker attribution
- No risk scoring
- No policy

Protocol structure fingerprint

Detects downgrade & replay patterns
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Optional, Sequence, Tuple, Union

from .fingerprint_types import Fingerprint, HandshakeObservation


def _safe_str(x: Any) -> str:
    if x is None:
        return ""
    try:
        s = str(x)
    except Exception:
        return ""
    return s.strip()


def _safe_tuple_str(values: Any) -> Tuple[str, ...]:
    """
    Ensures stable tuple[str,...] from incoming values (list/tuple/None).
    Removes empty values and normalizes whitespace.
    """
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        # a single string is not a list; treat as scalar
        v = _safe_str(values)
        return (v,) if v else ()

    out = []
    try:
        for v in values:
            sv = _safe_str(v)
            if sv:
                out.append(sv)
    except Exception:
        return ()
    return tuple(out)


def _min_hash_material(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Drop non-essential / unstable fields before hashing.

    This is critical for stability across:
    - collector differences
    - timestamp differences
    - partial telemetry
    """
    return {
        "tls_version": payload.get("tls_version", ""),
        "alpn": payload.get("alpn", ""),
        "sni": payload.get("sni", ""),
        "cipher_suites": payload.get("cipher_suites", []),
        "extensions": payload.get("extensions", []),
        "signature_algorithms": payload.get("signature_algorithms", []),
        "supported_groups": payload.get("supported_groups", []),
        "key_share_groups": payload.get("key_share_groups", []),
        # If present, include JA3/JA4 *as evidence fields*, not as authoritative source.
        "ja3": payload.get("ja3", ""),
        "ja4": payload.get("ja4", ""),
    }


def _compute_quality(payload: Dict[str, Any]) -> float:
    """
    Fingerprint quality heuristic.

    We do NOT interpret security impact.
    We only score "data completeness and stability".
    """
    score = 0.0

    # Basic fields
    if payload.get("tls_version"):
        score += 0.15
    if payload.get("alpn"):
        score += 0.10
    if payload.get("sni"):
        score += 0.05

    # Lists add most fingerprint identity
    if payload.get("cipher_suites"):
        score += 0.25
    if payload.get("extensions"):
        score += 0.25
    if payload.get("signature_algorithms"):
        score += 0.10
    if payload.get("supported_groups"):
        score += 0.05
    if payload.get("key_share_groups"):
        score += 0.05

    # Optional strong hints
    if payload.get("ja3"):
        score += 0.10
    if payload.get("ja4"):
        score += 0.10

    return Fingerprint.safe_quality(score)


def build_handshake_fingerprint(
    observation: Union[HandshakeObservation, Dict[str, Any]],
    *,
    kind: str = "handshake_fp_v1",
    version: int = 1,
) -> Fingerprint:
    """
    Build a deterministic handshake fingerprint.

    Inputs accepted:
    - HandshakeObservation dataclass
    - dict payload (for integration with existing collectors)

    Output:
    - Fingerprint (stable hash + stable vector)
    """
    # Normalize input into dict
    if isinstance(observation, HandshakeObservation):
        raw = observation.as_dict()
        entity_id = observation.entity_id
    elif isinstance(observation, dict):
        raw = dict(observation)
        entity_id = _safe_str(raw.get("entity_id", ""))
    else:
        raw = {}
        entity_id = ""

    # Normalize fields for stability
    payload = {
        "entity_id": entity_id,
        "tls_version": _safe_str(raw.get("tls_version")),
        "alpn": _safe_str(raw.get("alpn")),
        "sni": _safe_str(raw.get("sni")),
        "cipher_suites": list(_safe_tuple_str(raw.get("cipher_suites"))),
        "extensions": list(_safe_tuple_str(raw.get("extensions"))),
        "signature_algorithms": list(_safe_tuple_str(raw.get("signature_algorithms"))),
        "supported_groups": list(_safe_tuple_str(raw.get("supported_groups"))),
        "key_share_groups": list(_safe_tuple_str(raw.get("key_share_groups"))),
        "ja3": _safe_str(raw.get("ja3")),
        "ja4": _safe_str(raw.get("ja4")),
        # We intentionally do NOT include timestamps/collector_id into the stable hash.
        # Those remain in source_fields only.
        "observed_at_ms": raw.get("observed_at_ms"),
        "collector_id": _safe_str(raw.get("collector_id")),
    }

    # Hash material excludes unstable fields
    stable_payload = _min_hash_material(payload)
    fp_hash = Fingerprint.stable_hash_from_payload(stable_payload)

    # Comparable vector:
    # We encode lengths and categorical presence into a stable low-dim vector.
    # This is not cryptographically meaningful; it's for similarity grouping.
    vec = Fingerprint.make_vector(
        [
            1.0 if stable_payload.get("tls_version") else 0.0,
            1.0 if stable_payload.get("alpn") else 0.0,
            1.0 if stable_payload.get("sni") else 0.0,
            float(len(stable_payload.get("cipher_suites", []) or [])),
            float(len(stable_payload.get("extensions", []) or [])),
            float(len(stable_payload.get("signature_algorithms", []) or [])),
            float(len(stable_payload.get("supported_groups", []) or [])),
            float(len(stable_payload.get("key_share_groups", []) or [])),
            1.0 if stable_payload.get("ja3") else 0.0,
            1.0 if stable_payload.get("ja4") else 0.0,
        ],
        quantize_decimals=3,
    )

    quality = _compute_quality(stable_payload)

    return Fingerprint(
        entity_id=entity_id,
        kind=kind,
        version=version,
        hash=fp_hash,
        vector=vec,
        quality=quality,
        source_fields={
            # Source fields: kept for explainability/debug. Not part of identity hash.
            "tls_version": stable_payload.get("tls_version", ""),
            "alpn": stable_payload.get("alpn", ""),
            "sni_present": bool(stable_payload.get("sni")),
            "cipher_suites_count": len(stable_payload.get("cipher_suites", []) or []),
            "extensions_count": len(stable_payload.get("extensions", []) or []),
            "signature_algorithms_count": len(stable_payload.get("signature_algorithms", []) or []),
            "supported_groups_count": len(stable_payload.get("supported_groups", []) or []),
            "key_share_groups_count": len(stable_payload.get("key_share_groups", []) or []),
            "ja3_present": bool(stable_payload.get("ja3")),
            "ja4_present": bool(stable_payload.get("ja4")),
        },
    )



# -----------------------------------------------------------------------------
# Public API stability shim (Avyakta Layer-0 contract)
#
# observe.py expects: compute_handshake_fingerprint(...)
# Some earlier iterations used: build_handshake_fingerprint(...)
# or similar names.
#
# This ensures merge-safety by providing the canonical API name.
# -----------------------------------------------------------------------------

def compute_handshake_fingerprint(*args, **kwargs):
    """
    Canonical Layer-0 public function.

    This is the stable entrypoint that observe.py imports.
    It delegates to the implementation function in this module.
    """
    # Preferred: if the module already defines build_handshake_fingerprint
    impl = globals().get("build_handshake_fingerprint")
    if callable(impl):
        return impl(*args, **kwargs)

    # Fallback: if the module already defines compute_handshake_fp
    impl = globals().get("compute_handshake_fp")
    if callable(impl):
        return impl(*args, **kwargs)

    raise ImportError(
        "handshake_fp.py must define build_handshake_fingerprint(...) "
        "or compute_handshake_fp(...) as the implementation."
    )
