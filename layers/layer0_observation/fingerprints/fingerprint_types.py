"""
fingerprint_types.py

Canonical Layer 0 Fingerprint contract.

Layer 0 fingerprints are:
- deterministic
- external-safe
- stable across noise
- comparable across sessions
- schema versioned

They are NOT risk decisions, NOT policy signals, NOT attacker attribution.


What it does

Defines canonical fingerprint shape

Stable hashing

Vector construction

Metaphor

Evidence bag standards in forensics.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _json_safe(value):
    """
    Convert tuples to lists recursively for Layer0 JSON-safe guarantees.
    """
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return value

def __post_init__(self):
    # guarantee JSON-safe source_fields
    sf = _json_safe(self.source_fields or {})
    object.__setattr__(self, "source_fields", sf)

def _json_sanitize(value: Any) -> Any:
    """
    Ensure Layer-0 fingerprints emit JSON-safe metadata.

    Allowed:
      - None
      - bool
      - int / float / str
      - list
      - dict

    Disallowed:
      - tuple / set (convert to list)
      - custom objects (convert to str)
    """
    if value is None:
        return None
    if isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, tuple):
        return [_json_sanitize(v) for v in list(value)]
    if isinstance(value, set):
        return [_json_sanitize(v) for v in sorted(list(value))]
    if isinstance(value, list):
        return [_json_sanitize(v) for v in value]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            out[str(k)] = _json_sanitize(v)
        return out
    # fallback: do not crash layer0 because of metadata
    return str(value)




def _now_ms() -> int:
    return int(time.time() * 1000)


def _stable_json(obj: Any) -> str:
    """
    Stable JSON encoding:
    - consistent ordering
    - no whitespace variance
    - safe for hashing
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    try:
        x = float(x)
    except Exception:
        return lo
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


@dataclass(frozen=True, kw_only=True)
class Fingerprint:
    """
    Canonical fingerprint object emitted by Layer 0.

    Required fields:
    - fingerprint_id: unique event id (not the fingerprint identity itself)
    - entity_id: what this fingerprint belongs to (endpoint/service/etc)
    - kind: fingerprint kind string, e.g. "handshake_fp_v1"
    - version: schema version int
    - created_ms: timestamp ms
    - hash: stable identity hash for this fingerprint
    - quality: 0..1 confidence/quality of the fingerprint
    - source_fields: minimal explainability + debugging aid
    - vector: numeric comparable embedding (optional but recommended)
    """

    fingerprint_id: str = ""
    entity_id: str = ""
    kind: str = "unknown_fp_v1"
    version: int = 1
    created_ms: int = field(default_factory=_now_ms)

    # Identity artifacts
    hash: str = ""
    vector: Tuple[float, ...] = ()

    # Operational metadata
    quality: float = 0.0
    source_fields: Dict[str, Any] = field(default_factory=dict)

    
    
    def __post_init__(self) -> None:
        sf = self.source_fields
        if sf is None:
            return
        if not isinstance(sf, dict):
            object.__setattr__(self, "source_fields", {"value": _json_sanitize(sf)})
            return

        clean: Dict[str, Any] = {}
        for k, v in sf.items():
            clean[str(k)] = _json_sanitize(v)

        object.__setattr__(self, "source_fields", clean)

        # Ensure vector is always list (some utilities return tuple)
        if self.vector is not None and not isinstance(self.vector, list):
            object.__setattr__(self, "vector", list(self.vector))

        if not str(self.fingerprint_id or "").strip():
            material = {
                "entity_id": str(self.entity_id or ""),
                "kind": str(self.kind or ""),
                "version": int(self.version or 0),
                "hash": str(self.hash or ""),
                "vector": list(self.vector or []),
                "source_fields": dict(self.source_fields or {}),
            }
            object.__setattr__(
                self,
                "fingerprint_id",
                f"fp_{_sha256_hex(_stable_json(material))[:12]}",
            )

    
    
    @staticmethod
    def stable_hash_from_payload(payload: Dict[str, Any]) -> str:
        """
        Deterministic stable hash generation from a JSON payload.
        """
        return _sha256_hex(_stable_json(payload))

    @staticmethod
    def make_vector(values: Sequence[float], *, quantize_decimals: int = 4) -> Tuple[float, ...]:
        """
        Convert numeric signals into a stable vector representation.

        Quantization is important:
        - prevents tiny float jitter from changing identity
        - stabilizes hashing and distance comparisons
        """
        vec: List[float] = []
        for v in values:
            try:
                fv = float(v)
                if fv != fv:  # NaN guard
                    fv = 0.0
            except Exception:
                fv = 0.0
            vec.append(round(fv, quantize_decimals))
        return list(vec)

    @staticmethod
    def safe_quality(quality: float) -> float:
        return _clamp(quality, 0.0, 1.0)


@dataclass(frozen=True, kw_only=True)
class HandshakeObservation:
    """
    Optional Layer 0 observation contract that handshake fingerprinting consumes.

    This is NOT a Layer 2 object. It's raw-ish Layer 0 observation.
    All fields are optional to support partial telemetry.

    If you already have an existing schema elsewhere, you can ignore this and
    pass plain dicts into handshake_fp.build_handshake_fingerprint(...).
    """

    entity_id: str = ""

    tls_version: Optional[str] = None
    alpn: Optional[str] = None
    sni: Optional[str] = None

    cipher_suites: Tuple[str, ...] = ()
    extensions: Tuple[str, ...] = ()
    signature_algorithms: Tuple[str, ...] = ()

    key_share_groups: Tuple[str, ...] = ()
    supported_groups: Tuple[str, ...] = ()

    # Optional stable hints
    ja3: Optional[str] = None
    ja4: Optional[str] = None

    observed_at_ms: int = field(default_factory=_now_ms)
    collector_id: str = "unknown_collector"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "tls_version": self.tls_version,
            "alpn": self.alpn,
            "sni": self.sni,
            "cipher_suites": list(self.cipher_suites),
            "extensions": list(self.extensions),
            "signature_algorithms": list(self.signature_algorithms),
            "key_share_groups": list(self.key_share_groups),
            "supported_groups": list(self.supported_groups),
            "ja3": self.ja3,
            "ja4": self.ja4,
            "observed_at_ms": self.observed_at_ms,
            "collector_id": self.collector_id,
        }

@staticmethod
def _json_safe(obj):
    if obj is None or isinstance(obj, (int, float, str, bool)):
        return obj
    if isinstance(obj, tuple):
        return [Fingerprint._json_safe(x) for x in obj]
    if isinstance(obj, list):
        return [Fingerprint._json_safe(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): Fingerprint._json_safe(v) for k, v in obj.items()}
    if isinstance(obj, set):
        return sorted([Fingerprint._json_safe(x) for x in obj])
    return str(obj)
