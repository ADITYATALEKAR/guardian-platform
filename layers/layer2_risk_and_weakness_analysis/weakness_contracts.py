"""
weakness_contracts.py

Layer 2 — canonical output contracts for weakness emission.

Bank-grade goals:
- Stable handoff contract Layer 4 can consume.
- Deterministic ordering (replay-safe).
- Bounded evidence references (no raw vectors, no raw source_fields).
- Numeric-only metrics (float) to keep serialization stable across systems.

Evidence Discipline:
- EvidenceAnchor: stable identity (kind, hash)
- EvidenceRef: anchor + bounded fingerprint_id sample list (audit tracing)

IMPORTANT:
- Layer2 does NOT decide "attacker". It emits structured weakness signals only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from core_utils.safety import clamp01 as _clamp01
from core_utils.safety import safe_float as _safe_float
from core_utils.safety import safe_str as _safe_str

def _round_stable(x: Any, ndigits: int = 6) -> float:
    v = _safe_float(x, 0.0)
    assert v is not None
    return float(round(v, ndigits))


# -------------------------
# Evidence contracts
# -------------------------
@dataclass(frozen=True, kw_only=True)
class EvidenceAnchor:
    """
    Stable anchor to Layer 0 evidence identity.

    kind: fingerprint kind namespace (e.g., "handshake_fp_v1")
    hash: stable identity hash (stable unless version bump)
    """
    kind: str
    hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _safe_str(self.kind))
        object.__setattr__(self, "hash", _safe_str(self.hash))


@dataclass(frozen=True, kw_only=True)
class EvidenceRef:
    """
    Bounded reference to Layer 0 evidence.

    anchor: stable identity anchor (kind + hash)
    fingerprint_ids: bounded list of event IDs for audit sampling (not full history)
    """
    anchor: EvidenceAnchor
    fingerprint_ids: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        ids = [_safe_str(i) for i in (self.fingerprint_ids or []) if _safe_str(i)]
        ids = sorted(set(ids))[:12]  # bounded audit sample
        object.__setattr__(self, "fingerprint_ids", ids)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.anchor.kind,
            "hash": self.anchor.hash,
            "fingerprint_ids": list(self.fingerprint_ids),
        }


# -------------------------
# Weakness output contracts
# -------------------------
@dataclass(frozen=True, kw_only=True)
class WeaknessSignal:
    """
    Canonical Layer 2 signal (Layer 4 consumes this).

    Required properties:
    - deterministic, bounded, JSON-safe
    - entity + session grounding
    - severity/confidence in [0..1]
    - bounded evidence refs
    - bounded numeric-only metrics
    """
    entity_id: str
    session_id: str
    ts_ms: int

    weakness_id: str
    weakness_kind: str  # coherence/drift/entropy/fallback/correlation/transition/fusion

    severity_01: float
    confidence_01: float

    evidence_refs: List[EvidenceRef] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)

    # Hard caps (aligned with thresholds defaults: max_evidence_refs_per_signal=8)
    MAX_EVIDENCE_REFS: int = 8
    MAX_METRICS: int = 24

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _safe_str(self.entity_id, "unknown"))
        object.__setattr__(self, "session_id", _safe_str(self.session_id, "unknown"))

        try:
            ts = int(self.ts_ms)
        except Exception:
            ts = 0
        if ts < 0:
            ts = 0
        object.__setattr__(self, "ts_ms", ts)

        object.__setattr__(self, "weakness_id", _safe_str(self.weakness_id, "unknown_weakness_v1"))
        object.__setattr__(self, "weakness_kind", _safe_str(self.weakness_kind, "unknown"))

        object.__setattr__(self, "severity_01", _round_stable(_clamp01(self.severity_01)))
        object.__setattr__(self, "confidence_01", _round_stable(_clamp01(self.confidence_01)))

        # Bound evidence refs deterministically
        refs = list(self.evidence_refs or [])
        if len(refs) > self.MAX_EVIDENCE_REFS:
            refs = refs[: self.MAX_EVIDENCE_REFS]
        object.__setattr__(self, "evidence_refs", refs)

        # Bound metrics (numeric-only floats)
        bounded: Dict[str, float] = {}
        for k, v in (self.metrics or {}).items():
            ks = _safe_str(k)
            if not ks:
                continue
            bounded[ks] = _round_stable(v)
            if len(bounded) >= self.MAX_METRICS:
                break
        object.__setattr__(self, "metrics", bounded)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "session_id": self.session_id,
            "ts_ms": int(self.ts_ms),
            "weakness_id": self.weakness_id,
            "weakness_kind": self.weakness_kind,
            "severity_01": float(self.severity_01),
            "confidence_01": float(self.confidence_01),
            "evidence_refs": [r.to_dict() for r in self.evidence_refs],
            "metrics": dict(self.metrics),
        }


@dataclass(frozen=True, kw_only=True)
class WeaknessBundle:
    """
    One deterministic Layer 2 output bundle per (entity_id, session_id, ts_ms).

    Layer 4 should consume ONE bundle at a time to avoid integration drift.
    """
    entity_id: str
    session_id: str
    ts_ms: int

    signals: List[WeaknessSignal] = field(default_factory=list)

    MAX_SIGNALS: int = 32

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _safe_str(self.entity_id, "unknown"))
        object.__setattr__(self, "session_id", _safe_str(self.session_id, "unknown"))

        try:
            ts = int(self.ts_ms)
        except Exception:
            ts = 0
        if ts < 0:
            ts = 0
        object.__setattr__(self, "ts_ms", ts)

        sigs = list(self.signals or [])
        sigs.sort(key=lambda s: (s.weakness_kind, s.weakness_id, -s.severity_01, -s.confidence_01))
        object.__setattr__(self, "signals", sigs[: self.MAX_SIGNALS])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "session_id": self.session_id,
            "ts_ms": int(self.ts_ms),
            "signals": [s.to_dict() for s in self.signals],
        }
