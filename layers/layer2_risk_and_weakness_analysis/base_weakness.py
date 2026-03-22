"""
base_weakness.py

Layer 2 — Risk & Weakness Analysis
Canonical base contract for weakness artifacts.

Layer 2 doctrine (Avyakta):
- Layer 0: deterministic evidence fingerprints + physics primitives
- Layer 1: deterministic structural graph grounding (entity/session/evidence)
- Layer 2: typed weakness signals (bounded, baseline-aware, audit-safe)
- Layer 4: attribution / narrative / bank reports (NOT Layer 2)

Production rules for BaseWeakness:
- Immutable dataclass (weakness objects are facts/events)
- Keyword-only (safe inheritance ordering)
- Primitive fields only (safe JSON serialization)
- Deterministic identifiers (no UUID churn)
- Replay-stable timestamps by default (no now_ms churn inside detectors)

IMPORTANT:
- Detectors should NOT call time-based defaults directly.
  Timestamps must come from orchestration (Layer 2 engine) later.
  Until then, first_seen_ms=0 ensures replay stability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True, kw_only=True)
class BaseWeakness:
    """
    Canonical base model for Layer 2 weakness artifacts.

    Fields:
      weakness_id:
        Deterministic kind/version ID (example: "coherence_weakness_v1").
        Must NOT be UUID-based.

      entity_id:
        Structural entity this weakness is grounded to (endpoint/session/etc).
        Detectors should enforce non-empty entity_id (except rare fallbacks).

      severity:
        Normalized [0..1] magnitude of weakness.

      confidence:
        Normalized [0..1] confidence of weakness validity.

      first_seen_ms:
        Replay-stable timestamp. Default 0 until Layer 2 engine supplies time.
    """

    weakness_id: str = ""
    entity_id: str = ""

    severity: float = 0.0
    confidence: float = 0.0

    first_seen_ms: int = 0

    def __post_init__(self) -> None:
        wid = str(self.weakness_id or "").strip()
        eid = str(self.entity_id or "").strip()

        # NEW: never allow empty weakness_id (bank-grade logging discipline)
        if not wid:
            wid = "unknown_weakness_v1"

        sev = self.clamp01(self.severity)
        conf = self.clamp01(self.confidence)

        try:
            ts = int(self.first_seen_ms)
        except Exception:
            ts = 0
        if ts < 0:
            ts = 0

        object.__setattr__(self, "weakness_id", wid)
        object.__setattr__(self, "entity_id", eid)
        object.__setattr__(self, "severity", float(sev))
        object.__setattr__(self, "confidence", float(conf))
        object.__setattr__(self, "first_seen_ms", int(ts))

    # ----------------------------
    # Deterministic helpers
    # ----------------------------
    @staticmethod
    def clamp01(x: Any) -> float:
        try:
            v = float(x)
        except Exception:
            return 0.0

        if v != v:  # NaN
            return 0.0
        if v == float("inf") or v == float("-inf"):
            return 0.0

        if v < 0.0:
            return 0.0
        if v > 1.0:
            return 1.0
        return v

    @staticmethod
    def stable_kind_id(kind: str, version: int = 1) -> str:
        k = str(kind or "").strip().lower()
        if not k:
            k = "unknown"

        try:
            v = int(version)
        except Exception:
            v = 1
        if v <= 0:
            v = 1

        return f"{k}_weakness_v{v}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "weakness_id": self.weakness_id,
            "entity_id": self.entity_id,
            "severity": float(self.severity),
            "confidence": float(self.confidence),
            "first_seen_ms": int(self.first_seen_ms),
        }
