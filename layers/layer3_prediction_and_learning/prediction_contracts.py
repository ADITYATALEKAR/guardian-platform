"""
prediction_contracts.py

Layer 3 — Prediction & Learning
Canonical prediction contracts + shared utilities (bank-grade).

Layer-3 doctrine:
- Input: Layer2 WeaknessBundle-like object (JSON/dict)
- Output: Layer3 PredictionBundle with PredictionSignals
- Deterministic, bounded, JSON-safe

Bank-grade requirements enforced by tests:
- PredictionSignal MUST include:
    entity_id, session_id, ts_ms
    evidence_refs (list)
- All floats must be NaN/Inf safe and clamped where applicable
- Output bounded in size and deterministic in ordering
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core_utils.safety import clamp01 as _clamp01
from core_utils.safety import safe_float as _safe_float
from core_utils.safety import safe_int as _safe_int
from core_utils.safety import safe_str as _safe_str

def _stable_round(x: Any, ndigits: int = 6) -> float:
    v = _safe_float(x, 0.0)
    assert v is not None
    return float(round(v, ndigits))


def _json_safe_metrics(
    metrics: Any,
    *,
    max_items: int = 32,
    max_key_len: int = 64,
) -> Dict[str, float]:
    """
    JSON-safe numeric-only metric map.
    Deterministic key ordering and bounded size.
    """
    out: Dict[str, float] = {}
    if not isinstance(metrics, dict):
        return out

    for k in sorted(metrics.keys(), key=lambda z: str(z)):
        if len(out) >= max_items:
            break
        key = _safe_str(k, "")
        if not key:
            continue
        key = key[:max_key_len]
        out[key] = _stable_round(_safe_float(metrics.get(k), 0.0))
    return out


def _sanitize_evidence_refs(
    evidence_refs: Any,
    *,
    max_refs: int = 8,
    max_kind_len: int = 64,
    max_hash_len: int = 128,
    max_fp_ids: int = 8,
    max_fp_id_len: int = 96,
) -> List[Dict[str, Any]]:
    """
    Bounded evidence reference sanitizer.

    EvidenceRef shape expected (Layer2-compatible):
      {
        "kind": str,
        "hash": str,
        "fingerprint_ids": List[str]
      }

    Hardening:
    - deterministic ordering
    - bounded list sizes
    - safe string truncation
    - fingerprint_ids bounded and deduped
    """
    if not isinstance(evidence_refs, list):
        return []

    cleaned: List[Dict[str, Any]] = []

    for ref in evidence_refs:
        if not isinstance(ref, dict):
            continue

        kind = _safe_str(ref.get("kind"), "")[:max_kind_len]
        h = _safe_str(ref.get("hash"), "")[:max_hash_len]
        if not kind or not h:
            continue

        fp_ids_raw = ref.get("fingerprint_ids", [])
        fp_ids: List[str] = []
        if isinstance(fp_ids_raw, list):
            for f in fp_ids_raw:
                fid = _safe_str(f, "")[:max_fp_id_len]
                if not fid:
                    continue
                fp_ids.append(fid)

        # dedupe + deterministic order
        fp_ids = sorted(set(fp_ids))[:max_fp_ids]

        cleaned.append(
            {
                "kind": kind,
                "hash": h,
                "fingerprint_ids": fp_ids,
            }
        )

    # deterministic ordering, bounded count
    cleaned.sort(key=lambda r: (r.get("kind", ""), r.get("hash", "")))
    return cleaned[:max_refs]


# ----------------------------
# Canonical Layer-3 Contracts
# ----------------------------
@dataclass(frozen=True, kw_only=True)
class PredictionSignal:
    """
    Canonical prediction signal consumed by Layer 4.

    Required grounding:
    - entity_id, session_id, ts_ms

    Required auditability:
    - evidence_refs (bounded list)

    Prediction payload:
    - prediction_kind
    - severity_01
    - confidence_01
    - horizon_days
    - metrics (numeric-only)
    """

    entity_id: str = "unknown"
    session_id: str = "unknown"
    ts_ms: int = 0

    prediction_kind: str = "unknown"
    severity_01: float = 0.0
    confidence_01: float = 0.0
    horizon_days: int = 0

    metrics: Dict[str, float] = field(default_factory=dict)
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)

    # bounds
    MAX_METRICS: int = 32
    MAX_EVIDENCE_REFS: int = 8
    MAX_ID_LEN: int = 128
    MAX_KIND_LEN: int = 64

    def __post_init__(self) -> None:
        eid = _safe_str(self.entity_id, "unknown")[: self.MAX_ID_LEN]
        sid = _safe_str(self.session_id, "unknown")[: self.MAX_ID_LEN]
        ts = max(0, _safe_int(self.ts_ms, 0))

        pk = _safe_str(self.prediction_kind, "unknown")[: self.MAX_KIND_LEN]
        sev = _stable_round(_clamp01(self.severity_01))
        conf = _stable_round(_clamp01(self.confidence_01))
        hz = max(0, _safe_int(self.horizon_days, 0))

        metrics_clean = _json_safe_metrics(self.metrics, max_items=self.MAX_METRICS)

        ev_clean = _sanitize_evidence_refs(
            self.evidence_refs,
            max_refs=self.MAX_EVIDENCE_REFS,
        )

        object.__setattr__(self, "entity_id", eid)
        object.__setattr__(self, "session_id", sid)
        object.__setattr__(self, "ts_ms", int(ts))

        object.__setattr__(self, "prediction_kind", pk)
        object.__setattr__(self, "severity_01", float(sev))
        object.__setattr__(self, "confidence_01", float(conf))
        object.__setattr__(self, "horizon_days", int(hz))
        object.__setattr__(self, "metrics", metrics_clean)
        object.__setattr__(self, "evidence_refs", list(ev_clean))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "session_id": self.session_id,
            "ts_ms": int(self.ts_ms),
            "prediction_kind": self.prediction_kind,
            "severity_01": float(self.severity_01),
            "confidence_01": float(self.confidence_01),
            "horizon_days": int(self.horizon_days),
            "metrics": dict(self.metrics),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True, kw_only=True)
class PredictionBundle:
    """
    Canonical bundle of Layer-3 predictions.
    """

    entity_id: str = "unknown"
    session_id: str = "unknown"
    ts_ms: int = 0
    signals: List[PredictionSignal] = field(default_factory=list)

    MAX_SIGNALS: int = 24
    MAX_ID_LEN: int = 128

    def __post_init__(self) -> None:
        eid = _safe_str(self.entity_id, "unknown")[: self.MAX_ID_LEN]
        sid = _safe_str(self.session_id, "unknown")[: self.MAX_ID_LEN]
        ts = max(0, _safe_int(self.ts_ms, 0))

        sigs = [s for s in (self.signals or []) if isinstance(s, PredictionSignal)]

        sigs.sort(
            key=lambda s: (
                s.prediction_kind,
                -float(s.severity_01),
                -float(s.confidence_01),
                int(s.horizon_days),
            )
        )
        sigs = sigs[: self.MAX_SIGNALS]

        object.__setattr__(self, "entity_id", eid)
        object.__setattr__(self, "session_id", sid)
        object.__setattr__(self, "ts_ms", int(ts))
        object.__setattr__(self, "signals", list(sigs))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "session_id": self.session_id,
            "ts_ms": int(self.ts_ms),
            "signals": [s.to_dict() for s in self.signals],
        }
