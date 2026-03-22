"""
Layer 4 — Core risk aggregation (deterministic, bounded).

Constraints:
- Uses ONLY severity_01 and confidence_01 from PredictionSignals.
- No reinforcement / volatility / reliability reuse.
- Deterministic ordering and bounded outputs.
"""

from typing import Any, Dict, Iterable, List, Tuple


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def _clamp01(x: Any) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def score_signal(
    signal: Dict[str, Any],
    *,
    weight_severity: float = 0.55,
    weight_confidence: float = 0.45,
) -> float:
    """
    Deterministic score using ONLY severity_01 and confidence_01.
    """
    sev = _clamp01(signal.get("severity_01", 0.0))
    conf = _clamp01(signal.get("confidence_01", 0.0))
    return _clamp01(weight_severity * sev + weight_confidence * conf)


def _better(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """
    True if a should rank ahead of b.
    Deterministic tie-breaker ordering.
    """
    return (
        -float(a["score"]),
        -float(a["severity_01"]),
        -float(a["confidence_01"]),
        str(a["prediction_kind"]),
    ) < (
        -float(b["score"]),
        -float(b["severity_01"]),
        -float(b["confidence_01"]),
        str(b["prediction_kind"]),
    )


def aggregate_risk(
    signals: Iterable[Dict[str, Any]],
    *,
    weight_severity: float = 0.55,
    weight_confidence: float = 0.45,
    top_k: int = 3,
) -> Tuple[float, List[Dict[str, Any]]]:
    """
    Returns:
      overall_risk_score: float in [0,1]
      scored_signals: list of dicts in deterministic input order

    O(N) top-k selection with deterministic tie-breakers.
    """
    scored: List[Dict[str, Any]] = []
    top: List[Dict[str, Any]] = []
    k = max(1, int(top_k))

    for s in signals or []:
        if not isinstance(s, dict):
            continue
        score = score_signal(
            s,
            weight_severity=weight_severity,
            weight_confidence=weight_confidence,
        )
        item = {
            "prediction_kind": str(s.get("prediction_kind", "")),
            "severity_01": _clamp01(s.get("severity_01", 0.0)),
            "confidence_01": _clamp01(s.get("confidence_01", 0.0)),
            "score": score,
        }
        scored.append(item)

        # maintain top-k list (deterministic, O(k) per item)
        inserted = False
        for i, cur in enumerate(top):
            if _better(item, cur):
                top.insert(i, item)
                inserted = True
                break
        if not inserted:
            top.append(item)
        if len(top) > k:
            top = top[:k]

    if not scored:
        return 0.0, []

    denom = float(min(len(top), k))
    overall = _clamp01(sum(s["score"] for s in top) / denom)
    return overall, scored
