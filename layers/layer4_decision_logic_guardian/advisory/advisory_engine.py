"""
Deterministic advisory engine.

Maps campaign phase + risk class + pattern labels to response posture.
"""

from typing import Iterable, List

from .advisory_catalog import ADVISORY_BY_PHASE, ADVISORY_BY_RISK_CLASS


def _safe_str(x: object, default: str = "") -> str:
    s = str(x or "").strip()
    return s if s else default


def build_advisory(
    *,
    campaign_phase: str,
    risk_class: str,
    pattern_labels: Iterable[str],
) -> str:
    phase = _safe_str(campaign_phase, "transitional").lower()
    risk = _safe_str(risk_class, "low").lower()
    labels: List[str] = sorted({_safe_str(l) for l in (pattern_labels or []) if _safe_str(l)})

    phase_msg = ADVISORY_BY_PHASE.get(phase, ADVISORY_BY_PHASE["transitional"])
    risk_msg = ADVISORY_BY_RISK_CLASS.get(risk, ADVISORY_BY_RISK_CLASS["low"])

    if labels:
        label_msg = f"Observed patterns: {', '.join(labels)}."
    else:
        label_msg = "No pattern labels identified."

    return f"{phase_msg} {risk_msg} {label_msg}"
