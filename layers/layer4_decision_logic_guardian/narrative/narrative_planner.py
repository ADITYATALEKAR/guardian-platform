"""
Deterministic narrative microplanner.

Inputs:
- campaign_phase
- risk_class
- sync_index
- pattern_labels
- overall_risk_score

Outputs:
- structured narrative string (deterministic)
"""

from typing import Iterable, List

from core_utils.safety import clamp01, safe_str
from .narrative_templates import PHASE_DESCRIPTIONS, RISK_CLASS_DESCRIPTIONS, SECTION_HEADERS


def _safe_str(x: object, default: str = "") -> str:
    return safe_str(x, default)


def _clamp01(x: float) -> float:
    return clamp01(x)


def build_narrative(
    *,
    campaign_phase: str,
    risk_class: str,
    sync_index: float,
    overall_risk_score: float,
    pattern_labels: Iterable[str],
) -> str:
    phase = _safe_str(campaign_phase, "transitional").lower()
    risk = _safe_str(risk_class, "low").lower()

    phase_desc = PHASE_DESCRIPTIONS.get(phase, PHASE_DESCRIPTIONS["transitional"])
    risk_desc = RISK_CLASS_DESCRIPTIONS.get(risk, RISK_CLASS_DESCRIPTIONS["low"])

    labels: List[str] = sorted({_safe_str(l) for l in (pattern_labels or []) if _safe_str(l)})
    label_text = ", ".join(labels) if labels else "none"

    sync = _clamp01(float(sync_index))
    risk_score = _clamp01(float(overall_risk_score))

    summary = f"{phase_desc} {risk_desc}"
    drivers = f"Pattern labels: {label_text}."
    structure = f"Synchronization index is {sync:.2f}."
    phase_line = f"Current phase: {phase}."
    outlook = f"Overall risk score is {risk_score:.2f}."

    sections = [
        f"{SECTION_HEADERS['summary']}: {summary}",
        f"{SECTION_HEADERS['drivers']}: {drivers}",
        f"{SECTION_HEADERS['structure']}: {structure}",
        f"{SECTION_HEADERS['phase']}: {phase_line}",
        f"{SECTION_HEADERS['outlook']}: {outlook}",
    ]
    return " ".join(sections)
