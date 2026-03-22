"""
Here’s what **`advisory_analysis.py`** actually is and why it matters.

---

## What this file is

It’s the **context layer** for Guardian.

It takes:

* the **patterns** Guardian identified
* the **history of confidence** over time

and turns them into:

* **trend** (escalating / stable / declining)
* **which patterns matter most**
* **what we don’t know**
* a **business-level interpretation**

It answers:

> “What does this situation look like over time, and how should a human understand it?”

Not:

> “What should we do?”

---

## What it does **not** do

This file never:

* changes alert level
* recommends actions
* assigns blame
* claims attackers
* modifies policy

It cannot make anything more urgent or less urgent. It only **adds meaning**.

---

## Why it’s critical

Without this, Guardian says:

> “ORANGE alert. Confidence 0.74.”

With this, Guardian says:

> “ORANGE alert. The risk is escalating, entropy-related patterns dominate, confidence is moderate, and uncertainty remains.”

That’s the difference between a **machine output** and an **executive-grade security briefing**.

---

## Why this belongs here (Layer 4.5)

Layer 3 predicts
Layer 4 decides
**Layer 4.5 explains what that decision *means over time***

You need this because banks don’t just want alarms — they want **situational awareness**.

---

## In one line

**`advisory_analysis.py` turns Guardian’s alerts into human-understandable risk narratives — without ever touching authority, policy, or decisions.**


"""



"""
advisory_analysis.py
===================

PURPOSE
-------
Provide contextual, human-readable interpretation of Guardian alerts
over time, WITHOUT exercising authority.

This module exists to explain:
- trend (escalating / stable / declining)
- which observed behavioral patterns dominate
- where uncertainty remains
- what this means in business / risk terms

This module MUST NEVER:
- change alert level
- recommend actions
- attribute attackers or identities
- assert malicious intent
- prescribe remediation
"""

from dataclasses import dataclass
from typing import List
import statistics


# ---------------------------------------------------------------------
# Semantic constraints (LOCK THESE)
# ---------------------------------------------------------------------

DISALLOWED_LANGUAGE = {
    "attacker",
    "breach",
    "compromise",
    "exfiltration",
    "malicious",
    "malware",
    "ransomware",
    "apt",
    "nation-state",
    "hacker",
    "stolen",
    "attack",
}

ALLOWED_TRENDS = {"escalating", "stable", "declining"}


def _validate_safe_language(text: str) -> None:
    """
    Enforce non-accusatory, risk-based language.
    """
    lower = text.lower()
    for word in DISALLOWED_LANGUAGE:
        if word in lower:
            raise ValueError(
                f"Disallowed language detected in advisory output: '{word}'. "
                "Use risk-neutral, observational phrasing instead."
            )


# ---------------------------------------------------------------------
# Advisory output object
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class AdvisorySummary:
    """
    Read-only advisory enrichment for Guardian alerts.

    This object represents CONTEXT, not DECISION.

    It MUST NOT:
    - modify alert severity
    - suggest actions
    - attribute intent or identity
    """

    trend: str                      # escalating | stable | declining
    pattern_priority: List[str]     # ordered, descriptive labels
    uncertainty_notes: List[str]    # explicit limits of knowledge
    business_interpretation: str    # non-technical, non-accusatory


# ---------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------

class AdvisoryAnalyzer:
    """
    Produces advisory context from observed patterns and confidence history.

    This is NOT a policy engine.
    This is NOT a threat attribution engine.
    """

    def analyze(
        self,
        pattern_labels: List[str],
        historical_confidences: List[float],
    ) -> AdvisorySummary:
        # ----------------------------
        # Temporal trend (confidence-based)
        # ----------------------------
        trend = "stable"
        if len(historical_confidences) >= 3:
            delta = historical_confidences[-1] - statistics.mean(
                historical_confidences[:-1]
            )
            if delta > 0.1:
                trend = "escalating"
            elif delta < -0.1:
                trend = "declining"

        if trend not in ALLOWED_TRENDS:
            raise ValueError("Invalid trend classification")

        # ----------------------------
        # Pattern prioritization
        # (descriptive, not urgency-based)
        # ----------------------------
        priority_order = [
            "entropy exhaustion pattern",
            "adversarial masking behavior",
            "downgrade probing",
            "possible harvest-now-decrypt-later",
        ]

        ordered_patterns = (
            [p for p in priority_order if p in pattern_labels]
            + [p for p in pattern_labels if p not in priority_order]
        )

        # ----------------------------
        # Uncertainty explanation
        # ----------------------------
        uncertainty_notes: List[str] = []

        if not pattern_labels:
            uncertainty_notes.append(
                "No dominant behavioral patterns were identified; interpretation confidence is limited."
            )

        if len(historical_confidences) < 3:
            uncertainty_notes.append(
                "Historical signal depth is limited; trend assessment may be unreliable."
            )

        if historical_confidences and max(historical_confidences) < 0.7:
            uncertainty_notes.append(
                "Observed signals remain moderate in confidence and may reflect benign variation."
            )

        # ----------------------------
        # Business interpretation
        # ----------------------------
        business_interpretation = (
            "Observed behavior indicates degradation in trust-related system properties over time. "
            "While no direct unauthorized access is asserted, prolonged instability may elevate "
            "operational, resilience, and compliance risk."
        )

        if trend == "escalating":
            business_interpretation += (
                " The direction of change suggests that exposure is increasing rather than stabilizing."
            )

        # ----------------------------
        # Enforce language safety
        # ----------------------------
        _validate_safe_language(business_interpretation)
        for note in uncertainty_notes:
            _validate_safe_language(note)

        return AdvisorySummary(
            trend=trend,
            pattern_priority=ordered_patterns,
            uncertainty_notes=uncertainty_notes,
            business_interpretation=business_interpretation,
        )
