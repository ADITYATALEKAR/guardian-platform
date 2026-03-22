"""
Layer 4 / Guardian Threshold Governance

Purpose
-------
Defines bank-grade deterministic thresholds used by GuardianCore to:
- convert Layer3 predictions into alerts
- compute aggregate severity/confidence
- keep outputs bounded and stable

Who depends on this file?
-------------------------
- guardian_core.py (direct)
- aggregation_rules.py (optional)
- impact_analysis.py (optional)
- tests/test_layer4/* (direct)

Bank-grade design rules
-----------------------
- Must be deterministic (no randomness, no timestamps)
- Must be bounded (caps on counts, string sizes)
- Must expose a stable public symbol: GuardianThresholds
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class GuardianThresholds:
    """
    GuardianThresholds
    ------------------
    Bank-grade configuration for decision escalation.

    Notes
    -----
    These defaults are intentionally conservative:
    - We only raise alerts once risk is meaningful.
    - We cap outputs to protect downstream UI / APIs.
    """

    # Output caps
    max_alerts: int = 64
    max_patterns: int = 64
    max_campaigns: int = 16
    max_justification_chars: int = 1200

    # Decision logic thresholds
    min_signal_confidence_for_action: float = 0.55
    min_signal_severity_for_action: float = 0.55

    # Cross-axis amplification (multi-signal convergence)
    cross_axis_boost_per_extra_signal: float = 0.05
    cross_axis_boost_cap: float = 0.20

    # Overall aggregation weights (bounded [0..1])
    weight_severity: float = 0.55
    weight_confidence: float = 0.45

    def clamp01(self, x: float) -> float:
        if x != x:  # NaN
            return 0.0
        if x < 0.0:
            return 0.0
        if x > 1.0:
            return 1.0
        return float(x)
    
# ------------------------------------------------------------------
# Compatibility exports (public Layer4 contract)
# ------------------------------------------------------------------

# Legacy public symbols expected by tests and integrations
MIN_CONFIDENCE: float = GuardianThresholds().min_signal_confidence_for_action
MIN_SEVERITY: float = GuardianThresholds().min_signal_severity_for_action


# ------------------------------------------------------------------
# Predictor convergence requirements (Layer4 contract)
# ------------------------------------------------------------------

# Minimum number of independent predictors required to escalate to RED
RED_MIN_PREDICTORS: int = 2

# Backward-compatible alias (defensive)
MIN_RED_PREDICTORS: int = RED_MIN_PREDICTORS


# ------------------------------------------------------------------
# Predictor count thresholds (Layer4 governance)
# ------------------------------------------------------------------
# These define how many independent predictors (signals / axes)
# are required before escalation is allowed.
#
# IMPORTANT:
# - This does NOT create signals
# - This does NOT modify Layer0–3 logic
# - This ONLY gates escalation decisions

ORANGE_MIN_PREDICTORS: int = 1
RED_MIN_PREDICTORS: int = 2

YELLOW_MIN_PREDICTORS : int= 1



# ------------------------------------------------------------------
# Public confidence band aliases (Layer4 contract)
# ------------------------------------------------------------------

_THRESHOLDS = GuardianThresholds()

# Canonical Avyakta bands
GREEN_CONFIDENCE: float = 0.0
ORANGE_CONFIDENCE: float = _THRESHOLDS.min_signal_confidence_for_action
RED_CONFIDENCE: float = max(
    _THRESHOLDS.min_signal_confidence_for_action,
    _THRESHOLDS.min_signal_severity_for_action,
)

# ------------------------------------------------------------------
# Backward compatibility aliases (DO NOT REMOVE)
# ------------------------------------------------------------------
# Some tests / integrations historically used YELLOW naming.
# YELLOW == ORANGE in Avyakta semantics.

YELLOW_CONFIDENCE: float = ORANGE_CONFIDENCE

