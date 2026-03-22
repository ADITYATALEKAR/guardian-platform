"""
Here’s what **`pattern_labels.py`** really is and why it matters.

---

## What this file is

This file gives Guardian **language**.

It turns raw technical signals (weaknesses) into **human-meaningful descriptions** of what the system’s behavior *resembles*.

It answers:

> “What kind of situation does this look like?”

—not—

> “Who is attacking?” or “What should we do?”

---

## What it consumes

It reads **Layer 2 weaknesses**:

* Drift
* Entropy
* Fallback
* Coherence
* Correlation

These are already facts.
This file just **looks for combinations** of those facts.

---

## What it produces

It outputs **PatternLabel** objects like:

* *“possible harvest-now-decrypt-later exposure”*
* *“downgrade probing behavior pattern”*
* *“entropy exhaustion pattern”*
* *“adversarial masking behavior”*

Each label includes:

* A short name
* A plain-English description
* Which weaknesses triggered it

This makes Guardian **explainable to humans and auditors**.

---

## Why this is safe

These labels:

* ❌ Do **not** change alert levels
* ❌ Do **not** change confidence
* ❌ Do **not** apply policy
* ❌ Do **not** accuse attackers

They are **descriptive, not judgmental**.

Guardian still decides risk.
This file just says what the situation *looks like*.

---

## Why this is powerful

Without this file, Guardian says:

> “Red alert, confidence 0.83”

With this file, Guardian can say:

> “Red alert. This looks like entropy decay combined with drift, consistent with possible harvest-now-decrypt-later exposure.”

That is what banks, SOC teams, and regulators actually need.

---

## In one line

**`pattern_labels.py` turns cold risk signals into intelligible security narratives — without ever touching policy or decisions.**

"""

from dataclasses import dataclass
from typing import List, Set

from layers.layer2_risk_and_weakness_analysis.drift_weakness import DriftWeakness
from layers.layer2_risk_and_weakness_analysis.entropy_weakness import EntropyWeakness
from layers.layer2_risk_and_weakness_analysis.fallback_weakness import FallbackWeakness
from layers.layer2_risk_and_weakness_analysis.coherence_weakness import CoherenceWeakness
from layers.layer2_risk_and_weakness_analysis.correlation_weakness import CorrelationWeakness


@dataclass(frozen=True)
class PatternLabel:
    label: str
    description: str
    evidence_weakness_ids: List[str]


class PatternLabeler:
    """
    Derives high-level descriptive patterns from weaknesses.

    IMPORTANT:
    - No intent attribution
    - No attacker claims
    - No alert decisions
    - No policy influence
    """

    def derive(self, weaknesses: List[object]) -> List[PatternLabel]:
        labels: List[PatternLabel] = []

        ids: Set[str] = {
            getattr(w, "weakness_id", "")
            for w in weaknesses
            if hasattr(w, "weakness_id")
        }

        has_entropy = any(isinstance(w, EntropyWeakness) for w in weaknesses)
        has_drift = any(isinstance(w, DriftWeakness) for w in weaknesses)
        has_fallback = any(isinstance(w, FallbackWeakness) for w in weaknesses)
        has_coherence = any(isinstance(w, CoherenceWeakness) for w in weaknesses)
        has_correlation = any(isinstance(w, CorrelationWeakness) for w in weaknesses)

        # ----------------------------
        # Canonical Pattern: entropy_exhaustion
        # (entropy + drift is a strong indicator)
        # ----------------------------
        if has_entropy and has_drift:
            labels.append(
                PatternLabel(
                    label="possible harvest-now-decrypt-later exposure",
                    description=(
                        "Observed cryptographic entropy degradation combined with "
                        "long-term behavioral drift suggests increased future "
                        "decryption risk if traffic is recorded over time."
                    ),
                    evidence_weakness_ids=list(ids),
                )
            )

        # ----------------------------
        # Canonical Pattern: protocol_downgrade
        # ----------------------------
        if has_fallback and has_coherence:
            labels.append(
                PatternLabel(
                    label="protocol_downgrade",
                    description=(
                        "Repeated fallback activity combined with reduced behavioral "
                        "coherence suggests systematic exploration of weaker protocol paths."
                    ),
                    evidence_weakness_ids=list(ids),
                )
            )

        # ----------------------------
        # Canonical Pattern: anomalous_access_pattern
        # ----------------------------
        if has_correlation and has_coherence and not has_drift:
            labels.append(
                PatternLabel(
                    label="anomalous_access_pattern",
                    description=(
                        "Correlation anomalies without corresponding drift suggest "
                        "adaptive behavior intended to blend into baseline activity."
                    ),
                    evidence_weakness_ids=list(ids),
                )
            )

        # ----------------------------
        # Pattern: session replay behavior
        # ----------------------------
        has_session_replay = any(
            getattr(w, "type", None) == "session_replay"
            or getattr(w, "label", None) == "session_replay"
            for w in weaknesses
        )

        if has_session_replay:
            labels.append(
                PatternLabel(
                    label="session_replay",
                    description=(
                        "Repeated use of the same session identifier across requests "
                        "suggests possible session replay or token reuse behavior."
                    ),
                    evidence_weakness_ids=list(ids),
                )
            )

        return labels
