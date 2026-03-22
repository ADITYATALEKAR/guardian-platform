Perfect — we’ll do **both**, but in the **only order that makes architectural sense**.

We will **start by writing `guardian_output_model.md` line by line**, grounded in *your real system*.
Then, once that document exists, **auditing Layer-4 responses becomes trivial and mechanical**.

Trying to audit *before* the model is written would be backwards.

So this answer does **Step 1** completely and cleanly.

---

#  `guardian_output_model.md`

*(Authoritative, conceptual, non-enforced)*

> **Status:** Draft (to be frozen)
> **Scope:** Layer 4 → Layer 5 projection boundary
> **Audience:** Product, UI, API, investors, future engineers
> **Non-goal:** This document does **not** describe how Guardian thinks. It describes how Guardian speaks.

---

## 1. Purpose

Guardian is a **decision system**, not a data platform and not a dashboard.

This document defines the **single outward-facing model** through which Guardian communicates its judgments to humans and downstream systems.

> **Layer 4 emits decisions.
> Layer 5 renders decisions.
> No other layer is allowed to speak to the UI.**

This boundary is deliberate and permanent.

---

## 2. Architectural Positioning

Guardian Output sits **at the boundary between Layer 4 and Layer 5**.

```
Layer 0–3  →  Layer 4 (Guardian)  →  Guardian Output Model  →  Layer 5 (UI)
```

### What Guardian Output IS

* A projection of Guardian’s belief
* Stable across internal refactors
* Minimal, explainable, human-oriented

### What Guardian Output IS NOT

* Internal reasoning graphs
* Raw observations
* Predictor outputs
* Physics metrics
* Confidence math
* Dependency structures

Any UI feature that requires those is **architecturally invalid**.

---

## 3. Core Principle

> **Guardian speaks in judgments, not mechanisms.**

Every field in this model must answer a **human question**.

If a field answers:

* *“How did you compute this?”* →  invalid
* *“Why should I care?”* →  valid

---

## 4. Canonical Shape: `GuardianDecision`

This is the **conceptual shape** of Guardian’s outward worldview.

It is **not a schema** yet.
It is a **semantic contract**.

```
GuardianDecision
├── identity
├── attention
├── severity
├── confidence
├── impact
├── explanation
├── time
└── actions (optional)
```

Each section is explained below.

---

## 5. Identity — “What is this about?”

```
identity:
  decision_id      // opaque, stable
  entity_type      // certificate | service | endpoint | account | system
  entity_id        // opaque identifier
  entity_label     // human-readable name
```

### Notes

* IDs are opaque. UI must never parse them.
* `entity_label` is for display only.
* Identity enables drill-down, bookmarking, correlation.

---

## 6. Attention — “Should I care right now?”

```
attention:
  level            // GREEN | YELLOW | ORANGE | RED
  rationale        // one sentence explaining urgency
```

### Key Rules

* Attention is **urgency**, not severity.
* UI sorts and prioritizes by `level`.
* Numeric attention scores may exist internally but **never cross this boundary**.

This maps directly to your existing **attention-first philosophy**.

---

## 7. Severity — “How bad is this if true?”

```
severity:
  classification   // informational | degraded | critical | catastrophic
  scope            // local | regional | global
```

### Important Distinction

* **Attention** = when to look
* **Severity** = consequence if real

Guardian may emit:

* High severity, low attention (watch closely)
* High attention, medium severity (act now, limited blast radius)

This distinction is intentional.

---

## 8. Confidence — “How sure are we?”

```
confidence:
  level            // LOW | MEDIUM | HIGH
  basis            // why this confidence exists
  limitations[]    // known blind spots
```

### Rules

* Confidence is a **statement**, not a number.
* Guardian must always express **epistemic limits**.
* Absence of limitations is a design failure.

This directly reflects your **Guardian restraint principle**.

---

## 9. Impact — “What does this affect?”

```
impact:
  summary:
    primary_count      // e.g. 1 certificate
    secondary_count    // e.g. 14 services
    tertiary_count     // e.g. 312 endpoints

  blast_radius:
    level              // LOW | MEDIUM | HIGH
    explanation        // why this radius was assigned

  categories[]         // service | endpoint | region | customer
```

### Critical Constraints

* Counts only, not entity lists
* Categories only, not graphs
* No dependency traversal exposed

Layer 4 owns synthesis.
Layer 5 owns presentation.

---

## 10. Explanation — “Why does Guardian believe this?”

This section is **mandatory for every decision**.

```
explanation:
  summary                // single calm sentence
  reasoning[]            // concrete bullet points
  supporting_factors[]   // what increases confidence
  limiting_factors[]     // what prevents escalation
```

### Guardian Restraint Principle (enforced here)

Guardian must explicitly explain:

* why something **is happening**
* and why it **is not worse**

This is the primary trust-building mechanism of the system.

---

## 11. Time — “When does this matter?”

```
time:
  detected_at
  predicted_horizon
  decay_expectation     // short | medium | long
```

Supports:

* timelines
* alert aging
* suppression
* prioritization

---

## 12. Actions (Optional) — “What should I consider doing?”

```
actions[]:
  action_type           // investigate | rotate | notify | ignore
  description
  urgency               // immediate | soon | backlog
```

### Rules

* Actions are **advisory**, never imperative
* Guardian suggests, humans decide
* Absence of actions is acceptable

---

## 13. Mandatory vs Optional Fields

| Section     | Required |
| ----------- | -------- |
| identity    | ✅        |
| attention   | ✅        |
| severity    | ✅        |
| confidence  | ✅        |
| impact      | ✅        |
| explanation | ✅        |
| time        | ✅        |
| actions     | ❌        |

If an alert exists, **an explanation must exist**.

---

## 14. Explicit Prohibitions (Hard Rules)

Layer 5 must **never** receive:

* fingerprints
* predictors
* entropy values
* correlation scores
* dependency graphs
* raw observations
* aggregation formulas

Violation of these rules breaks architectural integrity.

---

## 15. Why This Model Exists

Without this model:

* UI becomes arbitrary
* Naming drifts
* Trust erodes
* Refactors become dangerous

With this model:

* Guardian has a consistent voice
* UI becomes thin and expressive
* Product feels unified
* System scales safely

---

## 16. Status

This document defines the **Guardian Output Boundary**.

Once frozen:

* Internal Guardian logic may evolve freely
* UI may evolve freely
* This boundary remains stable


