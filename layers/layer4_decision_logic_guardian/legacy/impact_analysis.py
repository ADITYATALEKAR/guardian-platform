"""

Here’s what this file does, in plain terms:

---

## What this file is

This file is **Guardian’s “blast-radius explainer.”**

It answers one question for a bank:

> **“If this alert is real, what parts of my system could be affected?”**

Not *how likely*.
Not *how severe*.
Just **what would be touched if things go bad**.

---

## Why it exists

Alerts alone are not useful to a bank.

A bank needs to know:

* Which **endpoints** (apps, APIs)
* Which **services** (payments, auth, data)
* Which **identities** (certs, keys)
* Which **trust materials** (CAs, roots)

are connected to the risky thing.

This file turns:

> “Endpoint X is risky”
> into
> “Endpoint X touches Payments, Customer Auth, and two certificate chains.”

That’s what makes Guardian actionable.

---

## What the code actually does

1. It starts from the **alerted entity**
2. It walks the **Layer-1 trust graph**
3. It follows dependencies outward (up to a safe depth)
4. It collects everything that depends on that entity
5. It groups them by type (endpoint, service, identity, trust material)
6. It produces a clean, immutable **ImpactAnalysis** report

No guessing.
No risk scoring.
Just **structure**.

---

## Why this keeps architectural integrity

This file:

* Does **not** change the alert
* Does **not** recalculate risk
* Does **not** touch physics
* Does **not** touch predictors

It only answers:

> “What is connected to this?”

That’s exactly what Layer 4.5 is supposed to do.

---

## In one sentence

**This file tells a bank what will be affected if the alerted thing fails — turning a warning into operational understanding.**

"""



from dataclasses import dataclass
from typing import Set, Dict, List

from layers.layer4_decision_logic_guardian.legacy.node_adapters import ServiceNode


from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer1_trust_graph_dependency_modeling.nodes import (
    EndpointNode,
    IdentityNode,
    TrustMaterialNode,
)
from layers.layer4_decision_logic_guardian.legacy.alert import Alert


# ----------------------------
# Impact Analysis Result
# ----------------------------

@dataclass(frozen=True)
class ImpactAnalysis:
    """
    Immutable structural impact explanation.

    Describes WHAT may be affected if the alert entity degrades,
    without estimating likelihood or severity.
    """

    root_entity_id: str

    affected_endpoints: List[str]
    affected_services: List[str]
    affected_identities: List[str]
    affected_trust_material: List[str]

    max_depth_reached: int
    total_affected_count: int

    summary: str


# ----------------------------
# Impact Analyzer
# ----------------------------

class ImpactAnalyzer:
    """
    Traverses the Layer 1 trust graph to identify
    downstream structural dependencies.

    This class MUST remain:
    - read-only
    - policy-free
    - risk-agnostic
    """

    def __init__(self, max_depth: int = 3):
        if max_depth <= 0:
            raise ValueError("max_depth must be >= 1")
        self.max_depth = max_depth

    def analyze(
        self,
        alert: Alert,
        trust_graph: TrustGraph,
    ) -> ImpactAnalysis:
        """
        Perform bounded graph traversal starting from alert.entity_id.
        """

        visited: Set[str] = set()
        frontier: Set[str] = {alert.entity_id}

        affected_endpoints: Set[str] = set()
        affected_services: Set[str] = set()
        affected_identities: Set[str] = set()
        affected_trust_material: Set[str] = set()

        depth = 0

        while frontier and depth < self.max_depth:
            next_frontier: Set[str] = set()

            for node_id in frontier:
                if node_id in visited:
                    continue

                visited.add(node_id)
                node = trust_graph.get_node(node_id)

                if node is None:
                    continue

                # Classify by node type
                if isinstance(node, EndpointNode):
                    affected_endpoints.add(node.node_id)
                elif isinstance(node, ServiceNode):
                    affected_services.add(node.node_id)
                elif isinstance(node, IdentityNode):
                    affected_identities.add(node.node_id)
                elif isinstance(node, TrustMaterialNode):
                    affected_trust_material.add(node.node_id)

                # Traverse outward dependencies
                neighbors = trust_graph.get_neighbors(node_id)
                for neighbor_id in neighbors:
                    if neighbor_id not in visited:
                        next_frontier.add(neighbor_id)

            frontier = next_frontier
            depth += 1

        total_affected = (
            len(affected_endpoints)
            + len(affected_services)
            + len(affected_identities)
            + len(affected_trust_material)
        )

        summary = (
            f"Structural analysis indicates {total_affected} connected components "
            f"may be impacted within {depth} trust relationships."
        )

        return ImpactAnalysis(
            root_entity_id=alert.entity_id,
            affected_endpoints=sorted(affected_endpoints),
            affected_services=sorted(affected_services),
            affected_identities=sorted(affected_identities),
            affected_trust_material=sorted(affected_trust_material),
            max_depth_reached=depth,
            total_affected_count=total_affected,
            summary=summary,
        )
