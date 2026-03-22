"""
Simulation Validation
=====================

Deterministic validation helpers for simulator outputs and isolation.

No runtime mutations.
No storage access.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
import hashlib
import json

from simulator.core.sandbox_state import BaselineBundle
from simulator.core.runtime_pipeline import PipelineOutputs


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    issues: Tuple[ValidationIssue, ...]


class SimulationValidator:
    """
    Deterministic validator for simulator invariants.
    """

    def validate_isolation(self, *, sim_root: str, prod_root: str) -> ValidationResult:
        issues: List[ValidationIssue] = []
        sim_path = Path(sim_root).resolve()
        prod_path = Path(prod_root).resolve()

        if sim_path == prod_path:
            issues.append(ValidationIssue("isolation.same_root", "Simulation root equals production root"))
        try:
            sim_path.relative_to(prod_path)
            issues.append(ValidationIssue("isolation.nested_in_prod", "Simulation root is inside production root"))
        except ValueError:
            pass
        try:
            prod_path.relative_to(sim_path)
            issues.append(ValidationIssue("isolation.prod_inside_sim", "Production root is inside simulation root"))
        except ValueError:
            pass

        return ValidationResult(ok=(len(issues) == 0), issues=tuple(issues))

    def validate_baseline(self, baseline: BaselineBundle) -> ValidationResult:
        issues: List[ValidationIssue] = []

        if not isinstance(baseline.layer0_snapshot, dict):
            issues.append(ValidationIssue("baseline.layer0.invalid", "Layer0 snapshot missing or invalid"))
        else:
            for key in ("cycle_id", "timestamp_unix_ms", "endpoints"):
                if key not in baseline.layer0_snapshot:
                    issues.append(ValidationIssue("baseline.layer0.missing", f"Layer0 snapshot missing {key}"))

        if not isinstance(baseline.trust_graph_snapshot, dict):
            issues.append(ValidationIssue("baseline.graph.invalid", "TrustGraph snapshot missing or invalid"))
        else:
            for key in ("version", "nodes", "edges"):
                if key not in baseline.trust_graph_snapshot:
                    issues.append(ValidationIssue("baseline.graph.missing", f"TrustGraph snapshot missing {key}"))

        if baseline.layer3_snapshot is not None and not isinstance(baseline.layer3_snapshot, dict):
            issues.append(ValidationIssue("baseline.layer3.invalid", "Layer3 snapshot invalid"))

        return ValidationResult(ok=(len(issues) == 0), issues=tuple(issues))

    def validate_pipeline_outputs(self, outputs: PipelineOutputs) -> ValidationResult:
        issues: List[ValidationIssue] = []

        if outputs.snapshot is None:
            issues.append(ValidationIssue("pipeline.snapshot.missing", "DiscoverySnapshot missing"))

        if outputs.trust_graph is None:
            issues.append(ValidationIssue("pipeline.graph.missing", "TrustGraph missing"))
        else:
            try:
                outputs.trust_graph.validate_integrity()
            except Exception as exc:
                issues.append(ValidationIssue("pipeline.graph.invalid", str(exc)))

        return ValidationResult(ok=(len(issues) == 0), issues=tuple(issues))

    def validate_determinism(self, a: PipelineOutputs, b: PipelineOutputs) -> ValidationResult:
        issues: List[ValidationIssue] = []

        hash_a = self._stable_hash_outputs(a)
        hash_b = self._stable_hash_outputs(b)

        if hash_a != hash_b:
            issues.append(ValidationIssue("determinism.mismatch", "Pipeline outputs hash mismatch"))

        return ValidationResult(ok=(len(issues) == 0), issues=tuple(issues))

    def _stable_hash_outputs(self, outputs: PipelineOutputs) -> str:
        payload: Dict[str, Any] = {
            "snapshot": outputs.snapshot.to_dict() if hasattr(outputs.snapshot, "to_dict") else {},
            "graph_signature": outputs.trust_graph.signature() if outputs.trust_graph else None,
            "weaknesses": self._bundle_map(outputs.weaknesses),
            "predictions": self._bundle_map(outputs.predictions),
            "guardians": self._guardian_map(outputs.guardians),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _bundle_map(self, bundles: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k in sorted(bundles.keys()):
            b = bundles[k]
            out[k] = b.to_dict() if hasattr(b, "to_dict") else {}
        return out

    def _guardian_map(self, guardians: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k in sorted(guardians.keys()):
            g = guardians[k]
            out[k] = g.to_dict() if hasattr(g, "to_dict") else {}
        return out
