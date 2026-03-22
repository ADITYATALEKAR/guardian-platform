from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from infrastructure.storage_manager.storage_manager import StorageManager

from ..io import atomic_write_json, policy_root, read_json_fail_loud
from ..policies.updates import (
    PolicyUpdateApprovalStore,
    PolicyUpdateExecutor,
    PolicyUpdatePlanStore,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.approved_pattern_mapping import (
    ApprovedPatternMapping,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.proposed_policy import (
    ProposedPolicy,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.engine.policy_engine import (
    PolicyEngine,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.registry.file_policy_registry import (
    FilePolicyRegistry,
)

logger = logging.getLogger(__name__)


def _safe_str(value: object, default: str = "") -> str:
    token = str(value or "").strip()
    return token if token else default


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def _to_iso_ymd(value: str) -> str:
    text = _safe_str(value, "")[:10]
    return text if len(text) == 10 else "1970-01-01"


@dataclass(frozen=True)
class PolicyRuntimeBridge:
    """
    Runtime bridge:
    - Processes due policy activation requests from canonical policy integration.
    - Materializes approved policies + mappings into Layer4 registry for enforcement.
    - Evaluates pattern labels through PolicyEngine for active cycle decisions.
    """

    storage_manager: StorageManager
    tenant_id: str

    def _policy_root(self) -> Path:
        return policy_root(self.storage_manager, self.tenant_id)

    def _activation_request_dir(self) -> Path:
        path = self._policy_root() / "updates" / "activation_requests"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _activation_applied_dir(self) -> Path:
        path = self._policy_root() / "updates" / "activation_applied"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _registry(self) -> FilePolicyRegistry:
        return FilePolicyRegistry(storage_root=self.storage_manager.base_path / "policy_enforcement")

    def _policy_engine(self) -> PolicyEngine:
        return PolicyEngine(self._registry())

    def _approvals(self) -> PolicyUpdateApprovalStore:
        return PolicyUpdateApprovalStore(storage_manager=self.storage_manager, tenant_id=self.tenant_id)

    def _executor(self) -> PolicyUpdateExecutor:
        return PolicyUpdateExecutor(
            storage_manager=self.storage_manager,
            tenant_id=self.tenant_id,
            approvals=self._approvals(),
        )

    def _plan_store(self) -> PolicyUpdatePlanStore:
        return PolicyUpdatePlanStore(storage_manager=self.storage_manager, tenant_id=self.tenant_id)

    def _applied_marker(self, plan_id: str) -> Path:
        safe = _safe_str(plan_id, "unknown")
        return self._activation_applied_dir() / f"{safe}.json"

    def execute_due_activations(self, *, now_ts_ms: int, max_to_execute: int = 32) -> List[str]:
        return self._executor().execute_due_activations(now_ts_ms=now_ts_ms, max_to_execute=max_to_execute)

    def apply_pending_activation_requests(self, *, now_ts_ms: int, max_to_apply: int = 64) -> List[str]:
        applied_plan_ids: List[str] = []
        request_dir = self._activation_request_dir()
        plan_store = self._plan_store()
        registry = self._registry()
        approved_by = "policy_runtime_bridge"

        request_files = sorted(request_dir.glob("*.json"), key=lambda p: p.name)
        for request_path in request_files[: max(0, int(max_to_apply))]:
            try:
                request = read_json_fail_loud(request_path, context="policy activation request")
            except Exception as exc:
                raise RuntimeError(f"corrupt policy activation request: {request_path.name}") from exc

            plan_id = _safe_str(request.get("plan_id"))
            if not plan_id:
                raise RuntimeError(f"policy activation request missing plan_id: {request_path.name}")

            marker = self._applied_marker(plan_id)
            if marker.exists():
                try:
                    request_path.unlink()
                except FileNotFoundError:
                    pass
                continue

            plan = plan_store.get_plan(plan_id)
            if plan is None:
                atomic_write_json(
                    marker,
                    {
                        "tenant_id": _safe_str(self.tenant_id, "unknown"),
                        "plan_id": plan_id,
                        "status": "skipped_missing_plan",
                        "applied_ts_ms": _safe_int(now_ts_ms, 0),
                    },
                )
                try:
                    request_path.unlink()
                except FileNotFoundError:
                    pass
                continue

            policy_id = f"upd_{plan.plan_id[:24]}"
            framework = _safe_str(plan.raw_metadata.get("framework"), "POLICY_UPDATE")
            policy_name = _safe_str(plan.raw_metadata.get("policy_name"), _safe_str(plan.summary, "Policy update"))
            requirement_text = _safe_str(
                plan.raw_metadata.get("requirement_text"),
                _safe_str(plan.summary, "Policy update activated"),
            )
            violation_risk = _safe_str(plan.raw_metadata.get("violation_risk"), "MEDIUM")
            remediation_days = _safe_int(plan.raw_metadata.get("remediation_deadline_days"), 0)
            if remediation_days <= 0:
                remediation_days = None

            pattern_labels = self._extract_pattern_labels(plan.raw_metadata)
            mappings = [
                ApprovedPatternMapping(
                    mapping_id=f"map_{hashlib.sha256(f'{policy_id}:{label}'.encode('utf-8')).hexdigest()[:16]}",
                    policy_id=policy_id,
                    pattern_label=label,
                    trigger_type="DIRECT_VIOLATION",
                    approved_by=approved_by,
                    rationale="Runtime activation mapping",
                )
                for label in pattern_labels
            ]

            proposed = ProposedPolicy(
                proposed_policy_id=f"prop_{plan.plan_id[:24]}",
                tenant_id=_safe_str(self.tenant_id, "unknown"),
                source="INTERNAL_DOC",
                jurisdiction=_safe_str(plan.jurisdiction_id, "GLOBAL"),
                framework=framework,
                policy_name=policy_name,
                source_url=_safe_str(plan.source_url, ""),
                requirement_text=requirement_text,
                violation_risk=violation_risk,
                remediation_deadline_days=remediation_days,
                enforcement_authority=_safe_str(plan.raw_metadata.get("enforcement_authority"), "internal"),
                submitted_by=approved_by,
            )

            registry.approve_policy(
                proposed,
                approved_by=approved_by,
                policy_id=policy_id,
                policy_name=policy_name,
                framework=framework,
                source="INTERNAL",
                version=f"runtime-{_to_iso_ymd(plan.effective_date_utc)}",
                tenant_id=_safe_str(self.tenant_id, "unknown"),
                jurisdiction=_safe_str(plan.jurisdiction_id, "GLOBAL"),
                requirement_text=requirement_text,
                violation_risk=violation_risk,
                remediation_deadline_days=remediation_days,
                enforcement_authority=_safe_str(plan.raw_metadata.get("enforcement_authority"), "internal"),
                approved_mappings=mappings,
            )

            atomic_write_json(
                marker,
                {
                    "tenant_id": _safe_str(self.tenant_id, "unknown"),
                    "plan_id": plan_id,
                    "policy_id": policy_id,
                    "status": "applied",
                    "applied_ts_ms": _safe_int(now_ts_ms, 0),
                    "pattern_labels": sorted(m.pattern_label for m in mappings),
                },
            )
            try:
                request_path.unlink()
            except FileNotFoundError:
                pass
            applied_plan_ids.append(plan_id)
            logger.info(
                "[PolicyRuntimeBridge] Applied activation request",
                extra={"tenant_id": self.tenant_id, "plan_id": plan_id, "policy_id": policy_id},
            )

        return applied_plan_ids

    def sync_runtime_policies(self, *, now_ts_ms: int, max_to_execute: int = 32, max_to_apply: int = 64) -> Dict[str, Any]:
        due = self.execute_due_activations(now_ts_ms=now_ts_ms, max_to_execute=max_to_execute)
        applied = self.apply_pending_activation_requests(now_ts_ms=now_ts_ms, max_to_apply=max_to_apply)
        return {
            "due_activations": due,
            "applied_activations": applied,
        }

    def has_active_policies(self) -> bool:
        active = self._registry().get_active_policies(_safe_str(self.tenant_id, "unknown"))
        return len(active) > 0

    def evaluate_patterns(
        self,
        *,
        pattern_labels: Iterable[str],
        jurisdiction: Optional[str] = None,
    ) -> Dict[str, Any]:
        response = self._policy_engine().evaluate(
            tenant_id=_safe_str(self.tenant_id, "unknown"),
            pattern_labels=list(pattern_labels),
            jurisdiction=jurisdiction,
            include_internal=True,
            policy_version="runtime",
        )
        findings = [
            {
                "policy_id": f.policy_id,
                "policy_name": f.policy_name,
                "framework": f.framework,
                "status": str(f.status),
                "trigger_patterns": list(f.trigger_patterns),
                "requirement": f.requirement,
                "current_state": f.current_state,
                "violation_risk": f.violation_risk,
                "required_action": f.required_action,
                "remediation_deadline_days": f.remediation_deadline_days,
                "regulator": f.regulator,
                "violation_severity": str(f.violation_severity),
            }
            for f in response.findings
        ]
        return {
            "findings": findings,
            "overall_risk_level": str(response.overall_risk_level),
            "violation_count": int(response.violation_count),
            "at_risk_count": int(response.at_risk_count),
            "compliant_count": int(response.compliant_count),
            "immediate_action_required": bool(response.immediate_action_required),
            "most_urgent_deadline_days": response.most_urgent_deadline_days,
            "generated_at_utc": response.generated_at_utc.isoformat(),
            "policy_version": _safe_str(response.policy_version, "runtime"),
        }

    @staticmethod
    def _extract_pattern_labels(raw_metadata: Dict[str, Any]) -> List[str]:
        if not isinstance(raw_metadata, dict):
            return []

        values = raw_metadata.get("pattern_labels", [])
        labels: List[str] = []
        if isinstance(values, str):
            values = [part.strip() for part in values.split(",")]
        if isinstance(values, (list, tuple)):
            for value in values:
                token = _safe_str(value, "")
                if token:
                    labels.append(token)
        return sorted(set(labels))

