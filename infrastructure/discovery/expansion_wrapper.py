"""
expansion_wrapper.py

Pure surface expansion orchestrator.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from infrastructure.discovery.expansion_category_a import (
    ExpansionCategoryA,
    PassiveDiscoveryGraph,
    NodeType,
    normalize_host,
)
from infrastructure.discovery.expansion_category_bcde import (
    ExpansionCategoryBCDE,
    BCDEExpansionContext,
    extract_bcde_candidates,
)
from infrastructure.unified_discovery_v2.models import CycleBudgetExceeded

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExpansionConfig:
    aggressive: bool = True
    max_total_nodes: int = 250_000
    max_total_edges: int = 500_000
    max_total_endpoints: int = 100_000
    max_san_recursion: int = 3
    max_dns_recursion: int = 3
    max_spf_recursion: int = 5
    max_results: int = 10_000
    category_a_time_budget_seconds: int = 150
    bcde_time_budget_seconds: int = 150
    exploration_budget_seconds: int = 300
    exploitation_budget_seconds: int = 300
    module_time_slice_seconds: int = 30
    tls_verification_mode: str = "strict"


@dataclass(frozen=True)
class ExpansionResult:
    root_domain: str
    endpoint_candidates: Set[str]
    node_count: int
    edge_count: int
    ceilings_hit: bool
    diagnostics: Dict[str, Any]


@dataclass
class ExpansionSession:
    root_domain: str
    normalized_root: str
    config: ExpansionConfig
    graph: PassiveDiscoveryGraph
    category_a_supports_incremental: bool
    context_overrides: Dict[str, Any]
    context_a: Any = None
    context_bcde: Optional[BCDEExpansionContext] = None
    productive_a_modules: Set[str] = field(default_factory=set)
    productive_bcde_modules: Set[str] = field(default_factory=set)
    module_summaries: List[Dict[str, Any]] = field(default_factory=list)
    timing: Dict[str, float] = field(
        default_factory=lambda: {
            "a_exploration_s": 0.0,
            "bcde_exploration_s": 0.0,
            "a_exploitation_s": 0.0,
            "bcde_exploitation_s": 0.0,
        }
    )
    phase_outcomes: List[Dict[str, Any]] = field(default_factory=list)


class ExpansionWrapper:
    def __init__(
        self,
        category_a: Optional[ExpansionCategoryA] = None,
        category_bcde: Optional[ExpansionCategoryBCDE] = None,
    ):
        self._category_a = category_a or ExpansionCategoryA()
        self._category_bcde = category_bcde or ExpansionCategoryBCDE()

    def expand(
        self,
        root_domain: str,
        config: ExpansionConfig,
        stage_callback: Optional[Callable[[str], None]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> ExpansionResult:
        session = self.build_session(root_domain, config)
        if session is None:
            return ExpansionResult(
                root_domain=root_domain,
                endpoint_candidates=set(),
                node_count=0,
                edge_count=0,
                ceilings_hit=False,
                diagnostics={"error": "invalid_root_domain"},
            )

        phase_plan = [
            ("category_a_exploration", max(0, int(config.category_a_time_budget_seconds))),
            ("category_bcde_exploration", max(0, int(config.bcde_time_budget_seconds))),
            ("category_a_exploitation", max(0, int(config.exploitation_budget_seconds))),
            ("category_bcde_exploitation", max(0, int(config.exploitation_budget_seconds))),
        ]
        remaining_category_a_exploration = max(0, int(config.category_a_time_budget_seconds))
        remaining_bcde_exploration = max(0, int(config.bcde_time_budget_seconds))
        remaining_exploitation = max(0, int(config.exploitation_budget_seconds))

        try:
            for phase_name, configured_budget in phase_plan:
                if phase_name == "category_a_exploration":
                    phase_budget = min(
                        max(0, int(configured_budget)),
                        remaining_category_a_exploration,
                    )
                elif phase_name == "category_bcde_exploration":
                    phase_budget = min(
                        max(0, int(configured_budget)),
                        remaining_bcde_exploration,
                    )
                else:
                    phase_budget = min(
                        max(0, int(configured_budget)),
                        remaining_exploitation,
                    )
                if stage_callback is not None:
                    stage_callback(phase_name)
                outcome = self.run_phase(
                    session,
                    phase_name=phase_name,
                    time_budget_seconds=phase_budget,
                    progress_callback=progress_callback,
                )
                spent_seconds = max(0, int(float(outcome.get("elapsed_s", 0.0) or 0.0) + 0.999))
                if phase_name == "category_a_exploration":
                    remaining_category_a_exploration = max(
                        0,
                        remaining_category_a_exploration - spent_seconds,
                    )
                elif phase_name == "category_bcde_exploration":
                    remaining_bcde_exploration = max(
                        0,
                        remaining_bcde_exploration - spent_seconds,
                    )
                else:
                    remaining_exploitation = max(0, remaining_exploitation - spent_seconds)
        except CycleBudgetExceeded:
            raise
        except Exception as exc:
            logger.error(
                "[ExpansionWrapper] Two-phase expansion failed for '%s': %s",
                session.normalized_root,
                exc,
            )
            return ExpansionResult(
                root_domain=root_domain,
                endpoint_candidates=set(),
                node_count=0,
                edge_count=0,
                ceilings_hit=False,
                diagnostics={"error": str(exc), "stage": "two_phase_expansion"},
            )

        return self.finalize_session(session)

    def build_session(
        self,
        root_domain: str,
        config: ExpansionConfig,
    ) -> Optional[ExpansionSession]:
        normalized_root = normalize_host(root_domain)
        if not normalized_root:
            return None
        graph: PassiveDiscoveryGraph = PassiveDiscoveryGraph()
        graph.add_node(normalized_root, NodeType.DOMAIN, method="root", confidence=1.0)
        category_a_supports_incremental = all(
            hasattr(self._category_a, attribute)
            for attribute in ("build_context", "run_modules")
        )
        context_overrides = self._build_context_overrides(config)
        context_a = None
        if category_a_supports_incremental:
            context_a = self._category_a.build_context(
                root=normalized_root,
                context_overrides=context_overrides,
            )
        return ExpansionSession(
            root_domain=root_domain,
            normalized_root=normalized_root,
            config=config,
            graph=graph,
            category_a_supports_incremental=category_a_supports_incremental,
            context_overrides=context_overrides,
            context_a=context_a,
            context_bcde=BCDEExpansionContext(
                root_domain=normalized_root,
                max_total_nodes=config.max_total_nodes,
                max_total_edges=config.max_total_edges,
                max_total_endpoints=config.max_total_endpoints,
                max_results=config.max_results,
                time_budget_seconds=max(
                    1,
                    int(config.bcde_time_budget_seconds + config.exploitation_budget_seconds),
                ),
                tls_verification_mode=config.tls_verification_mode,
            ),
        )

    def run_phase(
        self,
        session: ExpansionSession,
        *,
        phase_name: str,
        time_budget_seconds: int,
        per_module_time_slice_seconds: Optional[int] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        budget_seconds = max(0, int(time_budget_seconds))
        if budget_seconds <= 0:
            return self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=0.0,
                status="skipped",
                reason="phase_budget_exhausted",
                productive=False,
            )

        if phase_name == "category_a_exploration":
            return self._run_category_a_phase(
                session,
                phase_name=phase_name,
                enabled_module_names=None,
                time_budget_seconds=budget_seconds,
                per_module_time_slice_seconds=per_module_time_slice_seconds,
                progress_callback=progress_callback,
            )
        if phase_name == "category_bcde_exploration":
            if not session.config.aggressive:
                return self._record_phase_outcome(
                    session,
                    phase_name=phase_name,
                    elapsed_s=0.0,
                    status="skipped",
                    reason="aggressive_mode_disabled",
                    productive=False,
                )
            return self._run_category_bcde_phase(
                session,
                phase_name=phase_name,
                enabled_module_names=None,
                time_budget_seconds=budget_seconds,
                per_module_time_slice_seconds=per_module_time_slice_seconds,
                progress_callback=progress_callback,
            )
        if phase_name == "category_a_exploitation":
            if not session.productive_a_modules:
                return self._record_phase_outcome(
                    session,
                    phase_name=phase_name,
                    elapsed_s=0.0,
                    status="skipped",
                    reason="no_productive_modules",
                    productive=False,
                )
            return self._run_category_a_phase(
                session,
                phase_name=phase_name,
                enabled_module_names=set(session.productive_a_modules),
                time_budget_seconds=budget_seconds,
                per_module_time_slice_seconds=per_module_time_slice_seconds,
                progress_callback=progress_callback,
            )
        if phase_name == "category_bcde_exploitation":
            if not session.config.aggressive:
                return self._record_phase_outcome(
                    session,
                    phase_name=phase_name,
                    elapsed_s=0.0,
                    status="skipped",
                    reason="aggressive_mode_disabled",
                    productive=False,
                )
            if not session.productive_bcde_modules:
                return self._record_phase_outcome(
                    session,
                    phase_name=phase_name,
                    elapsed_s=0.0,
                    status="skipped",
                    reason="no_productive_modules",
                    productive=False,
                )
            return self._run_category_bcde_phase(
                session,
                phase_name=phase_name,
                enabled_module_names=set(session.productive_bcde_modules),
                time_budget_seconds=budget_seconds,
                per_module_time_slice_seconds=per_module_time_slice_seconds,
                progress_callback=progress_callback,
            )
        raise ValueError(f"Unsupported expansion phase: {phase_name}")

    def list_phase_module_names(
        self,
        session: ExpansionSession,
        *,
        phase_name: str,
    ) -> List[str]:
        if phase_name == "category_a_exploration":
            modules = self._category_a._resolve_modules(None)
        elif phase_name == "category_bcde_exploration":
            if not session.config.aggressive:
                return []
            modules = self._category_bcde._resolve_modules(None)
        elif phase_name == "category_a_exploitation":
            if not session.productive_a_modules:
                return []
            modules = self._category_a._resolve_modules(set(session.productive_a_modules))
        elif phase_name == "category_bcde_exploitation":
            if not session.config.aggressive or not session.productive_bcde_modules:
                return []
            modules = self._category_bcde._resolve_modules(set(session.productive_bcde_modules))
        else:
            raise ValueError(f"Unsupported expansion phase: {phase_name}")
        return [module.__class__.__name__ for module in modules]

    def run_module_turn(
        self,
        session: ExpansionSession,
        *,
        phase_name: str,
        module_name: str,
        time_budget_seconds: int,
        per_module_time_slice_seconds: Optional[int] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        available_modules = set(
            self.list_phase_module_names(
                session,
                phase_name=phase_name,
            )
        )
        token = str(module_name or "").strip()
        if not token:
            return self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=0.0,
                status="skipped",
                productive=False,
                reason="missing_module_name",
            )
        if token not in available_modules:
            payload = self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=0.0,
                status="skipped",
                productive=False,
                reason="module_unavailable",
            )
            payload["module_name"] = token
            payload["module_status"] = "skipped"
            payload["module_reason"] = "module_unavailable"
            return payload

        start_index = len(session.module_summaries)
        if phase_name.startswith("category_a") and not session.category_a_supports_incremental:
            phase_payload = self.run_phase(
                session,
                phase_name=phase_name,
                time_budget_seconds=time_budget_seconds,
                per_module_time_slice_seconds=per_module_time_slice_seconds,
                progress_callback=progress_callback,
            )
        elif phase_name.startswith("category_a"):
            phase_payload = self._run_category_a_phase(
                session,
                phase_name=phase_name,
                enabled_module_names={token},
                time_budget_seconds=time_budget_seconds,
                per_module_time_slice_seconds=per_module_time_slice_seconds,
                progress_callback=progress_callback,
            )
        elif phase_name.startswith("category_bcde"):
            phase_payload = self._run_category_bcde_phase(
                session,
                phase_name=phase_name,
                enabled_module_names={token},
                time_budget_seconds=time_budget_seconds,
                per_module_time_slice_seconds=per_module_time_slice_seconds,
                progress_callback=progress_callback,
                finalize_on_interrupt=False,
                emit_completion_log=False,
            )
        else:
            raise ValueError(f"Unsupported expansion phase: {phase_name}")

        payload = dict(phase_payload or {})
        payload["module_name"] = token
        module_rows = [
            row
            for row in session.module_summaries[start_index:]
            if str(row.get("module_name", "")).strip() == token
            and str(row.get("phase", "")).strip() == phase_name
        ]
        if module_rows:
            module_row = dict(module_rows[-1])
            payload["module_status"] = str(module_row.get("status", "")).strip() or None
            payload["module_reason"] = (
                str(module_row.get("stop_reason", "")).strip()
                or str(module_row.get("skip_reason", "")).strip()
                or str(module_row.get("error_message", "")).strip()
                or None
            )
            payload["module_summary"] = module_row
        return payload

    def finalize_session(self, session: ExpansionSession) -> ExpansionResult:
        if session.context_bcde is not None and hasattr(self._category_bcde, "finalize_graph"):
            self._category_bcde.finalize_graph(
                session.graph,
                session.context_bcde,
                emit_completion_log=True,
            )
        candidates_raw = extract_bcde_candidates(session.graph, session.normalized_root)
        endpoint_candidates: Set[str] = self._to_canonical_set(candidates_raw)
        candidate_rows = [
            {
                "entity_id": f"{str(candidate.host or '').strip().lower()}:{int(candidate.port or 0)}",
                "hostname": str(candidate.host or "").strip().lower(),
                "port": int(candidate.port or 0),
                "scheme": str(candidate.scheme or "https").strip().lower() or "https",
                "source": str(candidate.source or "").strip(),
                "confidence": round(float(candidate.confidence or 0.0), 4),
                "metadata": dict(candidate.metadata or {}),
            }
            for candidate in candidates_raw
            if str(candidate.host or "").strip() and int(candidate.port or 0) > 0
        ]
        final_node_count = len(session.graph.all_nodes())
        final_edge_count = len(session.graph.all_edges())
        final_endpoint_count = len(session.graph.get_nodes_by_type(NodeType.ENDPOINT))
        ceilings_hit = (
            final_node_count >= session.config.max_total_nodes
            or final_edge_count >= session.config.max_total_edges
            or final_endpoint_count >= session.config.max_total_endpoints
        )
        t_total = sum(float(value or 0.0) for value in session.timing.values())
        diagnostics: Dict[str, Any] = {
            "t_total_s": round(t_total, 3),
            "raw_candidate_count": len(candidates_raw),
            "canonical_candidate_count": len(endpoint_candidates),
            "candidate_rows": candidate_rows,
            "timing": {key: round(value, 3) for key, value in session.timing.items()},
            "productive_category_a_modules": sorted(session.productive_a_modules),
            "productive_bcde_modules": sorted(session.productive_bcde_modules),
            "module_summaries": list(session.module_summaries),
            "phase_outcomes": list(session.phase_outcomes),
            "module_timings": dict(session.graph.module_timings),
        }
        logger.info(
            "[ExpansionWrapper] Expansion complete: %s candidates | nodes=%s edges=%s | "
            "exploration=(A %.2fs, BCDE %.2fs) exploitation=(A %.2fs, BCDE %.2fs) | root=%s",
            len(endpoint_candidates),
            final_node_count,
            final_edge_count,
            session.timing["a_exploration_s"],
            session.timing["bcde_exploration_s"],
            session.timing["a_exploitation_s"],
            session.timing["bcde_exploitation_s"],
            session.normalized_root,
        )
        return ExpansionResult(
            root_domain=session.root_domain,
            endpoint_candidates=endpoint_candidates,
            node_count=final_node_count,
            edge_count=final_edge_count,
            ceilings_hit=ceilings_hit,
            diagnostics=diagnostics,
        )

    def _build_context_overrides(self, config: ExpansionConfig) -> Dict[str, Any]:
        return {
            "max_san_recursion": config.max_san_recursion,
            "max_dns_recursion": config.max_dns_recursion,
            "max_spf_recursion": config.max_spf_recursion,
            "max_results": config.max_results,
            "time_budget_seconds": config.category_a_time_budget_seconds,
            "max_total_nodes": config.max_total_nodes,
            "max_total_edges": config.max_total_edges,
            "max_total_endpoints": config.max_total_endpoints,
            "tls_verification_mode": config.tls_verification_mode,
        }

    def _module_recorder(
        self,
        session: ExpansionSession,
        phase_name: str,
    ) -> Callable[[Dict[str, Any]], None]:
        def _record_module(summary: Dict[str, Any]) -> None:
            payload = dict(summary)
            payload.setdefault("phase", phase_name)
            session.module_summaries.append(payload)
            if not bool(payload.get("productive")):
                return
            module_name = str(payload.get("module_name", "")).strip()
            if not module_name:
                return
            category = str(payload.get("category", "")).strip().upper()
            if category == "A":
                session.productive_a_modules.add(module_name)
            elif category == "BCDE":
                session.productive_bcde_modules.add(module_name)

        return _record_module

    def _run_category_a_phase(
        self,
        session: ExpansionSession,
        *,
        phase_name: str,
        enabled_module_names: Optional[Set[str]],
        time_budget_seconds: int,
        per_module_time_slice_seconds: Optional[int] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        if not session.category_a_supports_incremental:
            t0 = time.time()
            session.graph = self._category_a.get_full_graph(
                session.normalized_root,
                context_overrides=session.context_overrides,
            )
            elapsed_s = max(0.0, time.time() - t0)
            session.timing["a_exploration_s" if phase_name.endswith("exploration") else "a_exploitation_s"] += elapsed_s
            return self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=elapsed_s,
                status="completed",
                productive=len(session.graph.all_nodes()) > 1,
            )

        start_index = len(session.module_summaries)
        t0 = time.time()
        session.graph = self._category_a.run_modules(
            session.graph,
            session.context_a,
            enabled_module_names=enabled_module_names,
            progress_callback=progress_callback,
            module_observer=self._module_recorder(session, phase_name),
            time_budget_seconds=time_budget_seconds,
            per_module_time_slice_seconds=(
                max(1, int(per_module_time_slice_seconds))
                if per_module_time_slice_seconds is not None
                else session.config.module_time_slice_seconds
            ),
        )
        elapsed_s = max(0.0, time.time() - t0)
        timing_key = "a_exploration_s" if phase_name.endswith("exploration") else "a_exploitation_s"
        session.timing[timing_key] += elapsed_s
        return self._summarize_phase(
            session,
            phase_name=phase_name,
            start_index=start_index,
            elapsed_s=elapsed_s,
        )

    def _run_category_bcde_phase(
        self,
        session: ExpansionSession,
        *,
        phase_name: str,
        enabled_module_names: Optional[Set[str]],
        time_budget_seconds: int,
        per_module_time_slice_seconds: Optional[int] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        finalize_on_interrupt: bool = True,
        emit_completion_log: bool = True,
    ) -> Dict[str, Any]:
        start_index = len(session.module_summaries)
        bcde_context = session.context_bcde or BCDEExpansionContext(
            root_domain=session.normalized_root,
            max_total_nodes=session.config.max_total_nodes,
            max_total_edges=session.config.max_total_edges,
            max_total_endpoints=session.config.max_total_endpoints,
            max_results=session.config.max_results,
            time_budget_seconds=time_budget_seconds,
            tls_verification_mode=session.config.tls_verification_mode,
        )
        bcde_context.time_budget_seconds = max(1, int(time_budget_seconds))
        bcde_context.deadline_unix_ms = int(time.time() * 1000) + (time_budget_seconds * 1000)
        bcde_context.cancel_requested = False
        session.context_bcde = bcde_context
        t0 = time.time()
        resolved_time_slice_seconds = (
            max(1, int(per_module_time_slice_seconds))
            if per_module_time_slice_seconds is not None
            else session.config.module_time_slice_seconds
        )
        if phase_name == "category_bcde_exploration":
            resolved_time_slice_seconds = min(
                max(1, int(resolved_time_slice_seconds)),
                50,
            )
        session.graph = self._category_bcde.run_modules(
            session.graph,
            bcde_context,
            enabled_module_names=enabled_module_names,
            progress_callback=progress_callback,
            module_observer=self._module_recorder(session, phase_name),
            time_budget_seconds=time_budget_seconds,
            per_module_time_slice_seconds=resolved_time_slice_seconds,
            finalize_on_interrupt=finalize_on_interrupt,
            emit_completion_log=emit_completion_log,
        )
        elapsed_s = max(0.0, time.time() - t0)
        timing_key = "bcde_exploration_s" if phase_name.endswith("exploration") else "bcde_exploitation_s"
        session.timing[timing_key] += elapsed_s
        return self._summarize_phase(
            session,
            phase_name=phase_name,
            start_index=start_index,
            elapsed_s=elapsed_s,
        )

    def _summarize_phase(
        self,
        session: ExpansionSession,
        *,
        phase_name: str,
        start_index: int,
        elapsed_s: float,
    ) -> Dict[str, Any]:
        phase_rows = [
            row
            for row in session.module_summaries[start_index:]
            if str(row.get("phase", "")).strip() == phase_name
        ]
        statuses = {str(row.get("status", "")).strip().lower() for row in phase_rows}
        productive = any(bool(row.get("productive")) for row in phase_rows)
        if not phase_rows:
            return self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=elapsed_s,
                status="skipped",
                reason="no_modules_executed",
                productive=False,
            )
        if "interrupted" in statuses:
            return self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=elapsed_s,
                status="interrupted",
                reason="module_deadline_exhausted",
                productive=productive,
            )
        if productive:
            return self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=elapsed_s,
                status="completed",
                productive=True,
            )
        if "failed" in statuses and statuses <= {"failed"}:
            return self._record_phase_outcome(
                session,
                phase_name=phase_name,
                elapsed_s=elapsed_s,
                status="failed",
                reason="all_modules_failed",
                productive=False,
            )
        return self._record_phase_outcome(
            session,
            phase_name=phase_name,
            elapsed_s=elapsed_s,
            status="low_yield",
            reason="no_productive_modules",
            productive=False,
        )

    def _record_phase_outcome(
        self,
        session: ExpansionSession,
        *,
        phase_name: str,
        elapsed_s: float,
        status: str,
        productive: bool,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {
            "phase": str(phase_name).strip(),
            "status": str(status).strip() or "unknown",
            "elapsed_s": round(float(elapsed_s or 0.0), 3),
            "productive": bool(productive),
        }
        if reason:
            payload["reason"] = str(reason).strip()
        session.phase_outcomes.append(payload)
        return payload

    @staticmethod
    def _to_canonical_set(candidates: List) -> Set[str]:
        import ipaddress

        result: Set[str] = set()
        for c in candidates:
            host = getattr(c, "host", None)
            port = getattr(c, "port", 443)
            if not host:
                continue
            host = host.lower().strip()
            for prefix in ("https://", "http://"):
                if host.startswith(prefix):
                    host = host[len(prefix):]
            host = host.split("/")[0]
            if host.startswith("["):
                if "]:" in host:
                    result.add(host)
                else:
                    result.add(f"{host}:{port}")
                continue
            try:
                addr = ipaddress.ip_address(host)
                if addr.version == 6:
                    result.add(f"[{host}]:{port}")
                else:
                    result.add(f"{host}:{port}")
                continue
            except ValueError:
                pass
            if ":" in host:
                result.add(host)
            else:
                result.add(f"{host}:{port}")
        return result


class StubExpansionWrapper:
    def expand(
        self,
        root_domain: str,
        config: ExpansionConfig,
        stage_callback: Optional[Callable[[str], None]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> ExpansionResult:
        _ = config
        _ = stage_callback
        _ = progress_callback
        root = normalize_host(root_domain)
        endpoints = {f"{root}:443"} if root else set()
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates=endpoints,
            node_count=len(endpoints),
            edge_count=0,
            ceilings_hit=False,
            diagnostics={"stub": True},
        )


__all__ = [
    "ExpansionConfig",
    "ExpansionResult",
    "ExpansionSession",
    "ExpansionWrapper",
    "StubExpansionWrapper",
]
