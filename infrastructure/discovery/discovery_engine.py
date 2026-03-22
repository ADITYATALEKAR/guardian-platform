from __future__ import annotations

import inspect
import logging
import random
import threading
import time
import ipaddress
import hashlib
import re
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlsplit

from infrastructure.discovery.scope_utils import extract_registrable_base
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.models import CycleBudgetExceeded
from infrastructure.discovery.expansion_wrapper import (
    ExpansionConfig,
    ExpansionWrapper,
)
from infrastructure.policy_integration.compliance import resolve_tenant_frameworks
from infrastructure.posture.finding_engine import PostureFindingEngine
from infrastructure.posture.signal_extractor import PostureSignalExtractor

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge


logger = logging.getLogger(__name__)


def _deterministic_jitter(endpoint: str, attempt: int, backoff: float) -> float:
    upper_bound = max(0.0, float(backoff) * 0.2)
    if upper_bound <= 0.0:
        return 0.0
    material = f"{str(endpoint or '').strip()}|{int(attempt)}".encode("utf-8")
    bucket = int(hashlib.sha256(material).hexdigest()[:8], 16)
    ratio = bucket / 0xFFFFFFFF
    return upper_bound * ratio


class DiscoveryEngine:
    """
    Concurrency-safe, schema-agnostic discovery engine.

    Responsibilities:
        - Resolve seed endpoints
        - Acquire protocol observations
        - Persist telemetry
        - Expand SAN domains
        - Return raw protocol objects

    Does NOT:
        - Construct RawObservation
        - Enforce Layer0 schema
        - Build snapshots
        - Perform validation
    """

    _MULTI_LABEL_SUFFIXES = {
        ("co", "uk"),
        ("org", "uk"),
        ("gov", "uk"),
        ("ac", "uk"),
        ("com", "au"),
        ("net", "au"),
        ("org", "au"),
        ("co", "jp"),
        ("com", "br"),
        ("com", "mx"),
        ("com", "cn"),
        ("com", "pa"),
    }
    _COMMON_SCOPE_LABELS = {
        "ac",
        "app",
        "bank",
        "cn",
        "co",
        "com",
        "dev",
        "edu",
        "gov",
        "http",
        "https",
        "id",
        "img",
        "io",
        "jp",
        "mail",
        "mx",
        "net",
        "org",
        "pa",
        "prod",
        "qa",
        "stg",
        "stage",
        "static",
        "test",
        "uk",
        "www",
    }
    _PROVIDER_HOST_SUFFIXES = (
        "akamai.net",
        "amazon.com",
        "amazonaws-china.com",
        "amazonaws.com",
        "amazonses.com",
        "azureedge.net",
        "cloudflare.com",
        "cloudflare.net",
        "cloudfront.net",
        "edgekey.net",
        "edgesuite.net",
        "fastly.net",
        "forcepoint.net",
        "forcepoint.tools",
        "googleapis.com",
        "gstatic.com",
        "mail.protection.outlook.com",
        "mailcontrol.com",
        "mimecast.com",
        "office365.com",
        "outlook.com",
        "protection.outlook.com",
        "sendgrid.net",
        "trafficmanager.net",
        "websense.com",
        "websense.net",
        "windows.net",
        "zendesk.com",
    )

    def __init__(
        self,
        storage: StorageManager,
        max_workers: int = 10,
        max_endpoints: int = 5_000,
        samples_per_endpoint: int = 8,
        expansion_wrapper: Optional[ExpansionWrapper] = None,
        expansion_max_total_nodes: int = 250_000,
        expansion_max_total_edges: int = 500_000,
        expansion_max_total_endpoints: int = 100_000,
        max_san_recursion: int = 5,
        max_dns_recursion: int = 5,
        max_spf_recursion: int = 5,
        expansion_max_results: int = 10_000,
        category_a_time_budget_seconds: int = 150,
        bcde_time_budget_seconds: int = 150,
        cycle_time_budget_seconds: int = 600,
        exploration_budget_seconds: int = 300,
        exploitation_budget_seconds: int = 300,
        module_time_slice_seconds: int = 30,
        include_http_probe: bool = True,
        enable_phase5_findings: bool = True,
        enable_ct_longitudinal: bool = False,
        max_ct_calls_per_cycle: int = 5,
        tls_verification_mode: str = "strict",
        allow_insecure_tls: bool = False,
    ):
        self.storage = storage
        self.max_workers = min(
            max(1, int(max_workers)),
            self.MAX_WORKERS_CAP,
        )
        self.max_endpoints = min(
            max(1, int(max_endpoints)),
            self.MAX_ENDPOINTS_CAP,
        )
        self.samples_per_endpoint = max(5, int(samples_per_endpoint))

        self.expansion_max_total_nodes = min(
            max(1_000, int(expansion_max_total_nodes)),
            self.MAX_EXPANSION_CEILING_NODES,
        )
        self.expansion_max_total_edges = min(
            max(1_000, int(expansion_max_total_edges)),
            self.MAX_EXPANSION_CEILING_EDGES,
        )
        self.expansion_max_total_endpoints = min(
            max(100, int(expansion_max_total_endpoints)),
            self.MAX_EXPANSION_CEILING_ENDPOINTS,
        )
        self.max_san_recursion = min(max(1, int(max_san_recursion)), 10)
        self.max_dns_recursion = min(max(1, int(max_dns_recursion)), 10)
        self.max_spf_recursion = min(max(1, int(max_spf_recursion)), 15)
        self.expansion_max_results = min(
            max(100, int(expansion_max_results)),
            self.MAX_EXPANSION_RESULTS_CAP,
        )
        self.category_a_time_budget_seconds = min(
            max(1, int(category_a_time_budget_seconds)),
            self.MAX_CATEGORY_A_TIME_BUDGET_SECONDS,
        )
        self.bcde_time_budget_seconds = min(
            max(1, int(bcde_time_budget_seconds)),
            self.MAX_BCDE_TIME_BUDGET_SECONDS,
        )
        self.cycle_time_budget_seconds = min(
            max(1, int(cycle_time_budget_seconds)),
            self.MAX_CYCLE_TIME_BUDGET_SECONDS,
        )
        self.exploration_budget_seconds = min(
            max(1, int(exploration_budget_seconds)),
            self.MAX_CYCLE_TIME_BUDGET_SECONDS,
        )
        self.exploitation_budget_seconds = min(
            max(1, int(exploitation_budget_seconds)),
            self.MAX_CYCLE_TIME_BUDGET_SECONDS,
        )
        self.module_time_slice_seconds = min(
            max(1, int(module_time_slice_seconds)),
            self.MAX_CYCLE_TIME_BUDGET_SECONDS,
        )
        self.include_http_probe = bool(include_http_probe)
        self.enable_phase5_findings = bool(enable_phase5_findings)
        mode = str(tls_verification_mode or "strict").strip().lower()
        if mode not in {"strict", "insecure"}:
            raise ValueError("tls_verification_mode must be 'strict' or 'insecure'")
        if mode == "insecure" and not bool(allow_insecure_tls):
            raise ValueError(
                "insecure TLS mode is blocked by default; set allow_insecure_tls=True "
                "explicitly to enable non-validating probes"
            )
        self.tls_verification_mode = mode
        if self.tls_verification_mode == "insecure":
            logger.warning(
                "[DiscoveryEngine] TLS verification disabled by explicit config. "
                "Use only in controlled non-production environments."
            )

        self._expansion_wrapper = expansion_wrapper or ExpansionWrapper()
        self._lock = threading.Lock()
        self._bridge = ObservationBridge()
        self._posture_extractor = PostureSignalExtractor()
        self._finding_engine = PostureFindingEngine(
            enable_ct_longitudinal=bool(enable_ct_longitudinal),
            max_ct_calls_per_cycle=max_ct_calls_per_cycle,
        )
        self._last_reporting_metrics: Dict[str, Any] = {
            "total_discovered_domains": 0,
            "total_successful_observations": 0,
            "total_failed_observations": 0,
            "discovered_surface": [],
            "expansion_summary": {},
        }
        self._last_raw_results: List[object] = []

    def get_last_reporting_metrics(self) -> Dict[str, Any]:
        return dict(self._last_reporting_metrics)

    def get_last_raw_results(self) -> List[object]:
        """Return whatever raw observations were collected in the last run.

        Safe to call even if run_discovery raised CycleBudgetExceeded — returns
        whatever was accumulated before the budget was exhausted.
        """
        return list(self._last_raw_results)

    # ==========================================================
    # PUBLIC ENTRYPOINT
    # ==========================================================

    def run_discovery(
        self,
        tenant_id: str,
        rate_controller,
        cycle_id: str,
        seed_endpoints: Optional[List[str]] = None,
        expansion_mode: str = "A_BCDE",
        stage_callback: Optional[Callable[[str], None]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        enable_ct_longitudinal: Optional[bool] = None,
        cycle_deadline_unix_ms: Optional[int] = None,
    ) -> List[object]:

        if not self.storage.tenant_exists(tenant_id):
            raise ValueError(f"Tenant does not exist: {tenant_id}")

        roots = self._resolve_roots(tenant_id, seed_endpoints)

        if not roots:
            raise RuntimeError(
                f"No discovery roots available for tenant '{tenant_id}'."
            )

        # =====================================================
        # EXPANSION — surface intelligence (additive only)
        # =====================================================
        # Extract unique root domains from ALL seeds, not just the first.
        # Each distinct root domain gets its own expansion pass.
        # Candidates from all roots are merged additively.
        # Expansion candidates never remove or downgrade known seeds.
        # If expansion throws for any root, that root falls back silently.
        #
        # SINGLE-ROOT NOTE: If a cycle is intentionally single-root
        # (e.g. tenants always have one canonical domain), pass a single
        # seed and this loop runs exactly once.
        unique_root_domains: List[str] = []
        seen_roots: Set[str] = set()
        for ep in roots:
            rd = self._extract_root_domain(ep)
            if rd and rd not in seen_roots:
                seen_roots.add(rd)
                unique_root_domains.append(rd)

        planned_scopes: List[str] = []
        seen_scopes: Set[str] = set()
        for root_domain in unique_root_domains:
            for scope in (root_domain, self._extract_registrable_base(root_domain)):
                if not scope or scope in seen_scopes:
                    continue
                seen_scopes.add(scope)
                planned_scopes.append(scope)

        last_progress_emit = 0.0
        effective_cycle_deadline_ms = (
            int(cycle_deadline_unix_ms)
            if cycle_deadline_unix_ms is not None
            else int((time.time() + float(self.cycle_time_budget_seconds)) * 1000)
        )

        def _cycle_budget_remaining_seconds() -> int:
            remaining_ms = effective_cycle_deadline_ms - int(time.time() * 1000)
            return max(0, remaining_ms // 1000)

        def _cycle_budget_remaining_seconds_precise() -> float:
            remaining_ms = effective_cycle_deadline_ms - int(time.time() * 1000)
            return max(0.0, float(remaining_ms) / 1000.0)

        def _assert_cycle_budget(stage_name: str) -> None:
            if int(time.time() * 1000) > effective_cycle_deadline_ms:
                raise CycleBudgetExceeded(f"cycle time budget exceeded during {stage_name}")

        def _emit_progress(
            updates: Optional[Dict[str, Any]] = None,
            *,
            force: bool = False,
            **extra_updates: Any,
        ) -> None:
            nonlocal last_progress_emit
            if progress_callback is None:
                return
            payload: Dict[str, Any] = {}
            if isinstance(updates, dict):
                payload.update(updates)
            elif updates is not None:
                raise TypeError("discovery progress updates must be a mapping")
            payload.update(extra_updates)
            payload = {
                k: v
                for k, v in payload.items()
                if v is not None
            }
            if not payload:
                return
            now = time.time()
            is_expansion_update = any(str(key).startswith("expansion_") for key in payload)
            if not force and not is_expansion_update and (now - last_progress_emit) < 0.75:
                return
            progress_callback(payload)
            last_progress_emit = now

        _emit_progress(
            force=True,
            seed_endpoint_count=len(roots),
            root_scope_count=len(planned_scopes),
            planned_scope_count=len(planned_scopes),
            expansion_scope_processed_count=0,
            expanded_candidate_count=0,
            total_candidate_count=len(roots),
            discovered_related_count_live=0,
            inflight_candidate_count=0,
            candidate_count_by_scope={},
            observation_target_count=0,
            observation_cap_hit=False,
            observed_completed_count=0,
            observed_successful_count=0,
            observed_failed_count=0,
        )

        expanded_candidates: Set[str] = set()
        if expansion_mode not in {"A_ONLY", "A_BCDE"}:
            raise ValueError(f"Invalid expansion_mode: {expansion_mode}")

        expansion_config = ExpansionConfig(
            aggressive=(expansion_mode == "A_BCDE"),
            max_total_nodes=self.expansion_max_total_nodes,
            max_total_edges=self.expansion_max_total_edges,
            max_total_endpoints=self.expansion_max_total_endpoints,
            max_san_recursion=self.max_san_recursion,
            max_dns_recursion=self.max_dns_recursion,
            max_spf_recursion=self.max_spf_recursion,
            max_results=self.expansion_max_results,
            category_a_time_budget_seconds=self.category_a_time_budget_seconds,
            bcde_time_budget_seconds=self.bcde_time_budget_seconds,
            exploration_budget_seconds=self.exploration_budget_seconds,
            exploitation_budget_seconds=self.exploitation_budget_seconds,
            module_time_slice_seconds=self.module_time_slice_seconds,
            tls_verification_mode=self.tls_verification_mode,
        )

        scopes_processed: Set[str] = set()
        expansion_scope_summaries: List[Dict[str, Any]] = []
        expansion_errors: List[Dict[str, Any]] = []
        expansion_phase_history: List[Dict[str, Any]] = []
        remaining_category_a_exploration_seconds = max(
            0,
            int(expansion_config.category_a_time_budget_seconds),
        )
        remaining_bcde_exploration_seconds = max(
            0,
            int(expansion_config.bcde_time_budget_seconds),
        )
        remaining_exploitation_seconds = max(0, int(expansion_config.exploitation_budget_seconds))
        try:
            expand_signature = inspect.signature(self._expansion_wrapper.expand)
            wrapper_supports_progress = "progress_callback" in expand_signature.parameters
        except Exception:
            wrapper_supports_progress = True
        try:
            turn_signature = inspect.signature(self._expansion_wrapper.run_module_turn)
            wrapper_supports_turn_progress = "progress_callback" in turn_signature.parameters
        except Exception:
            wrapper_supports_turn_progress = wrapper_supports_progress
        window_phase_api = all(
            callable(getattr(self._expansion_wrapper, name, None))
            for name in ("build_session", "list_phase_module_names", "run_module_turn", "finalize_session")
        )
        cycle_phase_api = all(
            callable(getattr(self._expansion_wrapper, name, None))
            for name in ("build_session", "run_phase", "finalize_session")
        )
        if window_phase_api:
            scope_sessions: List[tuple[str, Any]] = []
            for scope in planned_scopes:
                try:
                    session = self._expansion_wrapper.build_session(scope, expansion_config)
                    if session is None:
                        expansion_errors.append({"scope": scope, "error": "invalid_scope"})
                        continue
                    scope_sessions.append((scope, session))
                except Exception as exc:
                    expansion_errors.append({"scope": scope, "error": str(exc)})
                    logger.error(
                        "[DiscoveryEngine] Expansion session build failed for '%s': %s",
                        scope,
                        exc,
                    )

            window_specs = [
                {
                    "window_name": "category_a_window",
                    "stage_name": "category_a_exploration",
                    "active_category": "A",
                    "budget_seconds": int(expansion_config.category_a_time_budget_seconds),
                    "turn_slice_seconds": 15,
                },
                {
                    "window_name": "category_bcde_window",
                    "stage_name": "category_bcde_exploration",
                    "active_category": "BCDE",
                    "budget_seconds": int(expansion_config.bcde_time_budget_seconds),
                    "turn_slice_seconds": 15,
                },
                {
                    "window_name": "productive_exploitation_window",
                    "stage_name": "productive_exploitation",
                    "active_category": "A+BCDE",
                    "budget_seconds": int(expansion_config.exploitation_budget_seconds),
                    "turn_slice_seconds": 25,
                },
            ]

            def _collect_productive_modules() -> tuple[List[str], List[str]]:
                productive_a: Set[str] = set()
                productive_bcde: Set[str] = set()
                for _, session in scope_sessions:
                    productive_a.update(
                        str(name).strip()
                        for name in getattr(session, "productive_a_modules", set()) or set()
                        if str(name).strip()
                    )
                    productive_bcde.update(
                        str(name).strip()
                        for name in getattr(session, "productive_bcde_modules", set()) or set()
                        if str(name).strip()
                    )
                return sorted(productive_a), sorted(productive_bcde)

            def _list_phase_modules(session: Any, phase_name: str) -> List[str]:
                try:
                    rows = self._expansion_wrapper.list_phase_module_names(
                        session,
                        phase_name=phase_name,
                    )
                except TypeError:
                    rows = self._expansion_wrapper.list_phase_module_names(session, phase_name)
                return [
                    str(name).strip()
                    for name in list(rows or [])
                    if str(name).strip()
                ]

            def _build_window_scope_states(window_name: str) -> tuple[List[Dict[str, Any]], int]:
                scope_states: List[Dict[str, Any]] = []
                total_entries = 0
                for scope, session in scope_sessions:
                    if window_name == "category_a_window":
                        phase_names = ["category_a_exploration"]
                    elif window_name == "category_bcde_window":
                        if not expansion_config.aggressive:
                            continue
                        phase_names = ["category_bcde_exploration"]
                    else:
                        phase_names = ["category_a_exploitation"]
                        if expansion_config.aggressive:
                            phase_names.append("category_bcde_exploitation")
                    entries: List[Dict[str, Any]] = []
                    for phase_name in phase_names:
                        for module_name in _list_phase_modules(session, phase_name):
                            entries.append(
                                {
                                    "scope": scope,
                                    "session": session,
                                    "phase_name": phase_name,
                                    "module_name": module_name,
                                    "category": (
                                        "A"
                                        if phase_name.startswith("category_a")
                                        else "BCDE"
                                    ),
                                    "seen_once": False,
                                    "retired": False,
                                    "turns_completed": 0,
                                    "first_turn_seen": False,
                                }
                            )
                    if entries:
                        total_entries += len(entries)
                        scope_states.append(
                            {
                                "scope": scope,
                                "session": session,
                                "entries": entries,
                                "cursor": 0,
                                "turns_completed": 0,
                                "seen_once": False,
                            }
                        )
                return scope_states, total_entries

            def _scope_has_runnable_entries(
                scope_state: Dict[str, Any],
                *,
                initial_pass_completed: bool,
            ) -> bool:
                for entry in list(scope_state.get("entries") or []):
                    if bool(entry.get("retired")):
                        continue
                    if not initial_pass_completed and bool(entry.get("seen_once")):
                        continue
                    return True
                return False

            def _count_runnable_entries(
                scope_state_rows: List[Dict[str, Any]],
                *,
                initial_pass_completed: bool,
            ) -> int:
                count = 0
                for scope_state in scope_state_rows:
                    for entry in list(scope_state.get("entries") or []):
                        if bool(entry.get("retired")):
                            continue
                        if not initial_pass_completed and bool(entry.get("seen_once")):
                            continue
                        count += 1
                return count

            def _select_scope_index(
                scope_state_rows: List[Dict[str, Any]],
                *,
                start_index: int,
                initial_pass_completed: bool,
            ) -> Optional[int]:
                total = len(scope_state_rows)
                if total <= 0:
                    return None
                for offset in range(total):
                    index = (start_index + offset) % total
                    if _scope_has_runnable_entries(
                        scope_state_rows[index],
                        initial_pass_completed=initial_pass_completed,
                    ):
                        return index
                return None

            def _select_entry_index(
                scope_state: Dict[str, Any],
                *,
                initial_pass_completed: bool,
            ) -> Optional[int]:
                entries = list(scope_state.get("entries") or [])
                total = len(entries)
                if total <= 0:
                    return None
                start_index = max(0, int(scope_state.get("cursor", 0) or 0)) % total
                for offset in range(total):
                    index = (start_index + offset) % total
                    entry = entries[index]
                    if bool(entry.get("retired")):
                        continue
                    if not initial_pass_completed and bool(entry.get("seen_once")):
                        continue
                    return index
                return None

            def _should_retire_turn(turn_result: Dict[str, Any]) -> bool:
                module_status = str(
                    turn_result.get("module_status")
                    or turn_result.get("status")
                    or ""
                ).strip().lower()
                module_reason = str(
                    turn_result.get("module_reason")
                    or turn_result.get("reason")
                    or ""
                ).strip().lower()
                if module_status == "failed":
                    return True
                return module_reason in {
                    "module_unavailable",
                    "unsupported_module",
                    "scope_quality_requires_registrable_base",
                    "aggressive_mode_disabled",
                }

            inflight_surface_ids: Set[str] = set()
            inflight_candidate_ids: Set[str] = set()
            inflight_surface_by_scope: Dict[str, Set[str]] = {}

            def _record_live_surface(scope: str, module_summary: Optional[Dict[str, Any]]) -> None:
                if not isinstance(module_summary, dict):
                    return
                scope_token = str(scope or "").strip()
                if not scope_token:
                    return
                scope_surface = inflight_surface_by_scope.setdefault(scope_token, set())
                changed = False
                for field_name in ("new_domain_ids", "new_endpoint_ids"):
                    values = module_summary.get(field_name)
                    if not isinstance(values, list):
                        continue
                    for value in values:
                        token = str(value or "").strip()
                        if not token:
                            continue
                        if token not in inflight_surface_ids:
                            inflight_surface_ids.add(token)
                            changed = True
                        scope_surface.add(token)
                        if field_name == "new_endpoint_ids":
                            inflight_candidate_ids.add(token)
                if not changed:
                    return
                _emit_progress(
                    force=True,
                    discovered_related_count_live=len(inflight_surface_ids),
                    inflight_candidate_count=len(inflight_candidate_ids),
                    candidate_count_by_scope={
                        key: len(values)
                        for key, values in sorted(inflight_surface_by_scope.items())
                    },
                    expanded_candidate_count=max(
                        len(expanded_candidates),
                        len(inflight_candidate_ids),
                    ),
                    total_candidate_count=max(
                        len(set(roots) | expanded_candidates),
                        len(roots) + len(inflight_candidate_ids),
                    ),
                )

            for window_index, spec in enumerate(window_specs, start=1):
                if _cycle_budget_remaining_seconds() <= 0:
                    break
                if not expansion_config.aggressive and spec["active_category"] == "BCDE":
                    timestamp = int(time.time() * 1000)
                    expansion_phase_history.append(
                        {
                            "phase": spec["stage_name"],
                            "window": spec["window_name"],
                            "status": "skipped",
                            "reason": "aggressive_mode_disabled",
                            "scope_total_count": len(scope_sessions),
                            "scope_completed_count": 0,
                            "module_turn_count": 0,
                            "budget_allocated_seconds": int(spec["budget_seconds"]),
                            "budget_consumed_seconds": 0,
                            "budget_remaining_seconds": int(spec["budget_seconds"]),
                            "logical_turn_budget_seconds": 0,
                            "actual_elapsed_seconds": 0.0,
                            "idle_gap_seconds": float(spec["budget_seconds"]),
                            "started_at_unix_ms": timestamp,
                            "ended_at_unix_ms": timestamp,
                        }
                    )
                    continue

                scope_states, coverage_entries_total = _build_window_scope_states(
                    spec["window_name"]
                )
                phase_started_at_unix_ms = int(time.time() * 1000)
                window_budget_seconds = max(0, int(spec["budget_seconds"]))
                follow_up_turn_slice_seconds = max(1, int(spec["turn_slice_seconds"]))
                if stage_callback is not None:
                    stage_callback(spec["stage_name"])

                if not scope_states or window_budget_seconds <= 0:
                    expansion_phase_history.append(
                        {
                            "phase": spec["stage_name"],
                            "window": spec["window_name"],
                            "status": "skipped",
                            "reason": "no_modules_available",
                            "scope_total_count": len(scope_states),
                            "scope_completed_count": 0,
                            "module_turn_count": 0,
                            "budget_allocated_seconds": int(window_budget_seconds),
                            "budget_consumed_seconds": 0,
                            "budget_remaining_seconds": int(window_budget_seconds),
                            "logical_turn_budget_seconds": 0,
                            "actual_elapsed_seconds": 0.0,
                            "idle_gap_seconds": float(window_budget_seconds),
                            "initial_pass_completed": coverage_entries_total == 0,
                            "coverage_entries_total": int(coverage_entries_total),
                            "coverage_entries_completed": 0,
                            "modules_seen_once_count": 0,
                            "scopes_seen_once_count": 0,
                            "started_at_unix_ms": phase_started_at_unix_ms,
                            "ended_at_unix_ms": int(time.time() * 1000),
                        }
                    )
                    _emit_progress(
                        force=True,
                        expansion_window=spec["window_name"],
                        expansion_window_index=window_index,
                        expansion_window_total_count=len(window_specs),
                        expansion_window_budget_seconds=window_budget_seconds,
                        expansion_window_actual_elapsed_seconds=0.0,
                        expansion_window_consumed_seconds=0,
                        expansion_window_remaining_seconds=window_budget_seconds,
                        expansion_turn_slice_seconds=follow_up_turn_slice_seconds,
                        expansion_phase=spec["stage_name"],
                        expansion_active_category=spec["active_category"],
                        expansion_pass_type="initial_pass",
                        initial_pass_completed=(coverage_entries_total == 0),
                        coverage_entries_total=coverage_entries_total,
                        coverage_entries_completed=0,
                        expansion_scope_total_count=len(scope_states),
                        expansion_scope_seen_once_count=0,
                        expansion_modules_seen_once_count=0,
                        discovered_related_count_live=len(inflight_surface_ids),
                        inflight_candidate_count=len(inflight_candidate_ids),
                        candidate_count_by_scope={
                            key: len(values)
                            for key, values in sorted(inflight_surface_by_scope.items())
                        },
                        expansion_phase_history=list(expansion_phase_history),
                    )
                    continue

                window_remaining_seconds = float(window_budget_seconds)
                window_actual_elapsed_seconds = 0.0
                logical_turn_budget_seconds = 0.0
                turns_completed = 0
                productive_scopes: Set[str] = set()
                touched_scopes: Set[str] = set()
                scopes_seen_once: Set[str] = set()
                coverage_entries_completed = 0
                initial_pass_completed = coverage_entries_total == 0
                scope_queue_index = 0
                last_turn_status = "completed"
                last_turn_reason: Optional[str] = None

                _emit_progress(
                    force=True,
                    expansion_window=spec["window_name"],
                    expansion_window_index=window_index,
                    expansion_window_total_count=len(window_specs),
                    expansion_window_budget_seconds=window_budget_seconds,
                    expansion_window_actual_elapsed_seconds=0.0,
                    expansion_window_consumed_seconds=0,
                    expansion_window_remaining_seconds=window_remaining_seconds,
                    expansion_turn_slice_seconds=follow_up_turn_slice_seconds,
                    expansion_phase=spec["stage_name"],
                    expansion_active_category=spec["active_category"],
                    expansion_phase_scope_total_count=len(scope_states),
                    expansion_phase_scope_completed_count=0,
                    expansion_scope_total_count=len(scope_states),
                    expansion_scope_seen_once_count=0,
                    expansion_pass_type=(
                        "follow_up_pass" if initial_pass_completed else "initial_pass"
                    ),
                    initial_pass_completed=initial_pass_completed,
                    coverage_entries_total=coverage_entries_total,
                    coverage_entries_completed=coverage_entries_completed,
                    expansion_modules_seen_once_count=coverage_entries_completed,
                    discovered_related_count_live=len(inflight_surface_ids),
                    inflight_candidate_count=len(inflight_candidate_ids),
                    candidate_count_by_scope={
                        key: len(values)
                        for key, values in sorted(inflight_surface_by_scope.items())
                    },
                    expansion_phase_history=list(expansion_phase_history),
                )

                while (
                    scope_states
                    and window_remaining_seconds > 0.0
                    and _cycle_budget_remaining_seconds_precise() > 0.0
                ):
                    _assert_cycle_budget(spec["stage_name"])
                    if not initial_pass_completed and _count_runnable_entries(
                        scope_states,
                        initial_pass_completed=False,
                    ) <= 0:
                        initial_pass_completed = True
                    selected_scope_index = _select_scope_index(
                        scope_states,
                        start_index=scope_queue_index,
                        initial_pass_completed=initial_pass_completed,
                    )
                    if selected_scope_index is None:
                        break
                    scope_state = scope_states[selected_scope_index]
                    entry_index = _select_entry_index(
                        scope_state,
                        initial_pass_completed=initial_pass_completed,
                    )
                    if entry_index is None:
                        scope_queue_index = (selected_scope_index + 1) % max(
                            1,
                            len(scope_states),
                        )
                        continue
                    if not initial_pass_completed:
                        remaining_unseen_entries = max(
                            1,
                            _count_runnable_entries(
                                scope_states,
                                initial_pass_completed=False,
                            ),
                        )
                        scheduled_turn_slice_seconds = max(
                            1,
                            min(
                                5,
                                int(window_remaining_seconds // remaining_unseen_entries)
                                if window_remaining_seconds > 0
                                else 1,
                            ),
                        )
                    else:
                        scheduled_turn_slice_seconds = follow_up_turn_slice_seconds
                    remaining_cycle_seconds = _cycle_budget_remaining_seconds_precise()
                    turn_budget_seconds = min(
                        float(scheduled_turn_slice_seconds),
                        float(window_remaining_seconds),
                        float(remaining_cycle_seconds),
                    )
                    if turn_budget_seconds <= 0.0:
                        break
                    turn = list(scope_state.get("entries") or [])[entry_index]
                    scope = str(turn["scope"]).strip()
                    session = turn["session"]
                    phase_name = str(turn["phase_name"]).strip()
                    module_name = str(turn["module_name"]).strip()
                    module_category = str(turn["category"]).strip() or spec["active_category"]
                    module_turn_index = turns_completed + 1
                    module_index_within_scope = entry_index + 1
                    productive_a_modules, productive_bcde_modules = _collect_productive_modules()

                    def _turn_progress(
                        updates: Optional[Dict[str, Any]] = None,
                        **extra_updates: Any,
                    ) -> None:
                        _emit_progress(
                            updates,
                            force=True,
                            expansion_window=spec["window_name"],
                            expansion_window_index=window_index,
                            expansion_window_total_count=len(window_specs),
                            expansion_window_budget_seconds=window_budget_seconds,
                            expansion_window_actual_elapsed_seconds=round(
                                window_actual_elapsed_seconds,
                                3,
                            ),
                            expansion_window_consumed_seconds=round(
                                window_actual_elapsed_seconds,
                                3,
                            ),
                            expansion_window_remaining_seconds=window_remaining_seconds,
                            expansion_turn_slice_seconds=scheduled_turn_slice_seconds,
                            expansion_active_category=module_category,
                            expansion_phase=phase_name,
                            expansion_pass_type=(
                                "follow_up_pass" if initial_pass_completed else "initial_pass"
                            ),
                            initial_pass_completed=initial_pass_completed,
                            coverage_entries_total=coverage_entries_total,
                            coverage_entries_completed=coverage_entries_completed,
                            expansion_current_scope=scope,
                            expansion_phase_scope_total_count=len(scope_states),
                            expansion_phase_scope_completed_count=len(touched_scopes),
                            expansion_scope_index=selected_scope_index + 1,
                            expansion_scope_total_count=len(scope_states),
                            expansion_scope_seen_once_count=len(scopes_seen_once),
                            expansion_current_module=module_name,
                            expansion_module_index_within_scope=module_index_within_scope,
                            expansion_modules_completed_count=turns_completed,
                            expansion_module_total_count=coverage_entries_total,
                            expansion_modules_seen_once_count=coverage_entries_completed,
                            expansion_module_turn_index=module_turn_index,
                            expansion_module_turns_completed=turns_completed,
                            expansion_productive_category_a_modules=productive_a_modules,
                            expansion_productive_bcde_modules=productive_bcde_modules,
                            discovered_related_count_live=len(inflight_surface_ids),
                            inflight_candidate_count=len(inflight_candidate_ids),
                            candidate_count_by_scope={
                                key: len(values)
                                for key, values in sorted(inflight_surface_by_scope.items())
                            },
                            expansion_phase_history=list(expansion_phase_history),
                            **extra_updates,
                        )

                    turn_started_at = time.monotonic()
                    try:
                        turn_result = self._expansion_wrapper.run_module_turn(
                            session,
                            phase_name=phase_name,
                            module_name=module_name,
                            time_budget_seconds=max(1, int(turn_budget_seconds + 0.999)),
                            per_module_time_slice_seconds=max(
                                1,
                                int(min(turn_budget_seconds, scheduled_turn_slice_seconds) + 0.999),
                            ),
                            progress_callback=(
                                _turn_progress if wrapper_supports_turn_progress else None
                            ),
                        )
                    except CycleBudgetExceeded:
                        raise
                    except Exception as exc:
                        turn_result = {
                            "phase": phase_name,
                            "module_name": module_name,
                            "module_status": "failed",
                            "module_reason": str(exc),
                            "status": "failed",
                            "reason": str(exc),
                            "elapsed_s": 0.0,
                            "productive": False,
                        }
                        expansion_errors.append({"scope": scope, "error": str(exc)})
                        logger.error(
                            "[DiscoveryEngine] Expansion turn '%s/%s' failed for '%s': %s",
                            phase_name,
                            module_name,
                            scope,
                            exc,
                        )
                    measured_elapsed_seconds = max(0.0, time.monotonic() - turn_started_at)
                    turn_actual_elapsed_seconds = round(
                        max(
                            measured_elapsed_seconds,
                            self._safe_float(
                                turn_result.get("actual_elapsed_s", turn_result.get("elapsed_s"))
                            ),
                        ),
                        3,
                    )

                    turns_completed += 1
                    touched_scopes.add(scope)
                    scope_state["turns_completed"] = int(
                        scope_state.get("turns_completed", 0) or 0
                    ) + 1
                    turn["turns_completed"] = int(turn.get("turns_completed", 0) or 0) + 1
                    if not bool(turn.get("seen_once")):
                        turn["seen_once"] = True
                        turn["first_turn_seen"] = True
                        coverage_entries_completed += 1
                    if scope not in scopes_seen_once:
                        scopes_seen_once.add(scope)
                        scope_state["seen_once"] = True
                    logical_turn_budget_seconds = round(
                        logical_turn_budget_seconds + float(turn_budget_seconds),
                        3,
                    )
                    window_actual_elapsed_seconds = round(
                        window_actual_elapsed_seconds + float(turn_actual_elapsed_seconds),
                        3,
                    )
                    window_remaining_seconds = max(
                        0.0,
                        float(window_budget_seconds) - float(window_actual_elapsed_seconds),
                    )
                    if bool(turn_result.get("productive")):
                        productive_scopes.add(scope)
                    last_turn_status = str(
                        turn_result.get("module_status")
                        or turn_result.get("status")
                        or ""
                    ).strip().lower() or "completed"
                    last_turn_reason = str(
                        turn_result.get("module_reason")
                        or turn_result.get("reason")
                        or ""
                    ).strip() or None
                    latest_module_row = None
                    session_rows = getattr(session, "module_summaries", None)
                    if isinstance(session_rows, list):
                        for row in reversed(session_rows):
                            if not isinstance(row, dict):
                                continue
                            if (
                                str(row.get("module_name", "")).strip() == module_name
                                and str(row.get("phase", "")).strip() == phase_name
                            ):
                                latest_module_row = row
                                break
                    if isinstance(latest_module_row, dict):
                        latest_module_row["actual_elapsed_s"] = turn_actual_elapsed_seconds
                        latest_module_row["logical_budget_consumed_s"] = round(
                            float(turn_budget_seconds),
                            3,
                        )
                        latest_module_row["scheduled_turn_slice_seconds"] = int(
                            scheduled_turn_slice_seconds
                        )
                        latest_module_row["time_slice_exceeded"] = bool(
                            latest_module_row.get("time_slice_exceeded")
                            or str(last_turn_reason or "").strip().lower()
                            == "module_time_slice_exhausted"
                        )
                        latest_module_row["first_turn_seen"] = bool(
                            turn.get("first_turn_seen")
                        )
                        latest_module_row["resumed_turn_count"] = max(
                            0,
                            int(turn.get("turns_completed", 0) or 0) - 1,
                        )
                        latest_module_row["permanently_exhausted"] = False
                        module_summary = turn_result.get("module_summary")
                        if isinstance(module_summary, dict):
                            module_summary.update(latest_module_row)
                        _record_live_surface(scope, latest_module_row)
                    if _should_retire_turn(dict(turn_result or {})):
                        turn["retired"] = True
                        if isinstance(latest_module_row, dict):
                            latest_module_row["permanently_exhausted"] = True
                            module_summary = turn_result.get("module_summary")
                            if isinstance(module_summary, dict):
                                module_summary.update(latest_module_row)
                    scope_state["cursor"] = (
                        (entry_index + 1)
                        % max(1, len(list(scope_state.get("entries") or [])))
                    )
                    scope_queue_index = (selected_scope_index + 1) % max(
                        1,
                        len(scope_states),
                    )
                    if (
                        not initial_pass_completed
                        and coverage_entries_completed >= coverage_entries_total
                    ):
                        initial_pass_completed = True

                    productive_a_modules, productive_bcde_modules = _collect_productive_modules()
                    _emit_progress(
                        force=True,
                        expansion_window=spec["window_name"],
                        expansion_window_index=window_index,
                        expansion_window_total_count=len(window_specs),
                        expansion_window_budget_seconds=window_budget_seconds,
                        expansion_window_actual_elapsed_seconds=round(
                            window_actual_elapsed_seconds,
                            3,
                        ),
                        expansion_window_consumed_seconds=round(
                            window_actual_elapsed_seconds,
                            3,
                        ),
                        expansion_window_remaining_seconds=window_remaining_seconds,
                        expansion_turn_slice_seconds=scheduled_turn_slice_seconds,
                        expansion_active_category=module_category,
                        expansion_phase=phase_name,
                        expansion_current_scope=scope,
                        expansion_phase_scope_total_count=len(scope_states),
                        expansion_phase_scope_completed_count=len(touched_scopes),
                        expansion_scope_index=selected_scope_index + 1,
                        expansion_scope_total_count=len(scope_states),
                        expansion_scope_seen_once_count=len(scopes_seen_once),
                        expansion_current_module=module_name,
                        expansion_module_index_within_scope=module_index_within_scope,
                        expansion_modules_completed_count=turns_completed,
                        expansion_module_total_count=coverage_entries_total,
                        expansion_modules_seen_once_count=coverage_entries_completed,
                        expansion_module_turn_index=module_turn_index,
                        expansion_module_turns_completed=turns_completed,
                        expansion_pass_type=(
                            "follow_up_pass" if initial_pass_completed else "initial_pass"
                        ),
                        initial_pass_completed=initial_pass_completed,
                        coverage_entries_total=coverage_entries_total,
                        coverage_entries_completed=coverage_entries_completed,
                        expansion_productive_category_a_modules=productive_a_modules,
                        expansion_productive_bcde_modules=productive_bcde_modules,
                        discovered_related_count_live=len(inflight_surface_ids),
                        inflight_candidate_count=len(inflight_candidate_ids),
                        candidate_count_by_scope={
                            key: len(values)
                            for key, values in sorted(inflight_surface_by_scope.items())
                        },
                    )

                productive_scope_count = len(productive_scopes)
                phase_status = "completed"
                reason = None
                if turns_completed == 0:
                    phase_status = "skipped"
                    reason = "phase_budget_exhausted"
                elif _cycle_budget_remaining_seconds() <= 0 and window_remaining_seconds > 0:
                    phase_status = "interrupted"
                    reason = "cycle_budget_exhausted"
                elif _count_runnable_entries(
                    scope_states,
                    initial_pass_completed=initial_pass_completed,
                ) <= 0 and productive_scope_count == 0:
                    phase_status = "low_yield"
                    reason = last_turn_reason or "no_runnable_entries"
                elif productive_scope_count == 0:
                    phase_status = "low_yield"
                    reason = last_turn_reason or "no_productive_modules"
                elif last_turn_status in {"interrupted", "failed"}:
                    phase_status = last_turn_status
                    reason = last_turn_reason

                expansion_phase_history.append(
                    {
                        "phase": spec["stage_name"],
                        "window": spec["window_name"],
                        "status": phase_status,
                        "reason": reason,
                        "scope_total_count": len(scope_states),
                        "scope_completed_count": sum(
                            1
                            for state in scope_states
                            if not _scope_has_runnable_entries(
                                state,
                                initial_pass_completed=True,
                            )
                        ),
                        "productive_scope_count": productive_scope_count,
                        "module_turn_count": turns_completed,
                        "budget_allocated_seconds": int(window_budget_seconds),
                        "budget_consumed_seconds": round(
                            window_actual_elapsed_seconds,
                            3,
                        ),
                        "budget_remaining_seconds": round(window_remaining_seconds, 3),
                        "logical_turn_budget_seconds": round(
                            logical_turn_budget_seconds,
                            3,
                        ),
                        "actual_elapsed_seconds": round(
                            window_actual_elapsed_seconds,
                            3,
                        ),
                        "idle_gap_seconds": round(
                            max(
                                0.0,
                                float(window_budget_seconds)
                                - float(window_actual_elapsed_seconds),
                            ),
                            3,
                        ),
                        "initial_pass_completed": bool(initial_pass_completed),
                        "coverage_entries_total": int(coverage_entries_total),
                        "coverage_entries_completed": int(coverage_entries_completed),
                        "modules_seen_once_count": int(coverage_entries_completed),
                        "scopes_seen_once_count": int(len(scopes_seen_once)),
                        "started_at_unix_ms": phase_started_at_unix_ms,
                        "ended_at_unix_ms": int(time.time() * 1000),
                    }
                )
                productive_a_modules, productive_bcde_modules = _collect_productive_modules()
                _emit_progress(
                    force=True,
                    expansion_window=spec["window_name"],
                    expansion_window_index=window_index,
                    expansion_window_total_count=len(window_specs),
                    expansion_window_budget_seconds=window_budget_seconds,
                    expansion_window_actual_elapsed_seconds=round(
                        window_actual_elapsed_seconds,
                        3,
                    ),
                    expansion_window_consumed_seconds=round(
                        window_actual_elapsed_seconds,
                        3,
                    ),
                    expansion_window_remaining_seconds=window_remaining_seconds,
                    expansion_turn_slice_seconds=follow_up_turn_slice_seconds,
                    expansion_active_category=spec["active_category"],
                    expansion_phase=spec["stage_name"],
                    expansion_phase_history=list(expansion_phase_history),
                    expansion_phase_scope_total_count=len(scope_states),
                    expansion_phase_scope_completed_count=len(touched_scopes),
                    expansion_scope_total_count=len(scope_states),
                    expansion_scope_seen_once_count=len(scopes_seen_once),
                    expansion_modules_completed_count=turns_completed,
                    expansion_module_total_count=coverage_entries_total,
                    expansion_modules_seen_once_count=coverage_entries_completed,
                    expansion_module_turns_completed=turns_completed,
                    expansion_pass_type=(
                        "follow_up_pass" if initial_pass_completed else "initial_pass"
                    ),
                    initial_pass_completed=initial_pass_completed,
                    coverage_entries_total=coverage_entries_total,
                    coverage_entries_completed=coverage_entries_completed,
                    expansion_productive_category_a_modules=productive_a_modules,
                    expansion_productive_bcde_modules=productive_bcde_modules,
                    discovered_related_count_live=len(inflight_surface_ids),
                    inflight_candidate_count=len(inflight_candidate_ids),
                    candidate_count_by_scope={
                        key: len(values)
                        for key, values in sorted(inflight_surface_by_scope.items())
                    },
                )

            for scope, session in scope_sessions:
                if not getattr(session, "phase_outcomes", None):
                    continue
                scopes_processed.add(scope)
                expansion_result = self._expansion_wrapper.finalize_session(session)
                expansion_scope_summaries.append(
                    self._build_expansion_scope_summary(
                        scope=scope,
                        expansion_result=expansion_result,
                        module_time_slice_seconds=expansion_config.module_time_slice_seconds,
                    )
                )
                expanded_candidates |= expansion_result.endpoint_candidates
                _emit_progress(
                    force=True,
                    expansion_scope_processed_count=len(scopes_processed),
                    expanded_candidate_count=len(expanded_candidates),
                    total_candidate_count=len(set(roots) | expanded_candidates),
                )
                logger.info(
                    f"[DiscoveryEngine] Expansion for '{scope}': "
                    f"{len(expansion_result.endpoint_candidates)} candidates | "
                    f"nodes={expansion_result.node_count} "
                    f"edges={expansion_result.edge_count} "
                    f"ceilings_hit={expansion_result.ceilings_hit}"
                )
        elif cycle_phase_api:
            scope_sessions: List[tuple[str, Any]] = []
            for scope in planned_scopes:
                try:
                    session = self._expansion_wrapper.build_session(scope, expansion_config)
                    if session is None:
                        expansion_errors.append({"scope": scope, "error": "invalid_scope"})
                        continue
                    scope_sessions.append((scope, session))
                except Exception as exc:
                    expansion_errors.append({"scope": scope, "error": str(exc)})
                    logger.error(
                        "[DiscoveryEngine] Expansion session build failed for '%s': %s",
                        scope,
                        exc,
                    )

            phase_plan = [
                (
                    "category_a_exploration",
                    "A",
                    "category_a_exploration",
                    int(expansion_config.category_a_time_budget_seconds),
                ),
                (
                    "category_bcde_exploration",
                    "BCDE",
                    "category_bcde_exploration",
                    int(expansion_config.bcde_time_budget_seconds),
                ),
                (
                    "category_a_exploitation",
                    "A",
                    "exploitation",
                    int(expansion_config.exploitation_budget_seconds),
                ),
                (
                    "category_bcde_exploitation",
                    "BCDE",
                    "exploitation",
                    int(expansion_config.exploitation_budget_seconds),
                ),
            ]
            for phase_name, active_category, budget_type, configured_budget in phase_plan:
                if not expansion_config.aggressive and active_category == "BCDE":
                    timestamp = int(time.time() * 1000)
                    expansion_phase_history.append(
                        {
                            "phase": phase_name,
                            "status": "skipped",
                            "reason": "aggressive_mode_disabled",
                            "scope_total_count": len(scope_sessions),
                            "scope_completed_count": 0,
                            "started_at_unix_ms": timestamp,
                            "ended_at_unix_ms": timestamp,
                        }
                    )
                    continue

                phase_started_at_unix_ms = int(time.time() * 1000)
                if stage_callback is not None:
                    stage_callback(phase_name)
                _emit_progress(
                    force=True,
                    expansion_active_category=active_category,
                    expansion_phase=phase_name,
                    expansion_phase_scope_total_count=len(scope_sessions),
                    expansion_phase_scope_completed_count=0,
                    expansion_phase_history=list(expansion_phase_history),
                )
                phase_outcomes: List[Dict[str, Any]] = []
                phase_scope_completed = 0
                for scope, session in scope_sessions:
                    _assert_cycle_budget(phase_name)
                    remaining_cycle_seconds = _cycle_budget_remaining_seconds()
                    if budget_type == "category_a_exploration":
                        remaining_budget = remaining_category_a_exploration_seconds
                    elif budget_type == "category_bcde_exploration":
                        remaining_budget = remaining_bcde_exploration_seconds
                    else:
                        remaining_budget = remaining_exploitation_seconds
                    if remaining_cycle_seconds <= 0 or remaining_budget <= 0:
                        break

                    phase_budget_seconds = min(
                        max(0, int(configured_budget)),
                        remaining_budget,
                        remaining_cycle_seconds,
                    )

                    def _phase_progress(
                        updates: Optional[Dict[str, Any]] = None,
                        **extra_updates: Any,
                    ) -> None:
                        _emit_progress(
                            updates,
                            force=True,
                            expansion_phase=phase_name,
                            expansion_current_scope=scope,
                            expansion_phase_scope_total_count=len(scope_sessions),
                            expansion_phase_scope_completed_count=phase_scope_completed,
                            **extra_updates,
                        )

                    try:
                        phase_result = self._expansion_wrapper.run_phase(
                            session,
                            phase_name=phase_name,
                            time_budget_seconds=phase_budget_seconds,
                            progress_callback=_phase_progress if wrapper_supports_progress else None,
                        )
                    except Exception as exc:
                        phase_result = {
                            "phase": phase_name,
                            "status": "failed",
                            "reason": str(exc),
                            "elapsed_s": 0.0,
                            "productive": False,
                        }
                        expansion_errors.append({"scope": scope, "error": str(exc)})
                        logger.error(
                            "[DiscoveryEngine] Expansion phase '%s' failed for '%s': %s",
                            phase_name,
                            scope,
                            exc,
                        )

                    phase_outcomes.append(
                        {
                            "scope": scope,
                            **(dict(phase_result) if isinstance(phase_result, dict) else {}),
                        }
                    )
                    spent_seconds = max(
                        0,
                        int(float((phase_result or {}).get("elapsed_s", 0.0) or 0.0) + 0.999),
                    )
                    if budget_type == "category_a_exploration":
                        remaining_category_a_exploration_seconds = max(
                            0,
                            remaining_category_a_exploration_seconds - spent_seconds,
                        )
                    elif budget_type == "category_bcde_exploration":
                        remaining_bcde_exploration_seconds = max(
                            0,
                            remaining_bcde_exploration_seconds - spent_seconds,
                        )
                    else:
                        remaining_exploitation_seconds = max(
                            0,
                            remaining_exploitation_seconds - spent_seconds,
                        )
                    phase_scope_completed += 1
                    _emit_progress(
                        force=True,
                        expansion_phase=phase_name,
                        expansion_current_scope=scope,
                        expansion_phase_scope_total_count=len(scope_sessions),
                        expansion_phase_scope_completed_count=phase_scope_completed,
                    )

                productive_scope_count = sum(
                    1 for row in phase_outcomes if bool(row.get("productive"))
                )
                phase_status = "completed"
                if not phase_outcomes:
                    phase_status = "skipped"
                elif any(
                    str(row.get("status", "")).strip().lower() == "interrupted"
                    for row in phase_outcomes
                ):
                    phase_status = "interrupted"
                elif all(
                    str(row.get("status", "")).strip().lower() == "skipped"
                    for row in phase_outcomes
                ):
                    phase_status = "skipped"
                elif productive_scope_count == 0:
                    phase_status = "low_yield"
                phase_entry = {
                    "phase": phase_name,
                    "status": phase_status,
                    "scope_total_count": len(scope_sessions),
                    "scope_completed_count": phase_scope_completed,
                    "productive_scope_count": productive_scope_count,
                    "started_at_unix_ms": phase_started_at_unix_ms,
                    "ended_at_unix_ms": int(time.time() * 1000),
                }
                if not phase_outcomes:
                    phase_entry["reason"] = "phase_budget_exhausted"
                expansion_phase_history.append(phase_entry)
                _emit_progress(
                    force=True,
                    expansion_phase=phase_name,
                    expansion_phase_history=list(expansion_phase_history),
                    expansion_phase_scope_total_count=len(scope_sessions),
                    expansion_phase_scope_completed_count=phase_scope_completed,
                )
                if _cycle_budget_remaining_seconds() <= 0:
                    break

            for scope, session in scope_sessions:
                if not getattr(session, "phase_outcomes", None):
                    continue
                scopes_processed.add(scope)
                expansion_result = self._expansion_wrapper.finalize_session(session)
                expansion_scope_summaries.append(
                    self._build_expansion_scope_summary(
                        scope=scope,
                        expansion_result=expansion_result,
                        module_time_slice_seconds=expansion_config.module_time_slice_seconds,
                    )
                )
                expanded_candidates |= expansion_result.endpoint_candidates
                _emit_progress(
                    force=True,
                    expansion_scope_processed_count=len(scopes_processed),
                    expanded_candidate_count=len(expanded_candidates),
                    total_candidate_count=len(set(roots) | expanded_candidates),
                )
                logger.info(
                    f"[DiscoveryEngine] Expansion for '{scope}': "
                    f"{len(expansion_result.endpoint_candidates)} candidates | "
                    f"nodes={expansion_result.node_count} "
                    f"edges={expansion_result.edge_count} "
                    f"ceilings_hit={expansion_result.ceilings_hit}"
                )
        else:
            for root_domain in unique_root_domains:
                _assert_cycle_budget("discovery")
                scope_domains: List[str] = [root_domain]
                base_domain = self._extract_registrable_base(root_domain)
                if base_domain and base_domain != root_domain:
                    scope_domains.append(base_domain)

                for scope in scope_domains:
                    if scope in scopes_processed:
                        continue

                    try:
                        remaining_cycle_seconds = _cycle_budget_remaining_seconds()
                        if remaining_cycle_seconds <= 0:
                            logger.warning(
                                "[DiscoveryEngine] Cycle budget exhausted before scope '%s'. "
                                "Skipping remaining expansion.",
                                scope,
                            )
                            break
                        if remaining_category_a_exploration_seconds <= 0:
                            logger.info(
                                "[DiscoveryEngine] Category A exploration budget exhausted before scope '%s'. "
                                "Skipping remaining scope expansion.",
                                scope,
                            )
                            break
                        scopes_processed.add(scope)
                        scoped_exploration_seconds = min(
                            remaining_category_a_exploration_seconds,
                            remaining_cycle_seconds,
                        )
                        remaining_cycle_after_exploration = max(
                            0,
                            remaining_cycle_seconds - scoped_exploration_seconds,
                        )
                        scoped_exploitation_seconds = min(
                            remaining_exploitation_seconds,
                            remaining_cycle_after_exploration,
                        )
                        scoped_config = replace(
                            expansion_config,
                            category_a_time_budget_seconds=min(
                                expansion_config.category_a_time_budget_seconds,
                                scoped_exploration_seconds + scoped_exploitation_seconds,
                            ),
                            bcde_time_budget_seconds=min(
                                expansion_config.bcde_time_budget_seconds,
                                scoped_exploration_seconds + scoped_exploitation_seconds,
                            ),
                            exploration_budget_seconds=scoped_exploration_seconds,
                            exploitation_budget_seconds=scoped_exploitation_seconds,
                            module_time_slice_seconds=min(
                                expansion_config.module_time_slice_seconds,
                                max(1, scoped_exploration_seconds + scoped_exploitation_seconds),
                            ),
                        )
                        expand_kwargs: Dict[str, Any] = {
                            "root_domain": scope,
                            "config": scoped_config,
                            "stage_callback": stage_callback,
                        }
                        if wrapper_supports_progress:
                            expand_kwargs["progress_callback"] = _emit_progress
                        expansion_result = self._expansion_wrapper.expand(
                            **expand_kwargs,
                        )
                        expansion_scope_summaries.append(
                            self._build_expansion_scope_summary(
                                scope=scope,
                                expansion_result=expansion_result,
                                module_time_slice_seconds=scoped_config.module_time_slice_seconds,
                            )
                        )
                        expanded_candidates |= expansion_result.endpoint_candidates
                        timing = expansion_result.diagnostics.get("timing", {})
                        category_a_exploration_spent = float(
                            timing.get("a_exploration_s", 0.0) or 0.0
                        )
                        bcde_exploration_spent = float(
                            timing.get("bcde_exploration_s", 0.0) or 0.0
                        )
                        exploitation_spent = float(timing.get("a_exploitation_s", 0.0) or 0.0) + float(
                            timing.get("bcde_exploitation_s", 0.0) or 0.0
                        )
                        remaining_category_a_exploration_seconds = max(
                            0,
                            remaining_category_a_exploration_seconds
                            - int(category_a_exploration_spent + 0.999),
                        )
                        remaining_bcde_exploration_seconds = max(
                            0,
                            remaining_bcde_exploration_seconds
                            - int(bcde_exploration_spent + 0.999),
                        )
                        remaining_exploitation_seconds = max(
                            0,
                            remaining_exploitation_seconds - int(exploitation_spent + 0.999),
                        )
                        _emit_progress(
                            force=True,
                            expansion_scope_processed_count=len(scopes_processed),
                            expanded_candidate_count=len(expanded_candidates),
                            total_candidate_count=len(set(roots) | expanded_candidates),
                        )

                        logger.info(
                            f"[DiscoveryEngine] Expansion for '{scope}': "
                            f"{len(expansion_result.endpoint_candidates)} candidates | "
                            f"nodes={expansion_result.node_count} "
                            f"edges={expansion_result.edge_count} "
                            f"ceilings_hit={expansion_result.ceilings_hit}"
                        )
                    except Exception as exc:
                        expansion_errors.append(
                            {
                                "scope": scope,
                                "error": str(exc),
                            }
                        )
                        logger.error(
                            f"[DiscoveryEngine] Expansion failed for '{scope}', "
                            f"continuing without its candidates: {exc}"
                        )
                if remaining_category_a_exploration_seconds <= 0 or _cycle_budget_remaining_seconds() <= 0:
                    break

        logger.info(
            f"[DiscoveryEngine] Total expanded candidates across "
            f"{len(planned_scopes)} scope(s): {len(expanded_candidates)}"
        )

        # Merge: expansion adds candidates, never removes known seeds.
        # Absence of a known endpoint is a temporal concern (TemporalStateEngine),
        # never an expansion concern.
        #
        # CEILING NOTE — two independent caps are intentional:
        #   ExpansionConfig.max_total_endpoints  → governs graph growth inside wrapper
        #   DiscoveryEngine.max_endpoints        → governs observation queue size
        # The second cap is an observation concurrency governor, not a discovery limit.
        # Both caps must be kept in sync in deployment configuration.
        all_roots: set = set(roots) | expanded_candidates
        scope_profile = self._build_scope_profile(roots)
        capped_roots, observation_selection_summary = self._select_observation_targets(
            roots=roots,
            expanded_candidates=expanded_candidates,
            scope_profile=scope_profile,
            max_targets=self.max_endpoints,
        )
        observation_cap_hit = len(all_roots) > self.max_endpoints
        relevance_filter_dropped = max(0, len(all_roots) - len(capped_roots))

        if observation_cap_hit:
            logger.warning(
                f"[DiscoveryEngine] Observation cap reached: "
                f"{len(all_roots)} total endpoints discovered, "
                f"truncated to {self.max_endpoints} for observation. "
                f"{len(all_roots) - self.max_endpoints} endpoints will NOT be observed "
                f"this cycle. Consider raising max_endpoints or tightening expansion ceilings."
            )
        elif relevance_filter_dropped > 0:
            logger.info(
                "[DiscoveryEngine] Observation relevance filter kept %s of %s discovered endpoints. "
                "Breakdown=%s",
                len(capped_roots),
                len(all_roots),
                observation_selection_summary,
            )

        logger.info(
            f"[DiscoveryEngine] Observation surface: "
            f"{len(capped_roots)} endpoints | "
            f"seeds={len(roots)} expanded={len(expanded_candidates)} "
            f"merged={len(all_roots)} cap_hit={observation_cap_hit}"
        )
        expansion_summary = self._build_expansion_summary(
            requested_roots=unique_root_domains,
            processed_scopes=scopes_processed,
            scope_summaries=expansion_scope_summaries,
            scope_errors=expansion_errors,
            expanded_candidate_count=len(expanded_candidates),
            observation_target_count=len(capped_roots),
            observation_cap_hit=bool(observation_cap_hit),
            phase_history=expansion_phase_history,
        )
        _assert_cycle_budget("observation preparation")
        _emit_progress(
            force=True,
            expanded_candidate_count=len(expanded_candidates),
            total_candidate_count=len(all_roots),
            observation_target_count=len(capped_roots),
            observation_cap_hit=bool(observation_cap_hit),
        )
        if stage_callback is not None:
            stage_callback("endpoint_observation")
        work_queue: Queue[str] = Queue()
        for ep in capped_roots:
            work_queue.put(ep)

        seen_endpoints: Set[str] = set(capped_roots)
        self._last_raw_results = []
        raw_results: List[object] = self._last_raw_results
        sequence_counter = 0
        successful_observations = 0
        failed_observations = 0
        posture_waf_findings = 0
        posture_tls_findings = 0
        posture_hndl_flags = 0
        posture_crypto_score_sum = 0
        posture_crypto_score_count = 0
        posture_protection_score_sum = 0
        posture_protection_score_count = 0

        # Per-endpoint rate-limit retry tracking.
        # Prevents a misbehaving rate_controller from deadlocking work_queue.join().
        # Shared across workers — access serialised by self._lock.
        _MAX_RATE_RETRIES = 10
        _retry_counts: dict = {}
        tenant_frameworks = resolve_tenant_frameworks(self.storage, tenant_id)
        if self.enable_phase5_findings:
            self._finding_engine.begin_cycle(
                enable_ct_longitudinal=enable_ct_longitudinal
            )

        # =====================================================
        # WORKER
        # =====================================================

        def worker():
            nonlocal sequence_counter, successful_observations, failed_observations
            nonlocal posture_waf_findings, posture_tls_findings, posture_hndl_flags
            nonlocal posture_crypto_score_sum, posture_crypto_score_count
            nonlocal posture_protection_score_sum, posture_protection_score_count

            while True:
                try:
                    endpoint = work_queue.get(timeout=1)
                except Empty:
                    return

                _task_done_called = False

                try:
                    if int(time.time() * 1000) > effective_cycle_deadline_ms:
                        logger.warning(
                            "[DiscoveryEngine] Cycle time budget exceeded during observation. "
                            "Stopping remaining endpoint work."
                        )
                        return
                    # -------------------------------
                    # Rate gate (observation-level)
                    #
                    # rate_controller governs observation throughput.
                    # Expansion never sees this — it is expansion-agnostic.
                    # If rate_controller is absent or does not implement
                    # allow_request, the gate is skipped and acquisition
                    # proceeds unconstrained (safe for offline / test use).
                    #
                    # THROTTLE semantics (not shed):
                    # When rate-limited, the endpoint is requeued with
                    # exponential backoff (0.1s * 2^attempt, capped at 5s)
                    # plus random jitter to prevent thundering-herd requeue.
                    #
                    # BOUNDED RETRY (deadlock safety valve):
                    # If allow_request never returns True (misconfigured
                    # token bucket, broken rate controller, etc.) the cycle
                    # would hang at work_queue.join() indefinitely.
                    # After _MAX_RATE_RETRIES attempts the endpoint is dropped
                    # with an error log. This guarantees the cycle terminates.
                    # -------------------------------
                    if (
                        rate_controller is not None
                        and hasattr(rate_controller, "allow_request")
                        and not rate_controller.allow_request(f"observe:{endpoint}")
                    ):
                        target_id = f"observe:{endpoint}"
                        with self._lock:
                            attempt = _retry_counts.get(endpoint, 0) + 1
                            _retry_counts[endpoint] = attempt

                        max_retries = _MAX_RATE_RETRIES
                        if hasattr(rate_controller, "max_rate_limit_retries"):
                            try:
                                max_retries = max(
                                    1,
                                    int(rate_controller.max_rate_limit_retries()),
                                )
                            except Exception:
                                max_retries = _MAX_RATE_RETRIES

                        if attempt > max_retries:
                            logger.error(
                                f"[DiscoveryEngine] Rate limit retry exhausted after "
                                f"{max_retries} attempts -- dropping: {endpoint}. "
                                f"Check rate_controller configuration."
                            )
                            # Do NOT requeue -- let task_done fire in finally.
                        else:
                            backoff = min(0.1 * (2 ** (attempt - 1)), 5.0)
                            if hasattr(rate_controller, "register_rate_limited"):
                                try:
                                    backoff = float(
                                        rate_controller.register_rate_limited(
                                            target_id,
                                            retry_after_seconds=None,
                                            attempt=attempt,
                                        )
                                    )
                                except TypeError:
                                    try:
                                        backoff = float(rate_controller.register_rate_limited(target_id))
                                    except Exception:
                                        pass
                                except Exception:
                                    pass
                            elif hasattr(rate_controller, "suggested_retry_delay"):
                                try:
                                    backoff = float(
                                        rate_controller.suggested_retry_delay(
                                            attempt=attempt
                                        )
                                    )
                                except Exception:
                                    pass
                            jitter = _deterministic_jitter(endpoint, attempt, backoff)
                            logger.debug(
                                f"[DiscoveryEngine] Rate limited (attempt {attempt}/"
                                f"{max_retries}) -- requeueing in "
                                f"{backoff + jitter:.2f}s: {endpoint}"
                            )
                            time.sleep(backoff + jitter)
                            work_queue.put(endpoint)
                            work_queue.task_done()
                            _task_done_called = True
                        continue

                    target_id = f"observe:{endpoint}"
                    if rate_controller is not None and hasattr(rate_controller, "register_attempt"):
                        try:
                            rate_controller.register_attempt()
                        except Exception:
                            pass

                    try:
                        series = protocol_observer.observe_endpoint_series(
                            endpoint,
                            samples=self.samples_per_endpoint,
                            include_http=self.include_http_probe,
                        )
                    except TimeoutError:
                        if rate_controller is not None and hasattr(rate_controller, "register_timeout"):
                            try:
                                rate_controller.register_timeout(target_id)
                            except Exception:
                                pass
                        raise
                    except Exception:
                        if rate_controller is not None and hasattr(rate_controller, "register_error"):
                            try:
                                rate_controller.register_error(target_id)
                            except Exception:
                                pass
                        raise

                    if not series or not series.observations:
                        if rate_controller is not None and hasattr(rate_controller, "register_error"):
                            try:
                                rate_controller.register_error(target_id)
                            except Exception:
                                pass
                        continue

                    if rate_controller is not None and hasattr(rate_controller, "register_success"):
                        try:
                            rate_controller.register_success(target_id)
                        except Exception:
                            pass
                    with self._lock:
                        _retry_counts.pop(endpoint, None)

                    # Representative observation for snapshot/enrichment
                    protocol_obj = next(
                        (r for r in reversed(series.observations) if getattr(r, "success", False)),
                        series.observations[-1],
                    )

                    timestamp_ms = int(time.time() * 1000)

                    endpoint_value = getattr(
                        protocol_obj,
                        "endpoint",
                        getattr(protocol_obj, "endpoint_str", endpoint),
                    )

                    # Append raw protocol object (no schema enforcement)
                    with self._lock:
                        sequence_counter += 1
                        sequence = sequence_counter
                        raw_results.append(protocol_obj)
                        if bool(getattr(protocol_obj, "success", False)):
                            successful_observations += 1
                        else:
                            failed_observations += 1
                        completed_count = successful_observations + failed_observations
                        completed_snapshot = {
                            "observed_completed_count": int(completed_count),
                            "observed_successful_count": int(successful_observations),
                            "observed_failed_count": int(failed_observations),
                        }
                    if (
                        completed_snapshot["observed_completed_count"] <= 3
                        or completed_snapshot["observed_completed_count"] % 5 == 0
                    ):
                        _emit_progress(**completed_snapshot)

                    # -------------------------------
                    # Fingerprint extraction (best-effort)
                    # -------------------------------
                    try:
                        fingerprints = self._bridge.process_series(series.observations)
                    except Exception:
                        fingerprints = []

                    fp_dicts = []
                    for fp in fingerprints:
                        if hasattr(fp, "__dict__"):
                            fp_dicts.append(dict(fp.__dict__))
                        elif isinstance(fp, dict):
                            fp_dicts.append(fp)

                    # -------------------------------
                    # Phase 4 posture signal extraction (always attempt)
                    # -------------------------------
                    posture_signals: List[Dict[str, Any]] = []
                    posture_findings: Dict[str, Any] = {
                        "waf_findings": [],
                        "tls_findings": [],
                        "scores": {
                            "cryptographic_health_score": 0,
                            "protection_posture_score": 0,
                            "hndl_risk_flag": False,
                            "quantum_ready": "UNKNOWN",
                            "ct_history_summary": {},
                        },
                    }
                    try:
                        posture_signals = self._posture_extractor.extract_as_dicts(protocol_obj)
                        if self.enable_phase5_findings:
                            posture_findings = self._finding_engine.evaluate_from_signal_dicts(
                                posture_signals,
                                tenant_frameworks=tenant_frameworks,
                            )
                    except Exception as posture_exc:
                        logger.debug(
                            "[DiscoveryEngine] posture extraction failed for %s: %s",
                            endpoint,
                            posture_exc,
                        )

                    # -------------------------------
                    # Telemetry persistence
                    # -------------------------------
                    telemetry_event = {
                        "timestamp_ms": timestamp_ms,
                        "sequence": sequence,
                        "entity_id": endpoint_value,
                        "fingerprints": fp_dicts,
                        "posture_signals": posture_signals,
                        "posture_findings": posture_findings,
                        "sample_count": len(series.observations),
                        "elapsed_ms": int(series.elapsed_ms),
                    }

                    self.storage.persist_telemetry_record(
                        tenant_id=tenant_id,
                        cycle_id=cycle_id,
                        record=telemetry_event,
                    )

                    if self.enable_phase5_findings:
                        scores = posture_findings.get("scores", {}) if isinstance(posture_findings, dict) else {}
                        with self._lock:
                            posture_waf_findings += len(
                                (posture_findings.get("waf_findings", []) if isinstance(posture_findings, dict) else [])
                            )
                            posture_tls_findings += len(
                                (posture_findings.get("tls_findings", []) if isinstance(posture_findings, dict) else [])
                            )
                            if bool(scores.get("hndl_risk_flag", False)):
                                posture_hndl_flags += 1
                            crypto_score = scores.get("cryptographic_health_score")
                            if isinstance(crypto_score, (int, float)):
                                posture_crypto_score_sum += int(crypto_score)
                                posture_crypto_score_count += 1
                            protection_score = scores.get("protection_posture_score")
                            if isinstance(protection_score, (int, float)):
                                posture_protection_score_sum += int(protection_score)
                                posture_protection_score_count += 1

                    # -------------------------------
                    # Runtime SAN expansion
                    #
                    # ARCHITECTURAL DECISION (conscious overlap):
                    # Category A already performs recursive SAN chain expansion
                    # as part of ExpansionWrapper pre-observation.
                    #
                    # This runtime path is intentionally retained because:
                    #   1. Live observation may reveal SANs not yet in CT logs
                    #      or passive DNS — e.g. newly issued certs.
                    #   2. Expansion runs once per cycle (cold start); live SANs
                    #      are discovered per-endpoint as observations arrive.
                    #   3. This is the ONLY post-observation surface growth
                    #      permitted. It does not call expansion modules.
                    #
                    # If Category A SAN coverage is deemed sufficient, remove
                    # this block and set a SAN_EXPANSION_ENABLED flag to False.
                    # The worker loop will continue to function identically.
                    # -------------------------------
                    tls = getattr(protocol_obj, "tls", None)
                    if tls and getattr(tls, "cert_san", None):
                        for domain in tls.cert_san:
                            normalized = self._normalize_domain(domain)
                            if not normalized:
                                continue

                            with self._lock:
                                if (
                                    normalized not in seen_endpoints
                                    and len(seen_endpoints) < self.max_endpoints
                                    and self._should_expand_runtime_candidate(
                                        normalized,
                                        scope_profile=scope_profile,
                                    )
                                ):
                                    seen_endpoints.add(normalized)
                                    work_queue.put(normalized)

                except Exception as e:
                    logger.error(
                        f"Acquisition failed for {endpoint}: {e}"
                    )

                finally:
                    if not _task_done_called:
                        work_queue.task_done()

        # =====================================================
        # CONCURRENCY EXECUTION
        # =====================================================

        worker_count = max(1, min(self.max_workers, len(capped_roots), self.MAX_WORKERS_CAP))

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            for _ in range(worker_count):
                executor.submit(worker)

            work_queue.join()

        successful_entity_ids, failed_entity_ids = self._build_observation_outcome_sets(
            raw_results
        )
        discovered_surface = self._build_discovered_surface(
            roots=roots,
            expanded_candidates=expanded_candidates,
            scope_summaries=expansion_scope_summaries,
            selected_for_observation=capped_roots,
            successful_entity_ids=successful_entity_ids,
            failed_entity_ids=failed_entity_ids,
        )
        expansion_summary["discovered_surface_count"] = int(len(discovered_surface))

        self._last_reporting_metrics = {
            "total_discovered_domains": len(discovered_surface),
            "total_successful_observations": int(successful_observations),
            "total_failed_observations": int(failed_observations),
            "observation_cap_hit": bool(observation_cap_hit),
            "observation_relevance_filtered_count": int(relevance_filter_dropped),
            "observation_selection_summary": dict(observation_selection_summary),
            "total_expanded_candidates": len(expanded_candidates),
            "total_observed_endpoints": len(capped_roots),
            "expansion_scope_count": len(scopes_processed),
            "discovered_surface": discovered_surface,
            "posture_summary": {
                "waf_findings_count": int(posture_waf_findings),
                "tls_findings_count": int(posture_tls_findings),
                "hndl_flag_count": int(posture_hndl_flags),
                "avg_cryptographic_health_score": (
                    int(posture_crypto_score_sum / posture_crypto_score_count)
                    if posture_crypto_score_count > 0
                    else 0
                ),
                "avg_protection_posture_score": (
                    int(posture_protection_score_sum / posture_protection_score_count)
                    if posture_protection_score_count > 0
                    else 0
                ),
                "tenant_frameworks": list(tenant_frameworks),
            },
            "expansion_summary": expansion_summary,
        }
        _emit_progress(
            force=True,
            expanded_candidate_count=len(expanded_candidates),
            total_candidate_count=len(all_roots),
            observation_target_count=len(capped_roots),
            observation_cap_hit=bool(observation_cap_hit),
            observed_completed_count=int(successful_observations + failed_observations),
            observed_successful_count=int(successful_observations),
            observed_failed_count=int(failed_observations),
        )

        return raw_results

    # ==========================================================
    # ROOT RESOLUTION
    # ==========================================================

    def _resolve_roots(
        self,
        tenant_id: str,
        explicit_seeds: Optional[List[str]],
    ) -> List[str]:

        if explicit_seeds is not None:
            normalized = {
                canonical
                for seed in explicit_seeds
                for canonical in [self._normalize_seed_endpoint(seed)]
                if canonical is not None
            }
            return sorted(normalized)

        stored = self.storage.load_seed_endpoints(tenant_id)
        if stored:
            return sorted(set(stored))

        return []

    # ==========================================================
    # ROOT DOMAIN EXTRACTION (for expansion)
    # ==========================================================

    def _build_scope_profile(self, endpoints: List[str]) -> Dict[str, Set[str]]:
        exact_hosts: Set[str] = set()
        base_domains: Set[str] = set()
        scope_tokens: Set[str] = set()

        for endpoint in endpoints:
            host = self._extract_endpoint_host(endpoint)
            if not host:
                continue
            exact_hosts.add(host)
            base = self._extract_registrable_base(host)
            if base:
                base_domains.add(base)
            for label in host.split("."):
                token = self._normalize_scope_token(label)
                if token:
                    scope_tokens.add(token)
            if base:
                base_token = self._normalize_scope_token(base)
                if base_token:
                    scope_tokens.add(base_token)

        return {
            "exact_hosts": exact_hosts,
            "base_domains": base_domains,
            "scope_tokens": scope_tokens,
        }

    def _select_observation_targets(
        self,
        *,
        roots: List[str],
        expanded_candidates: Set[str],
        scope_profile: Dict[str, Set[str]],
        max_targets: int,
    ) -> tuple[List[str], Dict[str, int]]:
        grouped: Dict[str, List[str]] = {
            "seed": [],
            "first_party": [],
            "adjacent_dependency": [],
            "network_attachment": [],
            "provider_edge": [],
            "unknown": [],
        }
        roots_set = set(roots)
        all_candidates = roots_set | set(expanded_candidates)

        for endpoint in sorted(all_candidates):
            category = self._classify_observation_candidate(
                endpoint,
                roots_set=roots_set,
                scope_profile=scope_profile,
            )
            grouped.setdefault(category, []).append(endpoint)

        selected: List[str] = []
        seen: Set[str] = set()

        def _take(items: List[str], limit: Optional[int] = None) -> None:
            taken = 0
            for item in items:
                if item in seen:
                    continue
                if len(selected) >= max_targets:
                    return
                if limit is not None and taken >= limit:
                    return
                selected.append(item)
                seen.add(item)
                taken += 1

        _take(grouped.get("seed", []))
        _take(grouped.get("first_party", []))

        high_value_count = len(selected)
        adjacent_budget = min(
            max_targets,
            max(12, high_value_count * 2, max(1, len(roots_set)) * 6),
        )
        network_budget = min(
            max_targets,
            max(8, high_value_count, max(1, len(roots_set)) * 4),
        )
        provider_budget = min(
            max_targets,
            max(6, high_value_count // 2, max(1, len(roots_set)) * 4),
        )
        unknown_budget = min(
            max_targets,
            max(4, max(1, len(roots_set)) * 2),
        )

        _take(grouped.get("adjacent_dependency", []), adjacent_budget)
        _take(grouped.get("network_attachment", []), network_budget)
        _take(grouped.get("provider_edge", []), provider_budget)
        _take(grouped.get("unknown", []), unknown_budget)

        summary = {
            "seed_candidates": len(grouped.get("seed", [])),
            "first_party_candidates": len(grouped.get("first_party", [])),
            "adjacent_dependency_candidates": len(grouped.get("adjacent_dependency", [])),
            "network_attachment_candidates": len(grouped.get("network_attachment", [])),
            "provider_edge_candidates": len(grouped.get("provider_edge", [])),
            "unknown_candidates": len(grouped.get("unknown", [])),
            "provider_edge_budget": int(provider_budget),
            "unknown_budget": int(unknown_budget),
            "selected_total": len(selected),
            "dropped_total": max(0, len(all_candidates) - len(selected)),
        }
        return selected[:max_targets], summary

    def _classify_observation_candidate(
        self,
        endpoint: str,
        *,
        roots_set: Set[str],
        scope_profile: Dict[str, Set[str]],
    ) -> str:
        if endpoint in roots_set:
            return "seed"

        host = self._extract_endpoint_host(endpoint)
        if not host:
            return "unknown"
        if self._belongs_to_first_party_scope(host, scope_profile):
            return "first_party"
        if self._host_contains_scope_token(host, scope_profile):
            return "adjacent_dependency"
        if self._is_ip_literal(host):
            return "network_attachment"
        if self._looks_like_provider_edge(host):
            return "provider_edge"
        return "unknown"

    def _should_expand_runtime_candidate(
        self,
        endpoint: str,
        *,
        scope_profile: Dict[str, Set[str]],
    ) -> bool:
        category = self._classify_observation_candidate(
            endpoint,
            roots_set=set(),
            scope_profile=scope_profile,
        )
        return category in {"first_party", "adjacent_dependency"}

    @staticmethod
    def _extract_root_domain(endpoint: str) -> Optional[str]:
        """
        Derive a bare hostname from a seed endpoint string for expansion.

        Handles:
            - Schemes:          "https://api.example.com:443" → "api.example.com"
            - Ports:            "example.com:8443"            → "example.com"
            - Trailing dots:    "example.com."                → "example.com"
            - Bracketed IPv6:   "[::1]:443"                   → None (IP, skip)
            - Bare IPv6:        "2001:db8::1"                 → None (IP, skip)
            - Bare IPv4:        "192.168.1.1"                 → None (IP, skip)
            - IDN/Unicode:      "münchen.de"                  → "münchen.de" (preserved)
            - No dot:           "localhost"                   → None
        """
        if not endpoint:
            return None

        host = endpoint.lower().strip()

        # Strip scheme
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]

        # Strip path and query string
        host = host.split("/")[0].split("?")[0].strip()

        # Bracketed IPv6 — "[::1]:443" or "[::1]"
        if host.startswith("["):
            return None

        # Strip port — only rsplit on last ":" to avoid touching bare IPv6
        # that slipped through without brackets (handled by ip_address below)
        if ":" in host:
            # If more than one colon it could be bare IPv6 — try ip_address first
            try:
                ipaddress.ip_address(host)
                return None  # bare IPv6 with no port
            except ValueError:
                pass
            # Single colon → hostname:port
            host = host.rsplit(":", 1)[0]

        # Strip trailing DNS dot ("example.com." → "example.com")
        host = host.rstrip(".")

        if not host or len(host) < 3:
            return None

        # Reject bare IPs
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass

        # Must contain at least one dot (rejects "localhost", single labels)
        if "." not in host:
            return None

        return host

    @staticmethod
    def _extract_endpoint_host(endpoint: str) -> Optional[str]:
        raw = str(endpoint or "").strip()
        if not raw:
            return None
        try:
            parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        except Exception:
            return None
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        return host or None

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(str(host or "").strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def _extract_registrable_base(host: str) -> Optional[str]:
        return extract_registrable_base(host)

    @classmethod
    def _normalize_scope_token(cls, value: str) -> str:
        token = re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
        if len(token) < 4 or token in cls._COMMON_SCOPE_LABELS:
            return ""
        return token

    def _host_contains_scope_token(
        self,
        host: str,
        scope_profile: Dict[str, Set[str]],
    ) -> bool:
        normalized_host = self._normalize_scope_token(host)
        if not normalized_host:
            return False
        for token in scope_profile.get("scope_tokens", set()):
            if token and token in normalized_host:
                return True
        return False

    def _belongs_to_first_party_scope(
        self,
        host: str,
        scope_profile: Dict[str, Set[str]],
    ) -> bool:
        exact_hosts = scope_profile.get("exact_hosts", set())
        if host in exact_hosts:
            return True
        for base in scope_profile.get("base_domains", set()):
            if host == base or host.endswith(f".{base}"):
                return True
        return False

    def _looks_like_provider_edge(self, host: str) -> bool:
        hostname = str(host or "").strip().lower()
        if not hostname:
            return False
        return any(
            hostname == suffix or hostname.endswith(f".{suffix}")
            for suffix in self._PROVIDER_HOST_SUFFIXES
        )

    # ==========================================================
    # SAN NORMALIZATION
    # ==========================================================

    def _normalize_domain(self, domain: str) -> Optional[str]:

        if not domain:
            return None

        d = domain.lower().replace("*.", "").strip()

        if ":" in d:
            d = d.split(":")[0]

        if "." not in d or len(d) < 3:
            return None

        if d.startswith("localhost"):
            return None

        return f"{d}:443"

    @staticmethod
    def _normalize_seed_endpoint(seed: str) -> Optional[str]:
        raw = str(seed or "").strip()
        if not raw:
            return None

        try:
            parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        except Exception:
            return None

        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            return None
        if len(host) > 253 or "." not in host:
            return None
        if host.startswith("localhost"):
            return None

        labels = host.split(".")
        for label in labels:
            if not label or len(label) > 63:
                return None
            if label.startswith("-") or label.endswith("-"):
                return None

        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass

        try:
            port = parsed.port
        except ValueError:
            return None

        if port is None:
            if parsed.scheme and parsed.scheme.lower() == "http":
                port = 80
            else:
                port = 443

        if port < 1 or port > 65535:
            return None

        return f"{host}:{port}"

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)

    def _build_expansion_scope_summary(
        self,
        *,
        scope: str,
        expansion_result: Any,
        module_time_slice_seconds: int,
    ) -> Dict[str, Any]:
        diagnostics = (
            dict(expansion_result.diagnostics)
            if isinstance(getattr(expansion_result, "diagnostics", None), dict)
            else {}
        )
        timing_raw = diagnostics.get("timing", {})
        timing = (
            {
                str(key): round(self._safe_float(value), 3)
                for key, value in timing_raw.items()
            }
            if isinstance(timing_raw, dict)
            else {}
        )
        module_summaries_raw = diagnostics.get("module_summaries", [])
        module_summaries: List[Dict[str, Any]] = []
        if isinstance(module_summaries_raw, list):
            for item in module_summaries_raw:
                if not isinstance(item, dict):
                    continue
                module_summaries.append(
                    {
                        "category": str(item.get("category", "")).strip().upper(),
                        "module_name": str(item.get("module_name", "")).strip(),
                        "elapsed_s": round(self._safe_float(item.get("elapsed_s")), 3),
                        "new_domain_count": self._safe_int(item.get("new_domain_count")),
                        "new_endpoint_count": self._safe_int(item.get("new_endpoint_count")),
                        "new_candidate_count": self._safe_int(item.get("new_candidate_count")),
                        "productive": bool(item.get("productive")),
                        "status": str(item.get("status", "")).strip().lower() or "unknown",
                        "skip_reason": str(item.get("skip_reason", "")).strip() or None,
                        "stop_reason": str(item.get("stop_reason", "")).strip() or None,
                        "scope_quality": str(item.get("scope_quality", "")).strip() or None,
                        "new_domain_ids": [
                            str(value).strip()
                            for value in item.get("new_domain_ids", [])
                            if str(value).strip()
                        ]
                        if isinstance(item.get("new_domain_ids"), list)
                        else [],
                        "new_endpoint_ids": [
                            str(value).strip()
                            for value in item.get("new_endpoint_ids", [])
                            if str(value).strip()
                        ]
                        if isinstance(item.get("new_endpoint_ids"), list)
                        else [],
                        "hosts_attempted": self._safe_int(item.get("hosts_attempted")),
                        "ports_attempted": self._safe_int(item.get("ports_attempted")),
                        "endpoints_produced": self._safe_int(item.get("endpoints_produced")),
                        "banners_captured": self._safe_int(item.get("banners_captured")),
                        "http_responses": self._safe_int(item.get("http_responses")),
                        "pages_crawled": self._safe_int(item.get("pages_crawled")),
                        "js_files_fetched": self._safe_int(item.get("js_files_fetched")),
                        "api_paths_discovered": self._safe_int(item.get("api_paths_discovered")),
                        "schemas_found": self._safe_int(item.get("schemas_found")),
                        "surface_productive": bool(item.get("surface_productive")),
                        "dependency_productive": bool(item.get("dependency_productive")),
                        "evidence_productive": bool(item.get("evidence_productive")),
                        "historical_productive": bool(item.get("historical_productive")),
                        "productivity_classes": [
                            str(value).strip()
                            for value in item.get("productivity_classes", [])
                            if str(value).strip()
                        ]
                        if isinstance(item.get("productivity_classes"), list)
                        else [],
                        "actual_elapsed_s": round(
                            self._safe_float(
                                item.get("actual_elapsed_s", item.get("elapsed_s"))
                            ),
                            3,
                        ),
                        "logical_budget_consumed_s": round(
                            self._safe_float(item.get("logical_budget_consumed_s")),
                            3,
                        ),
                        "scheduled_turn_slice_seconds": self._safe_int(
                            item.get("scheduled_turn_slice_seconds")
                        ),
                        "first_turn_seen": bool(item.get("first_turn_seen")),
                        "resumed_turn_count": self._safe_int(item.get("resumed_turn_count")),
                        "permanently_exhausted": bool(item.get("permanently_exhausted")),
                        "time_per_produced_endpoint_s": round(
                            self._safe_float(item.get("time_per_produced_endpoint_s")),
                            3,
                        ),
                        "time_slice_exceeded": bool(
                            item.get("time_slice_exceeded")
                            or (
                                self._safe_float(item.get("elapsed_s"))
                                > float(max(1, int(module_time_slice_seconds)))
                            )
                        ),
                    }
                )
        phase_outcomes_raw = diagnostics.get("phase_outcomes", [])
        phase_outcomes: List[Dict[str, Any]] = []
        if isinstance(phase_outcomes_raw, list):
            for item in phase_outcomes_raw:
                if not isinstance(item, dict):
                    continue
                phase_outcomes.append(
                    {
                        "phase": str(item.get("phase", "")).strip(),
                        "status": str(item.get("status", "")).strip().lower() or "unknown",
                        "reason": str(item.get("reason", "")).strip() or None,
                        "elapsed_s": round(self._safe_float(item.get("elapsed_s")), 3),
                        "productive": bool(item.get("productive")),
                    }
                )

        return {
            "scope": str(scope or "").strip(),
            "root_domain": str(getattr(expansion_result, "root_domain", scope) or scope).strip(),
            "node_count": self._safe_int(getattr(expansion_result, "node_count", 0)),
            "edge_count": self._safe_int(getattr(expansion_result, "edge_count", 0)),
            "endpoint_candidate_count": len(
                getattr(expansion_result, "endpoint_candidates", set()) or set()
            ),
            "ceilings_hit": bool(getattr(expansion_result, "ceilings_hit", False)),
            "raw_candidate_count": self._safe_int(diagnostics.get("raw_candidate_count")),
            "canonical_candidate_count": self._safe_int(
                diagnostics.get("canonical_candidate_count")
            ),
            "candidate_rows": list(diagnostics.get("candidate_rows", []))
            if isinstance(diagnostics.get("candidate_rows"), list)
            else [],
            "productive_category_a_modules": sorted(
                {
                    str(name).strip()
                    for name in diagnostics.get("productive_category_a_modules", [])
                    if str(name).strip()
                }
            ),
            "productive_bcde_modules": sorted(
                {
                    str(name).strip()
                    for name in diagnostics.get("productive_bcde_modules", [])
                    if str(name).strip()
                }
            ),
            "timing": timing,
            "module_summaries": module_summaries,
            "module_timings": (
                {
                    str(key): round(self._safe_float(value), 3)
                    for key, value in diagnostics.get("module_timings", {}).items()
                }
                if isinstance(diagnostics.get("module_timings", {}), dict)
                else {}
            ),
            "phase_outcomes": phase_outcomes,
            "total_elapsed_s": round(self._safe_float(diagnostics.get("t_total_s")), 3),
        }

    def _build_expansion_summary(
        self,
        *,
        requested_roots: List[str],
        processed_scopes: Set[str],
        scope_summaries: List[Dict[str, Any]],
        scope_errors: List[Dict[str, Any]],
        expanded_candidate_count: int,
        observation_target_count: int,
        observation_cap_hit: bool,
        phase_history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        module_rollup: Dict[tuple[str, str], Dict[str, Any]] = {}
        productive_a_modules: Set[str] = set()
        productive_bcde_modules: Set[str] = set()
        timing_totals: Dict[str, float] = {}
        total_node_count = 0
        total_edge_count = 0
        total_scope_candidates = 0
        ceilings_hit_count = 0

        for scope_summary in scope_summaries:
            total_node_count += self._safe_int(scope_summary.get("node_count"))
            total_edge_count += self._safe_int(scope_summary.get("edge_count"))
            total_scope_candidates += self._safe_int(
                scope_summary.get("endpoint_candidate_count")
            )
            if bool(scope_summary.get("ceilings_hit")):
                ceilings_hit_count += 1

            for name in scope_summary.get("productive_category_a_modules", []):
                token = str(name).strip()
                if token:
                    productive_a_modules.add(token)
            for name in scope_summary.get("productive_bcde_modules", []):
                token = str(name).strip()
                if token:
                    productive_bcde_modules.add(token)

            timing = scope_summary.get("timing", {})
            if isinstance(timing, dict):
                for key, value in timing.items():
                    token = str(key).strip()
                    if not token:
                        continue
                    timing_totals[token] = round(
                        timing_totals.get(token, 0.0) + self._safe_float(value),
                        3,
                    )

            module_summaries = scope_summary.get("module_summaries", [])
            if not isinstance(module_summaries, list):
                continue
            for item in module_summaries:
                if not isinstance(item, dict):
                    continue
                category = str(item.get("category", "")).strip().upper() or "UNKNOWN"
                module_name = str(item.get("module_name", "")).strip()
                if not module_name:
                    continue
                key = (category, module_name)
                aggregate = module_rollup.setdefault(
                    key,
                    {
                        "category": category,
                        "module_name": module_name,
                        "invocation_count": 0,
                        "productive_runs": 0,
                        "produced_domain_count": 0,
                        "produced_endpoint_count": 0,
                        "produced_candidate_count": 0,
                        "total_elapsed_s": 0.0,
                        "max_elapsed_s": 0.0,
                        "total_actual_elapsed_s": 0.0,
                        "max_actual_elapsed_s": 0.0,
                        "logical_budget_consumed_s": 0.0,
                        "time_slice_exceeded_count": 0,
                        "initial_pass_seen_count": 0,
                        "follow_up_turn_count": 0,
                        "resumed_turn_count": 0,
                        "surface_productive_runs": 0,
                        "dependency_productive_runs": 0,
                        "evidence_productive_runs": 0,
                        "historical_productive_runs": 0,
                        "permanently_exhausted_runs": 0,
                        "hosts_attempted": 0,
                        "ports_attempted": 0,
                        "endpoints_produced": 0,
                        "banners_captured": 0,
                        "http_responses": 0,
                        "pages_crawled": 0,
                        "js_files_fetched": 0,
                        "api_paths_discovered": 0,
                        "schemas_found": 0,
                        "completed_runs": 0,
                        "low_yield_runs": 0,
                        "skipped_runs": 0,
                        "failed_runs": 0,
                        "interrupted_runs": 0,
                        "skip_reasons": set(),
                        "stop_reasons": set(),
                    },
                )
                aggregate["invocation_count"] += 1
                aggregate["productive_runs"] += 1 if bool(item.get("productive")) else 0
                status = str(item.get("status", "")).strip().lower()
                if status == "completed":
                    aggregate["completed_runs"] += 1
                elif status == "low_yield":
                    aggregate["low_yield_runs"] += 1
                elif status == "skipped":
                    aggregate["skipped_runs"] += 1
                elif status == "failed":
                    aggregate["failed_runs"] += 1
                elif status == "interrupted":
                    aggregate["interrupted_runs"] += 1
                aggregate["produced_domain_count"] += self._safe_int(
                    item.get("new_domain_count")
                )
                aggregate["produced_endpoint_count"] += self._safe_int(
                    item.get("new_endpoint_count")
                )
                aggregate["produced_candidate_count"] += self._safe_int(
                    item.get("new_candidate_count")
                )
                elapsed_s = round(self._safe_float(item.get("elapsed_s")), 3)
                actual_elapsed_s = round(
                    self._safe_float(item.get("actual_elapsed_s", elapsed_s)),
                    3,
                )
                aggregate["total_elapsed_s"] = round(
                    self._safe_float(aggregate.get("total_elapsed_s")) + elapsed_s,
                    3,
                )
                aggregate["max_elapsed_s"] = round(
                    max(self._safe_float(aggregate.get("max_elapsed_s")), elapsed_s),
                    3,
                )
                aggregate["total_actual_elapsed_s"] = round(
                    self._safe_float(aggregate.get("total_actual_elapsed_s"))
                    + actual_elapsed_s,
                    3,
                )
                aggregate["max_actual_elapsed_s"] = round(
                    max(
                        self._safe_float(aggregate.get("max_actual_elapsed_s")),
                        actual_elapsed_s,
                    ),
                    3,
                )
                aggregate["logical_budget_consumed_s"] = round(
                    self._safe_float(aggregate.get("logical_budget_consumed_s"))
                    + self._safe_float(item.get("logical_budget_consumed_s")),
                    3,
                )
                aggregate["time_slice_exceeded_count"] += (
                    1 if bool(item.get("time_slice_exceeded")) else 0
                )
                aggregate["initial_pass_seen_count"] += (
                    1 if bool(item.get("first_turn_seen")) else 0
                )
                aggregate["follow_up_turn_count"] += (
                    1 if self._safe_int(item.get("resumed_turn_count")) > 0 else 0
                )
                aggregate["resumed_turn_count"] += self._safe_int(
                    item.get("resumed_turn_count")
                )
                aggregate["surface_productive_runs"] += (
                    1 if bool(item.get("surface_productive")) else 0
                )
                aggregate["dependency_productive_runs"] += (
                    1 if bool(item.get("dependency_productive")) else 0
                )
                aggregate["evidence_productive_runs"] += (
                    1 if bool(item.get("evidence_productive")) else 0
                )
                aggregate["historical_productive_runs"] += (
                    1 if bool(item.get("historical_productive")) else 0
                )
                aggregate["permanently_exhausted_runs"] += (
                    1 if bool(item.get("permanently_exhausted")) else 0
                )
                aggregate["hosts_attempted"] += self._safe_int(
                    item.get("hosts_attempted")
                )
                aggregate["ports_attempted"] += self._safe_int(
                    item.get("ports_attempted")
                )
                aggregate["endpoints_produced"] += self._safe_int(
                    item.get("endpoints_produced")
                )
                aggregate["banners_captured"] += self._safe_int(
                    item.get("banners_captured")
                )
                aggregate["http_responses"] += self._safe_int(
                    item.get("http_responses")
                )
                aggregate["pages_crawled"] += self._safe_int(
                    item.get("pages_crawled")
                )
                aggregate["js_files_fetched"] += self._safe_int(
                    item.get("js_files_fetched")
                )
                aggregate["api_paths_discovered"] += self._safe_int(
                    item.get("api_paths_discovered")
                )
                aggregate["schemas_found"] += self._safe_int(
                    item.get("schemas_found")
                )
                skip_reason = str(item.get("skip_reason", "")).strip()
                if skip_reason:
                    aggregate["skip_reasons"].add(skip_reason)
                stop_reason = str(item.get("stop_reason", "")).strip()
                if stop_reason:
                    aggregate["stop_reasons"].add(stop_reason)

        module_scorecard = []
        for row in module_rollup.values():
            invocation_count = max(1, self._safe_int(row.get("invocation_count"), 1))
            productive_runs = self._safe_int(row.get("productive_runs"))
            total_elapsed_s = round(self._safe_float(row.get("total_elapsed_s")), 3)
            total_actual_elapsed_s = round(
                self._safe_float(row.get("total_actual_elapsed_s", total_elapsed_s)),
                3,
            )
            module_scorecard.append(
                {
                    **{
                        key: value
                        for key, value in row.items()
                        if key not in {"skip_reasons", "stop_reasons"}
                    },
                    "skip_reasons": sorted(str(value).strip() for value in row.get("skip_reasons", set()) if str(value).strip()),
                    "stop_reasons": sorted(str(value).strip() for value in row.get("stop_reasons", set()) if str(value).strip()),
                    "avg_elapsed_s": round(total_elapsed_s / invocation_count, 3),
                    "avg_actual_elapsed_s": round(
                        total_actual_elapsed_s / invocation_count,
                        3,
                    ),
                    "avg_logical_budget_consumed_s": round(
                        self._safe_float(row.get("logical_budget_consumed_s"))
                        / invocation_count,
                        3,
                    ),
                    "productivity_rate_01": round(productive_runs / invocation_count, 4),
                    "time_per_produced_endpoint_s": (
                        round(
                            total_actual_elapsed_s
                            / max(1, self._safe_int(row.get("endpoints_produced"), 1)),
                            3,
                        )
                        if self._safe_int(row.get("endpoints_produced"), 0) > 0
                        else 0.0
                    ),
                }
            )

        module_scorecard.sort(
            key=lambda row: (
                str(row.get("category", "")),
                -self._safe_int(row.get("produced_candidate_count")),
                -self._safe_float(row.get("productivity_rate_01")),
                str(row.get("module_name", "")),
            )
        )

        return {
            "strategy": "fixed_window_round_robin_scheduler",
            "category_a_discovery_budget_seconds": int(self.category_a_time_budget_seconds),
            "category_bcde_discovery_budget_seconds": int(self.bcde_time_budget_seconds),
            "exploration_budget_seconds": int(self.exploration_budget_seconds),
            "exploitation_budget_seconds": int(self.exploitation_budget_seconds),
            "module_time_slice_seconds": int(self.module_time_slice_seconds),
            "category_a_turn_slice_seconds": 15,
            "category_bcde_turn_slice_seconds": 15,
            "exploitation_turn_slice_seconds": 25,
            "bcde_hard_time_cap_seconds": 50,
            "requested_roots": list(requested_roots),
            "processed_scopes": sorted(str(scope).strip() for scope in processed_scopes if str(scope).strip()),
            "scope_count": len(processed_scopes),
            "scope_graph_node_count_sum": int(total_node_count),
            "scope_graph_edge_count_sum": int(total_edge_count),
            "scope_endpoint_candidate_count_sum": int(total_scope_candidates),
            "total_expanded_candidates": int(expanded_candidate_count),
            "observation_target_count": int(observation_target_count),
            "observation_cap_hit": bool(observation_cap_hit),
            "ceilings_hit_scope_count": int(ceilings_hit_count),
            "productive_category_a_modules": sorted(productive_a_modules),
            "productive_bcde_modules": sorted(productive_bcde_modules),
            "timing_totals": timing_totals,
            "phase_history": list(phase_history),
            "module_scorecard": module_scorecard,
            "scope_summaries": list(scope_summaries),
            "scope_errors": list(scope_errors),
        }

    @staticmethod
    def _split_entity_id(entity_id: str) -> tuple[str, int]:
        token = str(entity_id or "").strip().lower()
        if not token:
            return "", 0
        if "://" in token:
            try:
                parsed = urlsplit(token)
                host = str(parsed.hostname or "").strip().lower()
                port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
                return host, port
            except Exception:
                return "", 0
        try:
            parsed = urlsplit(f"//{token}")
            host = str(parsed.hostname or "").strip().lower()
            port = int(parsed.port or 443)
            return host, port
        except Exception:
            return "", 0

    def _build_observation_outcome_sets(
        self,
        raw_results: List[object],
    ) -> tuple[Set[str], Set[str]]:
        successful: Set[str] = set()
        failed: Set[str] = set()
        for row in raw_results:
            endpoint_value = getattr(
                row,
                "endpoint",
                getattr(row, "endpoint_str", ""),
            )
            host, port = self._split_entity_id(str(endpoint_value or ""))
            if not host or port <= 0:
                continue
            entity_id = f"{host}:{port}"
            if bool(getattr(row, "success", False)):
                successful.add(entity_id)
            else:
                failed.add(entity_id)
        return successful, failed

    def _build_discovered_surface(
        self,
        *,
        roots: List[str],
        expanded_candidates: Set[str],
        scope_summaries: List[Dict[str, Any]],
        selected_for_observation: List[str],
        successful_entity_ids: Set[str],
        failed_entity_ids: Set[str],
    ) -> List[Dict[str, Any]]:
        related_map: Dict[str, Dict[str, Any]] = {}
        observation_targets = {
            entity_id
            for entity_id in (
                self._normalize_seed_endpoint(value)
                for value in selected_for_observation
            )
            if entity_id
        }
        discovered_ids = {
            entity_id
            for entity_id in (
                self._normalize_seed_endpoint(value)
                for value in (list(roots) + list(expanded_candidates))
            )
            if entity_id
        }

        def _upsert(
            entity_id: str,
            *,
            hostname: str,
            port: int,
            scheme: str = "https",
            source: Optional[str] = None,
            discovery_sources: Optional[List[str]] = None,
            historical: bool = False,
            seed: bool = False,
        ) -> None:
            row = related_map.setdefault(
                entity_id,
                {
                    "entity_id": entity_id,
                    "hostname": hostname,
                    "port": int(port),
                    "scheme": str(scheme or "https").strip().lower() or "https",
                    "discovery_source": None,
                    "discovery_sources": [],
                    "surface_tags": [],
                    "historical": bool(historical),
                    "seed": bool(seed),
                    "observation_status": "not_yet_observed",
                    "observation_attempted": False,
                    "recorded_in_snapshot": False,
                },
            )
            if source and not row.get("discovery_source"):
                row["discovery_source"] = str(source).strip()
            merged_sources = set(row.get("discovery_sources", []))
            for token in discovery_sources or []:
                value = str(token).strip()
                if value:
                    merged_sources.add(value)
            row["discovery_sources"] = sorted(merged_sources)
            row["historical"] = bool(row.get("historical")) or bool(historical)
            row["seed"] = bool(row.get("seed")) or bool(seed)
            if row["seed"] and "seed" not in row["surface_tags"]:
                row["surface_tags"].append("seed")

        for value in roots:
            entity_id = self._normalize_seed_endpoint(value)
            if not entity_id:
                continue
            host, port = self._split_entity_id(entity_id)
            if not host or port <= 0:
                continue
            _upsert(
                entity_id,
                hostname=host,
                port=port,
                scheme="https" if port != 80 else "http",
                source="root",
                discovery_sources=["root"],
                seed=True,
            )

        for scope_summary in scope_summaries:
            candidate_rows = scope_summary.get("candidate_rows", [])
            if not isinstance(candidate_rows, list):
                continue
            for candidate in candidate_rows:
                if not isinstance(candidate, dict):
                    continue
                hostname = str(candidate.get("hostname", "")).strip().lower()
                port = self._safe_int(candidate.get("port"))
                if not hostname or port <= 0:
                    continue
                entity_id = f"{hostname}:{port}"
                metadata = candidate.get("metadata", {})
                all_sources = []
                if isinstance(metadata, dict) and isinstance(metadata.get("all_sources"), list):
                    all_sources = [
                        str(token).strip()
                        for token in metadata.get("all_sources", [])
                        if str(token).strip()
                    ]
                primary_source = str(candidate.get("source", "")).strip()
                merged_sources = all_sources or ([primary_source] if primary_source else [])
                historical = bool(metadata.get("historical")) if isinstance(metadata, dict) else False
                _upsert(
                    entity_id,
                    hostname=hostname,
                    port=port,
                    scheme=str(candidate.get("scheme", "https")).strip().lower() or "https",
                    source=primary_source or None,
                    discovery_sources=merged_sources,
                    historical=historical,
                )

        for entity_id in sorted(discovered_ids):
            if entity_id in related_map:
                continue
            host, port = self._split_entity_id(entity_id)
            if not host or port <= 0:
                continue
            _upsert(
                entity_id,
                hostname=host,
                port=port,
                scheme="https" if port != 80 else "http",
            )

        for entity_id, row in related_map.items():
            sources = set(str(token).strip() for token in row.get("discovery_sources", []) if str(token).strip())
            tags = set(str(token).strip() for token in row.get("surface_tags", []) if str(token).strip())
            attempted = entity_id in observation_targets or entity_id in successful_entity_ids or entity_id in failed_entity_ids
            if entity_id in successful_entity_ids:
                row["observation_status"] = "observed_successful"
                row["recorded_in_snapshot"] = True
                tags.add("observed_successful")
            elif entity_id in failed_entity_ids:
                row["observation_status"] = "observation_failed"
                tags.add("observation_failed")
            elif row.get("historical") or "ct_log" in sources:
                row["observation_status"] = "historical_or_ct_only"
                tags.add("historical_or_ct_only")
            else:
                row["observation_status"] = "not_yet_observed"
                tags.add("not_yet_observed")
            row["observation_attempted"] = bool(attempted)
            row["surface_tags"] = sorted(tags)

        return sorted(
            related_map.values(),
            key=lambda row: (
                0 if bool(row.get("seed")) else 1,
                0 if row.get("observation_status") == "observed_successful" else 1,
                str(row.get("hostname", "")),
                self._safe_int(row.get("port")),
            ),
        )

    MAX_WORKERS_CAP = 75
    MAX_ENDPOINTS_CAP = 250_000
    MAX_EXPANSION_RESULTS_CAP = 200_000
    MAX_EXPANSION_CEILING_NODES = 500_000
    MAX_EXPANSION_CEILING_EDGES = 1_000_000
    MAX_EXPANSION_CEILING_ENDPOINTS = 250_000
    MAX_CATEGORY_A_TIME_BUDGET_SECONDS = 1_800
    MAX_BCDE_TIME_BUDGET_SECONDS = 1_800
    MAX_CYCLE_TIME_BUDGET_SECONDS = 3_600
