"""
EngineRuntime
=============

UI/API-facing connector over persisted analytical state.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.storage_manager.storage_manager import StorageManager
from simulator.core.simulation_request import SimulationRequest
from simulator.core.simulation_service import SimulationService
from simulator.scenarios.scenario_catalog import get_default_scenarios


class EngineRuntime:
    """
    Read-only connector for UI/API access.

    Used by:
    - API layer
    - UI layer
    - Admin queries
    """

    def __init__(
        self,
        storage: StorageManager,
        *,
        simulation_root: Optional[str] = None,
    ):
        self.storage = storage
        self._simulation_root = simulation_root
        self._scan_status_cache: Dict[str, Dict[str, Any]] = {}
        self._scan_status_cache_ttl_ms = 1_000
        self.aggregation_engine = AggregationEngine(
            storage=self.storage,
            simulation_root=simulation_root,
        )

    # =========================================================
    # DASHBOARD
    # =========================================================

    def build_dashboard(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.build_dashboard(
            tenant_id,
            authz_scope=authz_scope,
        )

    # =========================================================
    # PAGINATED ENDPOINT TABLE
    # =========================================================

    def get_endpoint_page(
        self,
        tenant_id: str,
        page: int,
        page_size: int,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.get_endpoint_page(
            tenant_id,
            authz_scope=authz_scope,
            page=page,
            page_size=page_size,
        )

    def get_endpoint_detail(
        self,
        tenant_id: str,
        entity_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.get_endpoint_detail(
            tenant_id,
            entity_id,
            authz_scope=authz_scope,
        )

    # =========================================================
    # BUNDLE / TELEMETRY / SIMULATION
    # =========================================================

    def build_cycle_artifact_bundle(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        cycle_id: Optional[str] = None,
        telemetry_record_type: str = "all",
        telemetry_page: int = 1,
        telemetry_page_size: int = 500,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.build_cycle_artifact_bundle(
            tenant_id=tenant_id,
            authz_scope=authz_scope,
            cycle_id=cycle_id,
            telemetry_record_type=telemetry_record_type,
            telemetry_page=telemetry_page,
            telemetry_page_size=telemetry_page_size,
        )

    def get_cycle_telemetry(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        record_type: str = "all",
        page: int = 1,
        page_size: int = 500,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.get_cycle_telemetry(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            authz_scope=authz_scope,
            record_type=record_type,
            page=page,
            page_size=page_size,
        )

    def get_cycle_telemetry_summary(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        preview_page_size: int = 50,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.get_cycle_telemetry_summary(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            authz_scope=authz_scope,
            preview_page_size=preview_page_size,
        )

    def list_cycles(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        page: int = 1,
        page_size: int = 200,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.list_cycles(
            tenant_id=tenant_id,
            authz_scope=authz_scope,
            page=page,
            page_size=page_size,
        )

    def list_simulations(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.list_simulations(
            tenant_id=tenant_id,
            authz_scope=authz_scope,
            page=page,
            page_size=page_size,
        )

    def get_simulation(
        self,
        tenant_id: str,
        simulation_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        return self.aggregation_engine.get_simulation(
            tenant_id=tenant_id,
            simulation_id=simulation_id,
            authz_scope=authz_scope,
        )

    # =========================================================
    # SIMULATION EXECUTION
    # =========================================================

    def list_scenarios(self) -> Dict[str, Any]:
        scenarios = get_default_scenarios()
        return {
            "scenarios": [
                {
                    "id": s.id,
                    "injection_type": s.injection_type,
                    "description": s.description,
                }
                for s in scenarios
            ]
        }

    def run_simulation(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        scenario_id: str,
        scenario_params: Optional[Dict[str, Any]] = None,
        path_mode: str = "SAFE",
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)

        if not self._simulation_root:
            raise RuntimeError("simulation_root not configured")

        # Find latest completed cycle
        cycle_metadata = self.storage.load_cycle_metadata(tenant_id)
        completed = [
            r for r in cycle_metadata
            if str(r.get("status", "")).lower() == "completed"
        ]
        if not completed:
            raise RuntimeError("No completed cycles found for this tenant")

        latest = completed[-1]
        cycle_id = str(latest.get("cycle_id", "")).strip()
        cycle_number = int(latest.get("cycle_number", 1) or 1)
        if not cycle_id:
            raise RuntimeError("Latest cycle has no cycle_id")

        request = SimulationRequest(
            tenant_id=tenant_id,
            baseline_cycle_id=cycle_id,
            cycle_number=cycle_number,
            scenario_id=scenario_id,
            scenario_params=scenario_params or {},
            path_mode=path_mode,
        )

        service = SimulationService(
            production_root=str(self.storage.base_path),
            simulation_root=self._simulation_root,
        )
        response = service.run(request)

        result = response.to_dict()
        result["status"] = "completed"
        return result

    # =========================================================
    # RAW STATE ACCESSORS (FOR API)
    # =========================================================

    def get_latest_snapshot(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        return self.storage.load_latest_snapshot(tenant_id)

    def get_temporal_state(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        return self.storage.load_temporal_state(tenant_id)

    def get_cycle_metadata(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        return self.storage.load_latest_cycle_metadata(tenant_id)

    def get_scan_status(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        now_ms = int(time.time() * 1000)
        cached = self._scan_status_cache.get(tenant_id)
        if isinstance(cached, dict) and int(cached.get("expires_at_unix_ms", 0) or 0) > now_ms:
            payload = cached.get("payload")
            if isinstance(payload, dict):
                return dict(payload)

        lock = self.storage.load_cycle_lock(tenant_id)
        scheduler_state = self.storage.load_scheduler_state(tenant_id)
        cycle_metadata = self.storage.load_cycle_metadata(tenant_id)

        last_completed = next(
            (
                record
                for record in reversed(cycle_metadata)
                if str(record.get("status", "")).lower() == "completed"
            ),
            None,
        )
        latest = cycle_metadata[-1] if cycle_metadata else None
        runtime_summary = (
            latest.get("runtime_summary")
            if isinstance(latest, dict) and isinstance(latest.get("runtime_summary"), dict)
            else {}
        )
        latest_progress_snapshot = (
            runtime_summary.get("progress_snapshot")
            if isinstance(runtime_summary, dict)
            and isinstance(runtime_summary.get("progress_snapshot"), dict)
            else {}
        )
        progress_source = (
            lock
            if isinstance(lock, dict)
            else latest_progress_snapshot
            if isinstance(latest_progress_snapshot, dict)
            else None
        )
        status = "idle"
        cycle_id = ""
        stage = "idle"
        started_at_unix_ms = None
        stage_started_at_unix_ms = None
        updated_at_unix_ms = None
        elapsed_ms = 0

        if isinstance(lock, dict):
            status = "running"
            cycle_id = str(lock.get("cycle_id", "")).strip()
            stage = str(lock.get("stage", "running")).strip() or "running"
            started_at_unix_ms = int(lock.get("started_at_unix_ms", 0) or 0) or None
            stage_started_at_unix_ms = (
                int(lock.get("stage_started_at_unix_ms", 0) or 0) or started_at_unix_ms
            )
            updated_at_unix_ms = int(lock.get("updated_at_unix_ms", 0) or 0) or started_at_unix_ms
            if started_at_unix_ms is not None:
                elapsed_ms = max(0, now_ms - started_at_unix_ms)
        elif isinstance(latest, dict):
            latest_status = str(latest.get("status", "idle")).strip().lower() or "idle"
            if latest_status == "running":
                status = "failed"
                stage = "abandoned"
            else:
                status = latest_status
                stage = (
                    "completed"
                    if latest_status == "completed"
                    else "failed"
                    if latest_status == "failed"
                    else "idle"
                )
            cycle_id = str(latest.get("cycle_id", "")).strip()
            started_at_unix_ms = int(latest.get("timestamp_unix_ms", 0) or 0) or None
            updated_at_unix_ms = started_at_unix_ms
            elapsed_ms = int(latest.get("duration_ms", 0) or 0)

        last_completed_duration_ms = (
            int(last_completed.get("duration_ms", 0) or 0) if isinstance(last_completed, dict) else 0
        )
        estimated_remaining_ms = None
        if status == "running" and last_completed_duration_ms > 0:
            estimated_remaining_ms = max(0, last_completed_duration_ms - elapsed_ms)

        def _optional_int(source: Optional[Dict[str, Any]], key: str) -> Optional[int]:
            if not isinstance(source, dict):
                return None
            value = source.get(key)
            try:
                if value is None or value == "":
                    return None
                return int(value)
            except (TypeError, ValueError):
                return None

        def _optional_str(source: Optional[Dict[str, Any]], key: str) -> Optional[str]:
            if not isinstance(source, dict):
                return None
            value = source.get(key)
            if value is None:
                return None
            text = str(value).strip()
            return text or None

        def _optional_float(source: Optional[Dict[str, Any]], key: str) -> Optional[float]:
            if not isinstance(source, dict):
                return None
            value = source.get(key)
            try:
                if value is None or value == "":
                    return None
                return float(value)
            except (TypeError, ValueError):
                return None

        def _optional_bool(source: Optional[Dict[str, Any]], key: str) -> Optional[bool]:
            if not isinstance(source, dict):
                return None
            value = source.get(key)
            if value is None:
                return None
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"true", "1", "yes"}:
                    return True
                if lowered in {"false", "0", "no"}:
                    return False
                return None
            return bool(value)

        category_a_time_budget_seconds = _optional_int(
            progress_source,
            "category_a_time_budget_seconds",
        )
        bcde_time_budget_seconds = _optional_int(progress_source, "bcde_time_budget_seconds")
        exploration_budget_seconds = _optional_int(progress_source, "exploration_budget_seconds")
        exploitation_budget_seconds = _optional_int(progress_source, "exploitation_budget_seconds")
        module_time_slice_seconds = _optional_int(progress_source, "module_time_slice_seconds")
        cycle_time_budget_seconds = _optional_int(progress_source, "cycle_time_budget_seconds")
        cycle_deadline_unix_ms = _optional_int(progress_source, "cycle_deadline_unix_ms")
        expansion_window_budget_seconds = _optional_int(progress_source, "expansion_window_budget_seconds")
        expansion_window_actual_elapsed_seconds = _optional_float(
            progress_source,
            "expansion_window_actual_elapsed_seconds",
        )
        expansion_window_consumed_seconds = _optional_float(
            progress_source,
            "expansion_window_consumed_seconds",
        )
        expansion_window_remaining_seconds = _optional_float(
            progress_source,
            "expansion_window_remaining_seconds",
        )
        expansion_window_index = _optional_int(progress_source, "expansion_window_index")
        expansion_window_total_count = _optional_int(progress_source, "expansion_window_total_count")
        expansion_pass_type = _optional_str(progress_source, "expansion_pass_type")
        initial_pass_completed = _optional_bool(progress_source, "initial_pass_completed")
        coverage_entries_total = _optional_int(progress_source, "coverage_entries_total")
        coverage_entries_completed = _optional_int(progress_source, "coverage_entries_completed")
        expansion_scope_index = _optional_int(progress_source, "expansion_scope_index")
        expansion_scope_total_count = _optional_int(progress_source, "expansion_scope_total_count")
        expansion_scope_seen_once_count = _optional_int(
            progress_source,
            "expansion_scope_seen_once_count",
        )
        expansion_module_index_within_scope = _optional_int(
            progress_source,
            "expansion_module_index_within_scope",
        )
        expansion_modules_seen_once_count = _optional_int(
            progress_source,
            "expansion_modules_seen_once_count",
        )
        expansion_module_turn_index = _optional_int(progress_source, "expansion_module_turn_index")
        expansion_module_turns_completed = _optional_int(progress_source, "expansion_module_turns_completed")
        expansion_turn_slice_seconds = _optional_int(progress_source, "expansion_turn_slice_seconds")
        discovered_related_count_live = _optional_int(progress_source, "discovered_related_count_live")
        inflight_candidate_count = _optional_int(progress_source, "inflight_candidate_count")
        progress_channel_degraded = _optional_bool(progress_source, "progress_channel_degraded")
        lock_write_warning_count = _optional_int(progress_source, "lock_write_warning_count")
        last_lock_write_error = _optional_str(progress_source, "last_lock_write_error")
        candidate_count_by_scope = {}
        raw_candidate_count_by_scope = (
            progress_source.get("candidate_count_by_scope")
            if isinstance(progress_source, dict)
            else None
        )
        if isinstance(raw_candidate_count_by_scope, dict):
            candidate_count_by_scope = {
                str(key).strip(): int(value)
                for key, value in raw_candidate_count_by_scope.items()
                if str(key).strip() and isinstance(value, (int, float))
            }

        stage_budget_ms = None
        stage_token = str(stage or "").strip().lower()
        if stage_token == "category_a_discovery" and category_a_time_budget_seconds is not None:
            stage_budget_ms = int(category_a_time_budget_seconds) * 1000
        elif stage_token == "category_bcde_discovery" and bcde_time_budget_seconds is not None:
            stage_budget_ms = int(bcde_time_budget_seconds) * 1000
        elif stage_token in {"category_a_exploration", "category_bcde_exploration"}:
            if exploration_budget_seconds is not None:
                stage_budget_ms = int(exploration_budget_seconds) * 1000
        elif stage_token in {"category_a_exploitation", "category_bcde_exploitation"}:
            if exploitation_budget_seconds is not None:
                stage_budget_ms = int(exploitation_budget_seconds) * 1000
        elif stage_token == "productive_exploitation":
            if exploitation_budget_seconds is not None:
                stage_budget_ms = int(exploitation_budget_seconds) * 1000
        elif stage_token == "endpoint_observation":
            stage_budget_ms = None
        elif stage_token == "telemetry_grouping":
            stage_budget_ms = None
        if expansion_window_budget_seconds is not None and stage_token in {
            "category_a_exploration",
            "category_bcde_exploration",
            "productive_exploitation",
        }:
            stage_budget_ms = int(expansion_window_budget_seconds) * 1000

        live_stage_history = []
        raw_stage_history = (
            progress_source.get("stage_history")
            if isinstance(progress_source, dict)
            else None
        )
        if isinstance(raw_stage_history, list):
            for index, row in enumerate(raw_stage_history):
                if not isinstance(row, dict):
                    continue
                stage_name = str(row.get("stage", "")).strip()
                if not stage_name:
                    continue
                started_at = _optional_int(row, "started_at_unix_ms") or started_at_unix_ms
                live_stage_history.append(
                    {
                        "index": index + 1,
                        "stage": stage_name,
                        "started_at_unix_ms": started_at,
                    }
                )

        live_phase_history = []
        raw_phase_history = (
            progress_source.get("expansion_phase_history")
            if isinstance(progress_source, dict)
            else None
        )
        if isinstance(raw_phase_history, list):
            for row in raw_phase_history:
                if not isinstance(row, dict):
                    continue
                phase_name = str(row.get("phase", "")).strip()
                if not phase_name:
                    continue
                live_phase_history.append(
                    {
                        "phase": phase_name,
                        "window": _optional_str(row, "window"),
                        "status": str(row.get("status", "")).strip() or "unknown",
                        "reason": _optional_str(row, "reason"),
                        "scope_total_count": _optional_int(row, "scope_total_count"),
                        "scope_completed_count": _optional_int(row, "scope_completed_count"),
                        "productive_scope_count": _optional_int(row, "productive_scope_count"),
                        "module_turn_count": _optional_int(row, "module_turn_count"),
                        "budget_allocated_seconds": _optional_int(row, "budget_allocated_seconds"),
                        "budget_consumed_seconds": _optional_float(row, "budget_consumed_seconds"),
                        "budget_remaining_seconds": _optional_float(row, "budget_remaining_seconds"),
                        "logical_turn_budget_seconds": _optional_float(
                            row,
                            "logical_turn_budget_seconds",
                        ),
                        "actual_elapsed_seconds": _optional_float(row, "actual_elapsed_seconds"),
                        "idle_gap_seconds": _optional_float(row, "idle_gap_seconds"),
                        "initial_pass_completed": _optional_bool(
                            row,
                            "initial_pass_completed",
                        ),
                        "coverage_entries_total": _optional_int(
                            row,
                            "coverage_entries_total",
                        ),
                        "coverage_entries_completed": _optional_int(
                            row,
                            "coverage_entries_completed",
                        ),
                        "modules_seen_once_count": _optional_int(
                            row,
                            "modules_seen_once_count",
                        ),
                        "scopes_seen_once_count": _optional_int(
                            row,
                            "scopes_seen_once_count",
                        ),
                        "started_at_unix_ms": _optional_int(row, "started_at_unix_ms"),
                        "ended_at_unix_ms": _optional_int(row, "ended_at_unix_ms"),
                    }
                )

        stage_elapsed_ms = (
            max(0, now_ms - stage_started_at_unix_ms)
            if stage_started_at_unix_ms is not None and status == "running"
            else elapsed_ms
        )
        stage_estimated_remaining_ms = (
            max(0, stage_budget_ms - stage_elapsed_ms)
            if stage_budget_ms is not None
            else None
        )
        if status == "running" and expansion_window_remaining_seconds is not None:
            stage_estimated_remaining_ms = max(
                0,
                int(expansion_window_remaining_seconds) * 1000,
            )
        cycle_budget_remaining_ms = None
        if status == "running":
            if cycle_deadline_unix_ms is not None:
                cycle_budget_remaining_ms = max(0, cycle_deadline_unix_ms - now_ms)
            elif cycle_time_budget_seconds is not None:
                cycle_budget_remaining_ms = max(
                    0,
                    (int(cycle_time_budget_seconds) * 1000) - elapsed_ms,
                )

        payload = {
            "tenant_id": tenant_id,
            "status": status,
            "cycle_id": cycle_id,
            "stage": stage,
            "started_at_unix_ms": started_at_unix_ms,
            "stage_started_at_unix_ms": stage_started_at_unix_ms,
            "updated_at_unix_ms": updated_at_unix_ms,
            "elapsed_ms": elapsed_ms,
            "stage_elapsed_ms": stage_elapsed_ms,
            "last_completed_duration_ms": last_completed_duration_ms,
            "last_completed_timestamp_unix_ms": (
                int(last_completed.get("timestamp_unix_ms", 0) or 0)
                if isinstance(last_completed, dict)
                else 0
            )
            or None,
            "estimated_remaining_ms": estimated_remaining_ms,
            "stage_estimated_remaining_ms": stage_estimated_remaining_ms,
            "category_a_time_budget_seconds": category_a_time_budget_seconds,
            "bcde_time_budget_seconds": bcde_time_budget_seconds,
            "exploration_budget_seconds": exploration_budget_seconds,
            "exploitation_budget_seconds": exploitation_budget_seconds,
            "module_time_slice_seconds": module_time_slice_seconds,
            "cycle_time_budget_seconds": cycle_time_budget_seconds,
            "cycle_deadline_unix_ms": cycle_deadline_unix_ms,
            "cycle_budget_remaining_ms": cycle_budget_remaining_ms,
            "seed_endpoint_count": _optional_int(progress_source, "seed_endpoint_count"),
            "root_scope_count": _optional_int(progress_source, "root_scope_count"),
            "planned_scope_count": _optional_int(progress_source, "planned_scope_count"),
            "expansion_scope_processed_count": _optional_int(
                progress_source,
                "expansion_scope_processed_count",
            ),
            "expanded_candidate_count": _optional_int(progress_source, "expanded_candidate_count"),
            "total_candidate_count": _optional_int(progress_source, "total_candidate_count"),
            "expansion_window": _optional_str(progress_source, "expansion_window"),
            "expansion_window_index": expansion_window_index,
            "expansion_window_total_count": expansion_window_total_count,
            "expansion_window_budget_seconds": expansion_window_budget_seconds,
            "expansion_window_actual_elapsed_seconds": expansion_window_actual_elapsed_seconds,
            "expansion_window_consumed_seconds": expansion_window_consumed_seconds,
            "expansion_window_remaining_seconds": expansion_window_remaining_seconds,
            "expansion_active_category": _optional_str(progress_source, "expansion_active_category"),
            "expansion_phase": _optional_str(progress_source, "expansion_phase"),
            "expansion_pass_type": expansion_pass_type,
            "initial_pass_completed": initial_pass_completed,
            "coverage_entries_total": coverage_entries_total,
            "coverage_entries_completed": coverage_entries_completed,
            "expansion_current_scope": _optional_str(progress_source, "expansion_current_scope"),
            "expansion_phase_scope_completed_count": _optional_int(
                progress_source,
                "expansion_phase_scope_completed_count",
            ),
            "expansion_phase_scope_total_count": _optional_int(
                progress_source,
                "expansion_phase_scope_total_count",
            ),
            "expansion_scope_index": expansion_scope_index,
            "expansion_scope_total_count": expansion_scope_total_count,
            "expansion_scope_seen_once_count": expansion_scope_seen_once_count,
            "expansion_current_module": _optional_str(progress_source, "expansion_current_module"),
            "expansion_modules_completed_count": _optional_int(
                progress_source,
                "expansion_modules_completed_count",
            ),
            "expansion_module_total_count": _optional_int(
                progress_source,
                "expansion_module_total_count",
            ),
            "expansion_module_index_within_scope": expansion_module_index_within_scope,
            "expansion_modules_seen_once_count": expansion_modules_seen_once_count,
            "expansion_module_turn_index": expansion_module_turn_index,
            "expansion_module_turns_completed": expansion_module_turns_completed,
            "expansion_turn_slice_seconds": expansion_turn_slice_seconds,
            "expansion_node_count": _optional_int(progress_source, "expansion_node_count"),
            "expansion_edge_count": _optional_int(progress_source, "expansion_edge_count"),
            "expansion_graph_endpoint_count": _optional_int(
                progress_source,
                "expansion_graph_endpoint_count",
            ),
            "discovered_related_count_live": discovered_related_count_live,
            "inflight_candidate_count": inflight_candidate_count,
            "candidate_count_by_scope": candidate_count_by_scope,
            "progress_channel_degraded": progress_channel_degraded,
            "lock_write_warning_count": lock_write_warning_count,
            "last_lock_write_error": last_lock_write_error,
            "expansion_productive_category_a_modules": (
                [
                    str(item).strip()
                    for item in (
                        progress_source.get("expansion_productive_category_a_modules") or []
                    )
                    if str(item).strip()
                ]
                if isinstance(progress_source, dict)
                and isinstance(progress_source.get("expansion_productive_category_a_modules"), list)
                else []
            ),
            "expansion_productive_bcde_modules": (
                [
                    str(item).strip()
                    for item in (
                        progress_source.get("expansion_productive_bcde_modules") or []
                    )
                    if str(item).strip()
                ]
                if isinstance(progress_source, dict)
                and isinstance(progress_source.get("expansion_productive_bcde_modules"), list)
                else []
            ),
            "observation_target_count": _optional_int(progress_source, "observation_target_count"),
            "observation_cap_hit": _optional_bool(progress_source, "observation_cap_hit"),
            "observed_completed_count": _optional_int(progress_source, "observed_completed_count"),
            "observed_successful_count": _optional_int(progress_source, "observed_successful_count"),
            "observed_failed_count": _optional_int(progress_source, "observed_failed_count"),
            "snapshot_endpoint_count": _optional_int(progress_source, "snapshot_endpoint_count"),
            "new_endpoint_count": _optional_int(progress_source, "new_endpoint_count"),
            "removed_endpoint_count": _optional_int(progress_source, "removed_endpoint_count"),
            "stage_history": live_stage_history,
            "expansion_phase_history": live_phase_history,
            "scheduler_last_run_unix_ms": _optional_int(
                scheduler_state,
                "last_run_unix_ms",
            ),
            "scheduler_next_run_unix_ms": _optional_int(
                scheduler_state,
                "next_run_unix_ms",
            ),
            "scheduler_last_status": _optional_str(
                scheduler_state,
                "last_status",
            ),
            "scheduler_consecutive_failures": _optional_int(
                scheduler_state,
                "consecutive_failures",
            ),
            "scheduler_last_error": _optional_str(
                scheduler_state,
                "last_error",
            ),
        }
        self._scan_status_cache[tenant_id] = {
            "expires_at_unix_ms": now_ms + self._scan_status_cache_ttl_ms,
            "payload": dict(payload),
        }
        return payload

    # =========================================================
    # DEPRECATED METHODS (SAFE FAIL)
    # =========================================================

    def evaluate_cycle(self, *args, **kwargs):
        raise RuntimeError(
            "EngineRuntime no longer performs scoring. "
            "Use UnifiedCycleOrchestrator for analytical execution."
        )

    def _assert_authorized(self, authz_scope: AuthorizedTenantScope, tenant_id: str) -> None:
        if authz_scope is None:
            raise RuntimeError("unauthorized tenant access")
        authz_scope.assert_allowed(tenant_id)
