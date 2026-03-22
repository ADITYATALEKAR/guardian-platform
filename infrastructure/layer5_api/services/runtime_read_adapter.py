from __future__ import annotations

from typing import Any, Dict, Optional

from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.runtime.engine_runtime import EngineRuntime


class RuntimeReadAdapter:
    """
    Read-model adapter with Layer 5 endpoint shaping.
    """

    _TELEMETRY_PREVIEW_SIZE = 50

    def __init__(self, runtime: EngineRuntime):
        self._runtime = runtime

    def dashboard(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        return self._runtime.build_dashboard(tenant_id, authz_scope=authz_scope)

    def endpoint_page(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        page: int,
        page_size: int,
    ) -> Dict[str, Any]:
        return self._runtime.get_endpoint_page(
            tenant_id,
            page,
            page_size,
            authz_scope=authz_scope,
        )

    def cycle_bundle(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        bundle = self._runtime.build_cycle_artifact_bundle(
            tenant_id,
            authz_scope=authz_scope,
            cycle_id=cycle_id,
        )

        telemetry_summary = self._runtime.get_cycle_telemetry_summary(
            tenant_id,
            cycle_id,
            authz_scope=authz_scope,
            preview_page_size=self._TELEMETRY_PREVIEW_SIZE,
        )

        return {
            "tenant_id": bundle.get("tenant_id"),
            "cycle_id": bundle.get("cycle_id"),
            "snapshot": bundle.get("snapshot"),
            "cycle_metadata": bundle.get("cycle_metadata", []),
            "temporal_state": bundle.get("temporal_state"),
            "trust_graph_snapshot": bundle.get("trust_graph_snapshot"),
            "layer3_state_snapshot": bundle.get("layer3_state_snapshot"),
            "guardian_records": bundle.get("guardian_records", []),
            "integrity_summary": bundle.get("integrity_summary"),
            "telemetry_summary": telemetry_summary,
        }

    def scan_status(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        return self._runtime.get_scan_status(tenant_id, authz_scope=authz_scope)

    def cycle_telemetry(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        record_type: str,
        page: int,
        page_size: int,
    ) -> Dict[str, Any]:
        return self._runtime.get_cycle_telemetry(
            tenant_id,
            cycle_id,
            authz_scope=authz_scope,
            record_type=record_type,
            page=page,
            page_size=page_size,
        )

    def endpoint_detail(
        self,
        tenant_id: str,
        entity_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        return self._runtime.get_endpoint_detail(
            tenant_id,
            entity_id,
            authz_scope=authz_scope,
        )

    def list_cycles(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        page: int,
        page_size: int,
    ) -> Dict[str, Any]:
        return self._runtime.list_cycles(
            tenant_id,
            authz_scope=authz_scope,
            page=page,
            page_size=page_size,
        )

    def list_simulations(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        page: int,
        page_size: int,
    ) -> Dict[str, Any]:
        return self._runtime.list_simulations(
            tenant_id,
            authz_scope=authz_scope,
            page=page,
            page_size=page_size,
        )

    def simulation_detail(
        self,
        tenant_id: str,
        simulation_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
    ) -> Dict[str, Any]:
        return self._runtime.get_simulation(
            tenant_id,
            simulation_id,
            authz_scope=authz_scope,
        )

    def list_scenarios(self) -> Dict[str, Any]:
        return self._runtime.list_scenarios()

    def run_simulation(
        self,
        tenant_id: str,
        *,
        authz_scope: AuthorizedTenantScope,
        scenario_id: str,
        scenario_params: Optional[Dict[str, Any]] = None,
        path_mode: str = "SAFE",
    ) -> Dict[str, Any]:
        return self._runtime.run_simulation(
            tenant_id,
            authz_scope=authz_scope,
            scenario_id=scenario_id,
            scenario_params=scenario_params,
            path_mode=path_mode,
        )
