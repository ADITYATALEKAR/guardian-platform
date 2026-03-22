from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import time
from typing import Optional

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.layer5_api.app import Layer5API
from infrastructure.operator_plane.services.operator_service import OperatorService
from infrastructure.runtime.engine_runtime import EngineRuntime
from infrastructure.runtime.health import HealthState
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import UnifiedCycleOrchestrator
from layers.layer0_observation.acquisition.cycle_scheduler import CycleScheduler


@dataclass(frozen=True)
class Layer5BootstrapConfig:
    storage_root: str
    operator_storage_root: str
    simulation_root: str
    master_env: str = "OPERATOR_MASTER_PASSWORD"
    layer2_mode: str = "hybrid"
    discovery_max_workers: int = 10
    discovery_max_endpoints: int = 5_000
    discovery_samples_per_endpoint: int = 8
    discovery_max_san_recursion: int = 5
    discovery_max_dns_recursion: int = 5
    discovery_max_spf_recursion: int = 5
    discovery_max_ct_calls_per_cycle: int = 5
    discovery_category_a_time_budget_seconds: int = 150
    discovery_bcde_time_budget_seconds: int = 150
    cycle_time_budget_seconds: int = 600
    discovery_exploration_budget_seconds: int = 300
    discovery_exploitation_budget_seconds: int = 300
    discovery_module_time_slice_seconds: int = 30
    discovery_allow_insecure_tls: bool = False
    enable_background_scheduler: bool = True
    scheduler_cadence_seconds: int = 7_200
    scheduler_tick_seconds: int = 5


@dataclass(frozen=True)
class Layer5RuntimeBundle:
    storage: StorageManager
    identity_manager: IdentityManager
    discovery_engine: DiscoveryEngine
    orchestrator: UnifiedCycleOrchestrator
    runtime: EngineRuntime
    operator_service: OperatorService
    health_state: HealthState
    api: Layer5API
    scheduler: Optional[CycleScheduler] = None


def _seed_admin_from_env(operator_service: "OperatorService") -> None:
    """Re-create the admin account from env vars if it doesn't exist yet.

    This handles Render's free-tier ephemeral filesystem: every cold start
    wipes /data/operator_storage/, so we re-seed the account automatically
    using GUARDIAN_ADMIN_EMAIL and GUARDIAN_ADMIN_PASSWORD.
    """
    import logging
    logger = logging.getLogger(__name__)
    email = os.environ.get("GUARDIAN_ADMIN_EMAIL", "").strip()
    password = os.environ.get("GUARDIAN_ADMIN_PASSWORD", "").strip()
    if not email or not password:
        return
    try:
        operator_service.register_account_with_workspace(
            email=email,
            password=password,
            created_at_unix_ms=int(time.time() * 1000),
            status="ACTIVE",
            institution_name=os.environ.get("GUARDIAN_ADMIN_INSTITUTION", "").strip() or None,
        )
        logger.info("guardian_seed_admin created email=%s", email)
    except Exception as exc:
        msg = str(exc).lower()
        if "already exists" in msg or "email already" in msg:
            # Account exists — normal after first boot, nothing to do.
            pass
        else:
            logger.warning("guardian_seed_admin failed: %s", exc)


def _validate_runtime_path(root: str, label: str) -> str:
    candidate = str(root or "").strip()
    if not candidate:
        raise RuntimeError(f"{label} is required")
    path = Path(candidate)
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f".guardian_write_probe_{os.getpid()}_{time.time_ns()}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise RuntimeError(f"{label} is not writable: {candidate}") from exc
    return str(path)


def build_layer5_runtime_bundle(config: Layer5BootstrapConfig) -> Layer5RuntimeBundle:
    storage_root = _validate_runtime_path(config.storage_root, "storage_root")
    operator_storage_root = _validate_runtime_path(
        config.operator_storage_root,
        "operator_storage_root",
    )
    simulation_root = _validate_runtime_path(config.simulation_root, "simulation_root")

    storage = StorageManager(storage_root)
    identity_manager = IdentityManager(storage)

    discovery_engine = DiscoveryEngine(
        storage=storage,
        max_workers=config.discovery_max_workers,
        max_endpoints=config.discovery_max_endpoints,
        samples_per_endpoint=config.discovery_samples_per_endpoint,
        max_san_recursion=config.discovery_max_san_recursion,
        max_dns_recursion=config.discovery_max_dns_recursion,
        max_spf_recursion=config.discovery_max_spf_recursion,
        max_ct_calls_per_cycle=config.discovery_max_ct_calls_per_cycle,
        category_a_time_budget_seconds=config.discovery_category_a_time_budget_seconds,
        bcde_time_budget_seconds=config.discovery_bcde_time_budget_seconds,
        cycle_time_budget_seconds=config.cycle_time_budget_seconds,
        exploration_budget_seconds=config.discovery_exploration_budget_seconds,
        exploitation_budget_seconds=config.discovery_exploitation_budget_seconds,
        module_time_slice_seconds=config.discovery_module_time_slice_seconds,
        allow_insecure_tls=config.discovery_allow_insecure_tls,
    )

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=discovery_engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
        layer2_mode=config.layer2_mode,
        simulation_root=simulation_root,
        cycle_time_budget_seconds=config.cycle_time_budget_seconds,
    )

    runtime = EngineRuntime(
        storage=storage,
        simulation_root=simulation_root,
    )
    health_state = HealthState()

    operator_service = OperatorService(
        operator_storage_root=operator_storage_root,
        storage_manager=storage,
        identity_manager=identity_manager,
        simulation_root=simulation_root,
        orchestrator=orchestrator,
        master_env=config.master_env,
        layer2_mode=config.layer2_mode,
        discovery_max_workers=config.discovery_max_workers,
        discovery_max_endpoints=config.discovery_max_endpoints,
        discovery_samples_per_endpoint=config.discovery_samples_per_endpoint,
        discovery_max_san_recursion=config.discovery_max_san_recursion,
        discovery_max_dns_recursion=config.discovery_max_dns_recursion,
        discovery_max_spf_recursion=config.discovery_max_spf_recursion,
        discovery_max_ct_calls_per_cycle=config.discovery_max_ct_calls_per_cycle,
        discovery_category_a_time_budget_seconds=config.discovery_category_a_time_budget_seconds,
        discovery_bcde_time_budget_seconds=config.discovery_bcde_time_budget_seconds,
        cycle_time_budget_seconds=config.cycle_time_budget_seconds,
        discovery_exploration_budget_seconds=config.discovery_exploration_budget_seconds,
        discovery_exploitation_budget_seconds=config.discovery_exploitation_budget_seconds,
        discovery_module_time_slice_seconds=config.discovery_module_time_slice_seconds,
        allow_insecure_tls=config.discovery_allow_insecure_tls,
        scheduler_cadence_seconds=config.scheduler_cadence_seconds,
        scheduler_tick_seconds=config.scheduler_tick_seconds,
    )

    # Seed a default admin account from env vars on every startup.
    # On ephemeral filesystems (Render free tier), the operator storage is
    # wiped on each restart. GUARDIAN_ADMIN_EMAIL + GUARDIAN_ADMIN_PASSWORD
    # let an account persist across restarts by re-creating it automatically.
    _seed_admin_from_env(operator_service)

    api = Layer5API(
        runtime=runtime,
        operator_storage_root=operator_storage_root,
        operator_service=operator_service,
        health_state=health_state,
    )
    scheduler: Optional[CycleScheduler] = None
    scheduler_enabled = bool(config.enable_background_scheduler)
    if os.environ.get("PYTEST_CURRENT_TEST"):
        scheduler_enabled = False
    if scheduler_enabled:
        scheduler = CycleScheduler(
            operator_service=operator_service,
            storage=storage,
            cadence_seconds=config.scheduler_cadence_seconds,
            tick_seconds=config.scheduler_tick_seconds,
        )
        scheduler.start_in_background()
    health_state.mark_ready()

    return Layer5RuntimeBundle(
        storage=storage,
        identity_manager=identity_manager,
        discovery_engine=discovery_engine,
        orchestrator=orchestrator,
        runtime=runtime,
        operator_service=operator_service,
        health_state=health_state,
        api=api,
        scheduler=scheduler,
    )


def build_layer5_api(config: Layer5BootstrapConfig) -> Layer5API:
    return build_layer5_runtime_bundle(config).api
