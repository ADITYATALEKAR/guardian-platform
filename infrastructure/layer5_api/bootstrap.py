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
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager
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
    discovery_max_workers: int = 25
    discovery_max_endpoints: int = 500
    discovery_samples_per_endpoint: int = 3
    discovery_max_san_recursion: int = 2
    discovery_max_dns_recursion: int = 2
    discovery_max_spf_recursion: int = 2
    discovery_max_ct_calls_per_cycle: int = 3
    discovery_category_a_time_budget_seconds: int = 90
    discovery_bcde_time_budget_seconds: int = 90
    cycle_time_budget_seconds: int = 600
    discovery_exploration_budget_seconds: int = 120
    discovery_exploitation_budget_seconds: int = 120
    discovery_module_time_slice_seconds: int = 20
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
    """Idempotently seed the admin account from env vars on every cold start.

    On Render free tier, /data/ is ephemeral and wiped on each restart.
    This function re-creates the admin operator + workspace on every boot
    using deterministic IDs derived from the email, so the same tenant
    directory is always used and scan data survives within a session.

    Handles three cases:
      1. Fresh start — create operator + workspace from scratch.
      2. Operator exists, workspace exists — nothing to do.
      3. Operator exists, workspace wiped — re-create workspace with same
         deterministic tenant ID so the correct storage path is restored.
    """
    import hashlib
    import logging
    logger = logging.getLogger(__name__)
    email = os.environ.get("GUARDIAN_ADMIN_EMAIL", "").strip()
    password = os.environ.get("GUARDIAN_ADMIN_PASSWORD", "").strip()
    if not email or not password:
        return

    institution_name = os.environ.get("GUARDIAN_ADMIN_INSTITUTION", "").strip() or None

    # Derive the same deterministic operator_id the adapter uses.
    normalized = email.lower()
    local = normalized.split("@")[0] if "@" in normalized else normalized
    safe = "".join(ch for ch in local if ch.isalnum())[:12] or "user"
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:6]
    operator_id = f"usr_{safe}_{digest}"

    # Check if the admin account was intentionally deleted — don't revive it.
    try:
        from infrastructure.db.connection import use_postgres, get_setting
        if use_postgres() and get_setting(f"deleted_operator:{operator_id}") == "1":
            logger.info("guardian_seed_admin: admin account was deleted, skipping seed email=%s", email)
            return
    except Exception as exc:
        logger.warning("guardian_seed_admin: could not check deleted flag: %s", exc)

    try:
        # Attempt full registration (operator + workspace).
        operator_service.register_account_with_workspace(
            email=email,
            password=password,
            created_at_unix_ms=int(time.time() * 1000),
            status="ACTIVE",
            institution_name=institution_name,
        )
        logger.info("guardian_seed_admin: created operator+workspace email=%s", email)
        return
    except Exception as exc:
        msg = str(exc).lower()
        if "already exists" not in msg and "email already" not in msg and "workspace already" not in msg:
            logger.warning("guardian_seed_admin: full registration failed: %s", exc)
            return

    # Operator already exists. Check if workspace (tenant) also exists.
    try:
        from infrastructure.operator_plane.registry.operator_registry import list_tenants as _list_tenants
        existing_tenants = _list_tenants(operator_service._operator_storage_root, operator_id)
        if existing_tenants:
            # Both exist — nothing to do.
            logger.debug("guardian_seed_admin: operator+workspace already present email=%s", email)
            return
    except Exception as exc:
        logger.warning("guardian_seed_admin: could not check tenant list: %s", exc)
        return

    # Operator exists but workspace was wiped — re-create with deterministic tenant ID.
    try:
        deterministic_tenant_id = TenantLifecycleManager.derive_tenant_id_from_operator(operator_id)
        operator_service.create_workspace(
            operator_id=operator_id,
            institution_name=institution_name or local.replace(".", " ").title() or "Workspace",
        )
        logger.info(
            "guardian_seed_admin: re-created workspace tenant_id=%s email=%s",
            deterministic_tenant_id,
            email,
        )
    except Exception as exc:
        logger.warning("guardian_seed_admin: workspace re-creation failed: %s", exc)


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

    from infrastructure.db.connection import use_postgres
    if use_postgres():
        from infrastructure.db.schema import ensure_schema
        ensure_schema()
        from infrastructure.storage_manager.pg_storage_manager import PgStorageManager
        from infrastructure.storage_manager.pg_identity_manager import PgIdentityManager
        storage = PgStorageManager(storage_root)
        identity_manager = PgIdentityManager(storage)
    else:
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
