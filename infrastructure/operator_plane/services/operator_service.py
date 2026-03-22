from __future__ import annotations

import inspect
import os
import logging
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from infrastructure.operator_plane.registry.operator_registry import (
    authenticate_operator,
    create_operator,
    delete_operator_record_only,
    get_operator,
    list_operators,
    update_operator_email,
    update_operator_password,
)
from infrastructure.operator_plane.registry.operator_tenant_links import (
    add_link,
    get_tenant,
    list_operators_for_tenant,
    list_tenants,
    remove_operator,
)
from infrastructure.operator_plane.storage.operator_storage import (
    delete_session,
    ensure_operator_storage,
    read_operator_links,
    read_session,
    write_operator_links,
    write_session,
)
from infrastructure.runtime.tenant_lifecycle_manager import TenantLifecycleManager

_REAL_SUBPROCESS_POPEN = subprocess.Popen


class OperatorService:
    ROLE_OWNER = "OWNER"
    ROLE_ADMIN = "ADMIN"
    ROLE_MEMBER = "MEMBER"
    _INFRA_FAILURE_BACKOFF_MINUTES = (10, 20, 30)

    def __init__(
        self,
        operator_storage_root: str,
        storage_manager: Any,
        identity_manager: Any,
        simulation_root: str,
        orchestrator: Any,
        master_env: str = None,
        layer2_mode: str = "hybrid",
        discovery_max_workers: int = 10,
        discovery_max_endpoints: int = 5_000,
        discovery_samples_per_endpoint: int = 8,
        discovery_max_san_recursion: int = 5,
        discovery_max_dns_recursion: int = 5,
        discovery_max_spf_recursion: int = 5,
        discovery_max_ct_calls_per_cycle: int = 5,
        discovery_category_a_time_budget_seconds: int = 150,
        discovery_bcde_time_budget_seconds: int = 150,
        cycle_time_budget_seconds: int = 600,
        discovery_exploration_budget_seconds: int = 300,
        discovery_exploitation_budget_seconds: int = 300,
        discovery_module_time_slice_seconds: int = 30,
        allow_insecure_tls: bool = False,
        scheduler_cadence_seconds: int = 7_200,
        scheduler_tick_seconds: int = 5,
    ):
        ensure_operator_storage(operator_storage_root)
        self._operator_storage_root = operator_storage_root
        self._storage_manager = storage_manager
        self._identity_manager = identity_manager
        self._simulation_root = simulation_root
        self._orchestrator = orchestrator
        self._tenant_lifecycle = TenantLifecycleManager(
            storage_manager, identity_manager, simulation_root
        )
        self._master_env = master_env or "OPERATOR_MASTER_PASSWORD"
        self._logger = logging.getLogger(__name__)
        self._layer2_mode = str(layer2_mode or "hybrid")
        self._discovery_max_workers = int(discovery_max_workers)
        self._discovery_max_endpoints = int(discovery_max_endpoints)
        self._discovery_samples_per_endpoint = int(discovery_samples_per_endpoint)
        self._discovery_max_san_recursion = int(discovery_max_san_recursion)
        self._discovery_max_dns_recursion = int(discovery_max_dns_recursion)
        self._discovery_max_spf_recursion = int(discovery_max_spf_recursion)
        self._discovery_max_ct_calls_per_cycle = int(discovery_max_ct_calls_per_cycle)
        self._discovery_category_a_time_budget_seconds = int(
            discovery_category_a_time_budget_seconds
        )
        self._discovery_bcde_time_budget_seconds = int(
            discovery_bcde_time_budget_seconds
        )
        self._cycle_time_budget_seconds = int(cycle_time_budget_seconds)
        self._discovery_exploration_budget_seconds = int(
            discovery_exploration_budget_seconds
        )
        self._discovery_exploitation_budget_seconds = int(
            discovery_exploitation_budget_seconds
        )
        self._discovery_module_time_slice_seconds = int(
            discovery_module_time_slice_seconds
        )
        self._allow_insecure_tls = bool(allow_insecure_tls)
        self._scheduler_cadence_seconds = max(60, int(scheduler_cadence_seconds))
        self._scheduler_tick_seconds = max(1, int(scheduler_tick_seconds))

    def register_operator(
        self,
        operator_id: str,
        email: str,
        password: str,
        created_at_unix_ms: int,
        status: str = "ACTIVE",
        role: str = ROLE_OWNER,
    ) -> Dict[str, Any]:
        return create_operator(
            self._operator_storage_root,
            operator_id=operator_id,
            email=email,
            password=password,
            created_at_unix_ms=created_at_unix_ms,
            status=status,
            role=role,
        )

    def register_tenant(
        self,
        operator_id: str,
        institution_name: str,
        main_url: str,
        seed_endpoints: List[str],
        password: Optional[str],
        registration_metadata: Optional[Dict[str, Any]] = None,
        created_at_unix_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        _ = get_operator(self._operator_storage_root, operator_id)
        existing_tenants = list_tenants(self._operator_storage_root, operator_id)
        if existing_tenants:
            raise RuntimeError("additional tenant creation is not permitted")

        if not seed_endpoints:
            seed_endpoints = [self._normalize_seed_from_main_url(main_url)]

        tenant_password = str(password or "").strip() or self._generate_tenant_password()

        tenant_id = self._tenant_lifecycle.register_tenant(
            name=institution_name,
            password=tenant_password,
            main_url=main_url,
            seed_endpoints=seed_endpoints,
        )

        add_link(self._operator_storage_root, operator_id, tenant_id)

        cycle_number = self._get_next_cycle_number(tenant_id)
        cycle_id = f"cycle_{cycle_number:06d}"
        self.mark_manual_cycle_launch_for_scheduler(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            cycle_number=cycle_number,
        )
        try:
            inline_kwargs = {
                "cycle_id": cycle_id,
                "cycle_number": cycle_number,
            }
            try:
                signature = inspect.signature(self._orchestrator.run_cycle)
            except (TypeError, ValueError):
                signature = None
            if signature is not None and not any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            ):
                inline_kwargs = {
                    name: value
                    for name, value in inline_kwargs.items()
                    if name in signature.parameters
                }
            self._orchestrator.run_cycle(
                tenant_id,
                **inline_kwargs,
            )
            self.sync_scheduler_state_from_cycle_result(
                tenant_id=tenant_id,
                cycle_id=cycle_id,
                cycle_number=cycle_number,
                status="completed",
            )
        except Exception as exc:
            self.sync_scheduler_state_from_cycle_result(
                tenant_id=tenant_id,
                cycle_id=cycle_id,
                cycle_number=cycle_number,
                status="failed",
                error_message=str(exc),
            )
            raise
        return {"tenant_id": tenant_id, "cycle_started": True}

    def create_workspace(
        self,
        *,
        operator_id: str,
        institution_name: str,
    ) -> Dict[str, Any]:
        """
        Creates tenant workspace and link without triggering discovery.

        Intended for account-first onboarding flows where scan configuration
        is completed in a later explicit step.
        """
        _ = get_operator(self._operator_storage_root, operator_id)
        existing_tenants = list_tenants(self._operator_storage_root, operator_id)
        if existing_tenants:
            raise RuntimeError("workspace already exists for operator")
        if not institution_name or not str(institution_name).strip():
            raise ValueError("institution_name cannot be empty")

        tenant_password = self._generate_tenant_password()
        deterministic_tenant_id = TenantLifecycleManager.derive_tenant_id_from_operator(operator_id)
        tenant_id = self._tenant_lifecycle.register_pending_tenant(
            name=institution_name,
            password=tenant_password,
            tenant_id=deterministic_tenant_id,
        )
        try:
            add_link(self._operator_storage_root, operator_id, tenant_id)
        except Exception as exc:
            try:
                if self._storage_manager.tenant_exists(tenant_id):
                    self._storage_manager.delete_tenant(tenant_id)
            except Exception:
                pass
            try:
                if self._identity_manager.has_tenant(tenant_id):
                    self._identity_manager.delete_credentials(tenant_id, tenant_password)
            except Exception:
                pass
            raise RuntimeError("workspace creation failed") from exc
        self.seed_pending_scheduler_state(tenant_id)
        return {
            "tenant_id": tenant_id,
            "onboarding_status": "PENDING",
            "cycle_started": False,
        }

    def onboard_workspace_and_start_cycle(
        self,
        *,
        operator_id: str,
        tenant_id: str,
        institution_name: str,
        main_url: str,
        seed_endpoints: List[str],
    ) -> Dict[str, Any]:
        """
        Completes pending workspace onboarding and starts discovery cycle.
        """
        _ = get_operator(self._operator_storage_root, operator_id)
        linked_tenants = list_tenants(self._operator_storage_root, operator_id)
        if tenant_id not in linked_tenants:
            raise RuntimeError("tenant not found")

        seeds = list(seed_endpoints or [])
        if not seeds:
            seeds = [self._normalize_seed_from_main_url(main_url)]

        cycle_number = self._get_next_cycle_number(tenant_id)
        cycle_id = f"cycle_{cycle_number:06d}"
        self._storage_manager.reserve_cycle_launch(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            cycle_number=cycle_number,
        )
        try:
            self._tenant_lifecycle.configure_tenant_onboarding(
                tenant_id=tenant_id,
                name=institution_name,
                main_url=main_url,
                seed_endpoints=seeds,
            )
            self.mark_manual_cycle_launch_for_scheduler(
                tenant_id=tenant_id,
                cycle_id=cycle_id,
                cycle_number=cycle_number,
            )
            completed_inline = bool(self._start_cycle_async(
                tenant_id,
                cycle_id=cycle_id,
                cycle_number=cycle_number,
            ))
            if completed_inline:
                self.sync_scheduler_state_from_cycle_result(
                    tenant_id=tenant_id,
                    cycle_id=cycle_id,
                    cycle_number=cycle_number,
                    status="completed",
                )
        except Exception:
            self._storage_manager.release_cycle_lock(tenant_id)
            self.seed_pending_scheduler_state(tenant_id)
            raise
        return {
            "tenant_id": tenant_id,
            "onboarding_status": (
                self._tenant_lifecycle.ONBOARDING_COMPLETED
                if completed_inline
                else self._tenant_lifecycle.ONBOARDING_PENDING
            ),
            "cycle_started": True,
        }

    def _start_cycle_async(
        self,
        tenant_id: str,
        *,
        cycle_id: str,
        cycle_number: int,
    ) -> bool:
        if os.environ.get("PYTEST_CURRENT_TEST") and subprocess.Popen is _REAL_SUBPROCESS_POPEN:
            inline_kwargs = {
                "cycle_id": cycle_id,
                "cycle_number": cycle_number,
            }
            run_cycle = self._orchestrator.run_cycle
            try:
                signature = inspect.signature(run_cycle)
            except (TypeError, ValueError):
                signature = None
            if signature is not None and not any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            ):
                inline_kwargs = {
                    name: value
                    for name, value in inline_kwargs.items()
                    if name in signature.parameters
                }
            run_cycle(
                tenant_id,
                **inline_kwargs,
            )
            self._tenant_lifecycle.mark_tenant_onboarding_completed(tenant_id)
            return True

        worker_module = "infrastructure.operator_plane.services.cycle_worker"
        executable = Path(sys.executable)
        pythonw_executable = executable.with_name("pythonw.exe")
        worker_executable = (
            str(pythonw_executable)
            if os.name == "nt" and pythonw_executable.exists()
            else sys.executable
        )
        command = [
            worker_executable,
            "-u",
            "-m",
            worker_module,
            "--tenant-id",
            str(tenant_id),
            "--cycle-id",
            str(cycle_id),
            "--cycle-number",
            str(cycle_number),
            "--storage-root",
            str(self._storage_manager.base_path),
            "--operator-storage-root",
            str(self._operator_storage_root),
            "--simulation-root",
            str(self._simulation_root),
            "--master-env",
            str(self._master_env),
            "--layer2-mode",
            str(self._layer2_mode),
            "--discovery-max-workers",
            str(self._discovery_max_workers),
            "--discovery-max-endpoints",
            str(self._discovery_max_endpoints),
            "--discovery-samples-per-endpoint",
            str(self._discovery_samples_per_endpoint),
            "--discovery-max-san-recursion",
            str(self._discovery_max_san_recursion),
            "--discovery-max-dns-recursion",
            str(self._discovery_max_dns_recursion),
            "--discovery-max-spf-recursion",
            str(self._discovery_max_spf_recursion),
            "--discovery-max-ct-calls-per-cycle",
            str(self._discovery_max_ct_calls_per_cycle),
            "--discovery-category-a-time-budget-seconds",
            str(self._discovery_category_a_time_budget_seconds),
            "--discovery-bcde-time-budget-seconds",
            str(self._discovery_bcde_time_budget_seconds),
            "--cycle-time-budget-seconds",
            str(self._cycle_time_budget_seconds),
            "--discovery-exploration-budget-seconds",
            str(self._discovery_exploration_budget_seconds),
            "--discovery-exploitation-budget-seconds",
            str(self._discovery_exploitation_budget_seconds),
            "--discovery-module-time-slice-seconds",
            str(self._discovery_module_time_slice_seconds),
            "--scheduler-cadence-seconds",
            str(self._scheduler_cadence_seconds),
            "--scheduler-tick-seconds",
            str(self._scheduler_tick_seconds),
            "--allow-insecure-tls",
            "true" if self._allow_insecure_tls else "false",
        ]
        project_root = Path(__file__).resolve().parents[3]
        tenant_path = self._storage_manager.get_tenant_path(tenant_id)
        log_path = tenant_path / "cycle_metadata" / "worker.log"

        creation_flags = 0
        for flag_name in ("CREATE_NEW_PROCESS_GROUP", "DETACHED_PROCESS", "CREATE_NO_WINDOW"):
            creation_flags |= int(getattr(subprocess, flag_name, 0))
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
            startupinfo.wShowWindow = getattr(subprocess, "SW_HIDE", 0)

        with open(log_path, "ab") as log_handle:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            process = subprocess.Popen(
                command,
                cwd=str(project_root),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=log_handle,
                close_fds=True,
                creationflags=creation_flags,
                startupinfo=startupinfo,
                env=env,
            )
            time.sleep(0.35)
            poll = getattr(process, "poll", None)
            exit_code = poll() if callable(poll) else None
            if exit_code is not None:
                try:
                    log_handle.flush()
                except Exception:
                    pass
                failure_detail = ""
                try:
                    log_lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if log_lines:
                        failure_detail = log_lines[-1].strip()
                except Exception:
                    failure_detail = ""
                raise RuntimeError(
                    "cycle worker failed to start"
                    + (f": {failure_detail}" if failure_detail else "")
                )
        self._storage_manager.update_cycle_lock(
            tenant_id,
            {
                "cycle_id": cycle_id,
                "cycle_number": cycle_number,
                "pid": int(process.pid),
                "launcher_pid": os.getpid(),
                "stage": "launching",
            },
        )
        return False

    def start_scheduled_cycle(self, *, tenant_id: str) -> Dict[str, Any]:
        if not self._storage_manager.tenant_exists(tenant_id):
            raise RuntimeError("tenant not found")

        config = self._storage_manager.load_tenant_config(tenant_id)
        onboarding_status = str(config.get("onboarding_status", "")).strip().upper()
        seed_endpoints = config.get("seed_endpoints", [])
        if onboarding_status != self._tenant_lifecycle.ONBOARDING_COMPLETED:
            raise RuntimeError("scheduled cycle requires completed onboarding")
        if not str(config.get("main_url", "")).strip() or not isinstance(seed_endpoints, list) or not any(
            str(row).strip() for row in seed_endpoints
        ):
            raise RuntimeError("scheduled cycle requires configured discovery roots")

        cycle_number = self._get_next_cycle_number(tenant_id)
        cycle_id = f"cycle_{cycle_number:06d}"
        self._storage_manager.reserve_cycle_launch(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            cycle_number=cycle_number,
        )
        try:
            self._start_cycle_async(
                tenant_id,
                cycle_id=cycle_id,
                cycle_number=cycle_number,
            )
        except Exception:
            self._storage_manager.release_cycle_lock(tenant_id)
            raise
        return {
            "tenant_id": tenant_id,
            "cycle_id": cycle_id,
            "cycle_number": cycle_number,
        }

    def seed_pending_scheduler_state(self, tenant_id: str) -> None:
        now_ms = int(time.time() * 1000)
        existing = self._storage_manager.load_scheduler_state(tenant_id) or {}
        self._storage_manager.save_scheduler_state(
            tenant_id,
            {
                "last_run_unix_ms": int(existing.get("last_run_unix_ms", 0) or 0),
                "next_run_unix_ms": now_ms + (self._scheduler_tick_seconds * 1000),
                "last_status": "pending_onboarding",
                "consecutive_failures": 0,
            },
        )

    def mark_manual_cycle_launch_for_scheduler(
        self,
        *,
        tenant_id: str,
        cycle_id: str,
        cycle_number: int,
    ) -> None:
        now_ms = int(time.time() * 1000)
        existing = self._storage_manager.load_scheduler_state(tenant_id) or {}
        self._storage_manager.save_scheduler_state(
            tenant_id,
            {
                "last_run_unix_ms": now_ms,
                "next_run_unix_ms": now_ms + (self._scheduler_tick_seconds * 1000),
                "last_status": "manual_launch",
                "last_cycle_id": str(cycle_id or "").strip(),
                "last_cycle_number": int(cycle_number or 0),
                "consecutive_failures": int(existing.get("consecutive_failures", 0) or 0),
            },
        )

    def sync_scheduler_state_from_cycle_result(
        self,
        *,
        tenant_id: str,
        cycle_id: Optional[str] = None,
        cycle_number: Optional[int] = None,
        status: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        latest = self._storage_manager.load_latest_cycle_metadata(tenant_id)
        expected_cycle_id = str(cycle_id or "").strip()
        if not isinstance(latest, dict) or (
            expected_cycle_id and str(latest.get("cycle_id", "")).strip() != expected_cycle_id
        ):
            now_ms = int(time.time() * 1000)
            latest = {
                "cycle_id": expected_cycle_id,
                "cycle_number": int(cycle_number or 0),
                "timestamp_unix_ms": now_ms,
                "duration_ms": 0,
                "status": str(status or "failed").strip().lower() or "failed",
                "error_messages": [str(error_message or "").strip()] if error_message else [],
            }

        existing = self._storage_manager.load_scheduler_state(tenant_id) or {}
        latest_status = str(latest.get("status", status or "completed")).strip().lower() or "completed"
        started_at_ms = int(latest.get("timestamp_unix_ms", 0) or 0) or int(time.time() * 1000)
        duration_ms = max(0, int(latest.get("duration_ms", 0) or 0))
        finished_at_ms = started_at_ms + duration_ms
        if finished_at_ms <= 0:
            finished_at_ms = int(time.time() * 1000)
        config = self._storage_manager.load_tenant_config(tenant_id)
        onboarding_completed = (
            str(config.get("onboarding_status", "")).strip().upper()
            == self._tenant_lifecycle.ONBOARDING_COMPLETED
        )
        previous_cycle_id = str(existing.get("last_cycle_id", "")).strip()
        previous_status = str(existing.get("last_status", "")).strip().lower()
        previous_failures = int(existing.get("consecutive_failures", 0) or 0)
        cycle_error_message = str(error_message or "").strip()
        if latest_status == "failed" and not cycle_error_message:
            error_rows = latest.get("error_messages", [])
            if isinstance(error_rows, list):
                cycle_error_message = next(
                    (str(row).strip() for row in error_rows if str(row).strip()),
                    "",
                )
        failure_class = (
            self._classify_cycle_failure(cycle_error_message)
            if latest_status == "failed"
            else None
        )
        if latest_status == "completed":
            consecutive_failures = 0
            next_run_unix_ms = finished_at_ms + (self._scheduler_cadence_seconds * 1000)
        else:
            if previous_cycle_id == str(latest.get("cycle_id", "")).strip() and previous_status == latest_status:
                consecutive_failures = previous_failures
            else:
                consecutive_failures = previous_failures + 1
            if failure_class == "infrastructure":
                next_run_unix_ms = finished_at_ms + self._infra_failure_backoff_ms(
                    consecutive_failures
                )
            else:
                next_run_unix_ms = finished_at_ms + (self._scheduler_tick_seconds * 1000)
                if onboarding_completed:
                    next_run_unix_ms = finished_at_ms + (
                        self._scheduler_tick_seconds * 1000
                    )

        payload: Dict[str, Any] = {
            "last_run_unix_ms": finished_at_ms,
            "next_run_unix_ms": next_run_unix_ms,
            "last_status": latest_status,
            "last_cycle_id": str(latest.get("cycle_id", "")).strip(),
            "last_cycle_number": int(latest.get("cycle_number", cycle_number or 0) or 0),
            "consecutive_failures": consecutive_failures,
        }
        if latest_status == "failed":
            error_rows = latest.get("error_messages", [])
            if isinstance(error_rows, list):
                payload["last_error"] = next(
                    (str(row).strip() for row in error_rows if str(row).strip()),
                    str(error_message or "").strip(),
                )
            elif error_message:
                payload["last_error"] = str(error_message).strip()
            if failure_class:
                payload["last_failure_class"] = failure_class
                payload["failure_cooldown_expires_unix_ms"] = next_run_unix_ms
        self._storage_manager.save_scheduler_state(tenant_id, payload)
        return payload

    @classmethod
    def _classify_cycle_failure(cls, error_message: Optional[str]) -> str:
        text = str(error_message or "").strip().lower()
        if (
            ".cycle.lock" in text
            or "permissionerror" in text
            or "access is denied" in text
            or "winerror 5" in text
            or "winerror 32" in text
            or "stale cycle lock removal failed" in text
        ):
            return "infrastructure"
        return "scan"

    @classmethod
    def _infra_failure_backoff_ms(cls, consecutive_failures: int) -> int:
        failure_index = max(1, int(consecutive_failures or 1))
        if failure_index <= 1:
            minutes = cls._INFRA_FAILURE_BACKOFF_MINUTES[0]
        elif failure_index == 2:
            minutes = cls._INFRA_FAILURE_BACKOFF_MINUTES[1]
        else:
            minutes = cls._INFRA_FAILURE_BACKOFF_MINUTES[2]
        return int(minutes) * 60 * 1000

    def _generate_tenant_password(self) -> str:
        return f"tenant_{secrets.token_urlsafe(18)}"

    def _normalize_seed_from_main_url(self, main_url: str) -> str:
        parsed = urlparse(main_url)
        if parsed.scheme:
            host = parsed.hostname or ""
            port = parsed.port
        else:
            host = main_url
            port = None

        host = host.strip()
        if not host:
            raise ValueError("main_url cannot be empty")

        if port is not None:
            return f"{host}:{port}"

        if ":" in host:
            return host

        return f"{host}:443"

    def _get_next_cycle_number(self, tenant_id: str) -> int:
        records = self._storage_manager.load_cycle_metadata(tenant_id)
        if not records:
            if self._storage_manager.load_latest_snapshot(tenant_id) is not None:
                raise RuntimeError("cycle_metadata missing for existing snapshots")
            return 1
        highest_cycle_number = 0
        for record in records:
            try:
                highest_cycle_number = max(
                    highest_cycle_number,
                    int(record.get("cycle_number", 0) or 0),
                )
            except Exception:
                continue
        return highest_cycle_number + 1 if highest_cycle_number > 0 else 1

    def delete_operator(self, operator_id: str) -> None:
        _ = get_operator(self._operator_storage_root, operator_id)
        sessions_backup = self._snapshot_operator_sessions(operator_id)
        links_backup = list_tenants(self._operator_storage_root, operator_id)

        revoked_tokens: List[str] = []
        links_removed = False

        try:
            for token in sorted(sessions_backup.keys()):
                delete_session(self._operator_storage_root, token)
                revoked_tokens.append(token)

            remove_operator(self._operator_storage_root, operator_id)
            links_removed = True

            delete_operator_record_only(self._operator_storage_root, operator_id)
        except Exception as exc:
            try:
                if links_removed and links_backup:
                    write_operator_links(
                        self._operator_storage_root,
                        {
                            **{
                                k: v for k, v in read_operator_links(self._operator_storage_root).items()
                                if k != operator_id
                            },
                            operator_id: sorted(set(links_backup)),
                        },
                    )
                for token in revoked_tokens:
                    write_session(self._operator_storage_root, token, sessions_backup[token])
            except Exception as rollback_exc:
                raise RuntimeError("operator deletion rollback failed") from rollback_exc
            raise RuntimeError("operator deletion failed") from exc

    def list_users_for_tenant(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        resolved_tenant_id = self._resolve_operator_tenant(operator_id, tenant_id)
        self._require_tenant_owner(operator_id, resolved_tenant_id)
        operators = list_operators(self._operator_storage_root)
        rows = []
        for member_operator_id in list_operators_for_tenant(self._operator_storage_root, resolved_tenant_id):
            record = operators.get(member_operator_id)
            if not isinstance(record, dict):
                continue
            rows.append(
                {
                    "operator_id": member_operator_id,
                    "email": str(record.get("email", "")).strip(),
                    "created_at_unix_ms": record.get("created_at_unix_ms"),
                    "status": str(record.get("status", "ACTIVE")).strip() or "ACTIVE",
                    "role": self._operator_role(record),
                    "tenant_id": resolved_tenant_id,
                }
            )
        rows.sort(key=lambda item: (0 if item["role"] == self.ROLE_OWNER else 1, item["operator_id"]))
        return {"tenant_id": resolved_tenant_id, "users": rows}

    def add_user_to_tenant(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str],
        new_operator_id: str,
        email: str,
        password: str,
        created_at_unix_ms: int,
        status: str = "ACTIVE",
        role: str = ROLE_MEMBER,
    ) -> Dict[str, Any]:
        resolved_tenant_id = self._resolve_operator_tenant(operator_id, tenant_id)
        self._require_tenant_owner(operator_id, resolved_tenant_id)
        created = create_operator(
            self._operator_storage_root,
            operator_id=new_operator_id,
            email=email,
            password=password,
            created_at_unix_ms=created_at_unix_ms,
            status=status,
            role=role,
        )
        try:
            add_link(self._operator_storage_root, new_operator_id, resolved_tenant_id)
        except Exception as exc:
            try:
                delete_operator_record_only(self._operator_storage_root, new_operator_id)
            except Exception:
                pass
            raise RuntimeError("user creation failed") from exc
        return {
            "operator_id": created.get("operator_id", new_operator_id),
            "email": str(created.get("email", "")).strip(),
            "status": str(created.get("status", status)).strip() or status,
            "role": self._operator_role(created),
            "tenant_id": resolved_tenant_id,
            "linked": True,
        }

    def delete_user_from_tenant(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str],
        target_operator_id: str,
        current_password: str,
    ) -> Dict[str, Any]:
        resolved_tenant_id = self._resolve_operator_tenant(operator_id, tenant_id)
        self._require_tenant_owner(operator_id, resolved_tenant_id)
        if not str(current_password or ""):
            raise RuntimeError("current password required")
        try:
            _ = authenticate_operator(self._operator_storage_root, operator_id, current_password)
        except Exception as exc:
            raise RuntimeError("invalid credentials") from exc

        target = get_operator(self._operator_storage_root, target_operator_id)
        target_tenant_id = self._resolve_operator_tenant(target_operator_id, resolved_tenant_id)
        if target_tenant_id != resolved_tenant_id:
            raise RuntimeError("target user not found")
        if self._operator_role(target) == self.ROLE_OWNER:
            owner_count = self._count_owner_users(resolved_tenant_id)
            if owner_count <= 1:
                raise RuntimeError("cannot delete last owner")

        self.delete_operator(target_operator_id)
        return {"deleted": True, "operator_id": target_operator_id, "tenant_id": resolved_tenant_id}

    def change_user_password_in_tenant(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str],
        target_operator_id: str,
        current_password: str,
        new_password: str,
    ) -> Dict[str, Any]:
        resolved_tenant_id = self._resolve_operator_tenant(operator_id, tenant_id)
        self._require_tenant_owner(operator_id, resolved_tenant_id)
        if not str(current_password or ""):
            raise RuntimeError("current password required")
        if not str(new_password or ""):
            raise RuntimeError("new password required")
        try:
            _ = authenticate_operator(self._operator_storage_root, operator_id, current_password)
        except Exception as exc:
            raise RuntimeError("invalid credentials") from exc

        _ = get_operator(self._operator_storage_root, target_operator_id)
        target_tenant_id = self._resolve_operator_tenant(target_operator_id, resolved_tenant_id)
        if target_tenant_id != resolved_tenant_id:
            raise RuntimeError("target user not found")

        _ = update_operator_password(
            self._operator_storage_root,
            target_operator_id,
            str(new_password),
        )
        return {
            "operator_id": target_operator_id,
            "tenant_id": resolved_tenant_id,
            "password_changed": True,
        }

    def reset_workspace(
        self,
        *,
        operator_id: str,
        tenant_id: Optional[str],
        current_password: str,
    ) -> Dict[str, Any]:
        resolved_tenant_id = self._resolve_operator_tenant(operator_id, tenant_id)
        self._require_tenant_owner(operator_id, resolved_tenant_id)
        if not str(current_password or ""):
            raise RuntimeError("current password required")
        try:
            _ = authenticate_operator(self._operator_storage_root, operator_id, current_password)
        except Exception as exc:
            raise RuntimeError("invalid credentials") from exc

        result = self._tenant_lifecycle.reset_tenant_workspace(resolved_tenant_id)
        return {
            "tenant_id": resolved_tenant_id,
            "onboarding_status": result.get("onboarding_status", "PENDING"),
            "reset": True,
        }

    def delete_current_user(
        self,
        *,
        operator_id: str,
        current_password: str,
    ) -> Dict[str, Any]:
        record = get_operator(self._operator_storage_root, operator_id)
        if not str(current_password or ""):
            raise RuntimeError("current password required")

        try:
            _ = authenticate_operator(self._operator_storage_root, operator_id, current_password)
        except Exception as exc:
            raise RuntimeError("invalid credentials") from exc

        linked_tenants = list_tenants(self._operator_storage_root, operator_id)
        self.delete_operator(operator_id)
        return {
            "deleted": True,
            "operator_id": operator_id,
            "tenant_id": linked_tenants[0] if len(linked_tenants) == 1 else None,
            "self_deleted": True,
        }

    def update_profile(
        self,
        *,
        operator_id: str,
        tenant_id: str,
        current_password: str,
        email: Optional[str] = None,
        institution_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        _ = get_operator(self._operator_storage_root, operator_id)
        if tenant_id not in list_tenants(self._operator_storage_root, operator_id):
            raise RuntimeError("tenant not found")
        if not str(current_password or ""):
            raise RuntimeError("current password required")

        try:
            _ = authenticate_operator(self._operator_storage_root, operator_id, current_password)
        except Exception as exc:
            raise RuntimeError("invalid credentials") from exc

        updated_operator = get_operator(self._operator_storage_root, operator_id)
        if email is not None and str(email).strip():
            updated_operator = update_operator_email(
                self._operator_storage_root,
                operator_id,
                str(email).strip(),
            )

        if institution_name is not None and str(institution_name).strip():
            self._storage_manager.update_tenant_config_fields(
                tenant_id,
                {"name": str(institution_name).strip()},
            )

        tenant_config = self._storage_manager.load_tenant_config(tenant_id)
        return {
            "operator_id": operator_id,
            "tenant_id": tenant_id,
            "email": str(updated_operator.get("email", "")).strip(),
            "institution_name": str(tenant_config.get("name", "")).strip(),
            "updated": True,
        }

    def change_operator_password(
        self,
        *,
        operator_id: str,
        current_password: str,
        new_password: str,
    ) -> Dict[str, Any]:
        _ = get_operator(self._operator_storage_root, operator_id)
        if not str(current_password or ""):
            raise RuntimeError("current password required")
        if not str(new_password or ""):
            raise RuntimeError("new password required")

        try:
            _ = authenticate_operator(self._operator_storage_root, operator_id, current_password)
        except Exception as exc:
            raise RuntimeError("invalid credentials") from exc

        _ = update_operator_password(
            self._operator_storage_root,
            operator_id,
            str(new_password),
        )
        return {"operator_id": operator_id, "password_changed": True}

    def reset_password_by_identifier(
        self,
        *,
        identifier: str,
        new_password: str,
    ) -> Dict[str, Any]:
        ident = str(identifier or "").strip()
        if not ident:
            raise RuntimeError("identifier required")
        if not str(new_password or ""):
            raise RuntimeError("new password required")
        operators = list_operators(self._operator_storage_root)
        resolved_id = None
        for oid, op in operators.items():
            if oid == ident:
                resolved_id = oid
                break
            if str(op.get("email", "")).strip().lower() == ident.lower():
                resolved_id = oid
                break
        if resolved_id is None:
            raise RuntimeError("operator not found")
        _ = update_operator_password(
            self._operator_storage_root,
            resolved_id,
            str(new_password),
        )
        return {"operator_id": resolved_id, "password_reset": True}

    def _snapshot_operator_sessions(self, operator_id: str) -> Dict[str, Dict[str, Any]]:
        from pathlib import Path

        sessions_dir = Path(self._operator_storage_root) / "sessions"
        if not sessions_dir.exists():
            return {}
        backup: Dict[str, Dict[str, Any]] = {}
        for path in sorted(sessions_dir.glob("*.json")):
            payload = read_session(self._operator_storage_root, path.stem)
            if payload.get("operator_id") == operator_id:
                backup[path.stem] = payload
        return backup

    def _resolve_operator_tenant(self, operator_id: str, tenant_id: Optional[str]) -> str:
        linked_tenants = list_tenants(self._operator_storage_root, operator_id)
        if tenant_id:
            tid = str(tenant_id).strip()
            if tid not in linked_tenants:
                raise RuntimeError("tenant not found")
            return tid
        if len(linked_tenants) != 1:
            raise RuntimeError("tenant_id required")
        return linked_tenants[0]

    def _operator_role(self, record: Dict[str, Any]) -> str:
        role = str(record.get("role", self.ROLE_OWNER)).strip().upper()
        if role not in (self.ROLE_OWNER, self.ROLE_ADMIN, self.ROLE_MEMBER):
            return self.ROLE_MEMBER
        return role

    def _require_tenant_owner(self, operator_id: str, tenant_id: str) -> None:
        _ = self._resolve_operator_tenant(operator_id, tenant_id)
        record = get_operator(self._operator_storage_root, operator_id)
        if self._operator_role(record) not in (self.ROLE_OWNER, self.ROLE_ADMIN):
            raise RuntimeError("admin role required")

    def _count_owner_users(self, tenant_id: str) -> int:
        operators = list_operators(self._operator_storage_root)
        count = 0
        for member_operator_id in list_operators_for_tenant(self._operator_storage_root, tenant_id):
            record = operators.get(member_operator_id)
            if isinstance(record, dict) and self._operator_role(record) in (self.ROLE_OWNER, self.ROLE_ADMIN):
                count += 1
        return count
