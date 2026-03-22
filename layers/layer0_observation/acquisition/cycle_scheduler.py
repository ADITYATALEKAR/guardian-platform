from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from infrastructure.storage_manager.storage_manager import StorageManager


logger = logging.getLogger(__name__)


class CycleScheduler:
    """
    Background scheduler that launches tenant discovery cycles via OperatorService.

    Properties:
    - restart-safe via scheduler_state.json
    - multi-process safe via .scheduler.lock
    - launches reuse the existing detached cycle_worker path
    """

    def __init__(
        self,
        *,
        operator_service: Any,
        storage: StorageManager,
        cadence_seconds: int = 7200,
        tick_seconds: int = 5,
        tenant_ids: Optional[Iterable[str]] = None,
    ) -> None:
        self.operator_service = operator_service
        self.storage = storage
        self.cadence_seconds = max(60, int(cadence_seconds))
        self.tick_seconds = max(1, int(tick_seconds))
        self._tenant_ids = list(tenant_ids or [])
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start_in_background(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run_loop,
            name="guardian-cycle-scheduler",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "cycle_scheduler_started cadence_seconds=%s tick_seconds=%s",
            self.cadence_seconds,
            self.tick_seconds,
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=max(0.1, float(timeout)))

    def run_once(self) -> None:
        for tenant_id in self._list_tenant_ids():
            if self._stop_event.is_set():
                return
            self._run_tenant_if_due(tenant_id)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                logger.exception("cycle_scheduler_tick_failed")
            self._stop_event.wait(self.tick_seconds)

    def _list_tenant_ids(self) -> List[str]:
        if self._tenant_ids:
            return sorted(set(str(tid).strip() for tid in self._tenant_ids if str(tid).strip()))
        return self.storage.list_tenant_ids()

    def _scheduler_state_path(self, tenant_id: str) -> Path:
        tenant_path = self.storage.ensure_tenant_exists(tenant_id)
        return tenant_path / "scheduler_state.json"

    def _scheduler_lock_path(self, tenant_id: str) -> Path:
        tenant_path = self.storage.ensure_tenant_exists(tenant_id)
        return tenant_path / ".scheduler.lock"

    def _load_scheduler_state(self, tenant_id: str) -> Dict[str, Any]:
        path = self._scheduler_state_path(tenant_id)
        if path.exists():
            try:
                return self.storage._read_json(path)
            except Exception:
                logger.warning("cycle_scheduler_state_corrupt tenant_id=%s", tenant_id)

        latest = self.storage.load_latest_cycle_metadata(tenant_id)
        if isinstance(latest, dict):
            started_at = int(latest.get("timestamp_unix_ms", 0) or 0)
            duration_ms = int(latest.get("duration_ms", 0) or 0)
            last_run = started_at + max(0, duration_ms)
            if last_run > 0:
                return {
                    "last_run_unix_ms": last_run,
                    "next_run_unix_ms": last_run + (self.cadence_seconds * 1000),
                    "last_status": str(latest.get("status", "completed") or "completed"),
                    "consecutive_failures": 0,
                }

        return {
            "last_run_unix_ms": 0,
            "next_run_unix_ms": 0,
            "last_status": "never",
            "consecutive_failures": 0,
        }

    def _save_scheduler_state(self, tenant_id: str, state: Dict[str, Any]) -> None:
        self.storage.save_scheduler_state(tenant_id, state)

    def _active_cycle_snapshot(self, tenant_id: str, state: Dict[str, Any], now_ms: int) -> bool:
        lock = self.storage.load_cycle_lock(tenant_id)
        if not isinstance(lock, dict):
            return False
        started_at_unix_ms = int(lock.get("started_at_unix_ms", 0) or 0)
        active_state: Dict[str, Any] = {
            "last_run_unix_ms": started_at_unix_ms or int(state.get("last_run_unix_ms", 0) or 0),
            "next_run_unix_ms": now_ms + (self.tick_seconds * 1000),
            "last_status": "active_cycle",
            "consecutive_failures": int(state.get("consecutive_failures", 0) or 0),
            "last_cycle_id": str(lock.get("cycle_id", "")).strip(),
        }
        try:
            active_state["last_cycle_number"] = int(lock.get("cycle_number", 0) or 0)
        except Exception:
            pass
        self._save_scheduler_state(tenant_id, active_state)
        return True

    def _acquire_scheduler_lock(self, tenant_id: str) -> bool:
        lock_path = self._scheduler_lock_path(tenant_id)
        payload = {
            "started_at_unix_ms": int(time.time() * 1000),
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
        }
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=True, sort_keys=True)
        except Exception:
            try:
                lock_path.unlink(missing_ok=True)
            except Exception:
                pass
            return False
        return True

    def _release_scheduler_lock(self, tenant_id: str) -> None:
        lock_path = self._scheduler_lock_path(tenant_id)
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            logger.debug("cycle_scheduler_unlock_failed tenant_id=%s", tenant_id, exc_info=True)

    def _scheduler_readiness_status(self, tenant_id: str) -> Optional[str]:
        config = self.storage.load_tenant_config(tenant_id)
        onboarding_status = str(config.get("onboarding_status", "")).strip().upper()
        if onboarding_status != "COMPLETED":
            return "pending_onboarding"
        main_url = str(config.get("main_url", "")).strip()
        seed_endpoints = config.get("seed_endpoints", [])
        if not main_url or not isinstance(seed_endpoints, list) or not any(
            str(row).strip() for row in seed_endpoints
        ):
            return "awaiting_roots"
        return None

    def _classify_failure_message(self, error_message: Optional[str]) -> str:
        classifier = getattr(self.operator_service, "_classify_cycle_failure", None)
        if callable(classifier):
            try:
                return str(classifier(error_message)).strip().lower() or "scan"
            except Exception:
                pass
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

    def _infra_failure_backoff_ms(self, consecutive_failures: int) -> int:
        helper = getattr(self.operator_service, "_infra_failure_backoff_ms", None)
        if callable(helper):
            try:
                return int(helper(consecutive_failures))
            except Exception:
                pass
        if int(consecutive_failures or 0) <= 1:
            minutes = 10
        elif int(consecutive_failures or 0) == 2:
            minutes = 20
        else:
            minutes = 30
        return minutes * 60 * 1000

    def _recent_terminal_cycle_guard(
        self,
        tenant_id: str,
        state: Dict[str, Any],
        now_ms: int,
    ) -> Optional[Dict[str, Any]]:
        latest = self.storage.load_terminal_cycle_metadata(tenant_id)
        if not isinstance(latest, dict):
            return None
        latest_status = str(latest.get("status", "")).strip().lower()
        if latest_status != "failed":
            return None
        error_message = ""
        error_rows = latest.get("error_messages", [])
        if isinstance(error_rows, list):
            error_message = next(
                (str(row).strip() for row in error_rows if str(row).strip()),
                "",
            )
        failure_class = str(
            latest.get("failure_class")
            or state.get("last_failure_class")
            or self._classify_failure_message(error_message)
        ).strip().lower()
        if failure_class != "infrastructure":
            return None
        started_at_ms = int(latest.get("timestamp_unix_ms", 0) or 0)
        duration_ms = max(0, int(latest.get("duration_ms", 0) or 0))
        finished_at_ms = started_at_ms + duration_ms
        if finished_at_ms <= 0:
            finished_at_ms = now_ms
        consecutive_failures = max(1, int(state.get("consecutive_failures", 0) or 0))
        cooldown_expires_ms = finished_at_ms + self._infra_failure_backoff_ms(
            consecutive_failures
        )
        if cooldown_expires_ms <= now_ms:
            return None
        guarded_state = {
            "last_run_unix_ms": finished_at_ms,
            "next_run_unix_ms": cooldown_expires_ms,
            "last_status": "infra_cooldown",
            "last_cycle_id": str(latest.get("cycle_id", "")).strip(),
            "last_cycle_number": int(latest.get("cycle_number", 0) or 0),
            "consecutive_failures": consecutive_failures,
            "last_failure_class": failure_class,
            "last_error": error_message or str(state.get("last_error", "")).strip(),
            "failure_cooldown_expires_unix_ms": cooldown_expires_ms,
        }
        self._save_scheduler_state(tenant_id, guarded_state)
        return guarded_state

    def _reconcile_scheduler_state_from_latest_cycle(
        self,
        tenant_id: str,
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        latest = self.storage.load_terminal_cycle_metadata(tenant_id)
        if not isinstance(latest, dict):
            return state

        latest_status = str(latest.get("status", "")).strip().lower()
        if latest_status not in {"completed", "failed"}:
            return state

        latest_cycle_id = str(latest.get("cycle_id", "")).strip()
        latest_cycle_number = int(latest.get("cycle_number", 0) or 0)
        state_cycle_id = str(state.get("last_cycle_id", "")).strip()
        state_cycle_number = int(state.get("last_cycle_number", 0) or 0)
        state_status = str(state.get("last_status", "")).strip().lower()

        needs_reconcile = False
        if state_status in {"launched", "active_cycle"} and latest_cycle_id:
            if not state_cycle_id or latest_cycle_id == state_cycle_id:
                needs_reconcile = True
        elif latest_cycle_number > state_cycle_number:
            needs_reconcile = True

        if not needs_reconcile:
            return state

        sync = getattr(self.operator_service, "sync_scheduler_state_from_cycle_result", None)
        error_message = None
        if latest_status == "failed":
            error_rows = latest.get("error_messages", [])
            if isinstance(error_rows, list):
                error_message = next(
                    (str(row).strip() for row in error_rows if str(row).strip()),
                    None,
                )
        if callable(sync):
            try:
                updated = sync(
                    tenant_id=tenant_id,
                    cycle_id=latest_cycle_id,
                    cycle_number=latest_cycle_number,
                    status=latest_status,
                    error_message=error_message,
                )
                if isinstance(updated, dict):
                    return updated
            except Exception:
                logger.exception(
                    "cycle_scheduler_state_reconcile_failed tenant_id=%s cycle_id=%s",
                    tenant_id,
                    latest_cycle_id,
                )

        started_at_ms = int(latest.get("timestamp_unix_ms", 0) or 0)
        duration_ms = max(0, int(latest.get("duration_ms", 0) or 0))
        finished_at_ms = started_at_ms + duration_ms
        if finished_at_ms <= 0:
            finished_at_ms = int(time.time() * 1000)
        error_message = error_message or ""
        failure_class = (
            str(latest.get("failure_class") or self._classify_failure_message(error_message)).strip().lower()
            if latest_status == "failed"
            else None
        )
        if latest_status == "completed":
            next_run_unix_ms = finished_at_ms + (self.cadence_seconds * 1000)
        elif failure_class == "infrastructure":
            next_run_unix_ms = finished_at_ms + self._infra_failure_backoff_ms(
                int(state.get("consecutive_failures", 0) or 0) + 1
            )
        else:
            next_run_unix_ms = finished_at_ms + (self.tick_seconds * 1000)
        reconciled = {
            "last_run_unix_ms": finished_at_ms,
            "next_run_unix_ms": next_run_unix_ms,
            "last_status": latest_status,
            "last_cycle_id": latest_cycle_id,
            "last_cycle_number": latest_cycle_number,
            "consecutive_failures": 0 if latest_status == "completed" else int(state.get("consecutive_failures", 0) or 0) + 1,
        }
        if latest_status == "failed" and error_message:
            reconciled["last_error"] = error_message
        if latest_status == "failed" and failure_class:
            reconciled["last_failure_class"] = failure_class
            reconciled["failure_cooldown_expires_unix_ms"] = next_run_unix_ms
        self._save_scheduler_state(tenant_id, reconciled)
        return reconciled

    def _run_tenant_if_due(self, tenant_id: str) -> None:
        now_ms = int(time.time() * 1000)
        state = self._reconcile_scheduler_state_from_latest_cycle(
            tenant_id,
            self._load_scheduler_state(tenant_id),
        )
        next_run_unix_ms = int(state.get("next_run_unix_ms", 0) or 0)
        if next_run_unix_ms > now_ms:
            return

        if self._active_cycle_snapshot(tenant_id, state, now_ms):
            return

        guarded_state = self._recent_terminal_cycle_guard(tenant_id, state, now_ms)
        if isinstance(guarded_state, dict):
            return

        readiness_status = self._scheduler_readiness_status(tenant_id)
        if readiness_status is not None:
            self._save_scheduler_state(
                tenant_id,
                {
                    "last_run_unix_ms": int(state.get("last_run_unix_ms", 0) or 0),
                    "next_run_unix_ms": now_ms + (self.tick_seconds * 1000),
                    "last_status": readiness_status,
                    "consecutive_failures": 0,
                },
            )
            return

        if not self._acquire_scheduler_lock(tenant_id):
            return

        try:
            launch = self.operator_service.start_scheduled_cycle(tenant_id=tenant_id)
            scheduled_state = {
                "last_run_unix_ms": now_ms,
                "next_run_unix_ms": now_ms + (self.cadence_seconds * 1000),
                "last_status": "launched",
                "last_cycle_id": str(launch.get("cycle_id", "")).strip(),
                "last_cycle_number": int(launch.get("cycle_number", 0) or 0),
                "consecutive_failures": 0,
            }
            self._save_scheduler_state(tenant_id, scheduled_state)
        except RuntimeError as exc:
            message = str(exc or "").strip()
            if "Active cycle already running" in message:
                self._save_scheduler_state(
                    tenant_id,
                    {
                        "last_run_unix_ms": int(state.get("last_run_unix_ms", 0) or 0),
                        "next_run_unix_ms": now_ms + (self.tick_seconds * 1000),
                        "last_status": "active_cycle",
                        "consecutive_failures": int(state.get("consecutive_failures", 0) or 0),
                    },
                )
                return
            failure_state = {
                "last_run_unix_ms": now_ms,
                "next_run_unix_ms": now_ms + (self.tick_seconds * 1000),
                "last_status": "failed",
                "last_error": message,
                "consecutive_failures": int(state.get("consecutive_failures", 0) or 0) + 1,
            }
            failure_class = self._classify_failure_message(message)
            if failure_class == "infrastructure":
                failure_state["last_failure_class"] = failure_class
                failure_state["last_status"] = "infra_cooldown"
                failure_state["next_run_unix_ms"] = now_ms + self._infra_failure_backoff_ms(
                    int(failure_state["consecutive_failures"])
                )
                failure_state["failure_cooldown_expires_unix_ms"] = failure_state[
                    "next_run_unix_ms"
                ]
            self._save_scheduler_state(tenant_id, failure_state)
            logger.warning("cycle_scheduler_launch_failed tenant_id=%s error=%s", tenant_id, message)
        except Exception as exc:
            failure_state = {
                "last_run_unix_ms": now_ms,
                "next_run_unix_ms": now_ms + (self.tick_seconds * 1000),
                "last_status": "failed",
                "last_error": str(exc),
                "consecutive_failures": int(state.get("consecutive_failures", 0) or 0) + 1,
            }
            failure_class = self._classify_failure_message(str(exc))
            if failure_class == "infrastructure":
                failure_state["last_failure_class"] = failure_class
                failure_state["last_status"] = "infra_cooldown"
                failure_state["next_run_unix_ms"] = now_ms + self._infra_failure_backoff_ms(
                    int(failure_state["consecutive_failures"])
                )
                failure_state["failure_cooldown_expires_unix_ms"] = failure_state[
                    "next_run_unix_ms"
                ]
            self._save_scheduler_state(tenant_id, failure_state)
            logger.exception("cycle_scheduler_launch_failed tenant_id=%s", tenant_id)
        finally:
            self._release_scheduler_lock(tenant_id)
