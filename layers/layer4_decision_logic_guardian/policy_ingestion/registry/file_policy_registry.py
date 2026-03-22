from __future__ import annotations

from dataclasses import asdict
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import json
import os
import socket
import threading
import time
import uuid

from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.proposed_policy import ProposedPolicy
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.approved_policy import ApprovedPolicy
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.approved_pattern_mapping import ApprovedPatternMapping
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.policy_audit import PolicyAuditEvent


class FilePolicyRegistry:
    """
    Multi-tenant file-backed policy registry.

    Storage:
      storage_root/
        policy_registry/
          _global/
          <tenant_id>/
    """

    def __init__(self, storage_root: Path):
        self.storage_root = Path(storage_root)
        self.registry_root = self.storage_root / "policy_registry"
        self.registry_root.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()

    # -------------------------
    # Paths
    # -------------------------

    def _tenant_dir(self, tenant_id: Optional[str]) -> Path:
        return self.registry_root / ("_global" if tenant_id is None else tenant_id)

    def _approved_policies_path(self, tenant_id: Optional[str]) -> Path:
        return self._tenant_dir(tenant_id) / "approved_policies.json"

    def _approved_mappings_path(self, tenant_id: Optional[str]) -> Path:
        return self._tenant_dir(tenant_id) / "approved_mappings.json"

    def _audit_log_path(self, tenant_id: Optional[str]) -> Path:
        return self._tenant_dir(tenant_id) / "audit_log.jsonl"

    def _ensure_tenant_dir(self, tenant_id: Optional[str]) -> None:
        self._tenant_dir(tenant_id).mkdir(parents=True, exist_ok=True)

    def _tenant_lock_path(self, tenant_id: Optional[str]) -> Path:
        self._ensure_tenant_dir(tenant_id)
        return self._tenant_dir(tenant_id) / ".registry.lock"

    @contextmanager
    def _tenant_write_lock(
        self,
        tenant_id: Optional[str],
        *,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        stale_after_seconds: float = 300.0,
    ):
        lock_path = self._tenant_lock_path(tenant_id)
        deadline = time.time() + max(0.1, float(timeout_seconds))
        stale_after_ms = int(max(1.0, float(stale_after_seconds)) * 1000)
        acquired = False
        with self._write_lock:
            lock_fd: Optional[int] = None
            while time.time() < deadline:
                try:
                    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    payload = json.dumps(
                        {
                            "pid": os.getpid(),
                            "hostname": socket.gethostname(),
                            "locked_at_unix_ms": int(time.time() * 1000),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    os.write(lock_fd, payload)
                    os.fsync(lock_fd)
                    acquired = True
                    break
                except FileExistsError:
                    try:
                        payload = json.loads(lock_path.read_text(encoding="utf-8"))
                    except Exception:
                        payload = None
                    locked_at = payload.get("locked_at_unix_ms") if isinstance(payload, dict) else None
                    now_ms = int(time.time() * 1000)
                    is_stale = isinstance(locked_at, int) and (now_ms - locked_at) > stale_after_ms
                    if is_stale:
                        try:
                            lock_path.unlink()
                            continue
                        except FileNotFoundError:
                            continue
                        except Exception:
                            pass
                    time.sleep(max(0.01, float(poll_interval_seconds)))

            if not acquired:
                raise RuntimeError(f"policy registry lock timeout: {lock_path}")

            try:
                yield
            finally:
                if lock_fd is not None:
                    try:
                        os.close(lock_fd)
                    except Exception:
                        pass
                released = False
                for _ in range(50):
                    try:
                        lock_path.unlink()
                        released = True
                        break
                    except FileNotFoundError:
                        released = True
                        break
                    except PermissionError:
                        time.sleep(0.02)
                if not released:
                    raise RuntimeError(f"policy registry lock release failed: {lock_path}")

    # -------------------------
    # Low-level IO
    # -------------------------

    def _load_json(self, path: Path, default):
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def _save_json_atomic(self, path: Path, obj) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    def _append_audit(self, tenant_id: Optional[str], event: PolicyAuditEvent) -> None:
        self._ensure_tenant_dir(tenant_id)
        line = json.dumps(asdict(event), default=str)
        with open(self._audit_log_path(tenant_id), "a", encoding="utf-8") as f:
            f.write(line + "\n")

    # -------------------------
    # Proposed storage (optional)
    # -------------------------
    # For now: keep proposed policies out of registry storage.
    # We'll store only approvals + audit events.
    # Proposed objects can live in UI later.

    def submit_proposed_policy(self, proposed: ProposedPolicy) -> None:
        with self._tenant_write_lock(proposed.tenant_id):
            event = PolicyAuditEvent(
                event_type="PROPOSED_SUBMITTED",
                tenant_id=proposed.tenant_id,
                event_id=f"audit_{uuid.uuid4().hex}",
                actor=proposed.submitted_by or "unknown",
                data={
                    "proposed_policy_id": proposed.proposed_policy_id,
                    "source": proposed.source,
                    "framework": proposed.framework,
                    "jurisdiction": proposed.jurisdiction,
                },
            )
            self._append_audit(proposed.tenant_id, event)

    # -------------------------
    # Approval flow
    # -------------------------

    def approve_policy(
        self,
        proposed: ProposedPolicy,
        *,
        approved_by: str,
        policy_id: str,
        policy_name: str,
        framework: str,
        source: str,  # "REGULATORY" or "INTERNAL"
        version: str,
        tenant_id: Optional[str],
        jurisdiction: Optional[str],
        requirement_text: str,
        violation_risk: str,
        remediation_deadline_days: Optional[int],
        enforcement_authority: Optional[str],
        approved_mappings: List[ApprovedPatternMapping],
        supersedes_policy_id: Optional[str] = None,
    ) -> ApprovedPolicy:
        with self._tenant_write_lock(tenant_id):
            self._ensure_tenant_dir(tenant_id)

            approved = ApprovedPolicy(
                policy_id=policy_id,
                tenant_id=tenant_id,
                source=source,
                jurisdiction=jurisdiction,
                framework=framework,
                policy_name=policy_name,
                requirement_text=requirement_text,
                violation_risk=violation_risk,
                remediation_deadline_days=remediation_deadline_days,
                enforcement_authority=enforcement_authority,
                version=version,
                approved_by=approved_by,
                approved_at_utc=datetime.utcnow(),
                supersedes_policy_id=supersedes_policy_id,
            )

            # Load existing approved policies
            policies_path = self._approved_policies_path(tenant_id)
            policies_raw: Dict[str, dict] = self._load_json(policies_path, default={})

            # Mark superseded if requested
            if supersedes_policy_id and supersedes_policy_id in policies_raw:
                old = policies_raw[supersedes_policy_id]
                old["status"] = "SUPERSEDED"
                old["superseded_by_policy_id"] = approved.policy_id
                policies_raw[supersedes_policy_id] = old

            # Store new approved
            policies_raw[approved.policy_id] = asdict(approved)
            self._save_json_atomic(policies_path, policies_raw)

            # Store mappings
            mappings_path = self._approved_mappings_path(tenant_id)
            existing_mappings = self._load_json(mappings_path, default=[])

            for m in approved_mappings:
                if m.policy_id != approved.policy_id:
                    raise ValueError("ApprovedPatternMapping.policy_id must match approved policy_id")
                existing_mappings.append(asdict(m))

                self._append_audit(
                    tenant_id,
                    PolicyAuditEvent(
                        event_type="MAPPING_APPROVED",
                        tenant_id=tenant_id,
                        event_id=f"audit_{uuid.uuid4().hex}",
                        actor=approved_by,
                        data={
                            "policy_id": approved.policy_id,
                            "pattern_label": m.pattern_label,
                            "trigger_type": m.trigger_type,
                        },
                    ),
                )

            self._save_json_atomic(mappings_path, existing_mappings)

            # Audit approval
            self._append_audit(
                tenant_id,
                PolicyAuditEvent(
                    event_type="POLICY_APPROVED",
                    tenant_id=tenant_id,
                    event_id=f"audit_{uuid.uuid4().hex}",
                    actor=approved_by,
                    data={
                        "proposed_policy_id": proposed.proposed_policy_id,
                        "approved_policy_id": approved.policy_id,
                        "framework": approved.framework,
                        "jurisdiction": approved.jurisdiction,
                        "source": approved.source,
                        "version": approved.version,
                    },
                ),
            )

            return approved

    # -------------------------
    # Query methods
    # -------------------------

    def get_active_policies(
        self,
        tenant_id: str,
        *,
        jurisdiction: Optional[str] = None,
        include_internal: bool = True,
    ) -> List[ApprovedPolicy]:
        # Merge tenant + global
        results: List[ApprovedPolicy] = []
        results.extend(self._get_active_from_scope(tenant_id, jurisdiction, include_internal))
        results.extend(self._get_active_from_scope(None, jurisdiction, include_internal))
        return results

    def _get_active_from_scope(
        self,
        tenant_id: Optional[str],
        jurisdiction: Optional[str],
        include_internal: bool,
    ) -> List[ApprovedPolicy]:
        policies_raw = self._load_json(self._approved_policies_path(tenant_id), default={})
        out = []
        for _, data in policies_raw.items():
            p = ApprovedPolicy(**data)
            if p.status != "ACTIVE":
                continue
            if jurisdiction and p.jurisdiction not in (None, jurisdiction):
                continue
            if not include_internal and p.source == "INTERNAL":
                continue
            out.append(p)
        return out

    def get_policies_for_pattern(
        self,
        tenant_id: str,
        pattern_label: str,
        *,
        jurisdiction: Optional[str] = None,
        include_internal: bool = True,
    ) -> List[ApprovedPolicy]:

        # Load mappings from tenant + global
        mappings = []
        mappings.extend(self._load_json(self._approved_mappings_path(tenant_id), default=[]))
        mappings.extend(self._load_json(self._approved_mappings_path(None), default=[]))

        policy_ids = {m["policy_id"] for m in mappings if m["pattern_label"] == pattern_label}

        # Load policies from tenant + global, filter
        results = []
        for scope in (tenant_id, None):
            policies_raw = self._load_json(self._approved_policies_path(scope), default={})
            for pid in policy_ids:
                if pid not in policies_raw:
                    continue
                p = ApprovedPolicy(**policies_raw[pid])
                if p.status != "ACTIVE":
                    continue
                if jurisdiction and p.jurisdiction not in (None, jurisdiction):
                    continue
                if not include_internal and p.source == "INTERNAL":
                    continue
                results.append(p)

        return results
    
    def get_mappings_for_policy(
        self,
        *,
        tenant_id: str,
        policy_id: str,
    ) -> list[ApprovedPatternMapping]:
        raw: List[dict] = []
        raw.extend(self._load_json(self._approved_mappings_path(tenant_id), default=[]))
        raw.extend(self._load_json(self._approved_mappings_path(None), default=[]))


        results: List[ApprovedPatternMapping] = []
        for m in raw:
            if m.get("policy_id") == policy_id:
                results.append(ApprovedPatternMapping(**m))
        
        return results


