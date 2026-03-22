from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from infrastructure.layer5_api.bootstrap import (
    Layer5BootstrapConfig,
    build_layer5_runtime_bundle,
)
from infrastructure.layer5_api.models import APIRequest
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_category_a import PassiveDiscoveryGraph
from infrastructure.discovery.expansion_wrapper import ExpansionConfig, ExpansionWrapper
from infrastructure.operator_plane.registry import operator_registry
from infrastructure.operator_plane.services.operator_service import OperatorService
from infrastructure.operator_plane.sessions.session_manager import (
    create_session,
    validate_session,
)
from infrastructure.policy_integration.notifications import NotificationOutbox
from infrastructure.runtime.metrics_registry import MetricsRegistry
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.approved_pattern_mapping import (
    ApprovedPatternMapping,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.proposed_policy import (
    ProposedPolicy,
)
from layers.layer4_decision_logic_guardian.policy_ingestion.registry.file_policy_registry import (
    FilePolicyRegistry,
)

pytestmark = [pytest.mark.security, pytest.mark.concurrency]


def _storage_with_tenant(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage"))
    storage.create_tenant("tenant_a")
    return storage


def test_phase1_discovery_tls_mode_defaults_to_strict(tmp_path: Path) -> None:
    storage = _storage_with_tenant(tmp_path)
    engine = DiscoveryEngine(storage=storage)
    assert engine.tls_verification_mode == "strict"


def test_phase1_discovery_tls_insecure_requires_explicit_opt_in(tmp_path: Path) -> None:
    storage = _storage_with_tenant(tmp_path)
    with pytest.raises(ValueError, match="allow_insecure_tls=True"):
        DiscoveryEngine(storage=storage, tls_verification_mode="insecure")


def test_phase1_discovery_tls_insecure_allowed_only_when_explicit(tmp_path: Path) -> None:
    storage = _storage_with_tenant(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        tls_verification_mode="insecure",
        allow_insecure_tls=True,
    )
    assert engine.tls_verification_mode == "insecure"


def test_phase1_expansion_wrapper_propagates_tls_mode() -> None:
    class CaptureCategoryA:
        def __init__(self) -> None:
            self.context_overrides = None

        def get_full_graph(self, root_domain: str, context_overrides: dict | None = None):
            self.context_overrides = dict(context_overrides or {})
            return PassiveDiscoveryGraph()

    capture = CaptureCategoryA()
    wrapper = ExpansionWrapper(category_a=capture)
    wrapper.expand(
        "example.com",
        ExpansionConfig(aggressive=False, tls_verification_mode="insecure"),
    )
    assert capture.context_overrides is not None
    assert capture.context_overrides["tls_verification_mode"] == "insecure"


def test_phase1_notification_outbox_mark_sent_is_concurrency_safe(tmp_path: Path) -> None:
    storage = _storage_with_tenant(tmp_path)
    outbox = NotificationOutbox(storage_manager=storage, tenant_id="tenant_a")
    event_ids = [
        outbox.enqueue(
            kind="policy_update",
            title=f"update-{idx}",
            body="body",
            payload={"idx": idx},
        )
        for idx in range(24)
    ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(outbox.mark_sent, event_id) for event_id in event_ids]
        for future in as_completed(futures):
            future.result()

    assert outbox.list_pending() == []
    assert outbox._sent_path().exists()


def test_phase1_file_policy_registry_approve_policy_is_concurrency_safe(tmp_path: Path) -> None:
    registry = FilePolicyRegistry(storage_root=tmp_path / "policy_store")
    total = 16

    def _worker(index: int) -> str:
        policy_id = f"pol_{index}"
        proposed = ProposedPolicy(
            proposed_policy_id=f"prop_{index}",
            tenant_id="tenant_a",
            source="MANUAL_ENTRY",
            framework="INTERNAL",
            jurisdiction="IN",
            requirement_text=f"Requirement {index}",
            submitted_by="qa",
        )
        mapping = ApprovedPatternMapping(
            mapping_id=f"map_{index}",
            policy_id=policy_id,
            pattern_label=f"PATTERN_{index}",
            trigger_type="DIRECT_VIOLATION",
            approved_by="qa",
            rationale="phase1 concurrency test",
        )
        approved = registry.approve_policy(
            proposed,
            approved_by="qa",
            policy_id=policy_id,
            policy_name=f"Policy {index}",
            framework="INTERNAL",
            source="INTERNAL",
            version="1.0.0",
            tenant_id="tenant_a",
            jurisdiction="IN",
            requirement_text=f"Requirement {index}",
            violation_risk="HIGH",
            remediation_deadline_days=30,
            enforcement_authority="internal",
            approved_mappings=[mapping],
        )
        return approved.policy_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_worker, range(total)))

    assert len(results) == total
    active = registry.get_active_policies("tenant_a", include_internal=True)
    assert len(active) == total
    assert sorted(p.policy_id for p in active) == sorted(results)


def test_phase1_failed_auth_delay_is_hardened() -> None:
    assert operator_registry.FAILED_AUTH_DELAY_SEC >= 1.0


def test_phase1_operator_service_accepts_master_password_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = StorageManager(str(tmp_path / "storage"))
    operator_root = tmp_path / "operators"
    simulation_root = str(tmp_path / "simulation")
    secret_file = tmp_path / "master_secret.txt"
    secret_file.write_text("phase1-master\n", encoding="utf-8")
    monkeypatch.setenv("PHASE1_MASTER_PASSWORD_FILE", str(secret_file))

    service = OperatorService(
        operator_storage_root=str(operator_root),
        storage_manager=storage,
        identity_manager=IdentityManager(storage),
        simulation_root=simulation_root,
        orchestrator=None,
        master_env="PHASE1_MASTER_PASSWORD",
    )
    service.validate_master_password("phase1-master")


def test_phase1_session_is_bound_to_client_context(tmp_path: Path) -> None:
    root = str(tmp_path / "operators")
    session = create_session(
        root,
        "operator_a",
        client_ip="127.0.0.1",
        user_agent="guardian-test-agent",
    )

    assert (
        validate_session(
            root,
            session.token,
            client_ip="127.0.0.1",
            user_agent="guardian-test-agent",
        )
        == "operator_a"
    )

    with pytest.raises(RuntimeError, match="invalid session"):
        validate_session(
            root,
            session.token,
            client_ip="127.0.0.2",
            user_agent="guardian-test-agent",
        )


def test_phase1_bootstrap_validates_runtime_paths(tmp_path: Path) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")

    with pytest.raises(RuntimeError, match="storage_root is not writable"):
        build_layer5_runtime_bundle(
            Layer5BootstrapConfig(
                storage_root=str(blocked),
                operator_storage_root=str(tmp_path / "operators"),
                simulation_root=str(tmp_path / "simulation"),
            )
        )


def test_phase1_bootstrap_wires_health_state_ready_endpoint(tmp_path: Path) -> None:
    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(tmp_path / "storage"),
            operator_storage_root=str(tmp_path / "operators"),
            simulation_root=str(tmp_path / "simulation"),
        )
    )
    ready = bundle.api.handle(APIRequest(method="GET", path="/ready"))
    assert ready.status_code == 200
    assert ready.payload["data"]["ready"] is True


def test_phase1_metrics_registry_sanitizes_label_keys_and_values() -> None:
    metrics = MetricsRegistry()
    metrics.inc(
        "guardian_events_total",
        labels={
            'tenant id': 'tenant"a\n',
            "event-type": "cycle\\complete",
        },
    )
    rendered = metrics.render_prometheus()
    assert 'tenant_id="tenant\\"a"' in rendered
    assert 'event_type="cycle\\\\complete"' in rendered
