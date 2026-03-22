from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

import pytest

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.aggregation.artifact_migration import ArtifactMigrationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.discovery.discovery_engine import (
    DiscoveryEngine,
    _deterministic_jitter,
)
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.policy_integration.policies.policy_parser import PolicyParser
from infrastructure.storage_manager.storage_manager import StorageManager
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge
from layers.layer0_observation.acquisition.protocol_observer import (
    DNSObservation,
    HTTPObservation,
    RawObservation,
    TCPObservation,
    TLSObservation,
)
from layers.layer0_observation.fingerprints.fingerprint_types import Fingerprint
from layers.layer2_risk_and_weakness_analysis.entropy_weakness import (
    EntropyWeaknessDetector,
)

pytestmark = [pytest.mark.migration]


@dataclass
class _FakeSeries:
    observations: List[RawObservation]
    elapsed_ms: int = 10


class _StubExpansionWrapper:
    def expand(self, root_domain: str, config) -> ExpansionResult:
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates=set(),
            node_count=1,
            edge_count=0,
            ceilings_hit=False,
            diagnostics={},
        )


def _observation(endpoint: str) -> RawObservation:
    return RawObservation(
        endpoint=endpoint,
        entity_id=endpoint,
        observation_id=f"obs_{endpoint.replace(':', '_')}",
        timestamp_ms=1_710_000_000_123,
        dns=DNSObservation(resolved_ip="1.1.1.1", resolution_time_ms=10.0),
        tcp=TCPObservation(connected=True, connect_time_ms=8.5),
        tls=TLSObservation(
            handshake_time_ms=22.0,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cert_subject="commonName=pay.example.com",
            cert_issuer="commonName=Demo CA",
            cert_not_before="Jan  1 00:00:00 2026 GMT",
            cert_not_after="Jan  1 00:00:00 2027 GMT",
            cert_san=["pay.example.com"],
            cert_public_key_algorithm="RSA",
            cert_public_key_size_bits=2048,
            cert_must_staple=False,
            cert_ocsp_urls=[],
            alpn_protocol="h2",
            sni_mismatch=False,
            ocsp_stapled=False,
            error=None,
        ),
        http=HTTPObservation(
            status_code=200,
            response_time_ms=30.0,
            headers={"server": "cloudflare"},
            error=None,
        ),
        success=True,
        error=None,
    )


class _RateControllerOneThrottle:
    def __init__(self) -> None:
        self.allow_calls = 0
        self.attempt_calls = 0
        self.success_calls = 0
        self.rate_limited_calls = 0

    def allow_request(self, _key: str) -> bool:
        self.allow_calls += 1
        return self.allow_calls > 1

    def max_rate_limit_retries(self) -> int:
        return 3

    def register_rate_limited(self, _target: str, retry_after_seconds=None, *, attempt=None) -> float:
        self.rate_limited_calls += 1
        return 0.0

    def register_attempt(self) -> None:
        self.attempt_calls += 1

    def register_success(self, _target: str) -> None:
        self.success_calls += 1


class _RateControllerNeverAllow:
    def __init__(self) -> None:
        self.allow_calls = 0
        self.rate_limited_calls = 0

    def allow_request(self, _key: str) -> bool:
        self.allow_calls += 1
        return False

    def max_rate_limit_retries(self) -> int:
        return 2

    def register_rate_limited(self, _target: str, retry_after_seconds=None, *, attempt=None) -> float:
        self.rate_limited_calls += 1
        return 0.0


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
    return storage


def test_phase5_rate_limit_uses_controller_hooks_and_recovers(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=1,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )
    controller = _RateControllerOneThrottle()

    monkeypatch.setattr(time, "sleep", lambda _v: None)
    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(observations=[_observation(endpoint)], elapsed_ms=12),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    rows = engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=controller,
        cycle_id="cycle_000001",
        seed_endpoints=["pay.example.com:443"],
        expansion_mode="A_ONLY",
    )
    assert len(rows) == 1
    assert controller.rate_limited_calls == 1
    assert controller.attempt_calls == 1
    assert controller.success_calls == 1


def test_phase5_rate_limit_retry_bound_uses_controller_cap(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=1,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )
    controller = _RateControllerNeverAllow()

    monkeypatch.setattr(time, "sleep", lambda _v: None)
    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("acquisition must not run")),
    )

    t0 = time.time()
    rows = engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=controller,
        cycle_id="cycle_000001",
        seed_endpoints=["pay.example.com:443"],
        expansion_mode="A_ONLY",
    )
    assert rows == []
    assert controller.rate_limited_calls == 2
    assert time.time() - t0 < 3.0


def test_phase5_bundle_applies_read_time_artifact_migrations(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    storage.save_snapshot(
        "tenant_a",
        {
            "schema_version": "v1",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "snapshot_hash_sha256": "abc123",
            "endpoint_count": 1,
            "endpoints": [{"hostname": "api.bank.com", "port": 443}],
        },
    )
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "status": "COMPLETED",
            "timestamp_unix_ms": 1_710_000_000_500,
        },
    )
    storage.persist_telemetry_record(
        "tenant_a",
        "cycle_000001",
        {
            "sequence": 1,
            "timestamp_ms": 1_710_000_000_250,
            "entity_id": "api.bank.com:443",
            "fingerprints": [{"kind": "tls"}],
            "posture_signals": [],
            "posture_findings": {"unexpected": True},
        },
    )
    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 1_710_000_000_300,
            "entity_id": "api.bank.com:443",
            "severity": 6.0,
            "confidence": 0.8,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
        },
    )
    storage.save_temporal_state("tenant_a", {"endpoints": {}})

    scope = AuthorizedTenantScope.from_iterable("op_a", ["tenant_a"])
    engine = AggregationEngine(storage)
    bundle = engine.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope,
        cycle_id="cycle_000001",
    )

    assert bundle["snapshot"]["schema_version"] == "1.2"
    assert bundle["cycle_metadata"][0]["schema_version"] == "v2.6"
    assert bundle["cycle_metadata"][0]["status"] == "completed"
    assert bundle["telemetry"][0]["schema_version"] == "v1"
    assert isinstance(bundle["telemetry"][0]["posture_findings"]["waf_findings"], list)
    assert isinstance(bundle["telemetry"][0]["posture_findings"]["tls_findings"], list)
    assert bundle["guardian_records"][0]["schema_version"] == "v1"
    assert bundle["guardian_records"][0]["overall_severity_01"] == 6.0
    assert bundle["guardian_records"][0]["overall_confidence_01"] == 0.8
    assert bundle["temporal_state"]["schema_version"] == "v1"


def test_phase5_dashboard_enriches_endpoint_rows_with_temporal_and_provenance(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    storage.save_snapshot(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1_710_000_000_000,
            "snapshot_hash_sha256": "abc123",
            "endpoint_count": 1,
            "endpoints": [
                {
                    "hostname": "api.bank.com",
                    "port": 443,
                    "ip": "1.2.3.4",
                    "confidence": 0.6,
                    "discovered_by": ["ct_log", "protocol_observer"],
                }
            ],
        },
    )
    storage.append_cycle_metadata(
        "tenant_a",
        {
            "schema_version": "v2.6",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "status": "completed",
            "timestamp_unix_ms": 1_710_000_000_500,
            "duration_ms": 3210,
        },
    )
    storage.persist_guardian_record(
        "tenant_a",
        {
            "timestamp_ms": 1_710_000_000_300,
            "entity_id": "api.bank.com:443",
            "severity": 0.0,
            "confidence": 0.0,
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
        },
    )
    storage.save_temporal_state(
        "tenant_a",
        {
            "schema_version": "v1",
            "endpoints": {
                "api.bank.com:443": {
                    "endpoint_id": "api.bank.com:443",
                    "presence_history": [
                        {"cycle_number": 1, "timestamp_unix_ms": 1_710_000_000_100, "present": True},
                        {"cycle_number": 2, "timestamp_unix_ms": 1_710_000_000_200, "present": True},
                    ],
                    "volatility_score": 0.2,
                    "visibility_score": 0.9,
                    "consecutive_absence": 0,
                }
            },
        },
    )

    scope = AuthorizedTenantScope.from_iterable("op_a", ["tenant_a"])
    engine = AggregationEngine(storage)
    dashboard = engine.build_dashboard("tenant_a", authz_scope=scope)

    assert dashboard["risk_distribution"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    endpoint = dashboard["endpoints"][0]
    assert endpoint["confidence"] == 0.6
    assert endpoint["discovery_source"] == "ct_log, protocol_observer"
    assert endpoint["discovery_sources"] == ["ct_log", "protocol_observer"]
    assert endpoint["ownership_category"] == "adjacent_dependency"
    assert endpoint["relevance_score"] > 0.4
    assert endpoint["first_seen_ms"] == 1_710_000_000_100
    assert endpoint["last_seen_ms"] == 1_710_000_000_200


def test_phase5_cycle_bundle_uses_cycle_scoped_temporal_graph_and_layer3_state(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    for cycle_number, cycle_id, timestamp in (
        (1, "cycle_000001", 1_710_000_000_000),
        (2, "cycle_000002", 1_710_000_100_000),
    ):
        storage.save_snapshot(
            "tenant_a",
            {
                "schema_version": "v2.6",
                "cycle_id": cycle_id,
                "cycle_number": cycle_number,
                "timestamp_unix_ms": timestamp,
                "snapshot_hash_sha256": f"hash_{cycle_number}",
                "endpoint_count": 1,
                "endpoints": [{"hostname": "api.bank.com", "port": 443}],
            },
        )
        storage.append_cycle_metadata(
            "tenant_a",
            {
                "schema_version": "v2.6",
                "cycle_id": cycle_id,
                "cycle_number": cycle_number,
                "status": "completed",
                "timestamp_unix_ms": timestamp,
                "duration_ms": 1000,
            },
        )
        storage.save_temporal_state(
            "tenant_a",
            {
                "schema_version": "v1",
                "endpoints": {
                    "api.bank.com:443": {
                        "endpoint_id": "api.bank.com:443",
                        "visibility_score": 0.4 + (0.1 * cycle_number),
                    }
                },
            },
            cycle_id=cycle_id,
        )
        storage.persist_graph_snapshot(
            "tenant_a",
            {
                "version": 1,
                "created_at_ms": timestamp,
                "nodes": [{"id": f"endpoint:api.bank.com:443:{cycle_number}", "kind": "endpoint"}],
                "edges": [],
            },
            snapshot_id=str(timestamp),
            cycle_id=cycle_id,
        )
        assert storage.persist_layer3_snapshot(
            "tenant_a",
            {
                "schema_version": "v3",
                "entities": {
                    "api.bank.com:443": {"prediction_count": cycle_number}
                },
            },
            cycle_id=cycle_id,
        )

    scope = AuthorizedTenantScope.from_iterable("op_a", ["tenant_a"])
    engine = AggregationEngine(storage)

    bundle_a = engine.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope,
        cycle_id="cycle_000001",
    )
    bundle_b = engine.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope,
        cycle_id="cycle_000002",
    )

    assert bundle_a["temporal_state"]["endpoints"]["api.bank.com:443"]["visibility_score"] == 0.5
    assert bundle_b["temporal_state"]["endpoints"]["api.bank.com:443"]["visibility_score"] == pytest.approx(0.6)
    assert bundle_a["trust_graph_snapshot"]["nodes"][0]["id"].endswith(":1")
    assert bundle_b["trust_graph_snapshot"]["nodes"][0]["id"].endswith(":2")
    assert bundle_a["layer3_state_snapshot"]["entities"]["api.bank.com:443"]["prediction_count"] == 1
    assert bundle_b["layer3_state_snapshot"]["entities"]["api.bank.com:443"]["prediction_count"] == 2


def test_phase5_migrator_normalizes_trust_graph_legacy_shape() -> None:
    migrator = ArtifactMigrationEngine()
    migrated = migrator.migrate_trust_graph_snapshot(
        {"version": "1", "nodes": None, "edges": "bad"}
    )
    assert migrated["version"] == 1
    assert migrated["nodes"] == []
    assert migrated["edges"] == []


def test_phase5_rate_limit_jitter_is_deterministic_per_endpoint_attempt() -> None:
    a = _deterministic_jitter("pay.example.com:443", 2, 1.5)
    b = _deterministic_jitter("pay.example.com:443", 2, 1.5)
    c = _deterministic_jitter("pay.example.com:443", 3, 1.5)

    assert a == b
    assert a != c


def test_phase5_fingerprint_id_is_content_derived() -> None:
    fp1 = Fingerprint(
        entity_id="api.bank.com:443",
        kind="tls_fp_v1",
        version=1,
        hash="abc123",
        vector=[1.0, 2.0],
        source_fields={"issuer": "Demo CA"},
    )
    fp2 = Fingerprint(
        entity_id="api.bank.com:443",
        kind="tls_fp_v1",
        version=1,
        hash="abc123",
        vector=[1.0, 2.0],
        source_fields={"issuer": "Demo CA"},
    )

    assert fp1.fingerprint_id == fp2.fingerprint_id
    assert fp1.fingerprint_id.startswith("fp_")


def test_phase5_policy_parser_uses_canonical_json_hashing() -> None:
    parser = PolicyParser()
    left = parser.parse_policy_payload(
        filename="policy.txt",
        extracted_text="Sample requirement text",
        jurisdiction="IN",
        source="INTERNAL",
        tags=["banking", "critical"],
    )
    right = parser.parse_policy_payload(
        filename="policy.txt",
        extracted_text="Sample requirement text",
        jurisdiction="IN",
        source="INTERNAL",
        tags=["critical", "banking"],
    )

    assert left["policy_id"] == right["policy_id"]


def test_phase5_entropy_weakness_preserves_aliases_from_canonical_field() -> None:
    detector = EntropyWeaknessDetector()
    weakness = detector.evaluate(
        entity_id="api.bank.com:443",
        entropy_value=0.1,
        entropy_decay_rate=0.2,
        baseline_entropy_mean=0.9,
        baseline_entropy_std=0.1,
        entropy_floor=0.4,
    )
    assert weakness is not None
    assert weakness.entropy_decay_rate == weakness.decay_rate == weakness.entropy_decay
