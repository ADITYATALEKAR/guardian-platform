from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

import pytest

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import UnifiedCycleOrchestrator
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge
from layers.layer0_observation.acquisition.protocol_observer import (
    DNSObservation,
    HTTPObservation,
    RawObservation,
    TCPObservation,
    TLSObservation,
)


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


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
    return storage


def _observation(endpoint: str, *, success: bool) -> RawObservation:
    return RawObservation(
        endpoint=endpoint,
        entity_id=endpoint,
        observation_id=f"obs_{endpoint.replace(':', '_')}",
        timestamp_ms=1_710_000_000_123,
        dns=DNSObservation(resolved_ip="1.1.1.1", resolution_time_ms=10.0),
        tcp=TCPObservation(connected=bool(success), connect_time_ms=8.5 if success else None),
        tls=TLSObservation(
            handshake_time_ms=22.0 if success else None,
            tls_version="TLSv1.2" if success else None,
            cipher_suite="RSA-AES256-GCM-SHA384" if success else None,
            cert_subject="commonName=pay.example.com" if success else None,
            cert_issuer="commonName=Demo CA" if success else None,
            cert_not_before="Jan  1 00:00:00 2026 GMT" if success else None,
            cert_not_after="Jan  1 00:00:00 2027 GMT" if success else None,
            cert_san=["pay.example.com", "api.example.com"] if success else [],
            cert_public_key_algorithm="RSA" if success else None,
            cert_public_key_size_bits=2048 if success else None,
            cert_must_staple=False if success else None,
            cert_ocsp_urls=[],
            alpn_protocol="h2" if success else None,
            sni_mismatch=False if success else None,
            ocsp_stapled=False if success else None,
            error=None if success else "tls_failed",
        ),
        http=HTTPObservation(
            status_code=403 if success else None,
            response_time_ms=30.0 if success else None,
            headers=(
                {
                    "server": "cloudflare",
                    "cf-ray": "xyz123",
                    "strict-transport-security": "max-age=300",
                }
                if success
                else {}
            ),
            error=None if success else "http_unavailable",
        ),
        success=bool(success),
        error=None if success else "probe_failed",
    )


def _orchestrator(storage: StorageManager, engine: DiscoveryEngine) -> UnifiedCycleOrchestrator:
    return UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )


def test_phase9_master_happy_path_end_to_end_artifacts_and_dashboard(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=True,
        enable_ct_longitudinal=False,
    )
    orch = _orchestrator(storage, engine)

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_observation(endpoint, success=True)], elapsed_ms=12)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    result = orch.run_cycle("tenant_a")
    assert result.metadata.status.value == "completed"
    assert result.snapshot.endpoint_count >= 1

    # Persistence integrity
    assert storage.load_latest_snapshot("tenant_a") is not None
    assert storage.load_temporal_state("tenant_a") is not None
    assert storage.load_graph_snapshot("tenant_a") is not None
    assert storage.load_layer3_snapshot("tenant_a") is not None
    assert storage.load_latest_guardian_records("tenant_a")
    telemetry = storage.load_telemetry_for_cycle("tenant_a", result.metadata.cycle_id)
    assert telemetry
    assert all("posture_findings" in row for row in telemetry)

    # Metadata consistency
    metadata = storage.load_cycle_metadata("tenant_a")
    cycle_rows = [r for r in metadata if r.get("cycle_id") == result.metadata.cycle_id]
    statuses = [str(r.get("status", "")) for r in cycle_rows]
    assert "running" in statuses
    assert "completed" in statuses
    assert "failed" not in statuses

    # Lock must be released
    assert not (storage.get_tenant_path("tenant_a") / ".cycle.lock").exists()

    # Final report integrity
    scope = AuthorizedTenantScope.from_iterable("phase9", ["tenant_a"])
    dashboard = AggregationEngine(storage).build_dashboard("tenant_a", authz_scope=scope)
    assert isinstance(dashboard, dict)
    assert isinstance(dashboard.get("health_summary"), dict)
    assert isinstance(dashboard.get("risk_distribution"), dict)
    assert isinstance(dashboard.get("drift_report"), dict)
    assert isinstance(dashboard.get("endpoints"), list)


def test_phase9_master_degraded_network_completes_without_retry_storm(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )
    orch = _orchestrator(storage, engine)

    def _raise_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        raise TimeoutError("simulated timeout")

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _raise_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    t0 = time.time()
    result = orch.run_cycle("tenant_a")
    elapsed = time.time() - t0

    assert result.metadata.status.value == "completed"
    assert result.snapshot.endpoint_count == 0
    assert elapsed < 5.0
    assert not (storage.get_tenant_path("tenant_a") / ".cycle.lock").exists()


def test_phase9_master_telemetry_corruption_fails_loud_marks_failed_and_releases_lock(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)

    class _CorruptingDiscoveryEngine(DiscoveryEngine):
        def run_discovery(self, tenant_id, rate_controller, cycle_id, seed_endpoints=None, expansion_mode="A_BCDE"):
            telemetry_dir = storage.get_tenant_path(tenant_id) / "telemetry"
            telemetry_dir.mkdir(parents=True, exist_ok=True)
            (telemetry_dir / f"{cycle_id}.jsonl").write_text("{bad-json\n", encoding="utf-8")
            self._last_reporting_metrics = {
                "total_discovered_domains": 0,
                "total_successful_observations": 0,
                "total_failed_observations": 0,
                "posture_summary": {},
            }
            return []

    engine = _CorruptingDiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=1,
        expansion_wrapper=_StubExpansionWrapper(),
    )
    orch = _orchestrator(storage, engine)

    with pytest.raises(RuntimeError, match="Corrupt telemetry records"):
        orch.run_cycle("tenant_a")

    rows = storage.load_cycle_metadata("tenant_a")
    assert any(str(r.get("status")) == "failed" for r in rows)
    assert not (storage.get_tenant_path("tenant_a") / ".cycle.lock").exists()


def test_phase9_master_stale_lock_recovery(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=1,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )
    orch = _orchestrator(storage, engine)

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_observation(endpoint, success=True)], elapsed_ms=10)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    # Create stale lock manually
    lock_path = storage.get_tenant_path("tenant_a") / ".cycle.lock"
    stale_started = int(time.time() * 1000) - (StorageManager.STALE_CYCLE_LOCK_THRESHOLD_MS + 10_000)
    lock_path.write_text(
        json.dumps(
            {
                "cycle_id": "cycle_999999",
                "cycle_number": 999999,
                "started_at_unix_ms": stale_started,
                "pid": 0,
                "hostname": "test-host",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = orch.run_cycle("tenant_a")
    assert result.metadata.status.value == "completed"
    assert not lock_path.exists()


def test_phase9_master_rate_limit_retry_exhaustion_is_bounded(tmp_path: Path, monkeypatch) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=1,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=False,
    )

    class _NeverAllow:
        def allow_request(self, key: str) -> bool:
            return False

    monkeypatch.setattr(time, "sleep", lambda _: None)
    monkeypatch.setattr("infrastructure.discovery.discovery_engine.random.uniform", lambda a, b: 0.0)
    # If acquisition is called, retry gate is broken
    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("acquisition should not be called")),
    )

    t0 = time.time()
    results = engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=_NeverAllow(),
        cycle_id="cycle_000001",
        seed_endpoints=["pay.example.com:443"],
        expansion_mode="A_ONLY",
    )
    elapsed = time.time() - t0
    assert results == []
    assert elapsed < 3.0
