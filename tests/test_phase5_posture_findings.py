from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List
import time

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.policy_integration.compliance import resolve_tenant_frameworks
from infrastructure.policy_integration.policies import PolicyStore
from infrastructure.posture.finding_engine import PostureFindingEngine
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
    return storage


def _legacy_tls_observation() -> RawObservation:
    return RawObservation(
        endpoint="pay.example.com:443",
        entity_id="pay.example.com:443",
        observation_id="obs_phase5_1",
        timestamp_ms=1_710_000_000_123,
        dns=DNSObservation(resolved_ip="1.1.1.1", resolution_time_ms=10.0),
        tcp=TCPObservation(connected=True, connect_time_ms=8.5),
        tls=TLSObservation(
            handshake_time_ms=22.0,
            tls_version="TLSv1.2",
            cipher_suite="RSA-AES256-GCM-SHA384",
            cert_subject="commonName=pay.example.com",
            cert_issuer="commonName=Demo CA",
            cert_not_before="Jan  1 00:00:00 2026 GMT",
            cert_not_after="Jan  1 00:00:00 2027 GMT",
            cert_san=["pay.example.com", "api.example.com"],
            cert_public_key_algorithm="RSA",
            cert_public_key_size_bits=2048,
            cert_must_staple=False,
            cert_ocsp_urls=[],
            alpn_protocol="h2",
            sni_mismatch=False,
            ocsp_stapled=False,
        ),
        http=HTTPObservation(
            status_code=403,
            response_time_ms=30.0,
            headers={
                "server": "cloudflare",
                "cf-ray": "xyz123",
                "strict-transport-security": "max-age=300",
            },
        ),
        success=True,
    )


def _legacy_tls_observation_for_endpoint(endpoint: str) -> RawObservation:
    base = _legacy_tls_observation()
    return RawObservation(
        endpoint=endpoint,
        entity_id=endpoint,
        observation_id=f"obs_{endpoint.replace(':', '_')}",
        timestamp_ms=base.timestamp_ms,
        dns=base.dns,
        tcp=base.tcp,
        tls=base.tls,
        http=base.http,
        success=base.success,
        error=base.error,
        probe_duration_ms=base.probe_duration_ms,
        packet_spacing_ms=list(base.packet_spacing_ms),
        attempt_count=base.attempt_count,
        attempt_protocols=list(base.attempt_protocols),
        attempt_path=base.attempt_path,
    )


def test_phase5_finding_engine_emits_split_findings_scores_and_hndl() -> None:
    from infrastructure.posture.signal_extractor import PostureSignalExtractor

    raw = _legacy_tls_observation()
    extractor = PostureSignalExtractor()
    signals = extractor.extract_as_dicts(raw)

    engine = PostureFindingEngine(enable_ct_longitudinal=False)
    output = engine.evaluate_from_signal_dicts(signals)

    assert "waf_findings" in output
    assert "tls_findings" in output
    assert "scores" in output
    assert output["scores"]["quantum_ready"] == "NO"
    assert output["scores"]["hndl_risk_flag"] is True
    assert output["scores"]["cryptographic_health_score"] < 100
    assert output["scores"]["protection_posture_score"] < 100
    assert output["scores"]["ct_history_summary"]["status"] == "disabled"

    assert len(output["waf_findings"]) >= 1
    assert len(output["tls_findings"]) >= 1
    assert all(
        finding.get("finding_language_mode") == "defensive_posture"
        for finding in (output["waf_findings"] + output["tls_findings"])
    )
    assert any("PCI-DSS" in " ".join(f.get("compliance_controls", [])) for f in output["tls_findings"])


def test_phase5_discovery_telemetry_includes_posture_findings(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=True,
        enable_ct_longitudinal=False,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_legacy_tls_observation()], elapsed_ms=12)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=None,
        cycle_id="cycle_000001",
        seed_endpoints=["pay.example.com:443"],
        expansion_mode="A_ONLY",
    )

    telemetry = storage.load_telemetry_for_cycle("tenant_a", "cycle_000001")
    assert telemetry
    for record in telemetry:
        findings = record.get("posture_findings")
        assert isinstance(findings, dict)
        assert "waf_findings" in findings
        assert "tls_findings" in findings
        assert "scores" in findings
        assert "AVYAKTA" not in str(findings)


def test_phase5_orchestrator_surfaces_posture_summary_in_cycle_artifact(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=2,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=True,
        enable_ct_longitudinal=False,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(
            observations=[_legacy_tls_observation_for_endpoint(endpoint)],
            elapsed_ms=12,
        )

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    orchestrator = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )
    result = orchestrator.run_cycle("tenant_a")
    posture_summary = result.build_stats.posture_summary

    assert isinstance(posture_summary, dict)
    assert posture_summary.get("waf_findings_count", 0) >= 1
    assert posture_summary.get("tls_findings_count", 0) >= 1
    assert "avg_cryptographic_health_score" in posture_summary
    assert "avg_protection_posture_score" in posture_summary

    telemetry = storage.load_telemetry_for_cycle("tenant_a", result.metadata.cycle_id)
    assert telemetry
    assert all("posture_findings" in record for record in telemetry)


def test_phase5_ct_longitudinal_enabled_remains_bounded(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    endpoints = [f"host{i}.example.com:443" for i in range(1, 5)]

    engine = DiscoveryEngine(
        storage=storage,
        max_workers=4,
        max_endpoints=8,
        expansion_wrapper=_StubExpansionWrapper(),
        enable_phase5_findings=True,
        enable_ct_longitudinal=True,
        max_ct_calls_per_cycle=1,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(
            observations=[_legacy_tls_observation_for_endpoint(endpoint)],
            elapsed_ms=10,
        )

    def _slow_fetch(self, domain: str):
        time.sleep(0.2)
        return []

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])
    monkeypatch.setattr(
        "infrastructure.posture.ct_longitudinal.CTLongitudinalAnalyzer._fetch_ct_rows",
        _slow_fetch,
    )

    t0 = time.time()
    engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=None,
        cycle_id="cycle_000001",
        seed_endpoints=endpoints,
        expansion_mode="A_ONLY",
    )
    elapsed = time.time() - t0

    telemetry = storage.load_telemetry_for_cycle("tenant_a", "cycle_000001")
    ct_statuses = [
        (
            record.get("posture_findings", {})
            .get("scores", {})
            .get("ct_history_summary", {})
            .get("status")
        )
        for record in telemetry
    ]
    assert elapsed < 2.0
    assert "deferred" in ct_statuses


def test_phase5_tenant_policy_aware_compliance_mapping(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    store = PolicyStore(storage_manager=storage, tenant_id="tenant_a")
    store.save_approved_policy(
        {
            "policy_id": "approved_rbi_1",
            "title": "RBI Transport Policy",
            "jurisdiction": "INDIA",
            "tags": ["rbi", "transport", "tls"],
        }
    )
    frameworks = resolve_tenant_frameworks(storage, "tenant_a")
    assert frameworks == ["RBI"]

    from infrastructure.posture.signal_extractor import PostureSignalExtractor

    raw = _legacy_tls_observation()
    signals = PostureSignalExtractor().extract_as_dicts(raw)
    findings = PostureFindingEngine(enable_ct_longitudinal=False).evaluate_from_signal_dicts(
        signals,
        tenant_frameworks=frameworks,
    )

    controls = []
    for finding in findings.get("tls_findings", []):
        controls.extend(finding.get("compliance_controls", []))
    for finding in findings.get("waf_findings", []):
        controls.extend(finding.get("compliance_controls", []))

    assert controls
    assert all(control.startswith("RBI") for control in controls)
