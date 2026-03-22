from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.posture.contracts_v1 import FINDING_LANGUAGE_MODE_DEFENSIVE, TriState
from infrastructure.posture.signal_extractor import PostureSignalExtractor
from infrastructure.storage_manager.storage_manager import StorageManager
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
    elapsed_ms: int = 9


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


def _cloudflare_raw_observation() -> RawObservation:
    return RawObservation(
        endpoint="api.example.com:443",
        entity_id="api.example.com:443",
        observation_id="obs_1",
        timestamp_ms=1_710_000_000_000,
        dns=DNSObservation(resolved_ip="1.1.1.1", resolution_time_ms=12.1),
        tcp=TCPObservation(connected=True, connect_time_ms=8.2),
        tls=TLSObservation(
            handshake_time_ms=25.0,
            tls_version="TLSv1.2",
            cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
            cert_subject="commonName=api.example.com, organizationName=Bank Example Corp",
            cert_issuer="commonName=DigiCert Global G2",
            cert_not_before="Jan  1 00:00:00 2026 GMT",
            cert_not_after="Jan  1 00:00:00 2027 GMT",
            cert_serial="123456",
            cert_san=["api.example.com", "www.example.com"],
            cert_public_key_algorithm="RSA",
            cert_public_key_size_bits=2048,
            cert_must_staple=False,
            cert_ocsp_urls=["http://ocsp.digicert.com"],
            alpn_protocol="h2",
            sni_mismatch=False,
            ocsp_stapled=False,
        ),
        http=HTTPObservation(
            status_code=403,
            response_time_ms=35.5,
            headers={
                "server": "cloudflare",
                "cf-ray": "abcde12345",
                "cf-cache-status": "DYNAMIC",
                "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                "content-security-policy": "default-src 'self'",
            },
        ),
        success=True,
    )


def test_phase4_extracts_waf_and_tls_signals_on_blocked_response() -> None:
    raw = _cloudflare_raw_observation()
    extractor = PostureSignalExtractor()
    waf_signal, tls_signal = extractor.extract(raw)

    waf_payload = waf_signal.to_dict()
    tls_payload = tls_signal.to_dict()

    assert waf_payload["http_status"] == 403
    assert waf_payload["waf_vendor"] == "Cloudflare"
    assert waf_payload["classification_confidence"] == "HIGH"
    assert waf_payload["challenge_type"] == "forbidden_or_challenge"
    assert waf_payload["header_completeness"] in {"FULL", "PARTIAL", "MINIMAL"}
    assert waf_payload["finding_language_mode"] == FINDING_LANGUAGE_MODE_DEFENSIVE

    assert tls_payload["negotiated_tls_version"] == "TLSv1.2"
    assert tls_payload["negotiated_cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert tls_payload["certificate_validation_type"] == "OV"
    assert tls_payload["hsts_present"] == TriState.YES.value
    assert tls_payload["hsts_max_age_seconds"] == 31536000
    assert tls_payload["hsts_include_subdomains"] == TriState.YES.value
    assert tls_payload["hsts_preload"] == TriState.YES.value
    assert tls_payload["ocsp_stapling_status"] == TriState.NO.value
    assert tls_payload["must_staple_status"] == TriState.NO.value
    assert tls_payload["forward_secrecy_status"] == TriState.YES.value
    assert tls_payload["tls_downgrade_surface"] == TriState.YES.value
    assert tls_payload["edge_observed"] is True


def test_phase4_unknown_fields_are_explicit_when_not_observed() -> None:
    raw = RawObservation(
        endpoint="unreachable.example.com:443",
        entity_id="unreachable.example.com:443",
        observation_id="obs_2",
        timestamp_ms=1_710_000_000_100,
        dns=DNSObservation(resolved_ip=None, error="dns fail"),
        tls=TLSObservation(handshake_time_ms=None, tls_version=None, error="tls failed"),
        success=False,
        error="probe failed",
    )
    extractor = PostureSignalExtractor()
    waf_signal, tls_signal = extractor.extract(raw)

    waf_payload = waf_signal.to_dict()
    tls_payload = tls_signal.to_dict()

    assert waf_payload["waf_vendor"] is None
    assert waf_payload["header_completeness"] == "UNKNOWN"
    assert tls_payload["sni_behavior"] == TriState.UNKNOWN.value
    assert tls_payload["ocsp_stapling_status"] == TriState.UNKNOWN.value
    assert tls_payload["must_staple_status"] == TriState.UNKNOWN.value
    assert tls_payload["hsts_present"] == TriState.UNKNOWN.value
    assert tls_payload["zero_rtt_status"] == TriState.UNKNOWN.value
    assert tls_payload["quantum_ready"] == TriState.UNKNOWN.value


def test_phase4_discovery_telemetry_includes_posture_signals(monkeypatch, tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=4,
        max_endpoints=4,
        expansion_wrapper=_StubExpansionWrapper(),
        include_http_probe=True,
    )

    def _fake_observe(endpoint: str, samples: int, **kwargs) -> _FakeSeries:
        return _FakeSeries(observations=[_cloudflare_raw_observation()], elapsed_ms=11)

    monkeypatch.setattr(protocol_observer, "observe_endpoint_series", _fake_observe)
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    results = engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=None,
        cycle_id="cycle_000001",
        seed_endpoints=["api.example.com:443"],
        expansion_mode="A_ONLY",
    )
    assert len(results) >= 1

    telemetry = storage.load_telemetry_for_cycle("tenant_a", "cycle_000001")
    assert len(telemetry) >= 1
    for record in telemetry:
        assert "posture_signals" in record
        assert len(record["posture_signals"]) == 2
        assert all(signal.get("schema_version") == "v1" for signal in record["posture_signals"])
    assert any(
        signal.get("waf_vendor") == "Cloudflare"
        for record in telemetry
        for signal in record["posture_signals"]
    )
