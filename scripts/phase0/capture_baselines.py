from __future__ import annotations

import json
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer
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
from simulator.core.simulation_request import SimulationRequest
from simulator.core.simulation_service import SimulationService, _snapshot_hash
from layers.layer3_prediction_and_learning.learning_state_v2 import LearningState


@dataclass
class _FakeSeries:
    observations: List[RawObservation]
    elapsed_ms: int = 12


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
        tcp=TCPObservation(connected=True, connect_time_ms=8.0),
        tls=TLSObservation(
            handshake_time_ms=20.0,
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


def _seed_simulation_baseline(prod_root: Path, tenant_id: str, cycle_id: str) -> None:
    tenant_path = prod_root / "tenant_data_storage" / "tenants" / tenant_id
    tenant_path.mkdir(parents=True, exist_ok=True)
    endpoints = [
        {
            "hostname": "example.com",
            "port": 443,
            "tls_version": "TLS1.2",
            "certificate_sha256": "abc",
            "certificate_expiry_unix_ms": 0,
            "ip": "1.2.3.4",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "cert_issuer": "issuer",
            "entropy_score": 0.1,
            "ports_responding": [],
            "services_detected": [],
            "discovered_by": ["snapshot"],
            "confidence": 0.9,
            "tls_jarm": None,
        }
    ]
    snapshot = {
        "schema_version": "1.2",
        "cycle_id": cycle_id,
        "cycle_number": 1,
        "timestamp_unix_ms": 1,
        "snapshot_hash_sha256": _snapshot_hash({"endpoints": endpoints}),
        "endpoint_count": 1,
        "endpoints": endpoints,
    }
    (tenant_path / "snapshots").mkdir(parents=True, exist_ok=True)
    (tenant_path / "trust_graph").mkdir(parents=True, exist_ok=True)
    (tenant_path / "layer3_state").mkdir(parents=True, exist_ok=True)
    (tenant_path / "snapshots" / f"{cycle_id}.json").write_text(
        json.dumps(snapshot, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    (tenant_path / "trust_graph" / "latest.json").write_text(
        json.dumps({"version": 1, "created_at_ms": 1, "nodes": [], "edges": []}, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    (tenant_path / "layer3_state" / "layer3_state_snapshot.json").write_text(
        json.dumps(LearningState.to_snapshot({}, tenant_id=tenant_id), sort_keys=True, indent=2),
        encoding="utf-8",
    )


def capture() -> dict:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        storage = StorageManager(str(root / "prod"))
        storage.create_tenant("tenant_a")
        storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])

        engine = DiscoveryEngine(
            storage=storage,
            max_workers=1,
            max_endpoints=1,
            expansion_wrapper=_StubExpansionWrapper(),
            enable_phase5_findings=False,
        )
        orchestrator = UnifiedCycleOrchestrator(
            storage=storage,
            discovery_engine=engine,
            snapshot_builder=SnapshotBuilder(),
            temporal_engine=TemporalStateEngine(),
        )

        original_observe = protocol_observer.observe_endpoint_series
        original_bridge = ObservationBridge.process_series
        try:
            protocol_observer.observe_endpoint_series = (
                lambda endpoint, samples, **kwargs: _FakeSeries(observations=[_observation(endpoint)], elapsed_ms=12)
            )
            ObservationBridge.process_series = lambda self, raws: []
            t0 = time.perf_counter()
            result = orchestrator.run_cycle("tenant_a")
            cycle_runtime_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            cycle_status = result.metadata.status.value
        finally:
            protocol_observer.observe_endpoint_series = original_observe
            ObservationBridge.process_series = original_bridge

        cycle_id = "cycle_000001"
        telemetry_records = 1000
        for i in range(telemetry_records):
            storage.persist_telemetry_record(
                "tenant_a",
                cycle_id,
                {
                    "sequence": i + 1,
                    "timestamp_ms": 1_710_000_000_000 + i,
                    "entity_id": "api.example.com:443",
                    "fingerprints": [],
                    "posture_signals": [],
                    "posture_findings": {"waf_findings": [], "tls_findings": []},
                },
            )
        t1 = time.perf_counter()
        loaded = storage.load_telemetry_for_cycle("tenant_a", cycle_id)
        telemetry_read_ms = round((time.perf_counter() - t1) * 1000.0, 3)

        sim_prod = root / "sim_prod"
        sim_out = root / "sim_out"
        _seed_simulation_baseline(sim_prod, tenant_id="tenant_a", cycle_id=cycle_id)
        sim_service = SimulationService(production_root=str(sim_prod), simulation_root=str(sim_out))
        sim_req = SimulationRequest(
            tenant_id="tenant_a",
            baseline_cycle_id=cycle_id,
            cycle_number=1,
            scenario_id="certificate_compromise",
            scenario_params={"target_selector": {"entity_id": "example.com:443"}},
            max_mitigations=0,
        )
        t2 = time.perf_counter()
        sim_res = sim_service.run(sim_req)
        simulation_runtime_ms = round((time.perf_counter() - t2) * 1000.0, 3)

        return {
            "captured_at_unix_ms": int(time.time() * 1000),
            "cycle_runtime": {
                "tenant_id": "tenant_a",
                "status": cycle_status,
                "runtime_ms": cycle_runtime_ms,
            },
            "simulation_runtime": {
                "tenant_id": "tenant_a",
                "simulation_id": sim_res.simulation_id,
                "runtime_ms": simulation_runtime_ms,
            },
            "jsonl_storage": {
                "tenant_id": "tenant_a",
                "cycle_id": cycle_id,
                "records": telemetry_records,
                "loaded_records": len(loaded),
                "read_ms": telemetry_read_ms,
            },
        }


def main() -> None:
    payload = capture()
    out_path = Path("docs") / "baselines" / "phase0_baseline.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Baseline written: {out_path}")


if __name__ == "__main__":
    main()
