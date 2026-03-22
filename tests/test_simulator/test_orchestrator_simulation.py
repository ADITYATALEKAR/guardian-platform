import json
import tempfile
from pathlib import Path

from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import UnifiedCycleOrchestrator
from simulator.core.simulation_request import SimulationRequest
from simulator.core.simulation_service import _snapshot_hash


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)


def test_orchestrator_run_simulation_manual():
    with tempfile.TemporaryDirectory() as tmpdir:
        prod_root = Path(tmpdir) / "prod"
        sim_root = Path(tmpdir) / "sim"

        storage = StorageManager(str(prod_root))
        tenant_id = "tenant_test"
        storage.create_tenant(tenant_id)

        tenant_path = storage.get_tenant_path(tenant_id)

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
        snapshot_hash = _snapshot_hash({"endpoints": endpoints})
        snapshot = {
            "schema_version": "1.2",
            "cycle_id": "cycle_000001",
            "cycle_number": 1,
            "timestamp_unix_ms": 1,
            "snapshot_hash_sha256": snapshot_hash,
            "endpoint_count": 1,
            "endpoints": endpoints,
        }

        _write_json(tenant_path / "snapshots" / "cycle_000001.json", snapshot)

        trust_graph_snapshot = {
            "version": 1,
            "created_at_ms": 1,
            "nodes": [],
            "edges": [],
        }
        _write_json(tenant_path / "trust_graph" / "latest.json", trust_graph_snapshot)

        orchestrator = UnifiedCycleOrchestrator(
            storage=storage,
            discovery_engine=DiscoveryEngine(storage),
            snapshot_builder=SnapshotBuilder(),
            temporal_engine=TemporalStateEngine(),
            simulation_root=str(sim_root),
        )

        req = SimulationRequest(
            tenant_id=tenant_id,
            baseline_cycle_id="cycle_000001",
            cycle_number=1,
            scenario_id="certificate_compromise",
            scenario_params={"target_selector": {"entity_id": "example.com:443"}},
        )

        resp = orchestrator.run_simulation(req)
        assert resp.simulation_id
        assert resp.tenant_id == tenant_id
