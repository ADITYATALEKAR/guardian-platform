import json
import os
from pathlib import Path
import pytest

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionConfig, ExpansionWrapper
from infrastructure.operator_plane.services.operator_service import OperatorService
from infrastructure.operator_plane.storage.operator_storage import ensure_operator_storage
from infrastructure.storage_manager.identity_manager import IdentityManager
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import (
    UnifiedCycleOrchestrator,
)

pytestmark = [pytest.mark.network]


class CappedExpansionWrapper(ExpansionWrapper):
    def __init__(
        self,
        max_nodes: int,
        max_edges: int,
        max_endpoints: int,
        max_depth: int,
    ):
        super().__init__()
        self._max_nodes = int(max_nodes)
        self._max_edges = int(max_edges)
        self._max_endpoints = int(max_endpoints)
        self._max_depth = int(max_depth)

    def expand(self, root_domain: str, config: ExpansionConfig):
        capped = ExpansionConfig(
            aggressive=config.aggressive,
            max_total_nodes=min(config.max_total_nodes, self._max_nodes),
            max_total_edges=min(config.max_total_edges, self._max_edges),
            max_total_endpoints=min(config.max_total_endpoints, self._max_endpoints),
        )
        return super().expand(root_domain, capped)


def test_real_world_banconal_e2e(tmp_path: Path) -> None:
    operator_root = tmp_path / "operator_storage"
    prod_root = tmp_path / "tenant_storage"
    sim_root = tmp_path / "simulation_storage"

    original_persist = StorageManager.persist_layer3_snapshot

    def debug_persist(self, tenant_id, snapshot):
        try:
            json.dumps(snapshot, sort_keys=True)
        except Exception as e:
            print("\n=== LAYER3 SNAPSHOT SERIALIZATION ERROR ===")
            print("Error type:", type(e))
            print("Error repr:", repr(e))
            print("Snapshot content preview:", str(snapshot)[:2000])
            raise
        return original_persist(self, tenant_id, snapshot)

    StorageManager.persist_layer3_snapshot = debug_persist

    ensure_operator_storage(operator_root, created_at_unix_ms=0)

    master_password_env = "OPERATOR_MASTER_PASSWORD"
    previous_master = os.environ.get(master_password_env)
    os.environ[master_password_env] = "TestMasterPassword!123"

    try:
        storage = StorageManager(str(prod_root))
        identity = IdentityManager(storage)

        expansion_wrapper = CappedExpansionWrapper(
            max_nodes=1000,
            max_edges=2000,
            max_endpoints=100,
            max_depth=10,
        )
        discovery_engine = DiscoveryEngine(
            storage=storage,
            max_workers=50,
            max_endpoints=1000,
            expansion_wrapper=expansion_wrapper,
        )

        snapshot_builder = SnapshotBuilder()
        temporal_engine = TemporalStateEngine()

        orchestrator = UnifiedCycleOrchestrator(
            storage=storage,
            discovery_engine=discovery_engine,
            snapshot_builder=snapshot_builder,
            temporal_engine=temporal_engine,
            simulation_root=str(sim_root),
        )

        operator_service = OperatorService(
            operator_storage_root=str(operator_root),
            storage_manager=storage,
            identity_manager=identity,
            simulation_root=str(sim_root),
            orchestrator=orchestrator,
        )

        operator_service.register_operator(
            operator_id="operator_admin",
            email="ops@example.com",
            password="StrongOperatorPassword123!",
            created_at_unix_ms=0,
            master_password="TestMasterPassword!123",
        )

        response = operator_service.register_tenant(
            operator_id="operator_admin",
            institution_name="Banco Nacional de Panama",
            main_url="https://www.banconal.com.pa/",
            seed_endpoints=None,
            password="StrongTestPassword123!",
        )

        tenant_id = response.get("tenant_id")
        cycle_started = response.get("cycle_started")
        assert tenant_id
        assert cycle_started is True

        tenant_path = storage.get_tenant_path(tenant_id)
        assert tenant_path.exists()

        metadata = storage.load_cycle_metadata(tenant_id)
        statuses = [str(record.get("status", "")).lower() for record in metadata]
        assert "running" in statuses
        assert "completed" in statuses
        assert "failed" not in statuses

        snapshots = list((tenant_path / "snapshots").glob("cycle_*.json"))
        assert snapshots

        guardian_records = storage.load_latest_guardian_records(tenant_id)
        assert guardian_records

        lock_path = tenant_path / ".cycle.lock"
        assert not lock_path.exists()

        storage_root = tenant_path
        assert storage_root.exists()
        assert (storage_root / "snapshots").is_dir()
        assert (storage_root / "trust_graph").is_dir()
        assert (storage_root / "layer3_state").is_dir()

        endpoint_count = 0
        previous_count = -1
        for cycle_index in range(1, 6):
            if cycle_index > 1:
                orchestrator.run_cycle(tenant_id)

            snapshot_dict = storage.load_latest_snapshot(tenant_id)
            endpoint_count = snapshot_dict.get("endpoint_count", 0) if snapshot_dict else 0
            if endpoint_count > 1000:
                raise RuntimeError("endpoint cap exceeded")

            graph_snapshot = storage.load_graph_snapshot(tenant_id) or {}
            graph_nodes = len(graph_snapshot.get("nodes", []))
            graph_edges = len(graph_snapshot.get("edges", []))

            print(
                json.dumps(
                    {
                        "cycle": cycle_index,
                        "total_endpoints_discovered": endpoint_count,
                        "graph_nodes": graph_nodes,
                        "graph_edges": graph_edges,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )

            if endpoint_count == previous_count:
                break
            previous_count = endpoint_count

        if endpoint_count < 50:
            raise AssertionError("Expansion did not reach minimum expected breadth")
        if endpoint_count > 100:
            raise AssertionError("Expansion exceeded maximum expected breadth")

        if len(guardian_records) < 50:
            raise AssertionError("Guardian records below expected minimum")
        print("Sample Guardian Record:", guardian_records[0])

        layer3_snapshot = storage.load_layer3_snapshot(tenant_id) or {}
        layer3_entity_count = len(layer3_snapshot.get("entities", {}))

        summary = {
            "tenant_id": tenant_id,
            "total_snapshots": len(snapshots),
            "total_guardian_records": len(guardian_records),
            "cycle_status": "COMPLETED",
            "total_endpoints_discovered": endpoint_count,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))

        print(
            json.dumps(
                {
                    "cycle_status": "COMPLETED",
                    "endpoints": endpoint_count,
                    "guardian_records": len(guardian_records),
                    "graph_nodes": graph_nodes,
                    "graph_edges": graph_edges,
                },
                indent=2,
            )
        )

        print(
            json.dumps(
                {
                    "layer0_snapshot_endpoints": endpoint_count,
                    "layer1_graph_nodes": graph_nodes,
                    "layer1_graph_edges": graph_edges,
                    "layer3_entities": layer3_entity_count,
                    "layer4_guardian_records": len(guardian_records),
                    "simulator_output": None,
                },
                indent=2,
            )
        )
    finally:
        StorageManager.persist_layer3_snapshot = original_persist
        if previous_master is None:
            os.environ.pop(master_password_env, None)
        else:
            os.environ[master_password_env] = previous_master
