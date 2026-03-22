from __future__ import annotations

from pathlib import Path

from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from infrastructure.unified_discovery_v2.temporal_state_engine import TemporalStateEngine
from infrastructure.unified_discovery_v2.unified_cycle_orchestrator import UnifiedCycleOrchestrator
from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from simulator.core.graph_slice_builder import build_graph_slice
from simulator.core.physics_extractor import extract_physics_signals
from simulator.mitigation.mitigation_actions import MitigationAction
from simulator.mitigation.mitigation_engine import MitigationEngine
from simulator.scenarios.scenario_catalog import AttackScenario
from simulator.scenarios.scenario_injector import ScenarioInjector


def _new_orchestrator(tmp_path: Path) -> UnifiedCycleOrchestrator:
    storage = StorageManager(str(tmp_path / "storage"))
    storage.create_tenant("tenant_a")
    engine = DiscoveryEngine(storage=storage)
    return UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )


def test_phase4_orchestrator_delegates_to_shared_weakness_helpers(monkeypatch, tmp_path: Path) -> None:
    orchestrator = _new_orchestrator(tmp_path)

    def _fake_physics(_fps):
        return {"drift_rate": 0.42}

    sentinel = object()

    def _fake_graph_slice(*, entity_id: str, trust_graph: TrustGraph):
        assert entity_id == "host:443"
        assert isinstance(trust_graph, TrustGraph)
        return sentinel

    monkeypatch.setattr(
        "infrastructure.unified_discovery_v2.unified_cycle_orchestrator.build_physics_signals",
        _fake_physics,
    )
    monkeypatch.setattr(
        "infrastructure.unified_discovery_v2.unified_cycle_orchestrator.build_graph_slice_for_layer2",
        _fake_graph_slice,
    )

    assert orchestrator._extract_physics_signals([{"kind": "x"}]) == {"drift_rate": 0.42}
    assert (
        orchestrator._build_layer2_graph_slice(entity_id="host:443", trust_graph=TrustGraph())
        is sentinel
    )


def test_phase4_simulator_wrappers_delegate_to_shared_helpers(monkeypatch) -> None:
    monkeypatch.setattr(
        "simulator.core.physics_extractor._extract_shared_physics_signals",
        lambda fps: {"momentum": 0.7},
    )
    sentinel = object()
    monkeypatch.setattr(
        "simulator.core.graph_slice_builder._build_shared_graph_slice",
        lambda *, entity_id, trust_graph: sentinel,
    )

    assert extract_physics_signals([{"kind": "k"}]) == {"momentum": 0.7}
    assert build_graph_slice(entity_id="x:443", trust_graph=TrustGraph()) is sentinel


def test_phase4_shared_observation_mutation_keeps_scenario_and_mitigation_consistent() -> None:
    observations = [
        {"entity_id": "a:443", "entropy_score": 0.1},
        {"entity_id": "b:443", "entropy_score": 0.2},
    ]
    scenario = AttackScenario(
        id="test",
        injection_type="delta",
        target_selector={"entity_id": "b:443"},
        injection_payload={"entropy_score": 0.9},
        description="x",
    )
    injected = ScenarioInjector().inject(observations, scenario)
    assert injected[0]["entropy_score"] == 0.1
    assert injected[1]["entropy_score"] == 0.9

    action = MitigationAction(
        action_type="delta",
        target={"entity_id": "b:443"},
        delta={"entropy_score": 0.3},
        description="y",
    )
    mitigated = MitigationEngine().apply(injected, action)
    assert mitigated[0]["entropy_score"] == 0.1
    assert mitigated[1]["entropy_score"] == 0.3
