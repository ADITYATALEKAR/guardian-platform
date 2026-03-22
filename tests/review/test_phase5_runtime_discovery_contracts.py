from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import layers.layer0_observation.acquisition.protocol_observer as protocol_observer

from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.discovery.expansion_wrapper import ExpansionResult
from infrastructure.runtime.engine_runtime import EngineRuntime
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
    elapsed_ms: int = 12


class _DiagnosticsExpansionWrapper:
    def expand(
        self,
        root_domain: str,
        config,
        stage_callback=None,
        progress_callback=None,
    ) -> ExpansionResult:
        if callable(stage_callback):
            stage_callback("category_a_exploration")
        if callable(progress_callback):
            progress_callback(
                {
                    "expansion_active_category": "BCDE",
                    "expansion_current_module": "CommonPortScanModule",
                    "expansion_modules_completed_count": 3,
                    "expansion_module_total_count": 5,
                    "expansion_node_count": 9,
                    "expansion_edge_count": 12,
                    "expansion_graph_endpoint_count": 3,
                }
            )
        return ExpansionResult(
            root_domain=root_domain,
            endpoint_candidates={"api.example.com:443"},
            node_count=9,
            edge_count=12,
            ceilings_hit=False,
            diagnostics={
                "t_total_s": 3.4,
                "raw_candidate_count": 4,
                "canonical_candidate_count": 1,
                "timing": {
                    "a_exploration_s": 1.2,
                    "bcde_exploration_s": 1.0,
                    "a_exploitation_s": 0.6,
                    "bcde_exploitation_s": 0.5,
                },
                "productive_category_a_modules": ["CertificateTransparencyModule"],
                "productive_bcde_modules": ["CommonPortScanModule"],
                "module_timings": {
                    "CertificateTransparencyModule": 1.2,
                    "CommonPortScanModule": 1.0,
                },
                "module_summaries": [
                    {
                        "category": "A",
                        "module_name": "CertificateTransparencyModule",
                        "elapsed_s": 1.2,
                        "new_domain_count": 1,
                        "new_endpoint_count": 0,
                        "new_candidate_count": 1,
                        "productive": True,
                    },
                    {
                        "category": "A",
                        "module_name": "NameMutationModule",
                        "elapsed_s": 0.4,
                        "new_domain_count": 0,
                        "new_endpoint_count": 0,
                        "new_candidate_count": 0,
                        "productive": False,
                    },
                    {
                        "category": "BCDE",
                        "module_name": "CommonPortScanModule",
                        "elapsed_s": 1.0,
                        "new_domain_count": 0,
                        "new_endpoint_count": 1,
                        "new_candidate_count": 1,
                        "productive": True,
                    },
                ],
            },
        )


@dataclass
class _PhaseSession:
    scope: str
    phase_outcomes: List[dict] = field(default_factory=list)


class _CyclePhaseExpansionWrapper:
    def __init__(self) -> None:
        self.phase_calls: List[tuple[str, str]] = []

    def expand(self, root_domain: str, config, stage_callback=None, progress_callback=None) -> ExpansionResult:
        _ = root_domain
        _ = config
        _ = stage_callback
        _ = progress_callback
        raise AssertionError("Legacy expand() path should not be used in this test")

    def build_session(self, root_domain: str, config) -> _PhaseSession:
        _ = config
        return _PhaseSession(scope=root_domain)

    def run_phase(self, session: _PhaseSession, *, phase_name: str, time_budget_seconds: int, progress_callback=None) -> dict:
        _ = time_budget_seconds
        if callable(progress_callback):
            progress_callback(
                {
                    "expansion_active_category": "A" if phase_name.startswith("category_a") else "BCDE",
                    "expansion_current_module": "SyntheticModule",
                    "expansion_modules_completed_count": 1,
                    "expansion_module_total_count": 1,
                }
            )
        self.phase_calls.append((phase_name, session.scope))
        payload = {
            "phase": phase_name,
            "status": "completed" if session.scope == "example.com" else "low_yield",
            "elapsed_s": 1.0,
            "productive": session.scope == "example.com",
        }
        session.phase_outcomes.append(payload)
        return payload

    def finalize_session(self, session: _PhaseSession) -> ExpansionResult:
        productive = any(bool(row.get("productive")) for row in session.phase_outcomes)
        return ExpansionResult(
            root_domain=session.scope,
            endpoint_candidates={f"api.{session.scope}:443"} if productive else set(),
            node_count=2 if productive else 1,
            edge_count=1 if productive else 0,
            ceilings_hit=False,
            diagnostics={
                "t_total_s": 4.0,
                "raw_candidate_count": 1 if productive else 0,
                "canonical_candidate_count": 1 if productive else 0,
                "timing": {
                    "a_exploration_s": 1.0,
                    "bcde_exploration_s": 1.0,
                    "a_exploitation_s": 1.0,
                    "bcde_exploitation_s": 1.0,
                },
                "productive_category_a_modules": ["SyntheticAModule"] if productive else [],
                "productive_bcde_modules": ["SyntheticBCDEModule"] if productive else [],
                "module_timings": {"SyntheticModule": 1.0},
                "phase_outcomes": list(session.phase_outcomes),
                "module_summaries": [
                    {
                        "category": "A" if phase.startswith("category_a") else "BCDE",
                        "module_name": "SyntheticModule",
                        "elapsed_s": 1.0,
                        "new_domain_count": 1 if productive and phase.startswith("category_a") else 0,
                        "new_endpoint_count": 1 if productive and phase.startswith("category_bcde") else 0,
                        "new_candidate_count": 1 if productive else 0,
                        "productive": productive,
                        "status": row.get("status"),
                        "phase": phase,
                    }
                    for row in session.phase_outcomes
                    for phase in [row["phase"]]
                ],
            },
        )


@dataclass
class _WindowSession:
    scope: str
    productive_a_modules: set[str] = field(default_factory=set)
    productive_bcde_modules: set[str] = field(default_factory=set)
    module_summaries: List[dict] = field(default_factory=list)
    phase_outcomes: List[dict] = field(default_factory=list)
    endpoint_candidates: set[str] = field(default_factory=set)
    evidence_candidates: set[str] = field(default_factory=set)


class _WindowSchedulerExpansionWrapper:
    def __init__(self) -> None:
        self.turn_calls: List[tuple[str, str, str, int]] = []

    def build_session(self, root_domain: str, config) -> _WindowSession:
        _ = config
        return _WindowSession(scope=root_domain)

    def list_phase_module_names(self, session: _WindowSession, *, phase_name: str) -> List[str]:
        _ = session
        if phase_name == "category_a_exploration":
            return ["SyntheticAModule", "PassiveDNSModule"]
        if phase_name == "category_bcde_exploration":
            return ["CommonPortScanModule", "HTTPProbeModule"]
        if phase_name == "category_a_exploitation":
            return sorted(session.productive_a_modules)
        if phase_name == "category_bcde_exploitation":
            return sorted(session.productive_bcde_modules)
        return []

    def run_module_turn(
        self,
        session: _WindowSession,
        *,
        phase_name: str,
        module_name: str,
        time_budget_seconds: int,
        per_module_time_slice_seconds: int | None = None,
        progress_callback=None,
    ) -> dict:
        self.turn_calls.append((phase_name, module_name, session.scope, int(time_budget_seconds)))
        productive = False
        new_endpoint_ids: List[str] = []
        productivity_classes: List[str] = []
        actual_elapsed_s = float(max(1, int(time_budget_seconds)))
        if phase_name == "category_a_exploration" and module_name == "SyntheticAModule":
            productive = True
            session.productive_a_modules.add(module_name)
            productivity_classes = ["surface_productive"]
        if phase_name == "category_bcde_exploration" and module_name == "CommonPortScanModule":
            productive = True
            session.productive_bcde_modules.add(module_name)
            endpoint_id = f"api.{session.scope}:443"
            session.endpoint_candidates.add(endpoint_id)
            new_endpoint_ids = [endpoint_id]
            productivity_classes = ["surface_productive"]
        if (
            phase_name == "category_bcde_exploration"
            and module_name == "HTTPProbeModule"
            and session.endpoint_candidates
        ):
            productive = True
            session.productive_bcde_modules.add(module_name)
            session.evidence_candidates.add(f"http.{session.scope}")
            productivity_classes = ["evidence_productive"]
        if phase_name == "category_a_exploitation" and module_name in session.productive_a_modules:
            productive = True
            productivity_classes = ["surface_productive"]
        if phase_name == "category_bcde_exploitation" and module_name in session.productive_bcde_modules:
            productive = True
            if module_name == "CommonPortScanModule":
                endpoint_id = f"api.{session.scope}:443"
                session.endpoint_candidates.add(endpoint_id)
                new_endpoint_ids = [endpoint_id]
                productivity_classes = ["surface_productive"]
            else:
                session.evidence_candidates.add(f"http.{session.scope}")
                productivity_classes = ["evidence_productive"]

        if callable(progress_callback):
            progress_callback(
                {
                    "expansion_active_category": "A" if phase_name.startswith("category_a") else "BCDE",
                    "expansion_current_module": module_name,
                    "expansion_node_count": 2 if productive else 1,
                    "expansion_edge_count": 1 if productive else 0,
                    "expansion_graph_endpoint_count": len(session.endpoint_candidates),
                }
            )

        module_summary = {
            "category": "A" if phase_name.startswith("category_a") else "BCDE",
            "phase": phase_name,
            "module_name": module_name,
            "elapsed_s": actual_elapsed_s,
            "actual_elapsed_s": actual_elapsed_s,
            "logical_budget_consumed_s": actual_elapsed_s,
            "scheduled_turn_slice_seconds": max(
                1,
                int(per_module_time_slice_seconds or time_budget_seconds),
            ),
            "new_domain_count": 0,
            "new_endpoint_count": len(new_endpoint_ids),
            "new_candidate_count": len(new_endpoint_ids),
            "productive": productive,
            "status": "completed" if productive else "low_yield",
            "new_endpoint_ids": list(new_endpoint_ids),
            "surface_productive": "surface_productive" in productivity_classes,
            "dependency_productive": "dependency_productive" in productivity_classes,
            "evidence_productive": "evidence_productive" in productivity_classes,
            "historical_productive": "historical_productive" in productivity_classes,
            "productivity_classes": list(productivity_classes),
            "time_slice_exceeded": False,
        }
        session.module_summaries.append(module_summary)
        payload = {
            "phase": phase_name,
            "status": "completed" if productive else "low_yield",
            "elapsed_s": actual_elapsed_s,
            "actual_elapsed_s": actual_elapsed_s,
            "productive": productive,
            "module_name": module_name,
            "module_status": "completed" if productive else "low_yield",
            "module_summary": module_summary,
        }
        session.phase_outcomes.append(payload)
        return payload

    def finalize_session(self, session: _WindowSession) -> ExpansionResult:
        return ExpansionResult(
            root_domain=session.scope,
            endpoint_candidates=set(session.endpoint_candidates),
            node_count=2 if session.endpoint_candidates else 1,
            edge_count=1 if session.endpoint_candidates else 0,
            ceilings_hit=False,
            diagnostics={
                "t_total_s": round(
                    sum(float(row.get("actual_elapsed_s", row.get("elapsed_s", 0.0)) or 0.0) for row in session.module_summaries),
                    3,
                ),
                "raw_candidate_count": len(session.endpoint_candidates),
                "canonical_candidate_count": len(session.endpoint_candidates),
                "timing": {
                    "a_exploration_s": 300.0,
                    "bcde_exploration_s": 300.0,
                    "a_exploitation_s": 0.0 if not session.productive_a_modules else 300.0,
                    "bcde_exploitation_s": 300.0 if session.productive_bcde_modules else 0.0,
                },
                "productive_category_a_modules": sorted(session.productive_a_modules),
                "productive_bcde_modules": sorted(session.productive_bcde_modules),
                "module_timings": {
                    "SyntheticAModule": 300.0,
                    "CommonPortScanModule": 300.0,
                },
                "phase_outcomes": list(session.phase_outcomes),
                "module_summaries": list(session.module_summaries),
            },
        )


def _observation_for(endpoint: str) -> RawObservation:
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
            status_code=200,
            response_time_ms=30.0,
            headers={"server": "cloudflare"},
        ),
        success=True,
    )


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_seed_endpoints("tenant_a", ["pay.example.com:443"])
    return storage


def _orchestrator(storage: StorageManager) -> UnifiedCycleOrchestrator:
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=2,
        max_endpoints=10,
        expansion_wrapper=_DiagnosticsExpansionWrapper(),
        enable_phase5_findings=False,
    )
    return UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    )


def test_phase5_cycle_metadata_persists_expansion_scorecard_and_runtime_trace(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)

    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(
            observations=[_observation_for(endpoint)],
            elapsed_ms=12,
        ),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    result = _orchestrator(storage).run_cycle("tenant_a")

    rows = storage.load_cycle_metadata_for_cycle("tenant_a", result.metadata.cycle_id)
    completed = [
        row for row in rows if str(row.get("status", "")).strip().lower() == "completed"
    ][0]

    build_stats = completed["build_stats"]
    expansion_summary = build_stats["expansion_summary"]
    runtime_summary = completed["runtime_summary"]

    assert expansion_summary["strategy"] == "fixed_window_round_robin_scheduler"
    assert expansion_summary["total_expanded_candidates"] == 1
    assert expansion_summary["scope_count"] >= 1
    assert any(
        row["module_name"] == "CertificateTransparencyModule"
        and row["productive_runs"] >= 1
        for row in expansion_summary["module_scorecard"]
    )
    assert any(
        row["module_name"] == "CommonPortScanModule"
        and row["produced_endpoint_count"] >= 1
        for row in expansion_summary["module_scorecard"]
    )
    assert runtime_summary["status"] == "completed"
    assert runtime_summary["within_budget"] is True
    assert runtime_summary["stage_count"] >= 3
    assert any(row["stage"] == "discovery" for row in runtime_summary["stage_history"])
    assert any(row["stage"] == "completed" for row in runtime_summary["stage_history"])
    assert runtime_summary["progress_snapshot"]["observation_target_count"] >= 1


def test_phase5_cycle_wide_phase_runtime_groups_phases_across_scopes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    wrapper = _CyclePhaseExpansionWrapper()
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=10,
        expansion_wrapper=wrapper,
        enable_phase5_findings=False,
    )

    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(
            observations=[_observation_for(endpoint)],
            elapsed_ms=12,
        ),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    result = UnifiedCycleOrchestrator(
        storage=storage,
        discovery_engine=engine,
        snapshot_builder=SnapshotBuilder(),
        temporal_engine=TemporalStateEngine(),
    ).run_cycle("tenant_a")

    rows = storage.load_cycle_metadata_for_cycle("tenant_a", result.metadata.cycle_id)
    completed = [
        row for row in rows if str(row.get("status", "")).strip().lower() == "completed"
    ][0]
    expansion_summary = completed["build_stats"]["expansion_summary"]

    assert wrapper.phase_calls == [
        ("category_a_exploration", "pay.example.com"),
        ("category_a_exploration", "example.com"),
        ("category_bcde_exploration", "pay.example.com"),
        ("category_bcde_exploration", "example.com"),
        ("category_a_exploitation", "pay.example.com"),
        ("category_a_exploitation", "example.com"),
        ("category_bcde_exploitation", "pay.example.com"),
        ("category_bcde_exploitation", "example.com"),
    ]
    assert [row["phase"] for row in expansion_summary["phase_history"]] == [
        "category_a_exploration",
        "category_bcde_exploration",
        "category_a_exploitation",
        "category_bcde_exploitation",
    ]
    assert expansion_summary["module_scorecard"][0]["module_name"] == "SyntheticModule"


def test_phase5_window_scheduler_consumes_turn_windows_before_switching_categories(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    wrapper = _WindowSchedulerExpansionWrapper()
    engine = DiscoveryEngine(
        storage=storage,
        max_workers=1,
        max_endpoints=10,
        expansion_wrapper=wrapper,
        enable_phase5_findings=False,
    )

    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(
            observations=[_observation_for(endpoint)],
            elapsed_ms=12,
        ),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    progress_rows: List[dict] = []
    results = engine.run_discovery(
        tenant_id="tenant_a",
        rate_controller=None,
        cycle_id="cycle_000001",
        progress_callback=lambda payload: progress_rows.append(dict(payload)),
        cycle_deadline_unix_ms=int(time.time() * 1000) + (1_800 * 1000),
    )

    assert len(results) >= 1
    assert len(wrapper.turn_calls) > 0
    a_turns = [row for row in wrapper.turn_calls if row[0] == "category_a_exploration"]
    bcde_turns = [row for row in wrapper.turn_calls if row[0] == "category_bcde_exploration"]
    exploitation_turns = [
        row for row in wrapper.turn_calls if row[0] in {"category_a_exploitation", "category_bcde_exploitation"}
    ]
    assert {scope for _, _, scope, _ in a_turns[:4]} == {"pay.example.com", "example.com"}
    assert {module for _, module, _, _ in a_turns[:4]} == {"SyntheticAModule", "PassiveDNSModule"}
    assert {scope for _, _, scope, _ in bcde_turns[:4]} == {"pay.example.com", "example.com"}
    assert {module for _, module, _, _ in bcde_turns[:4]} == {"CommonPortScanModule", "HTTPProbeModule"}
    assert any(
        phase == "category_bcde_exploitation" and module == "HTTPProbeModule"
        for phase, module, _, _ in exploitation_turns
    )
    assert any(
        phase == "category_bcde_exploitation" and module == "CommonPortScanModule"
        for phase, module, _, _ in exploitation_turns
    )
    assert any(row.get("expansion_window") == "category_a_window" for row in progress_rows)
    assert any(row.get("expansion_window") == "category_bcde_window" for row in progress_rows)
    assert any(row.get("expansion_window") == "productive_exploitation_window" for row in progress_rows)
    assert any(row.get("expansion_pass_type") == "initial_pass" for row in progress_rows)
    assert any(row.get("expansion_pass_type") == "follow_up_pass" for row in progress_rows)
    assert any((row.get("discovered_related_count_live") or 0) > 0 for row in progress_rows)
    assert any(
        isinstance(row.get("candidate_count_by_scope"), dict)
        and bool(row.get("candidate_count_by_scope"))
        for row in progress_rows
    )
    assert any(int(row.get("expansion_module_turn_index", 0) or 0) > 1 for row in progress_rows)
    assert any(
        float(row.get("expansion_window_actual_elapsed_seconds", 0.0) or 0.0) > 0.0
        for row in progress_rows
    )


def test_phase5_cycle_bundle_surfaces_expansion_scorecard_and_runtime_trace(
    monkeypatch,
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)

    monkeypatch.setattr(
        protocol_observer,
        "observe_endpoint_series",
        lambda endpoint, samples, **kwargs: _FakeSeries(
            observations=[_observation_for(endpoint)],
            elapsed_ms=12,
        ),
    )
    monkeypatch.setattr(ObservationBridge, "process_series", lambda self, raws: [])

    result = _orchestrator(storage).run_cycle("tenant_a")

    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    bundle = runtime.build_cycle_artifact_bundle(
        "tenant_a",
        authz_scope=scope,
        cycle_id=result.metadata.cycle_id,
    )

    completed = [
        row
        for row in bundle["cycle_metadata"]
        if str(row.get("status", "")).strip().lower() == "completed"
    ][0]
    build_stats = completed["build_stats"]
    expansion_summary = build_stats["expansion_summary"]
    runtime_summary = completed["runtime_summary"]

    assert expansion_summary["productive_category_a_modules"] == ["CertificateTransparencyModule"]
    assert expansion_summary["productive_bcde_modules"] == ["CommonPortScanModule"]
    assert isinstance(expansion_summary["scope_summaries"], list)
    assert isinstance(runtime_summary["stage_history"], list)
    assert runtime_summary["total_runtime_ms"] >= 0
    assert "progress_snapshot" in runtime_summary


def test_phase3_scan_status_surfaces_scheduler_state(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    scheduler_state_path = storage.get_tenant_path("tenant_a") / "scheduler_state.json"
    scheduler_state_path.write_text(
        json.dumps(
            {
                "last_run_unix_ms": 1_710_000_100_000,
                "next_run_unix_ms": 1_710_000_200_000,
                "last_status": "launched",
                "consecutive_failures": 2,
                "last_error": "temporary upstream failure",
            }
        ),
        encoding="utf-8",
    )

    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    payload = runtime.get_scan_status("tenant_a", authz_scope=scope)

    assert payload["status"] == "idle"
    assert payload["scheduler_last_run_unix_ms"] == 1_710_000_100_000
    assert payload["scheduler_next_run_unix_ms"] == 1_710_000_200_000
    assert payload["scheduler_last_status"] == "launched"
    assert payload["scheduler_consecutive_failures"] == 2
    assert payload["scheduler_last_error"] == "temporary upstream failure"


def test_phase5_scan_status_surfaces_live_window_scheduler_fields(tmp_path: Path) -> None:
    storage = _new_storage(tmp_path)
    tenant_path = storage.get_tenant_path("tenant_a")
    lock_path = tenant_path / ".cycle.lock"
    now_ms = int(time.time() * 1000)
    lock_path.write_text(
        json.dumps(
            {
                "tenant_id": "tenant_a",
                "status": "running",
                "cycle_id": "cycle_000001",
                "stage": "category_bcde_exploration",
                "started_at_unix_ms": now_ms - 20_000,
                "stage_started_at_unix_ms": now_ms - 10_000,
                "updated_at_unix_ms": now_ms,
                "category_a_time_budget_seconds": 300,
                "bcde_time_budget_seconds": 300,
                "exploration_budget_seconds": 600,
                "exploitation_budget_seconds": 600,
                "module_time_slice_seconds": 60,
                "cycle_time_budget_seconds": 1200,
                "cycle_deadline_unix_ms": now_ms + 600_000,
                "expansion_window": "category_bcde_window",
                "expansion_window_index": 2,
                "expansion_window_total_count": 3,
                "expansion_window_budget_seconds": 300,
                "expansion_window_actual_elapsed_seconds": 42.5,
                "expansion_window_consumed_seconds": 42.5,
                "expansion_window_remaining_seconds": 257.5,
                "expansion_pass_type": "follow_up_pass",
                "initial_pass_completed": True,
                "coverage_entries_total": 8,
                "coverage_entries_completed": 8,
                "expansion_current_scope": "www.boj.or.jp",
                "expansion_scope_index": 1,
                "expansion_scope_total_count": 2,
                "expansion_scope_seen_once_count": 2,
                "expansion_phase_scope_completed_count": 1,
                "expansion_phase_scope_total_count": 2,
                "expansion_current_module": "HTTPProbeModule",
                "expansion_module_index_within_scope": 2,
                "expansion_modules_seen_once_count": 8,
                "expansion_module_turn_index": 11,
                "expansion_module_turns_completed": 10,
                "expansion_turn_slice_seconds": 15,
                "discovered_related_count_live": 7,
                "inflight_candidate_count": 5,
                "candidate_count_by_scope": {
                    "www.boj.or.jp": 4,
                    "boj.or.jp": 1,
                },
            }
        ),
        encoding="utf-8",
    )

    runtime = EngineRuntime(storage=storage)
    scope = AuthorizedTenantScope.from_iterable("operator_a", ["tenant_a"])
    payload = runtime.get_scan_status("tenant_a", authz_scope=scope)

    assert payload["status"] == "running"
    assert payload["expansion_window"] == "category_bcde_window"
    assert payload["expansion_window_actual_elapsed_seconds"] == 42.5
    assert payload["expansion_pass_type"] == "follow_up_pass"
    assert payload["coverage_entries_total"] == 8
    assert payload["coverage_entries_completed"] == 8
    assert payload["expansion_scope_index"] == 1
    assert payload["expansion_scope_total_count"] == 2
    assert payload["expansion_scope_seen_once_count"] == 2
    assert payload["expansion_module_index_within_scope"] == 2
    assert payload["expansion_modules_seen_once_count"] == 8
    assert payload["discovered_related_count_live"] == 7
    assert payload["inflight_candidate_count"] == 5
    assert payload["candidate_count_by_scope"] == {
        "www.boj.or.jp": 4,
        "boj.or.jp": 1,
    }
