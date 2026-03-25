from __future__ import annotations

import inspect
import time
import traceback
import logging
from dataclasses import asdict, is_dataclass
from typing import Dict, Any, List, Sequence, Optional, TYPE_CHECKING



from .models import (
    CycleMetadata,
    CycleBudgetExceeded,
    CycleStatus,
    CycleResult,
)
from .snapshot_builder import SnapshotBuilder
from .temporal_state_engine import TemporalStateEngine
from .rate_controller import RateController
from .weakness_inputs import (
    extract_physics_signals as build_physics_signals,
    build_layer2_graph_slice as build_graph_slice_for_layer2,
)

from infrastructure.storage_manager.storage_manager import StorageManager
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.policy_integration.enforcement import PolicyRuntimeBridge

# Layer 0 baseline
from layers.layer0_observation.baselines.baseline_store import BaselineStore
from layers.layer0_observation.baselines.calibrator import TimingCalibrator
from layers.layer0_observation.baselines.baseline_serialization import (
    serialize_baseline_store,
    hydrate_baseline_store,
)

# Layer 1
from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph
from layers.layer1_trust_graph_dependency_modeling.dependency_builder import (
    build_trust_graph_delta,
    apply_graph_delta,
)

# Layer 2–4
from layers.layer2_risk_and_weakness_analysis.layer2_engine import Layer2Engine
from layers.layer2_risk_and_weakness_analysis.graph_slice import GraphSlice

from layers.layer3_prediction_and_learning.layer3_engine import Layer3Engine
from layers.layer4_decision_logic_guardian.guardian_core import GuardianCore
from layers.layer4_decision_logic_guardian.thresholds import GuardianThresholds

if TYPE_CHECKING:
    from simulator.core.simulation_request import SimulationRequest
    from simulator.core.simulation_response import SimulationResponse


class UnifiedCycleOrchestrator:

    SCHEMA_VERSION = "v2.6"
    POSTURE_PREDICTION_KIND_MAP = {
        "crypto_posture": "crypto_posture_risk",
        "protection_posture": "protection_posture_risk",
        "harvest_now_decrypt_later": "harvest_now_decrypt_later_risk",
    }

    def __init__(
        self,
        storage: StorageManager,
        discovery_engine: DiscoveryEngine,
        snapshot_builder: SnapshotBuilder,
        temporal_engine: TemporalStateEngine,
        layer2_mode: str = "hybrid",
        simulation_root: Optional[str] = None,
        cycle_time_budget_seconds: int = 600,
    ):
        self.storage = storage
        self.discovery_engine = discovery_engine
        self.snapshot_builder = snapshot_builder
        self.temporal_engine = temporal_engine

        self.layer2 = Layer2Engine()
        self.layer3 = Layer3Engine()
        self.guardian = GuardianCore(thresholds=GuardianThresholds())
        self.layer2_mode = str(layer2_mode or "hybrid").strip().lower()
        self._logger = logging.getLogger(__name__)
        self.simulation_root = simulation_root
        self.cycle_time_budget_seconds = max(1, int(cycle_time_budget_seconds))

    # ============================================================
    # MAIN ENTRY
    # ============================================================

    def run_cycle(
        self,
        tenant_id: str,
        *,
        cycle_id: Optional[str] = None,
        cycle_number: Optional[int] = None,
    ) -> CycleResult:

        cycle_start_time = int(time.time() * 1000)
        cycle_deadline_unix_ms = (
            cycle_start_time + (self.cycle_time_budget_seconds * 1000)
        )

        resolved_cycle_number = (
            int(cycle_number)
            if cycle_number is not None
            else self._get_next_cycle_number(tenant_id)
        )

        previous_snapshot_dict = self.storage.load_latest_snapshot(tenant_id)
        previous_snapshot_hash = None
        if previous_snapshot_dict:
            previous_snapshot_hash = previous_snapshot_dict.get(
                "snapshot_hash_sha256"
            )

        resolved_cycle_id = (
            str(cycle_id).strip()
            if cycle_id is not None
            else f"cycle_{resolved_cycle_number:06d}"
        )

        self.storage.acquire_cycle_lock(
            tenant_id=tenant_id,
            cycle_id=resolved_cycle_id,
            cycle_number=resolved_cycle_number,
        )
        stage_history: List[Dict[str, Any]] = []
        progress_channel_state: Dict[str, Any] = {
            "progress_channel_degraded": False,
            "lock_write_warning_count": 0,
            "last_lock_write_error": None,
            "last_persisted_at_unix_ms": 0,
            "last_persisted_snapshot": {},
        }
        live_progress_snapshot: Dict[str, Any] = {
            "cycle_id": resolved_cycle_id,
            "cycle_number": resolved_cycle_number,
            "started_at_unix_ms": cycle_start_time,
            "updated_at_unix_ms": cycle_start_time,
        }
        significant_progress_keys = {
            "stage",
            "expansion_window",
            "expansion_pass_type",
            "expansion_current_scope",
            "expansion_current_module",
            "discovered_related_count_live",
            "inflight_candidate_count",
            "expanded_candidate_count",
            "total_candidate_count",
            "observation_target_count",
            "observed_completed_count",
            "observed_successful_count",
            "observed_failed_count",
            "snapshot_endpoint_count",
            "new_endpoint_count",
            "removed_endpoint_count",
        }

        def _progress_channel_payload() -> Dict[str, Any]:
            return {
                "progress_channel_degraded": bool(
                    progress_channel_state["progress_channel_degraded"]
                ),
                "lock_write_warning_count": int(
                    progress_channel_state["lock_write_warning_count"]
                ),
                "last_lock_write_error": progress_channel_state["last_lock_write_error"],
            }

        def _merge_live_progress(payload: Dict[str, Any]) -> None:
            live_progress_snapshot.update(dict(payload or {}))
            live_progress_snapshot["updated_at_unix_ms"] = int(time.time() * 1000)
            if stage_history:
                live_progress_snapshot["stage_history"] = list(stage_history)
            live_progress_snapshot.update(_progress_channel_payload())

        def _record_lock_write_warning(exc: Exception) -> None:
            progress_channel_state["progress_channel_degraded"] = True
            progress_channel_state["lock_write_warning_count"] = int(
                progress_channel_state["lock_write_warning_count"]
            ) + 1
            progress_channel_state["last_lock_write_error"] = str(exc or "").strip() or type(exc).__name__
            _merge_live_progress({})
            logging.getLogger(__name__).warning(
                "cycle_lock_progress_write_failed tenant_id=%s cycle_id=%s warnings=%s error=%s",
                tenant_id,
                resolved_cycle_id,
                progress_channel_state["lock_write_warning_count"],
                progress_channel_state["last_lock_write_error"],
            )

        def _should_persist_progress(payload: Dict[str, Any], now_ms: int) -> bool:
            last_persisted_at = int(progress_channel_state["last_persisted_at_unix_ms"] or 0)
            if last_persisted_at <= 0:
                return True
            last_persisted_snapshot = progress_channel_state["last_persisted_snapshot"]
            for key in significant_progress_keys:
                if key in payload and last_persisted_snapshot.get(key) != live_progress_snapshot.get(key):
                    return True
            return (now_ms - last_persisted_at) >= 1000

        def _persist_cycle_lock(payload: Dict[str, Any], *, force: bool = False) -> None:
            if not payload:
                return
            now_ms = int(time.time() * 1000)
            _merge_live_progress(payload)
            if not force and not _should_persist_progress(payload, now_ms):
                return
            persisted_payload = dict(payload)
            persisted_payload.update(_progress_channel_payload())
            try:
                self.storage.update_cycle_lock(tenant_id, persisted_payload)
            except Exception as exc:
                _record_lock_write_warning(exc)
                return
            progress_channel_state["last_persisted_at_unix_ms"] = now_ms
            progress_channel_state["last_persisted_snapshot"] = {
                **dict(progress_channel_state["last_persisted_snapshot"] or {}),
                **persisted_payload,
            }

        def _current_progress_snapshot() -> Dict[str, Any]:
            _merge_live_progress({})
            return dict(live_progress_snapshot)

        def _set_cycle_stage(stage: str) -> None:
            normalized_stage = str(stage or "").strip() or "initializing"
            if stage_history and str(stage_history[-1].get("stage", "")).strip() == normalized_stage:
                return
            started_at_unix_ms = int(time.time() * 1000)
            stage_history.append({"stage": normalized_stage, "started_at_unix_ms": started_at_unix_ms})
            _persist_cycle_lock(
                {
                    "stage": normalized_stage,
                    "stage_started_at_unix_ms": started_at_unix_ms,
                    "stage_history": list(stage_history),
                },
                force=True,
            )

        def _set_cycle_progress(
            updates: Optional[Dict[str, Any]] = None,
            force: bool = False,
            **extra_updates: Any,
        ) -> None:
            payload: Dict[str, Any] = {}
            if isinstance(updates, dict):
                payload.update(updates)
            elif updates is not None:
                raise TypeError("cycle progress updates must be a mapping")
            payload.update(extra_updates)
            if not payload:
                return
            _persist_cycle_lock(payload, force=force)

        rate_controller = RateController()

        # Partial-result holders — populated as the cycle progresses so that
        # a budget-exceeded path can still persist whatever was discovered.
        _partial: Dict[str, Any] = {
            "raw_observations": None,
            "snapshot": None,
            "diff": None,
            "build_stats": None,
            "updated_temporal_state": None,
            "baseline_store": None,
            "reporting_metrics": None,
        }

        def _enforce_cycle_budget(stage_name: str) -> None:
            if int(time.time() * 1000) > cycle_deadline_unix_ms:
                raise CycleBudgetExceeded(f"cycle time budget exceeded during {stage_name}")

        try:
            _set_cycle_stage("initializing")
            _set_cycle_progress(
                category_a_time_budget_seconds=int(
                    self.discovery_engine.category_a_time_budget_seconds
                ),
                bcde_time_budget_seconds=int(
                    self.discovery_engine.bcde_time_budget_seconds
                ),
                exploration_budget_seconds=int(
                    self.discovery_engine.exploration_budget_seconds
                ),
                exploitation_budget_seconds=int(
                    self.discovery_engine.exploitation_budget_seconds
                ),
                module_time_slice_seconds=int(
                    self.discovery_engine.module_time_slice_seconds
                ),
                cycle_time_budget_seconds=int(self.cycle_time_budget_seconds),
                cycle_deadline_unix_ms=int(cycle_deadline_unix_ms),
            )
            policy_runtime_bridge = PolicyRuntimeBridge(
                storage_manager=self.storage,
                tenant_id=tenant_id,
            )
            policy_runtime_sync = policy_runtime_bridge.sync_runtime_policies(
                now_ts_ms=cycle_start_time,
            )
            policy_enforcement_enabled = bool(
                policy_runtime_bridge.has_active_policies()
            )

            # =====================================================
            # Cycle-scoped baseline state
            # =====================================================

            baseline_store = BaselineStore()
            calibrator = TimingCalibrator()

            persisted_baseline = self.storage.load_layer0_baseline(tenant_id)
            if persisted_baseline:
                baseline_store.hydrate(
                    hydrate_baseline_store(persisted_baseline)
                )

            # =====================================================
            # RUNNING metadata
            # =====================================================

            running_meta = CycleMetadata(
                schema_version=self.SCHEMA_VERSION,
                cycle_id=resolved_cycle_id,
                cycle_number=resolved_cycle_number,
                timestamp_unix_ms=cycle_start_time,
                duration_ms=0,
                status=CycleStatus.RUNNING,
                endpoints_scanned=0,
                new_endpoints=0,
                removed_endpoints=0,
                snapshot_hash="",
                rate_limited_events=0,
                error_messages=[],
            )

            self.storage.append_cycle_metadata(
                tenant_id,
                running_meta.__dict__,
            )

            # =====================================================
            # COLD START CHECK (fingerprint-first invariant)
            # =====================================================

            seed_endpoints: Optional[List[str]] = None

            if not self.storage.has_any_fingerprints(tenant_id):
                seed_endpoints = self.storage.load_seed_endpoints(
                    tenant_id
                )

            # =====================================================
            # DISCOVERY
            # =====================================================

            expansion_mode = "A_BCDE"
            _set_cycle_stage("discovery")
            _enforce_cycle_budget("discovery")

            # Pass the full cycle deadline to the discovery engine.
            # Expansion phases are capped by their own sub-budgets (45s each
            # for cat_a, bcde, exploitation) so they stop naturally at ~2 min.
            # The cycle_deadline_unix_ms (5 min from cycle start) acts as a
            # hard cutoff — checked after every module turn — ensuring the
            # entire discovery (expansion + observation) finishes within budget.
            raw_observations = self._run_discovery_compat(
                tenant_id=tenant_id,
                rate_controller=rate_controller,
                cycle_id=resolved_cycle_id,
                seed_endpoints=seed_endpoints,
                expansion_mode=expansion_mode,
                stage_callback=_set_cycle_stage,
                progress_callback=_set_cycle_progress,
                enable_ct_longitudinal=(resolved_cycle_number >= 2),
                cycle_deadline_unix_ms=cycle_deadline_unix_ms,
            )
            reporting_metrics = self.discovery_engine.get_last_reporting_metrics()
            _partial["raw_observations"] = raw_observations
            _partial["reporting_metrics"] = reporting_metrics
            # NOTE: Do NOT enforce cycle budget here. Discovery uses the full
            # cycle deadline for TLS observation, so the budget is almost always
            # exhausted when discovery returns. We MUST proceed to snapshot build
            # and persistence — skipping these causes the dashboard to show zeros.

            # =====================================================
            # SNAPSHOT
            # =====================================================
            _set_cycle_stage("snapshot_build")

            previous_temporal = self.storage.load_temporal_state(tenant_id)

            snapshot, diff, build_stats = self.snapshot_builder.build_snapshot(
                cycle_id=resolved_cycle_id,
                cycle_number=resolved_cycle_number,
                raw_observations=raw_observations,
                previous_snapshot=previous_snapshot_dict,
                previous_temporal_state=previous_temporal,
                reporting_metrics=reporting_metrics,
            )
            _partial["snapshot"] = snapshot
            _partial["diff"] = diff
            _partial["build_stats"] = build_stats
            _set_cycle_progress(
                snapshot_endpoint_count=int(snapshot.endpoint_count),
                new_endpoint_count=int(len(diff.new_endpoints)),
                removed_endpoint_count=int(len(diff.removed_endpoints)),
            )

            # =====================================================
            # BASELINE UPDATE (post-canonical identity)
            # =====================================================

            for endpoint in snapshot.endpoints:
                if str(getattr(endpoint, "observation_state", "observed") or "observed").lower() != "observed":
                    continue

                entity_id = endpoint.endpoint_id()

                matching_raw = next(
                    (
                        r
                        for r in raw_observations
                        if getattr(r, "endpoint", "") == entity_id
                    ),
                    None,
                )

                if not matching_raw:
                    continue

                samples = getattr(matching_raw, "packet_spacing_ms", [])
                if not samples:
                    continue

                previous = baseline_store.get(entity_id)

                updated = calibrator.update(
                    entity_id=entity_id,
                    metric_samples={"rtt_ms": samples},
                    previous=previous,
                )

                baseline_store.replace(entity_id, updated)

            # =====================================================
            # TEMPORAL STATE UPDATE
            # =====================================================
            _set_cycle_stage("temporal_update")

            updated_temporal_state = self.temporal_engine.update_state(
                current_snapshot=snapshot,
                previous_state=previous_temporal,
            )
            _partial["updated_temporal_state"] = updated_temporal_state
            _partial["baseline_store"] = baseline_store

            # =====================================================
            # TELEMETRY → GROUP FINGERPRINTS
            # =====================================================
            _set_cycle_stage("telemetry_grouping")

            telemetry_records = self.storage.load_telemetry_for_cycle(
                tenant_id=tenant_id,
                cycle_id=resolved_cycle_id,
            )

            fingerprints_by_entity: Dict[str, List[Dict[str, Any]]] = {}
            posture_signals_by_entity: Dict[str, List[Dict[str, Any]]] = {}
            posture_findings_by_entity: Dict[str, Dict[str, Any]] = {}

            for record in telemetry_records:
                entity_id = record.get("entity_id")
                fps = record.get("fingerprints", [])
                if not entity_id:
                    continue
                if fps:
                    fingerprints_by_entity.setdefault(entity_id, []).extend(fps)
                posture_signals = record.get("posture_signals", [])
                if isinstance(posture_signals, list) and posture_signals:
                    posture_signals_by_entity.setdefault(entity_id, []).extend(
                        [item for item in posture_signals if isinstance(item, dict)]
                    )
                posture_findings = record.get("posture_findings")
                if isinstance(posture_findings, dict) and posture_findings:
                    posture_findings_by_entity[entity_id] = posture_findings

            # =====================================================
            # TRUST GRAPH REPLAY (deterministic)
            # =====================================================
            _set_cycle_stage("trust_graph_replay")

            trust_graph = TrustGraph()
            previous_graph_snapshot = self.storage.load_graph_snapshot(tenant_id)
            if previous_graph_snapshot:
                trust_graph = TrustGraph.from_snapshot_dict(previous_graph_snapshot)
                trust_graph.validate_integrity()

            for entity_id, fps in fingerprints_by_entity.items():
                delta = build_trust_graph_delta(
                    fps,
                    ingestion_ts_ms=snapshot.timestamp_unix_ms,
                )
                apply_graph_delta(trust_graph, delta)

            # =====================================================
            # TRUST GRAPH SNAPSHOT (deterministic)
            # =====================================================
            trust_graph.prune_evidence(
                max_per_endpoint=trust_graph.MAX_EVIDENCE_PER_ENDPOINT
            )
            trust_graph.validate_integrity()
            graph_snapshot = trust_graph.to_snapshot_dict(
                created_at_ms=snapshot.timestamp_unix_ms,
            )
            self.storage.persist_graph_snapshot(
                tenant_id=tenant_id,
                snapshot=graph_snapshot,
                snapshot_id=str(snapshot.timestamp_unix_ms),
                cycle_id=resolved_cycle_id,
            )

            # =====================================================
            # LAYER 3 STATE SNAPSHOT LOAD (per-tenant, once)
            # =====================================================
            _set_cycle_stage("layer_evaluation")

            state_map = {}
            snapshot_doc = self.storage.load_layer3_snapshot(tenant_id)
            if isinstance(snapshot_doc, dict):
                from layers.layer3_prediction_and_learning.learning_state_v2 import LearningState
                state_map = LearningState.from_snapshot(snapshot_doc, tenant_id=tenant_id)

            # =====================================================
            # LAYER 2 → LAYER 3 → GUARDIAN
            # =====================================================

            guardian_records_buffer = []

            for endpoint in snapshot.endpoints:
                if str(getattr(endpoint, "observation_state", "observed") or "observed").lower() != "observed":
                    continue

                entity_id = endpoint.endpoint_id()
                fingerprints = fingerprints_by_entity.get(entity_id, [])
                posture_signals = posture_signals_by_entity.get(entity_id, [])
                posture_findings = posture_findings_by_entity.get(entity_id, {})

                physics_signals = self._extract_physics_signals(fingerprints)

                baseline_entity = baseline_store.get(entity_id)

                baseline_dict: Dict[str, float] = {}

                if baseline_entity and "rtt_ms" in baseline_entity.metrics:
                    stats = baseline_entity.metrics["rtt_ms"]
                    baseline_dict = {
                        "baseline_mean": float(stats.mean),
                        "baseline_mad": float(stats.mad),
                        "baseline_ewma": float(stats.ewma),
                    }

                graph_slice: GraphSlice | None = None
                if self.layer2_mode == "hybrid":
                    graph_slice = self._build_layer2_graph_slice(
                        entity_id=entity_id,
                        trust_graph=trust_graph,
                    )
                    if graph_slice is None:
                        self._logger.warning(
                            "layer2_hybrid_fallback: graph_slice_unavailable",
                            extra={"entity_id": entity_id, "cycle_id": resolved_cycle_id},
                        )

                weakness_bundle = self.layer2.evaluate(
                    entity_id=entity_id,
                    session_id=resolved_cycle_id,
                    ts_ms=snapshot.timestamp_unix_ms,
                    fingerprints=fingerprints,
                    physics_signals=physics_signals,
                    baseline=baseline_dict,
                    graph_slice=graph_slice,
                )
                weakness_bundle_dict = weakness_bundle.to_dict()
                weakness_bundle_dict["signals"] = list(
                    weakness_bundle_dict.get("signals", [])
                ) + self._build_posture_weakness_signals(
                    entity_id=entity_id,
                    session_id=resolved_cycle_id,
                    ts_ms=snapshot.timestamp_unix_ms,
                    posture_findings=posture_findings,
                    posture_signals=posture_signals,
                )

                l3_state = state_map.get(entity_id)
                prediction_bundle, updated_state = self.layer3.predict(
                    weakness_bundle=weakness_bundle_dict,
                    state=l3_state,
                    return_state=True,
                )
                state_map[entity_id] = updated_state
                prediction_bundle_dict = prediction_bundle.to_dict()
                prediction_bundle_dict["signals"] = list(
                    prediction_bundle_dict.get("signals", [])
                ) + self._build_posture_prediction_signals(
                    entity_id=entity_id,
                    session_id=resolved_cycle_id,
                    ts_ms=snapshot.timestamp_unix_ms,
                    posture_findings=posture_findings,
                    posture_signals=posture_signals,
                )

                guardian_response = self.guardian.evaluate(
                    tenant_id=tenant_id,
                    prediction_bundle=prediction_bundle_dict,
                    policy_mode="enabled" if policy_enforcement_enabled else "disabled",
                )
                policy_evaluation = None
                if policy_enforcement_enabled:
                    labels = getattr(guardian_response, "pattern_labels", None)
                    if not isinstance(labels, (list, tuple)):
                        labels = []
                    policy_evaluation = policy_runtime_bridge.evaluate_patterns(
                        pattern_labels=labels,
                    )

                alerts_raw = getattr(guardian_response, "alerts", []) or []
                alerts: List[Dict[str, Any]] = []
                for alert in alerts_raw:
                    if hasattr(alert, "to_dict"):
                        alerts.append(alert.to_dict())
                    elif is_dataclass(alert):
                        alerts.append(asdict(alert))
                    elif isinstance(alert, dict):
                        alerts.append(alert)
                    elif hasattr(alert, "__dict__"):
                        alerts.append(dict(alert.__dict__))
                    else:
                        alerts.append({"message": str(alert)})

                guardian_records_buffer.append(
                    {
                        "timestamp_ms": snapshot.timestamp_unix_ms,
                        "entity_id": entity_id,
                        "severity": float(
                            getattr(guardian_response, "overall_severity_01", 0.0)
                        ),
                        "confidence": float(
                            getattr(guardian_response, "overall_confidence_01", 0.0)
                        ),
                        "alerts": alerts,
                        "cycle_id": resolved_cycle_id,
                        "cycle_number": resolved_cycle_number,
                        "campaign_phase": getattr(guardian_response, "campaign_phase", None),
                        "sync_index": getattr(guardian_response, "sync_index", None),
                        "campaign_score_01": getattr(
                            guardian_response, "campaign_score_01", None
                        ),
                        "pattern_labels": getattr(guardian_response, "pattern_labels", None),
                        "advisory": getattr(guardian_response, "advisory", None),
                        "narrative": getattr(guardian_response, "narrative", None),
                        "policy_enforcement_mode": "enabled" if policy_enforcement_enabled else "disabled",
                        "policy_runtime_sync": dict(policy_runtime_sync),
                        "policy_evaluation": policy_evaluation,
                    }
                )

            # =====================================================
            # LAYER 3 STATE SNAPSHOT PERSIST (single write)
            # =====================================================

            from layers.layer3_prediction_and_learning.learning_state_v2 import LearningState
            snapshot_payload = LearningState.to_snapshot(state_map, tenant_id=tenant_id)
            if not self.storage.persist_layer3_snapshot(
                tenant_id,
                snapshot_payload,
                cycle_id=resolved_cycle_id,
            ):
                self._logger.error(
                    "layer3_snapshot_persist_failed",
                    extra={"cycle_id": resolved_cycle_id},
                )
                raise RuntimeError("layer3_snapshot_persist_failed")

            # =====================================================
            # LAYER 4 GUARDIAN RECORDS (after L3 snapshot)
            # =====================================================

            for record in guardian_records_buffer:
                self.storage.persist_guardian_record(tenant_id, record)

            # =====================================================
            # STRICT PERSIST ORDER (crash-safe)
            # =====================================================
            # NOTE: Never enforce the cycle budget here. Persistence MUST
            # complete regardless of elapsed time — skipping save_snapshot
            # causes the dashboard to show all zeros after a completed scan.
            _set_cycle_stage("artifact_persist")

            snapshot_payload = snapshot.to_dict()
            discovered_surface = reporting_metrics.get("discovered_surface", [])
            if isinstance(discovered_surface, list):
                snapshot_payload["discovered_surface"] = list(discovered_surface)
                snapshot_payload["discovered_surface_count"] = len(discovered_surface)
            self._logger.info(
                "[Orchestrator] Saving snapshot: tenant=%s cycle=%s endpoints=%d",
                tenant_id, resolved_cycle_id, snapshot.endpoint_count,
            )
            self.storage.save_snapshot(
                tenant_id,
                snapshot_payload,
            )
            self._logger.info(
                "[Orchestrator] Snapshot saved successfully: tenant=%s cycle=%s",
                tenant_id, resolved_cycle_id,
            )

            self.storage.save_temporal_state(
                tenant_id,
                updated_temporal_state.to_dict(),
                cycle_id=resolved_cycle_id,
            )

            serialized_baseline = serialize_baseline_store(
                baseline_store.snapshot()
            )

            self.storage.save_layer0_baseline(
                tenant_id,
                serialized_baseline,
            )

            rate_stats = rate_controller.finalize()
            duration_ms = int(time.time() * 1000) - cycle_start_time

            completed_meta = CycleMetadata(
                schema_version=self.SCHEMA_VERSION,
                cycle_id=resolved_cycle_id,
                cycle_number=resolved_cycle_number,
                timestamp_unix_ms=cycle_start_time,
                duration_ms=duration_ms,
                status=CycleStatus.COMPLETED,
                endpoints_scanned=int(build_stats.endpoints_canonical),
                new_endpoints=len(diff.new_endpoints),
                removed_endpoints=len(diff.removed_endpoints),
                snapshot_hash=snapshot.snapshot_hash_sha256,
                rate_limited_events=rate_stats.rate_limited,
                error_messages=[],
            )
            _set_cycle_stage("completed")
            cycle_end_time = int(time.time() * 1000)
            runtime_summary = self._build_runtime_summary(
                stage_history=stage_history,
                cycle_start_time=cycle_start_time,
                cycle_deadline_unix_ms=cycle_deadline_unix_ms,
                cycle_end_time=cycle_end_time,
                cycle_time_budget_seconds=self.cycle_time_budget_seconds,
                progress_snapshot=_current_progress_snapshot(),
                status="completed",
            )

            completed_meta_payload = dict(completed_meta.__dict__)
            completed_meta_payload["rate_controller_stats"] = (
                asdict(rate_stats) if is_dataclass(rate_stats) else {}
            )
            completed_meta_payload["build_stats"] = (
                asdict(build_stats) if is_dataclass(build_stats) else {}
            )
            completed_meta_payload["diff"] = (
                asdict(diff) if is_dataclass(diff) else {}
            )
            completed_meta_payload["policy_runtime_sync"] = dict(policy_runtime_sync)
            completed_meta_payload["policy_enforcement_enabled"] = bool(policy_enforcement_enabled)
            completed_meta_payload["runtime_summary"] = runtime_summary
            completed_meta_payload["progress_channel_degraded"] = bool(
                progress_channel_state["progress_channel_degraded"]
            )
            completed_meta_payload["lock_write_warning_count"] = int(
                progress_channel_state["lock_write_warning_count"]
            )
            if progress_channel_state["last_lock_write_error"]:
                completed_meta_payload["last_lock_write_error"] = str(
                    progress_channel_state["last_lock_write_error"]
                )

            self.storage.append_cycle_metadata(
                tenant_id,
                completed_meta_payload,
            )

            return CycleResult(
                metadata=completed_meta,
                snapshot=snapshot,
                previous_snapshot_hash=previous_snapshot_hash,
                diff=diff,
                rate_controller_stats=rate_stats,
                build_stats=build_stats,
            )

        except CycleBudgetExceeded:
            # Budget exhausted — save whatever partial results exist so
            # discovered endpoints are not lost, then complete gracefully.
            duration_ms = int(time.time() * 1000) - cycle_start_time
            cycle_end_time = int(time.time() * 1000)
            rate_stats = rate_controller.finalize()

            p_snapshot = _partial.get("snapshot")
            p_diff = _partial.get("diff")
            p_build_stats = _partial.get("build_stats")
            p_temporal = _partial.get("updated_temporal_state")
            p_baseline = _partial.get("baseline_store")
            p_raw = _partial.get("raw_observations")
            p_reporting = _partial.get("reporting_metrics")

            # If budget fired mid-discovery (before _partial was set), retrieve
            # whatever the engine accumulated before the exception.
            if p_raw is None:
                try:
                    p_raw = self.discovery_engine.get_last_raw_results()
                    p_reporting = self.discovery_engine.get_last_reporting_metrics()
                except Exception:
                    pass

            if p_snapshot is None and p_raw is not None:
                # Discovery completed but snapshot not yet built — build it now.
                try:
                    previous_temporal = self.storage.load_temporal_state(tenant_id)
                    p_snapshot, p_diff, p_build_stats = self.snapshot_builder.build_snapshot(
                        cycle_id=resolved_cycle_id,
                        cycle_number=resolved_cycle_number,
                        raw_observations=p_raw,
                        previous_snapshot=previous_snapshot_dict,
                        previous_temporal_state=previous_temporal,
                        reporting_metrics=p_reporting or {},
                    )
                    if p_temporal is None:
                        p_temporal = self.temporal_engine.update_state(
                            current_snapshot=p_snapshot,
                            previous_state=previous_temporal,
                        )
                except Exception:
                    pass

            if p_snapshot is None:
                # Nothing discovered at all — treat as a real failure.
                duration_ms = int(time.time() * 1000) - cycle_start_time
                cycle_end_time = int(time.time() * 1000)
                failure_class = "scan"
                failed_meta = CycleMetadata(
                    schema_version=self.SCHEMA_VERSION,
                    cycle_id=resolved_cycle_id,
                    cycle_number=resolved_cycle_number,
                    timestamp_unix_ms=cycle_start_time,
                    duration_ms=duration_ms,
                    status=CycleStatus.FAILED,
                    endpoints_scanned=0,
                    new_endpoints=0,
                    removed_endpoints=0,
                    snapshot_hash="",
                    rate_limited_events=rate_stats.rate_limited,
                    error_messages=["budget_exhausted_before_discovery"],
                )
                _set_cycle_stage("failed")
                failed_meta_payload = dict(failed_meta.__dict__)
                failed_meta_payload["failure_class"] = failure_class
                failed_meta_payload["runtime_summary"] = self._build_runtime_summary(
                    stage_history=stage_history,
                    cycle_start_time=cycle_start_time,
                    cycle_deadline_unix_ms=cycle_deadline_unix_ms,
                    cycle_end_time=cycle_end_time,
                    cycle_time_budget_seconds=self.cycle_time_budget_seconds,
                    progress_snapshot=_current_progress_snapshot(),
                    status="failed",
                )
                failed_meta_payload["progress_channel_degraded"] = bool(
                    progress_channel_state["progress_channel_degraded"]
                )
                failed_meta_payload["lock_write_warning_count"] = int(
                    progress_channel_state["lock_write_warning_count"]
                )
                self.storage.append_cycle_metadata(tenant_id, failed_meta_payload)
                raise RuntimeError("cycle time budget exhausted before discovery completed")

            # Persist partial snapshot so endpoints are not lost.
            try:
                snap_payload = p_snapshot.to_dict()
                if p_reporting and isinstance(p_reporting.get("discovered_surface"), list):
                    snap_payload["discovered_surface"] = list(p_reporting["discovered_surface"])
                    snap_payload["discovered_surface_count"] = len(p_reporting["discovered_surface"])
                self.storage.save_snapshot(tenant_id, snap_payload)
                self._logger.info(
                    "[Orchestrator] Partial snapshot saved: cycle=%s endpoints=%d",
                    resolved_cycle_id,
                    p_snapshot.endpoint_count,
                )
            except Exception as _save_exc:
                self._logger.error(
                    "[Orchestrator] Failed to save partial snapshot for cycle=%s: %s",
                    resolved_cycle_id,
                    _save_exc,
                )
            try:
                if p_temporal is not None:
                    self.storage.save_temporal_state(
                        tenant_id, p_temporal.to_dict(), cycle_id=resolved_cycle_id
                    )
            except Exception as _te:
                self._logger.warning("[Orchestrator] Failed to save temporal state: %s", _te)
            try:
                if p_baseline is not None:
                    self.storage.save_layer0_baseline(
                        tenant_id, serialize_baseline_store(p_baseline.snapshot())
                    )
            except Exception:
                pass

            endpoints_scanned = int(p_build_stats.endpoints_canonical) if p_build_stats else 0
            new_ep = len(p_diff.new_endpoints) if p_diff else 0
            removed_ep = len(p_diff.removed_endpoints) if p_diff else 0
            snap_hash = p_snapshot.snapshot_hash_sha256 if p_snapshot else ""

            _set_cycle_stage("completed")
            completed_meta = CycleMetadata(
                schema_version=self.SCHEMA_VERSION,
                cycle_id=resolved_cycle_id,
                cycle_number=resolved_cycle_number,
                timestamp_unix_ms=cycle_start_time,
                duration_ms=duration_ms,
                status=CycleStatus.COMPLETED,
                endpoints_scanned=endpoints_scanned,
                new_endpoints=new_ep,
                removed_endpoints=removed_ep,
                snapshot_hash=snap_hash,
                rate_limited_events=rate_stats.rate_limited,
                error_messages=["budget_exhausted"],
            )
            runtime_summary = self._build_runtime_summary(
                stage_history=stage_history,
                cycle_start_time=cycle_start_time,
                cycle_deadline_unix_ms=cycle_deadline_unix_ms,
                cycle_end_time=cycle_end_time,
                cycle_time_budget_seconds=self.cycle_time_budget_seconds,
                progress_snapshot=_current_progress_snapshot(),
                status="completed",
            )
            completed_meta_payload = dict(completed_meta.__dict__)
            completed_meta_payload["budget_exhausted"] = True
            completed_meta_payload["rate_controller_stats"] = (
                asdict(rate_stats) if is_dataclass(rate_stats) else {}
            )
            completed_meta_payload["runtime_summary"] = runtime_summary
            completed_meta_payload["progress_channel_degraded"] = bool(
                progress_channel_state["progress_channel_degraded"]
            )
            completed_meta_payload["lock_write_warning_count"] = int(
                progress_channel_state["lock_write_warning_count"]
            )
            self.storage.append_cycle_metadata(tenant_id, completed_meta_payload)

            return CycleResult(
                metadata=completed_meta,
                snapshot=p_snapshot,
                previous_snapshot_hash=previous_snapshot_hash,
                diff=p_diff,
                rate_controller_stats=rate_stats,
                build_stats=p_build_stats,
            )

        except Exception as e:
            _set_cycle_stage("failed")

            duration_ms = int(time.time() * 1000) - cycle_start_time
            cycle_end_time = int(time.time() * 1000)
            failure_class = self._classify_cycle_failure(str(e))

            failed_meta = CycleMetadata(
                schema_version=self.SCHEMA_VERSION,
                cycle_id=resolved_cycle_id,
                cycle_number=resolved_cycle_number,
                timestamp_unix_ms=cycle_start_time,
                duration_ms=duration_ms,
                status=CycleStatus.FAILED,
                endpoints_scanned=0,
                new_endpoints=0,
                removed_endpoints=0,
                snapshot_hash="",
                rate_limited_events=0,
                error_messages=[str(e), traceback.format_exc()],
            )
            failed_meta_payload = dict(failed_meta.__dict__)
            failed_meta_payload["failure_class"] = failure_class
            failed_meta_payload["runtime_summary"] = self._build_runtime_summary(
                stage_history=stage_history,
                cycle_start_time=cycle_start_time,
                cycle_deadline_unix_ms=cycle_deadline_unix_ms,
                cycle_end_time=cycle_end_time,
                cycle_time_budget_seconds=self.cycle_time_budget_seconds,
                progress_snapshot=_current_progress_snapshot(),
                status="failed",
            )
            failed_meta_payload["runtime_summary"]["failure_class"] = failure_class
            failed_meta_payload["progress_channel_degraded"] = bool(
                progress_channel_state["progress_channel_degraded"]
            )
            failed_meta_payload["lock_write_warning_count"] = int(
                progress_channel_state["lock_write_warning_count"]
            )
            if progress_channel_state["last_lock_write_error"]:
                failed_meta_payload["last_lock_write_error"] = str(
                    progress_channel_state["last_lock_write_error"]
                )

            self.storage.append_cycle_metadata(
                tenant_id,
                failed_meta_payload,
            )

            raise

        finally:
            self.storage.release_cycle_lock(tenant_id)

    # ============================================================
    # SIMULATION ENTRYPOINT (manual only)
    # ============================================================

    def run_simulation(self, request: "SimulationRequest") -> "SimulationResponse":
        if not self.simulation_root or not str(self.simulation_root).strip():
            raise RuntimeError("simulation_root not configured")

        from simulator.core.simulation_service import SimulationService

        service = SimulationService(
            production_root=str(self.storage.base_path),
            simulation_root=str(self.simulation_root),
        )
        return service.run(request)

    # ============================================================
    # PHYSICS EXTRACTION
    # ============================================================

    def _get_next_cycle_number(self, tenant_id: str) -> int:
        records = self.storage.load_cycle_metadata(tenant_id)
        if not records:
            # If snapshots exist but metadata is missing, treat as corruption.
            if self.storage.load_latest_snapshot(tenant_id) is not None:
                raise RuntimeError("cycle_metadata missing for existing snapshots")
            return 1
        highest_cycle_number = 0
        for record in records:
            try:
                highest_cycle_number = max(
                    highest_cycle_number,
                    int(record.get("cycle_number", 0) or 0),
                )
            except Exception:
                continue
        return highest_cycle_number + 1 if highest_cycle_number > 0 else 1

    def _extract_physics_signals(
        self,
        fps: Sequence[Dict[str, Any]],
    ) -> Dict[str, float]:
        return build_physics_signals(fps)

    def _run_discovery_compat(
        self,
        **kwargs: Any,
    ) -> List[object]:
        run_discovery = self.discovery_engine.run_discovery
        try:
            signature = inspect.signature(run_discovery)
        except (TypeError, ValueError):
            return run_discovery(**kwargs)

        if any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            return run_discovery(**kwargs)

        supported = {
            name: value
            for name, value in kwargs.items()
            if name in signature.parameters
        }
        return run_discovery(**supported)

    @staticmethod
    def _extract_runtime_progress_snapshot(
        progress_snapshot: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not isinstance(progress_snapshot, dict):
            return {}
        keys = (
            "seed_endpoint_count",
            "root_scope_count",
            "planned_scope_count",
            "expansion_scope_processed_count",
            "expanded_candidate_count",
            "total_candidate_count",
            "observation_target_count",
            "observation_cap_hit",
            "observed_completed_count",
            "observed_successful_count",
            "observed_failed_count",
            "snapshot_endpoint_count",
            "new_endpoint_count",
            "removed_endpoint_count",
            "expansion_active_category",
            "expansion_current_module",
            "expansion_modules_completed_count",
            "expansion_module_total_count",
            "expansion_node_count",
            "expansion_edge_count",
            "expansion_graph_endpoint_count",
            "expansion_phase",
            "expansion_current_scope",
            "expansion_phase_scope_completed_count",
            "expansion_phase_scope_total_count",
            "expansion_phase_history",
            "stage_history",
            "progress_channel_degraded",
            "lock_write_warning_count",
            "last_lock_write_error",
        )
        return {
            key: progress_snapshot.get(key)
            for key in keys
            if progress_snapshot.get(key) is not None
        }

    @classmethod
    def _build_runtime_summary(
        cls,
        *,
        stage_history: Sequence[Dict[str, Any]],
        cycle_start_time: int,
        cycle_deadline_unix_ms: int,
        cycle_end_time: int,
        cycle_time_budget_seconds: int,
        progress_snapshot: Optional[Dict[str, Any]],
        status: str,
    ) -> Dict[str, Any]:
        history_rows: List[Dict[str, Any]] = []
        normalized_history = [
            row
            for row in stage_history
            if isinstance(row, dict) and str(row.get("stage", "")).strip()
        ]
        for index, row in enumerate(normalized_history):
            started_at = int(row.get("started_at_unix_ms", cycle_start_time) or cycle_start_time)
            if started_at < cycle_start_time:
                started_at = cycle_start_time
            next_started_at = cycle_end_time
            if index + 1 < len(normalized_history):
                next_started_at = int(
                    normalized_history[index + 1].get("started_at_unix_ms", cycle_end_time)
                    or cycle_end_time
                )
            ended_at = max(started_at, min(next_started_at, cycle_end_time))
            history_rows.append(
                {
                    "index": index + 1,
                    "stage": str(row.get("stage", "")).strip(),
                    "started_at_unix_ms": started_at,
                    "ended_at_unix_ms": ended_at,
                    "duration_ms": max(0, ended_at - started_at),
                }
            )

        return {
            "status": str(status or "").strip() or "unknown",
            "cycle_started_at_unix_ms": int(cycle_start_time),
            "cycle_finished_at_unix_ms": int(cycle_end_time),
            "cycle_deadline_unix_ms": int(cycle_deadline_unix_ms),
            "cycle_time_budget_seconds": int(cycle_time_budget_seconds),
            "within_budget": int(cycle_end_time) <= int(cycle_deadline_unix_ms),
            "total_runtime_ms": max(0, int(cycle_end_time) - int(cycle_start_time)),
            "stage_count": len(history_rows),
            "stage_history": history_rows,
            "progress_snapshot": cls._extract_runtime_progress_snapshot(progress_snapshot),
        }

    @staticmethod
    def _classify_cycle_failure(error_message: str) -> str:
        text = str(error_message or "").strip().lower()
        if (
            ".cycle.lock" in text
            or "permissionerror" in text
            or "access is denied" in text
            or "winerror 5" in text
            or "winerror 32" in text
            or "stale cycle lock removal failed" in text
        ):
            return "infrastructure"
        return "scan"

    @staticmethod
    def _clamp01(value: Any) -> float:
        try:
            numeric = float(value)
        except Exception:
            return 0.0
        if numeric < 0.0:
            return 0.0
        if numeric > 1.0:
            return 1.0
        return float(numeric)

    @classmethod
    def _severity_to_score(cls, severity: Any) -> float:
        token = str(severity or "").strip().lower()
        mapping = {
            "critical": 1.0,
            "high": 0.85,
            "medium": 0.65,
            "low": 0.40,
            "info": 0.25,
        }
        return float(mapping.get(token, 0.0))

    def _build_posture_weakness_signals(
        self,
        *,
        entity_id: str,
        session_id: str,
        ts_ms: int,
        posture_findings: Dict[str, Any],
        posture_signals: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        findings = dict(posture_findings or {})
        scores = findings.get("scores", {}) if isinstance(findings, dict) else {}
        tls_findings = findings.get("tls_findings", []) if isinstance(findings, dict) else []
        waf_findings = findings.get("waf_findings", []) if isinstance(findings, dict) else []
        tls_findings = [item for item in tls_findings if isinstance(item, dict)]
        waf_findings = [item for item in waf_findings if isinstance(item, dict)]

        # Use sentinel -1 to distinguish "no score available" from a real score of 0.
        raw_crypto = scores.get("cryptographic_health_score")
        raw_protection = scores.get("protection_posture_score")
        crypto_observed = raw_crypto is not None and raw_crypto != 0
        protection_observed = raw_protection is not None and raw_protection != 0

        crypto_health_score = max(0.0, min(100.0, float(raw_crypto or 0)))
        protection_posture_score = max(0.0, min(100.0, float(raw_protection or 0)))
        # Only compute risk from score when we have actual observed data; otherwise
        # rely solely on explicit findings to avoid false CRITICAL alerts.
        crypto_risk = (1.0 - crypto_health_score / 100.0) if crypto_observed else 0.0
        protection_risk = (1.0 - protection_posture_score / 100.0) if protection_observed else 0.0

        max_tls_finding_score = max(
            (self._severity_to_score(item.get("severity")) for item in tls_findings),
            default=0.0,
        )
        max_waf_finding_score = max(
            (self._severity_to_score(item.get("severity")) for item in waf_findings),
            default=0.0,
        )
        posture_signal_count = len([item for item in posture_signals if isinstance(item, dict)])

        signals: List[Dict[str, Any]] = []
        crypto_severity = self._clamp01(max(crypto_risk, max_tls_finding_score))
        # Only emit crypto signal when there is actual evidence (findings or a real observed score).
        if crypto_severity >= 0.20 and (tls_findings or crypto_observed):
            signals.append(
                {
                    "entity_id": entity_id,
                    "session_id": session_id,
                    "ts_ms": int(ts_ms),
                    "weakness_id": "crypto_posture_v1",
                    "weakness_kind": "crypto_posture",
                    "severity_01": crypto_severity,
                    "confidence_01": self._clamp01(0.50 + (0.10 * min(len(tls_findings), 4))),
                    "evidence_refs": [],
                    "metrics": {
                        "cryptographic_health_score": crypto_health_score / 100.0,
                        "cryptographic_risk_score": crypto_risk,
                        "tls_finding_count": float(len(tls_findings)),
                    },
                }
            )

        protection_severity = self._clamp01(max(protection_risk, max_waf_finding_score))
        # Only emit protection signal when there is actual evidence.
        if protection_severity >= 0.20 and (waf_findings or protection_observed):
            signals.append(
                {
                    "entity_id": entity_id,
                    "session_id": session_id,
                    "ts_ms": int(ts_ms),
                    "weakness_id": "protection_posture_v1",
                    "weakness_kind": "protection_posture",
                    "severity_01": protection_severity,
                    "confidence_01": self._clamp01(0.45 + (0.10 * min(len(waf_findings), 4))),
                    "evidence_refs": [],
                    "metrics": {
                        "protection_posture_score": protection_posture_score / 100.0,
                        "protection_risk_score": protection_risk,
                        "waf_finding_count": float(len(waf_findings)),
                        "posture_signal_count": float(posture_signal_count),
                    },
                }
            )

        if bool(scores.get("hndl_risk_flag", False)):
            signals.append(
                {
                    "entity_id": entity_id,
                    "session_id": session_id,
                    "ts_ms": int(ts_ms),
                    "weakness_id": "hndl_posture_v1",
                    "weakness_kind": "harvest_now_decrypt_later",
                    "severity_01": 0.85,
                    "confidence_01": 0.80,
                    "evidence_refs": [],
                    "metrics": {
                        "hndl_risk_flag": 1.0,
                        "tls_finding_count": float(len(tls_findings)),
                    },
                }
            )

        return signals

    def _build_posture_prediction_signals(
        self,
        *,
        entity_id: str,
        session_id: str,
        ts_ms: int,
        posture_findings: Dict[str, Any],
        posture_signals: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        weaknesses = self._build_posture_weakness_signals(
            entity_id=entity_id,
            session_id=session_id,
            ts_ms=ts_ms,
            posture_findings=posture_findings,
            posture_signals=posture_signals,
        )
        predictions: List[Dict[str, Any]] = []
        for weakness in weaknesses:
            metrics = dict(weakness.get("metrics", {}))
            weakness_kind = str(weakness.get("weakness_kind", "posture")).strip().lower()
            predictions.append(
                {
                    "entity_id": entity_id,
                    "session_id": session_id,
                    "ts_ms": int(ts_ms),
                    "prediction_kind": self.POSTURE_PREDICTION_KIND_MAP.get(
                        weakness_kind,
                        "trajectory_deterioration_risk",
                    ),
                    "severity_01": self._clamp01(weakness.get("severity_01", 0.0)),
                    "confidence_01": self._clamp01(
                        float(weakness.get("confidence_01", 0.0) or 0.0)
                    ),
                    "horizon_days": 7,
                    "metrics": metrics,
                    "evidence_refs": [],
                }
            )
        return predictions

    # ============================================================
    # LAYER 2 GRAPH SLICE (1-HOP, EVIDENCE-ONLY)
    # ============================================================

    def _build_layer2_graph_slice(
        self,
        *,
        entity_id: str,
        trust_graph: TrustGraph,
    ) -> GraphSlice | None:
        return build_graph_slice_for_layer2(entity_id=entity_id, trust_graph=trust_graph)
