from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from infrastructure.aggregation.artifact_migration import ArtifactMigrationEngine
from infrastructure.storage_manager.storage_manager import StorageManager


@dataclass(frozen=True)
class CycleArtifactBundle:
    tenant_id: str
    cycle_id: Optional[str]
    snapshot: Optional[Dict[str, Any]]
    cycle_metadata: List[Dict[str, Any]]
    telemetry: List[Dict[str, Any]]
    temporal_state: Optional[Dict[str, Any]]
    trust_graph_snapshot: Optional[Dict[str, Any]]
    layer3_state_snapshot: Optional[Dict[str, Any]]
    guardian_records: List[Dict[str, Any]]
    integrity_summary: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "cycle_id": self.cycle_id,
            "snapshot": self.snapshot,
            "cycle_metadata": list(self.cycle_metadata),
            "telemetry": list(self.telemetry),
            "temporal_state": self.temporal_state,
            "trust_graph_snapshot": self.trust_graph_snapshot,
            "layer3_state_snapshot": self.layer3_state_snapshot,
            "guardian_records": list(self.guardian_records),
            "integrity_summary": self.integrity_summary,
        }


class CycleBundleBuilder:
    """
    Read-only builder for cycle deep-dive artifact bundles.

    This builder exposes existing backend artifacts verbatim with stable keys.
    """

    def __init__(
        self,
        storage: StorageManager,
        *,
        migration_engine: Optional[ArtifactMigrationEngine] = None,
    ):
        self._storage = storage
        self._migrator = migration_engine or ArtifactMigrationEngine()

    def build_cycle_artifact_bundle(
        self,
        tenant_id: str,
        *,
        cycle_id: Optional[str] = None,
        telemetry_record_type: str = "all",
        telemetry_page: int = 1,
        telemetry_page_size: int = 500,
    ) -> CycleArtifactBundle:
        tid = str(tenant_id or "").strip()
        resolved_cycle_id = self._resolve_cycle_id(tid, cycle_id)

        if resolved_cycle_id is None:
            # Stable empty/partial-cycle contract.
            return CycleArtifactBundle(
                tenant_id=tid,
                cycle_id=None,
                snapshot=None,
                cycle_metadata=[],
                telemetry=[],
                temporal_state=None,
                trust_graph_snapshot=None,
                layer3_state_snapshot=None,
                guardian_records=[],
                integrity_summary=None,
            )

        snapshot = self._migrator.migrate_snapshot(
            self._storage.load_snapshot_for_cycle(tid, resolved_cycle_id)
        )
        cycle_metadata = self._migrator.migrate_cycle_metadata_rows(
            self._storage.load_cycle_metadata_for_cycle(tid, resolved_cycle_id)
        )
        telemetry = self._paginate_telemetry(
            tid,
            resolved_cycle_id,
            record_type=telemetry_record_type,
            page=telemetry_page,
            page_size=telemetry_page_size,
        )
        all_telemetry_rows = self._migrator.migrate_telemetry_rows(
            self._storage.load_telemetry_for_cycle(tid, resolved_cycle_id)
        )
        guardian_records = self._migrator.migrate_guardian_records(
            self._storage.load_guardian_records_for_cycle(
                tid,
                resolved_cycle_id,
                limit=50_000,
            )
        )

        latest_snapshot = self._storage.load_latest_snapshot(tid)
        latest_cycle = str((latest_snapshot or {}).get("cycle_id", "")).strip()
        include_latest_state = latest_cycle == resolved_cycle_id

        temporal_state_raw, used_latest_temporal_state = self._load_cycle_state_artifact(
            cycle_loader=self._storage.load_temporal_state_for_cycle,
            latest_loader=self._storage.load_temporal_state,
            tenant_id=tid,
            cycle_id=resolved_cycle_id,
            allow_latest_fallback=include_latest_state,
        )
        temporal_state = self._migrator.migrate_temporal_state(temporal_state_raw)

        trust_graph_raw, used_latest_trust_graph = self._load_cycle_state_artifact(
            cycle_loader=self._storage.load_graph_snapshot_for_cycle,
            latest_loader=self._storage.load_graph_snapshot,
            tenant_id=tid,
            cycle_id=resolved_cycle_id,
            allow_latest_fallback=include_latest_state,
        )
        trust_graph = self._migrator.migrate_trust_graph_snapshot(trust_graph_raw)

        layer3_state_raw, used_latest_layer3_state = self._load_cycle_state_artifact(
            cycle_loader=self._storage.load_layer3_snapshot_for_cycle,
            latest_loader=self._storage.load_layer3_snapshot,
            tenant_id=tid,
            cycle_id=resolved_cycle_id,
            allow_latest_fallback=include_latest_state,
        )
        layer3_state = self._migrator.migrate_layer3_snapshot(layer3_state_raw)
        integrity_summary = self._build_integrity_summary(
            tenant_id=tid,
            cycle_id=resolved_cycle_id,
            snapshot=snapshot,
            cycle_metadata=cycle_metadata,
            telemetry_preview=telemetry,
            telemetry_all_rows=all_telemetry_rows,
            guardian_records=guardian_records,
            temporal_state=temporal_state,
            trust_graph=trust_graph,
            layer3_state=layer3_state,
            latest_cycle_id=latest_cycle,
            used_latest_temporal_state=used_latest_temporal_state,
            used_latest_trust_graph=used_latest_trust_graph,
            used_latest_layer3_state=used_latest_layer3_state,
        )

        return CycleArtifactBundle(
            tenant_id=tid,
            cycle_id=resolved_cycle_id,
            snapshot=snapshot,
            cycle_metadata=cycle_metadata,
            telemetry=telemetry,
            temporal_state=temporal_state,
            trust_graph_snapshot=trust_graph,
            layer3_state_snapshot=layer3_state,
            guardian_records=guardian_records,
            integrity_summary=integrity_summary,
        )

    def _build_integrity_summary(
        self,
        *,
        tenant_id: str,
        cycle_id: str,
        snapshot: Optional[Dict[str, Any]],
        cycle_metadata: List[Dict[str, Any]],
        telemetry_preview: List[Dict[str, Any]],
        telemetry_all_rows: List[Dict[str, Any]],
        guardian_records: List[Dict[str, Any]],
        temporal_state: Optional[Dict[str, Any]],
        trust_graph: Optional[Dict[str, Any]],
        layer3_state: Optional[Dict[str, Any]],
        latest_cycle_id: str,
        used_latest_temporal_state: bool,
        used_latest_trust_graph: bool,
        used_latest_layer3_state: bool,
    ) -> Dict[str, Any]:
        terminal_metadata = self._terminal_cycle_metadata(cycle_metadata)
        build_stats = terminal_metadata.get("build_stats", {}) if isinstance(terminal_metadata, dict) else {}
        snapshot_endpoints = snapshot.get("endpoints", []) if isinstance(snapshot, dict) else []
        discovered_surface = snapshot.get("discovered_surface", []) if isinstance(snapshot, dict) else []
        snapshot_entity_ids = {
            f"{str(row.get('hostname', '')).strip()}:{int(row.get('port', 0) or 0)}"
            for row in snapshot_endpoints
            if isinstance(row, dict) and str(row.get("hostname", "")).strip() and int(row.get("port", 0) or 0) > 0
        }
        discovered_surface_entity_ids = {
            str(row.get("entity_id", "")).strip()
            for row in discovered_surface
            if isinstance(row, dict) and str(row.get("entity_id", "")).strip()
        }
        visible_surface_entity_ids = snapshot_entity_ids | discovered_surface_entity_ids
        telemetry_entity_ids = {
            str(row.get("entity_id", "")).strip()
            for row in telemetry_all_rows
            if isinstance(row, dict) and str(row.get("entity_id", "")).strip()
        }
        guardian_entity_ids = {
            str(row.get("entity_id", "")).strip()
            for row in guardian_records
            if isinstance(row, dict) and str(row.get("entity_id", "")).strip()
        }
        guardian_nonzero_count = sum(
            1
            for row in guardian_records
            if isinstance(row, dict)
            and (
                float(row.get("overall_severity_01", row.get("severity", 0.0)) or 0.0) > 0.0
                or len(row.get("alerts", []) if isinstance(row.get("alerts"), list) else []) > 0
            )
        )
        temporal_entries = (
            temporal_state.get("endpoints", {})
            if isinstance(temporal_state, dict) and isinstance(temporal_state.get("endpoints"), dict)
            else {}
        )
        graph_nodes = trust_graph.get("nodes", []) if isinstance(trust_graph, dict) and isinstance(trust_graph.get("nodes"), list) else []
        graph_edges = trust_graph.get("edges", []) if isinstance(trust_graph, dict) and isinstance(trust_graph.get("edges"), list) else []
        layer3_entities = layer3_state.get("entities", {}) if isinstance(layer3_state, dict) and isinstance(layer3_state.get("entities"), dict) else {}

        exact_replayable = (
            isinstance(snapshot, dict)
            and len(cycle_metadata) > 0
            and not used_latest_temporal_state
            and not used_latest_trust_graph
            and not used_latest_layer3_state
            and temporal_state is not None
            and trust_graph is not None
            and layer3_state is not None
        )
        served_view_complete = (
            isinstance(snapshot, dict)
            and len(cycle_metadata) > 0
            and temporal_state is not None
            and trust_graph is not None
            and layer3_state is not None
        )

        telemetry_entities_not_in_snapshot = sorted(telemetry_entity_ids - visible_surface_entity_ids)
        guardian_entities_not_in_snapshot = sorted(guardian_entity_ids - visible_surface_entity_ids)
        missing_artifacts = [
            name
            for name, present in (
                ("snapshot", isinstance(snapshot, dict)),
                ("cycle_metadata", len(cycle_metadata) > 0),
                ("temporal_state", temporal_state is not None),
                ("trust_graph_snapshot", trust_graph is not None),
                ("layer3_state_snapshot", layer3_state is not None),
            )
            if not present
        ]
        warnings: List[str] = []
        if used_latest_temporal_state or used_latest_trust_graph or used_latest_layer3_state:
            warnings.append("served bundle used latest-state fallback for at least one per-cycle artifact")
        if len(guardian_entities_not_in_snapshot) > 0:
            warnings.append("guardian records reference entities not present in the served snapshot")
        if len(telemetry_entities_not_in_snapshot) > 0:
            warnings.append("telemetry contains entities outside the canonical snapshot surface")
        if len(guardian_records) > 0 and guardian_nonzero_count == 0:
            warnings.append("guardian records are present but all served outputs are zero/flat")

        metadata_endpoint_count = int(
            terminal_metadata.get("endpoints_scanned", build_stats.get("endpoints_canonical", 0))
            if isinstance(terminal_metadata, dict)
            else 0
        )
        snapshot_endpoint_count = len(snapshot_endpoints)
        snapshot_vs_metadata_match = snapshot_endpoint_count == metadata_endpoint_count

        return {
            "tenant_id": tenant_id,
            "cycle_id": cycle_id,
            "latest_cycle_match": str(latest_cycle_id or "").strip() == str(cycle_id or "").strip(),
            "exact_cycle_replayable": bool(exact_replayable),
            "served_view_complete": bool(served_view_complete),
            "missing_artifacts": missing_artifacts,
            "warnings": warnings,
            "fallbacks_used": {
                "temporal_state_latest": bool(used_latest_temporal_state),
                "trust_graph_latest": bool(used_latest_trust_graph),
                "layer3_state_latest": bool(used_latest_layer3_state),
            },
            "produced_counts": {
                "discovered_candidates": int(build_stats.get("total_discovered_domains", 0) or 0),
                "discovered_surface": int(build_stats.get("discovered_related_endpoints", len(discovered_surface_entity_ids)) or 0),
                "total_observations": int(build_stats.get("total_observations", 0) or 0),
                "successful_observations": int(build_stats.get("successful_observations", 0) or 0),
                "failed_observations": int(build_stats.get("failed_observations", 0) or 0),
                "canonical_endpoints": int(build_stats.get("endpoints_canonical", snapshot_endpoint_count) or 0),
            },
            "persisted_counts": {
                "cycle_metadata_rows": len(cycle_metadata),
                "snapshot_endpoints": snapshot_endpoint_count,
                "discovered_surface": len(discovered_surface_entity_ids),
                "telemetry_records": len(telemetry_all_rows),
                "guardian_records": len(guardian_records),
                "temporal_entries": len(temporal_entries),
                "graph_nodes": len(graph_nodes),
                "graph_edges": len(graph_edges),
                "layer3_entities": len(layer3_entities),
            },
            "served_counts": {
                "snapshot_endpoints": snapshot_endpoint_count,
                "discovered_surface": len(discovered_surface_entity_ids),
                "telemetry_records_preview": len(telemetry_preview),
                "guardian_records": len(guardian_records),
                "temporal_entries": len(temporal_entries),
                "graph_nodes": len(graph_nodes),
                "graph_edges": len(graph_edges),
                "layer3_entities": len(layer3_entities),
            },
            "coverage": {
                "snapshot_vs_metadata_endpoint_count_match": bool(snapshot_vs_metadata_match),
                "telemetry_entities_not_in_snapshot_count": len(telemetry_entities_not_in_snapshot),
                "guardian_entities_not_in_snapshot_count": len(guardian_entities_not_in_snapshot),
                "guardian_nonzero_record_count": int(guardian_nonzero_count),
                "guardian_nonzero_rate_01": (
                    round(guardian_nonzero_count / len(guardian_records), 4)
                    if len(guardian_records) > 0
                    else 0.0
                ),
            },
        }

    @staticmethod
    def _terminal_cycle_metadata(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not rows:
            return {}
        status_rank = {"running": 0, "failed": 1, "completed": 2}
        ordered = sorted(
            rows,
            key=lambda row: (
                status_rank.get(str(row.get("status", "")).strip().lower(), -1),
                int(row.get("timestamp_unix_ms", 0) or 0),
            ),
        )
        return dict(ordered[-1]) if ordered else {}

    def _resolve_cycle_id(self, tenant_id: str, cycle_id: Optional[str]) -> Optional[str]:
        cid = str(cycle_id or "").strip()
        if cid:
            return cid
        latest = self._storage.load_terminal_cycle_metadata(tenant_id)
        if not latest:
            return None
        latest_cycle = str(latest.get("cycle_id", "")).strip()
        return latest_cycle or None

    @staticmethod
    def _load_cycle_state_artifact(
        *,
        cycle_loader: Callable[[str, str], Optional[Dict[str, Any]]],
        latest_loader: Callable[[str], Optional[Dict[str, Any]]],
        tenant_id: str,
        cycle_id: str,
        allow_latest_fallback: bool,
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        cycle_value = cycle_loader(tenant_id, cycle_id)
        if cycle_value is not None:
            return cycle_value, False
        if not allow_latest_fallback:
            return None, False
        latest_value = latest_loader(tenant_id)
        if latest_value is None:
            return None, False
        return latest_value, True

    def _paginate_telemetry(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        record_type: str,
        page: int,
        page_size: int,
    ) -> List[Dict[str, Any]]:
        rtype = str(record_type or "all").strip().lower()
        if rtype not in {"all", "fingerprints", "posture_signals", "posture_findings"}:
            raise ValueError("telemetry_record_type")
        rows = self._storage.load_telemetry_for_cycle(tenant_id, cycle_id)

        if rtype != "all":
            rows = [row for row in rows if self._matches_record_type(row, rtype)]

        p = max(1, int(page))
        size = max(1, min(int(page_size), 10_000))
        start = (p - 1) * size
        end = start + size
        page_rows = rows[start:end]
        return self._migrator.migrate_telemetry_rows(page_rows)

    def _matches_record_type(self, row: Dict[str, Any], record_type: str) -> bool:
        if record_type == "fingerprints":
            values = row.get("fingerprints")
            return isinstance(values, list) and len(values) > 0
        if record_type == "posture_signals":
            values = row.get("posture_signals")
            return isinstance(values, list) and len(values) > 0
        if record_type == "posture_findings":
            values = row.get("posture_findings")
            if not isinstance(values, dict):
                return False
            waf = values.get("waf_findings")
            tls = values.get("tls_findings")
            return (
                (isinstance(waf, list) and len(waf) > 0)
                or (isinstance(tls, list) and len(tls) > 0)
            )
        return True
