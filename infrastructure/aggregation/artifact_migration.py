from __future__ import annotations

from typing import Any, Dict, List, Optional


class ArtifactMigrationEngine:
    """
    Read-time artifact upgrader.

    This engine never mutates persisted files. It normalizes legacy payloads
    into stable runtime shapes consumed by aggregation and Layer5 APIs.
    """

    SNAPSHOT_TARGET_VERSION = "1.2"
    CYCLE_METADATA_TARGET_VERSION = "v2.6"
    TELEMETRY_TARGET_VERSION = "v1"
    TEMPORAL_TARGET_VERSION = "v1"
    TRUST_GRAPH_TARGET_VERSION = 1
    LAYER3_TARGET_VERSION = "v3"
    GUARDIAN_TARGET_VERSION = "v1"

    def migrate_snapshot(self, snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(snapshot, dict):
            return snapshot
        out = dict(snapshot)
        version = str(out.get("schema_version", "")).strip().lower()
        if version in {"", "v1", "v1.0", "1", "1.0", "v2", "v2.0", "2", "2.0"}:
            out["schema_version"] = self.SNAPSHOT_TARGET_VERSION
        if "snapshot_hash_sha256" not in out and "snapshot_hash" in out:
            out["snapshot_hash_sha256"] = str(out.get("snapshot_hash") or "")
        endpoints = out.get("endpoints")
        if isinstance(endpoints, list):
            out["endpoint_count"] = len(endpoints)
        return out

    def migrate_cycle_metadata_rows(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out_rows: List[Dict[str, Any]] = []
        for row in rows or []:
            if not isinstance(row, dict):
                out_rows.append(row)
                continue
            out = dict(row)
            if not str(out.get("schema_version", "")).strip():
                out["schema_version"] = self.CYCLE_METADATA_TARGET_VERSION
            status = str(out.get("status", "")).strip()
            if status:
                out["status"] = status.lower()
            out_rows.append(out)
        return out_rows

    def migrate_telemetry_rows(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out_rows: List[Dict[str, Any]] = []
        for row in rows or []:
            if not isinstance(row, dict):
                out_rows.append(row)
                continue
            out = dict(row)
            if not str(out.get("schema_version", "")).strip():
                out["schema_version"] = self.TELEMETRY_TARGET_VERSION
            findings = out.get("posture_findings")
            if not isinstance(findings, dict):
                findings = {}
            waf_findings = findings.get("waf_findings")
            tls_findings = findings.get("tls_findings")
            scores = findings.get("scores")
            findings["waf_findings"] = waf_findings if isinstance(waf_findings, list) else []
            findings["tls_findings"] = tls_findings if isinstance(tls_findings, list) else []
            findings["scores"] = scores if isinstance(scores, dict) else {}
            out["posture_findings"] = findings
            out_rows.append(out)
        return out_rows

    def migrate_temporal_state(self, temporal_state: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(temporal_state, dict):
            return temporal_state
        out = dict(temporal_state)
        if not str(out.get("schema_version", "")).strip():
            out["schema_version"] = self.TEMPORAL_TARGET_VERSION
        if "endpoints" not in out or not isinstance(out.get("endpoints"), dict):
            out["endpoints"] = {}
        return out

    def migrate_trust_graph_snapshot(
        self,
        graph_snapshot: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(graph_snapshot, dict):
            return graph_snapshot
        out = dict(graph_snapshot)
        version = out.get("version")
        if isinstance(version, str) and version.isdigit():
            out["version"] = int(version)
        elif not isinstance(version, int):
            out["version"] = self.TRUST_GRAPH_TARGET_VERSION
        out["nodes"] = out.get("nodes") if isinstance(out.get("nodes"), list) else []
        out["edges"] = out.get("edges") if isinstance(out.get("edges"), list) else []
        return out

    def migrate_layer3_snapshot(self, snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(snapshot, dict):
            return snapshot
        out = dict(snapshot)
        if not str(out.get("schema_version", "")).strip():
            out["schema_version"] = self.LAYER3_TARGET_VERSION
        if "entities" not in out or not isinstance(out.get("entities"), dict):
            out["entities"] = {}
        return out

    def migrate_guardian_records(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out_rows: List[Dict[str, Any]] = []
        for row in rows or []:
            if not isinstance(row, dict):
                out_rows.append(row)
                continue
            out = dict(row)
            if not str(out.get("schema_version", "")).strip():
                out["schema_version"] = self.GUARDIAN_TARGET_VERSION
            alerts = out.get("alerts")
            out["alerts"] = alerts if isinstance(alerts, list) else []
            if "overall_severity_01" not in out:
                out["overall_severity_01"] = float(out.get("severity", 0.0) or 0.0)
            if "overall_confidence_01" not in out:
                out["overall_confidence_01"] = float(out.get("confidence", 0.0) or 0.0)
            pattern_labels = out.get("pattern_labels")
            out["pattern_labels"] = pattern_labels if isinstance(pattern_labels, list) else []
            out_rows.append(out)
        return out_rows
