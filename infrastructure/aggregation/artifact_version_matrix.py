from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class ArtifactVersionRule:
    artifact_name: str
    version_field: Optional[str]
    expected_value: Optional[str]
    notes: str


ARTIFACT_VERSION_RULES: Dict[str, ArtifactVersionRule] = {
    "snapshot": ArtifactVersionRule(
        artifact_name="snapshot",
        version_field="schema_version",
        expected_value="1.2",
        notes="DiscoverySnapshot payload",
    ),
    "cycle_metadata": ArtifactVersionRule(
        artifact_name="cycle_metadata",
        version_field="schema_version",
        expected_value=None,
        notes="CycleMetadata JSONL records",
    ),
    "trust_graph_snapshot": ArtifactVersionRule(
        artifact_name="trust_graph_snapshot",
        version_field="version",
        expected_value="1",
        notes="TrustGraph deterministic snapshot",
    ),
    "reporting_metrics": ArtifactVersionRule(
        artifact_name="reporting_metrics",
        version_field="schema_version",
        expected_value="v1",
        notes="Posture reporting metrics contract",
    ),
    "waf_posture_signal": ArtifactVersionRule(
        artifact_name="waf_posture_signal",
        version_field="schema_version",
        expected_value="v1",
        notes="WAF posture signal contract",
    ),
    "tls_posture_signal": ArtifactVersionRule(
        artifact_name="tls_posture_signal",
        version_field="schema_version",
        expected_value="v1",
        notes="TLS posture signal contract",
    ),
    "waf_finding": ArtifactVersionRule(
        artifact_name="waf_finding",
        version_field="schema_version",
        expected_value="v1",
        notes="WAF finding contract",
    ),
    "tls_finding": ArtifactVersionRule(
        artifact_name="tls_finding",
        version_field="schema_version",
        expected_value="v1",
        notes="TLS finding contract",
    ),
    "temporal_state": ArtifactVersionRule(
        artifact_name="temporal_state",
        version_field="schema_version",
        expected_value=None,
        notes="Temporal state document",
    ),
    "layer0_baseline": ArtifactVersionRule(
        artifact_name="layer0_baseline",
        version_field=None,
        expected_value=None,
        notes="No explicit version field today (legacy baseline store)",
    ),
    "layer3_snapshot": ArtifactVersionRule(
        artifact_name="layer3_snapshot",
        version_field=None,
        expected_value=None,
        notes="Learning state snapshot; schema governed by layer3 contract",
    ),
    "guardian_record": ArtifactVersionRule(
        artifact_name="guardian_record",
        version_field=None,
        expected_value=None,
        notes="Guardian record JSONL row, versionless today",
    ),
    "telemetry_record": ArtifactVersionRule(
        artifact_name="telemetry_record",
        version_field=None,
        expected_value=None,
        notes="Telemetry JSONL row, versionless today",
    ),
}
