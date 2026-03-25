from __future__ import annotations

import logging
import re
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from infrastructure.aggregation.artifact_migration import ArtifactMigrationEngine
from infrastructure.aggregation.authz_contract import AuthorizedTenantScope
from infrastructure.aggregation.cycle_bundle_builder import CycleBundleBuilder
from infrastructure.aggregation.simulation_query import SimulationQueryService
from infrastructure.aggregation.telemetry_query import TelemetryQueryService
from infrastructure.discovery.scope_utils import extract_registrable_base
from infrastructure.storage_manager.storage_manager import StorageManager

logger = logging.getLogger(__name__)


# ============================================================
# UI DATA CONTRACTS
# ============================================================

@dataclass(frozen=True)
class HealthSummary:
    tenant_id: str
    total_endpoints: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    max_severity: float
    last_cycle_id: Optional[str]
    last_cycle_duration_ms: Optional[int]
    last_cycle_timestamp_unix_ms: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


@dataclass(frozen=True)
class EndpointDTO:
    # Identity
    entity_id: str
    endpoint_gid: Optional[str]
    hostname: str
    port: int
    url: str

    # Network / infra
    ip: Optional[str]
    asn: Optional[str]

    # TLS / crypto
    tls_version: Optional[str]
    cipher: Optional[str]
    cert_issuer: Optional[str]
    certificate_sha256: Optional[str]
    certificate_expiry_unix_ms: Optional[int]

    # Physics / intelligence
    entropy_score: Optional[float]

    # Temporal
    volatility_score: float
    visibility_score: float
    consecutive_absence: int
    first_seen_ms: Optional[int]
    last_seen_ms: Optional[int]

    # Guardian
    guardian_risk: float
    confidence: float
    alert_count: int

    # Clustering
    shared_cert_cluster_id: Optional[str]
    lb_cluster_id: Optional[str]
    identity_cluster_id: Optional[str]

    # Provenance
    discovery_source: Optional[str]
    discovery_sources: List[str]
    ownership_category: str
    ownership_confidence: float
    relevance_score: float
    relevance_reason: str
    observation_status: str
    observation_attempted: bool
    recorded_in_snapshot: bool
    surface_tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


@dataclass(frozen=True)
class DriftReport:
    new_endpoints: int
    removed_endpoints: int
    risk_increased: bool

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


@dataclass(frozen=True)
class ObservationSummary:
    discovered_related: int
    observation_attempts: int
    observation_successes: int
    observation_failures: int
    recorded_endpoints: int
    unverified_historical: int
    tls_findings_count: int
    waf_findings_count: int

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


# ============================================================
# AGGREGATION ENGINE
# ============================================================

class AggregationEngine:
    """
    Deterministic read-only projection engine.

    Builds UI DTOs by merging:
    - Snapshot (identity + enrichment)
    - Temporal state (volatility/visibility)
    - Guardian output (risk)
    - TrustGraph metadata (clusters)
    """

    DASHBOARD_ENDPOINT_LIMIT = 5_000
    _MULTI_LABEL_SUFFIXES = {
        ("co", "uk"),
        ("org", "uk"),
        ("gov", "uk"),
        ("ac", "uk"),
        ("com", "au"),
        ("net", "au"),
        ("org", "au"),
        ("co", "jp"),
        ("com", "br"),
        ("com", "mx"),
        ("com", "cn"),
        ("com", "pa"),
    }
    _DEPENDENCY_DISCOVERY_METHODS = {
        "ct_log",
        "dns_ns",
        "dns_mx",
        "dns_txt",
        "tls_observation",
        "protocol_observer",
    }
    _PROVIDER_HOST_SUFFIXES = (
        "akamai.net",
        "amazon.com",
        "amazonaws-china.com",
        "amazonaws.com",
        "amazonses.com",
        "azureedge.net",
        "cloudflare.com",
        "cloudflare.net",
        "cloudfront.net",
        "edgekey.net",
        "edgesuite.net",
        "fastly.net",
        "forcepoint.net",
        "forcepoint.tools",
        "googleapis.com",
        "gstatic.com",
        "mail.protection.outlook.com",
        "mailcontrol.com",
        "mimecast.com",
        "office365.com",
        "outlook.com",
        "protection.outlook.com",
        "sendgrid.net",
        "trafficmanager.net",
        "websense.com",
        "websense.net",
        "windows.net",
        "zendesk.com",
    )
    _COMMON_SCOPE_LABELS = {
        "ac",
        "app",
        "bank",
        "cn",
        "co",
        "com",
        "dev",
        "edu",
        "gov",
        "http",
        "https",
        "id",
        "img",
        "io",
        "jp",
        "mail",
        "mx",
        "net",
        "org",
        "pa",
        "prod",
        "qa",
        "stg",
        "stage",
        "static",
        "test",
        "uk",
        "www",
    }

    def __init__(
        self,
        storage: StorageManager,
        simulation_root: Optional[str] = None,
    ):
        self.storage = storage
        self._migrator = ArtifactMigrationEngine()
        self._bundle_builder = CycleBundleBuilder(
            storage=storage,
            migration_engine=self._migrator,
        )
        self._telemetry_query = TelemetryQueryService(
            storage=storage,
            migration_engine=self._migrator,
        )
        self._simulation_query = (
            SimulationQueryService(simulation_root)
            if simulation_root
            else None
        )
        logger.info("AggregationEngine initialized")

    # =========================================================
    # DASHBOARD ENTRY
    # =========================================================

    def build_dashboard(
        self,
        tenant_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
    ) -> Dict[str, Any]:

        self._assert_authorized(authz_scope, tenant_id)

        self.storage.ensure_tenant_exists(tenant_id)

        now_ms = int(time.time() * 1000)
        tenant_config = self.storage.load_tenant_config(tenant_id)
        workspace = self._build_workspace_status(tenant_config)

        snapshot, temporal, guardian_records = self._load_latest_projection_artifacts(
            tenant_id,
            guardian_limit=200,
        )
        metadata_rows = self._migrator.migrate_cycle_metadata_rows(
            self.storage.load_cycle_metadata(tenant_id)
        )
        last_completed_metadata = next(
            (
                row
                for row in reversed(metadata_rows)
                if str(row.get("status", "")).strip().lower() == "completed"
            ),
            None,
        )

        if not snapshot:
            return {
                "timestamp_ms": now_ms,
                "tenant_id": tenant_id,
                "tenant_gid": None,
                "cycle_id": None,
                "cycle_gid": None,
                "workspace": workspace,
                "health_summary": None,
                "observation_summary": None,
                "risk_distribution": {},
                "drift_report": None,
                "endpoints": [],
            }

        endpoints = self._build_endpoint_rows(
            snapshot=snapshot,
            guardian_records=guardian_records,
            temporal_state=temporal,
            tenant_config=tenant_config,
            limit=self.DASHBOARD_ENDPOINT_LIMIT,
        )

        health_summary = self._build_health_summary(
            tenant_id,
            snapshot,
            endpoints,
            last_completed_metadata,
        )

        risk_distribution = self._build_risk_distribution(
            endpoints
        )

        drift_report = self._compute_drift(
            tenant_id,
            snapshot,
        )

        observation_summary = self._build_observation_summary(last_completed_metadata)

        return {
            "timestamp_ms": now_ms,
            "tenant_id": snapshot.get("tenant_id", tenant_id),
            "tenant_gid": snapshot.get("tenant_gid"),
            "cycle_id": snapshot.get("cycle_id"),
            "cycle_gid": snapshot.get("cycle_gid"),
            "workspace": workspace,
            "health_summary": health_summary.to_dict(),
            "observation_summary": observation_summary.to_dict(),
            "risk_distribution": risk_distribution,
            "drift_report": drift_report.to_dict(),
            "endpoints": [e.to_dict() for e in endpoints],
        }

    def get_endpoint_page(
        self,
        tenant_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
        page: int = 1,
        page_size: int = 200,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        tenant_config = self.storage.load_tenant_config(tenant_id)

        p = max(1, int(page))
        size = max(1, min(int(page_size), 5_000))
        snapshot, temporal, guardian_records = self._load_latest_projection_artifacts(
            tenant_id,
            guardian_limit=100_000,
        )
        if not snapshot:
            return {
                "tenant_id": tenant_id,
                "cycle_id": None,
                "page": p,
                "page_size": size,
                "total": 0,
                "rows": [],
            }

        rows = self._build_endpoint_rows(
            snapshot=snapshot,
            guardian_records=guardian_records,
            temporal_state=temporal,
            tenant_config=tenant_config,
            limit=None,
        )
        start = (p - 1) * size
        end = start + size
        return {
            "tenant_id": tenant_id,
            "cycle_id": snapshot.get("cycle_id"),
            "page": p,
            "page_size": size,
            "total": len(rows),
            "rows": [row.to_dict() for row in rows[start:end]],
        }

    def get_endpoint_detail(
        self,
        tenant_id: str,
        entity_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        tenant_config = self.storage.load_tenant_config(tenant_id)
        snapshot, temporal, guardian_records = self._load_latest_projection_artifacts(
            tenant_id,
            guardian_limit=100_000,
        )
        if not snapshot:
            return {
                "tenant_id": tenant_id,
                "cycle_id": None,
                "row": None,
            }

        rows = self._build_endpoint_rows(
            snapshot=snapshot,
            guardian_records=guardian_records,
            temporal_state=temporal,
            tenant_config=tenant_config,
            limit=None,
        )
        row = next((item for item in rows if item.entity_id == entity_id), None)
        return {
            "tenant_id": tenant_id,
            "cycle_id": snapshot.get("cycle_id"),
            "row": row.to_dict() if row is not None else None,
        }

    def _load_latest_projection_artifacts(
        self,
        tenant_id: str,
        *,
        guardian_limit: int,
    ) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        snapshot = self._migrator.migrate_snapshot(
            self.storage.load_latest_snapshot(tenant_id)
        )
        temporal = self._migrator.migrate_temporal_state(
            self.storage.load_temporal_state(tenant_id)
        )
        if not snapshot:
            return None, temporal, []

        latest_cycle_id = snapshot.get("cycle_id")
        guardian_records = self._migrator.migrate_guardian_records(
            self.storage.load_latest_guardian_records(
                tenant_id,
                limit=guardian_limit,
            )
        )
        guardian_records = [
            r for r in guardian_records
            if r.get("cycle_id") == latest_cycle_id
        ]
        return snapshot, temporal, guardian_records

    # =========================================================
    # RISK DISTRIBUTION
    # =========================================================

    def _build_risk_distribution(
        self,
        endpoint_rows: List[EndpointDTO],
    ) -> Dict[str, int]:

        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        rows = list(endpoint_rows)

        for row in rows:
            sev = float(row.guardian_risk or 0)
            if sev <= 0.0:
                continue

            if sev >= 0.8:
                dist["critical"] += 1
            elif sev >= 0.6:
                dist["high"] += 1
            elif sev >= 0.4:
                dist["medium"] += 1
            else:
                dist["low"] += 1

        return dist

    # =========================================================
    # HEALTH SUMMARY
    # =========================================================

    def _build_health_summary(
        self,
        tenant_id: str,
        snapshot: Dict[str, Any],
        endpoint_rows: List[EndpointDTO],
        metadata: Optional[Dict[str, Any]],
    ) -> HealthSummary:

        endpoint_count = len(endpoint_rows) if endpoint_rows else snapshot.get("endpoint_count", 0)

        low = medium = high = critical = 0
        max_severity = 0.0
        rows = list(endpoint_rows)

        for row in rows:
            severity = float(row.guardian_risk or 0)
            if severity <= 0.0:
                continue
            max_severity = max(max_severity, severity)

            if severity >= 0.8:
                critical += 1
            elif severity >= 0.6:
                high += 1
            elif severity >= 0.4:
                medium += 1
            else:
                low += 1

        return HealthSummary(
            tenant_id=tenant_id,
            total_endpoints=endpoint_count,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            max_severity=max_severity,
            last_cycle_id=metadata.get("cycle_id") if metadata else None,
            last_cycle_duration_ms=metadata.get("duration_ms") if metadata else None,
            last_cycle_timestamp_unix_ms=(
                metadata.get("timestamp_unix_ms") if metadata else None
            ),
        )

    def _tenant_relevant_endpoint_rows(
        self,
        endpoint_rows: List[EndpointDTO],
    ) -> List[EndpointDTO]:
        relevant = [
            row
            for row in endpoint_rows
            if row.ownership_category in {"first_party", "adjacent_dependency"}
            or float(row.relevance_score or 0.0) >= 0.55
        ]
        return relevant if relevant else list(endpoint_rows)

    # =========================================================
    # ENDPOINT TABLE (FULLY ENRICHED)
    # =========================================================

    def _build_endpoint_rows(
        self,
        snapshot: Dict[str, Any],
        guardian_records: List[Dict[str, Any]],
        temporal_state: Optional[Dict[str, Any]],
        *,
        tenant_config: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = DASHBOARD_ENDPOINT_LIMIT,
    ) -> List[EndpointDTO]:

        temporal_map = temporal_state.get("endpoints", {}) if temporal_state else {}
        scope_profile = self._build_scope_profile(tenant_config)

        guardian_map = {
            r.get("entity_id"): r
            for r in guardian_records
        }

        snapshot_cycle_number = self._safe_int(snapshot.get("cycle_number"))
        snapshot_rows = (
            snapshot.get("endpoints", [])
            if isinstance(snapshot.get("endpoints"), list)
            else []
        )
        snapshot_map: Dict[str, Dict[str, Any]] = {}
        for endpoint in snapshot_rows:
            if not isinstance(endpoint, dict):
                continue
            hostname = str(endpoint.get("hostname", "")).strip().lower()
            port = self._safe_int(endpoint.get("port"))
            if not hostname or port <= 0:
                continue
            snapshot_map[f"{hostname}:{port}"] = endpoint

        discovered_surface_rows = (
            snapshot.get("discovered_surface", [])
            if isinstance(snapshot.get("discovered_surface"), list)
            else []
        )
        discovered_surface_map: Dict[str, Dict[str, Any]] = {}
        for row in discovered_surface_rows:
            if not isinstance(row, dict):
                continue
            entity_id = str(row.get("entity_id", "")).strip().lower()
            hostname = str(row.get("hostname", "")).strip().lower()
            port = self._safe_int(row.get("port"))
            if not entity_id and hostname and port > 0:
                entity_id = f"{hostname}:{port}"
            if not entity_id:
                continue
            discovered_surface_map[entity_id] = row

        rows: List[EndpointDTO] = []
        entity_ids = sorted(set(snapshot_map.keys()) | set(discovered_surface_map.keys()))

        for entity_id in entity_ids:
            endpoint = dict(discovered_surface_map.get(entity_id, {}))
            snapshot_endpoint = snapshot_map.get(entity_id, {})
            if snapshot_endpoint:
                endpoint.update(snapshot_endpoint)

            hostname = str(endpoint.get("hostname", "")).strip().lower()
            port = self._safe_int(endpoint.get("port"))
            if not hostname or port <= 0:
                continue

            guardian = guardian_map.get(entity_id, {})
            temporal_entry = temporal_map.get(entity_id, {})
            first_seen_ms, last_seen_ms = self._temporal_seen_bounds(temporal_entry)
            if first_seen_ms is None:
                first_seen_ms = self._safe_int(endpoint.get("last_observed_unix_ms")) or None
            if last_seen_ms is None:
                last_seen_ms = self._safe_int(endpoint.get("last_observed_unix_ms")) or None
            guardian_confidence = float(guardian.get("confidence", 0) or 0)
            endpoint_confidence = float(endpoint.get("confidence", 0) or 0)
            discovery_sources = self._normalize_discovery_sources(endpoint)
            surface_row = discovered_surface_map.get(entity_id, {})
            if isinstance(surface_row.get("discovery_sources"), list):
                discovery_sources = sorted(
                    {
                        *discovery_sources,
                        *[
                            str(item).strip()
                            for item in surface_row.get("discovery_sources", [])
                            if str(item).strip()
                        ],
                    }
                )

            scheme = str(endpoint.get("scheme") or self._infer_scheme(port)).strip().lower() or self._infer_scheme(port)
            url = f"{scheme}://{hostname}:{port}"
            discovery_source = endpoint.get("discovery_source")
            if discovery_sources:
                discovery_source = ", ".join(discovery_sources)
            elif surface_row.get("discovery_source"):
                discovery_source = str(surface_row.get("discovery_source") or "").strip() or None

            observation_state = str(endpoint.get("observation_state", "")).strip().lower()
            observation_status = str(surface_row.get("observation_status", "")).strip().lower()
            if not observation_status:
                if observation_state == "observed":
                    observation_status = "observed_successful"
                elif observation_state == "stale":
                    observation_status = "historical_or_ct_only"
                else:
                    observation_status = "not_yet_observed"
            observation_attempted = bool(surface_row.get("observation_attempted"))
            if not observation_attempted:
                observation_attempted = observation_status in {
                    "observed_successful",
                    "observation_failed",
                }
            recorded_in_snapshot = bool(surface_row.get("recorded_in_snapshot"))
            if not recorded_in_snapshot and snapshot_endpoint:
                recorded_in_snapshot = (
                    observation_state == "observed"
                    and self._safe_int(endpoint.get("last_observed_cycle")) == snapshot_cycle_number
                )
            surface_tags = self._normalize_surface_tags(
                surface_row.get("surface_tags", [])
                if isinstance(surface_row.get("surface_tags"), list)
                else []
            )
            surface_tags.append(observation_status)
            if observation_state == "stale":
                surface_tags.append("historical_or_ct_only")

            ownership_category, ownership_confidence, relevance_score, relevance_reason = (
                self._classify_endpoint_relevance(
                    endpoint=endpoint,
                    guardian=guardian,
                    discovery_sources=discovery_sources,
                    endpoint_confidence=endpoint_confidence,
                    alert_count=len(guardian.get("alerts", [])),
                    scope_profile=scope_profile,
                )
            )

            rows.append(
                EndpointDTO(
                    entity_id=entity_id,
                    endpoint_gid=endpoint.get("endpoint_gid"),
                    hostname=hostname,
                    port=port,
                    url=url,

                    ip=endpoint.get("ip"),
                    asn=endpoint.get("asn"),

                    tls_version=endpoint.get("tls_version"),
                    cipher=endpoint.get("cipher"),
                    cert_issuer=endpoint.get("cert_issuer"),
                    certificate_sha256=endpoint.get("certificate_sha256"),
                    certificate_expiry_unix_ms=endpoint.get(
                        "certificate_expiry_unix_ms"
                    ),

                    entropy_score=endpoint.get("entropy_score"),

                    volatility_score=float(
                        temporal_entry.get("volatility_score", 0)
                    ),
                    visibility_score=float(
                        temporal_entry.get("visibility_score", 0)
                    ),
                    consecutive_absence=int(
                        temporal_entry.get("consecutive_absence", 0)
                    ),
                    first_seen_ms=first_seen_ms,
                    last_seen_ms=last_seen_ms,

                    guardian_risk=float(guardian.get("severity", 0)),
                    confidence=guardian_confidence if guardian_confidence > 0 else endpoint_confidence,
                    alert_count=len(guardian.get("alerts", [])),

                    shared_cert_cluster_id=endpoint.get(
                        "shared_cert_cluster_id"
                    ),
                    lb_cluster_id=endpoint.get("lb_cluster_id"),
                    identity_cluster_id=endpoint.get("identity_cluster_id"),

                    discovery_source=discovery_source,
                    discovery_sources=discovery_sources,
                    ownership_category=ownership_category,
                    ownership_confidence=ownership_confidence,
                    relevance_score=relevance_score,
                    relevance_reason=relevance_reason,
                    observation_status=observation_status,
                    observation_attempted=observation_attempted,
                    recorded_in_snapshot=recorded_in_snapshot,
                    surface_tags=sorted(set(surface_tags)),
                )
            )

        rows.sort(
            key=lambda r: (-r.relevance_score, -r.guardian_risk, -r.alert_count, r.hostname or "")
        )

        if limit is None:
            return rows
        return rows[: max(0, int(limit))]

    @staticmethod
    def _temporal_seen_bounds(entry: Dict[str, Any]) -> tuple[Optional[int], Optional[int]]:
        if not isinstance(entry, dict):
            return None, None
        explicit_first = entry.get("first_seen_ms")
        explicit_last = entry.get("last_seen_ms")
        if explicit_first or explicit_last:
            return explicit_first, explicit_last
        history = entry.get("presence_history")
        if not isinstance(history, list) or not history:
            return None, None
        timestamps = []
        for item in history:
            if not isinstance(item, dict):
                continue
            try:
                value = int(item.get("timestamp_unix_ms", 0) or 0)
            except Exception:
                value = 0
            if value > 0:
                timestamps.append(value)
        if not timestamps:
            return None, None
        return timestamps[0], timestamps[-1]

    @staticmethod
    def _normalize_surface_tags(values: List[Any]) -> List[str]:
        tags: List[str] = []
        seen: set[str] = set()
        for value in values:
            token = str(value or "").strip().lower()
            if not token or token in seen:
                continue
            seen.add(token)
            tags.append(token)
        return tags

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)

    # =========================================================
    # DRIFT
    # =========================================================

    def _compute_drift(
        self,
        tenant_id: str,
        current_snapshot: Dict[str, Any],
    ) -> DriftReport:

        previous_snapshot = self._migrator.migrate_snapshot(
            self.storage.load_previous_snapshot(tenant_id)
        )

        if not previous_snapshot:
            return DriftReport(0, 0, False)

        current_ids = {
            f"{e['hostname']}:{e['port']}"
            for e in current_snapshot.get("endpoints", [])
        }

        previous_ids = {
            f"{e['hostname']}:{e['port']}"
            for e in previous_snapshot.get("endpoints", [])
        }

        new_endpoints = len(current_ids - previous_ids)
        removed_endpoints = len(previous_ids - current_ids)

        guardian_records = self._migrator.migrate_guardian_records(
            self.storage.load_latest_guardian_records(
                tenant_id,
                limit=10_000,
            )
        )

        latest_cycle_id = current_snapshot.get("cycle_id")

        critical_now = any(
            float(r.get("severity", 0)) >= 0.8
            and r.get("cycle_id") == latest_cycle_id
            for r in guardian_records
        )

        return DriftReport(
            new_endpoints=new_endpoints,
            removed_endpoints=removed_endpoints,
            risk_increased=critical_now,
        )

    def _build_observation_summary(
        self,
        metadata: Optional[Dict[str, Any]],
    ) -> ObservationSummary:
        build_stats = metadata.get("build_stats", {}) if isinstance(metadata, dict) else {}
        posture_summary = build_stats.get("posture_summary", {}) if isinstance(build_stats, dict) else {}
        return ObservationSummary(
            discovered_related=int(
                build_stats.get(
                    "discovered_related_endpoints",
                    build_stats.get("total_discovered_domains", 0),
                )
                or 0
            ),
            observation_attempts=int(
                build_stats.get("observation_attempts", build_stats.get("total_observations", 0))
                or 0
            ),
            observation_successes=int(
                build_stats.get(
                    "observation_successes",
                    build_stats.get("successful_observations", 0),
                )
                or 0
            ),
            observation_failures=int(
                build_stats.get(
                    "observation_failures",
                    build_stats.get("failed_observations", 0),
                )
                or 0
            ),
            recorded_endpoints=int(
                build_stats.get("recorded_endpoints", build_stats.get("endpoints_canonical", 0))
                or 0
            ),
            unverified_historical=int(
                build_stats.get(
                    "unverified_historical_endpoints",
                    max(
                        0,
                        int(build_stats.get("total_discovered_domains", 0) or 0)
                        - int(build_stats.get("endpoints_canonical", 0) or 0),
                    ),
                )
                or 0
            ),
            tls_findings_count=int(posture_summary.get("tls_findings_count", 0) or 0),
            waf_findings_count=int(posture_summary.get("waf_findings_count", 0) or 0),
        )

    # =========================================================
    # CONNECTOR QUERIES
    # =========================================================

    def build_cycle_artifact_bundle(
        self,
        tenant_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
        cycle_id: Optional[str] = None,
        telemetry_record_type: str = "all",
        telemetry_page: int = 1,
        telemetry_page_size: int = 500,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        bundle = self._bundle_builder.build_cycle_artifact_bundle(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            telemetry_record_type=telemetry_record_type,
            telemetry_page=telemetry_page,
            telemetry_page_size=telemetry_page_size,
        )
        return bundle.to_dict()

    def get_cycle_telemetry(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
        record_type: str = "all",
        page: int = 1,
        page_size: int = 500,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        payload = self._telemetry_query.query_cycle_telemetry(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            record_type=record_type,
            page=page,
            page_size=page_size,
        )
        return payload.to_dict()

    def get_cycle_telemetry_summary(
        self,
        tenant_id: str,
        cycle_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
        preview_page_size: int = 50,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        return self._telemetry_query.summarize_cycle_telemetry(
            tenant_id=tenant_id,
            cycle_id=cycle_id,
            preview_page_size=preview_page_size,
        )

    def list_cycles(
        self,
        tenant_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
        page: int = 1,
        page_size: int = 200,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        self.storage.ensure_tenant_exists(tenant_id)
        ordered = self._migrator.migrate_cycle_metadata_rows(
            self.storage.list_terminal_cycle_metadata(tenant_id)
        )
        p = max(1, int(page))
        size = max(1, min(int(page_size), 1000))
        start = (p - 1) * size
        end = start + size
        return {
            "tenant_id": tenant_id,
            "page": p,
            "page_size": size,
            "total": len(ordered),
            "rows": ordered[start:end],
        }

    def list_simulations(
        self,
        tenant_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        if self._simulation_query is None:
            raise RuntimeError("simulation_root is not configured")
        payload = self._simulation_query.list_simulations(
            tenant_id=tenant_id,
            page=page,
            page_size=page_size,
        )
        return payload.to_dict()

    def get_simulation(
        self,
        tenant_id: str,
        simulation_id: str,
        *,
        authz_scope: Optional[AuthorizedTenantScope] = None,
    ) -> Dict[str, Any]:
        self._assert_authorized(authz_scope, tenant_id)
        if self._simulation_query is None:
            raise RuntimeError("simulation_root is not configured")
        return self._simulation_query.get_simulation(tenant_id, simulation_id)

    # =========================================================
    # UTIL
    # =========================================================

    def _assert_authorized(
        self,
        authz_scope: Optional[AuthorizedTenantScope],
        tenant_id: str,
    ) -> None:
        if authz_scope is None:
            raise RuntimeError("unauthorized tenant access")
        authz_scope.assert_allowed(tenant_id)

    def _infer_scheme(self, port: int) -> str:
        https_ports = {443, 8443, 9443, 10443}
        return "https" if port in https_ports else "http"

    def _build_scope_profile(
        self,
        tenant_config: Optional[Dict[str, Any]],
    ) -> Dict[str, set[str]]:
        cfg = tenant_config if isinstance(tenant_config, dict) else {}
        exact_hosts: set[str] = set()
        base_domains: set[str] = set()

        candidates: List[str] = []
        main_url = str(cfg.get("main_url", "")).strip()
        if main_url:
            candidates.append(main_url)
        raw_seeds = cfg.get("seed_endpoints", [])
        if isinstance(raw_seeds, list):
            candidates.extend(str(item).strip() for item in raw_seeds if str(item).strip())

        for candidate in candidates:
            host = self._extract_host(candidate)
            if not host:
                continue
            exact_hosts.add(host)
            base = self._registrable_base_domain(host)
            if base:
                base_domains.add(base)

        return {
            "exact_hosts": exact_hosts,
            "base_domains": base_domains,
        }

    def _normalize_discovery_sources(self, endpoint: Dict[str, Any]) -> List[str]:
        sources = endpoint.get("discovered_by")
        if isinstance(sources, list):
            return [
                str(item).strip()
                for item in sources
                if str(item).strip()
            ]
        discovery_source = str(endpoint.get("discovery_source", "")).strip()
        if not discovery_source:
            return []
        return [
            item.strip()
            for item in discovery_source.split(",")
            if item.strip()
        ]

    def _classify_endpoint_relevance(
        self,
        *,
        endpoint: Dict[str, Any],
        guardian: Dict[str, Any],
        discovery_sources: List[str],
        endpoint_confidence: float,
        alert_count: int,
        scope_profile: Dict[str, set[str]],
    ) -> tuple[str, float, float, str]:
        hostname = self._extract_host(endpoint.get("hostname"))
        exact_hosts = scope_profile.get("exact_hosts", set())
        base_domains = scope_profile.get("base_domains", set())
        endpoint_base = self._registrable_base_domain(hostname)
        scope_tokens = self._scope_tokens(scope_profile)
        provider_edge = bool(hostname and self._looks_like_provider_edge(hostname))
        scope_token_match = bool(hostname and self._host_contains_scope_token(hostname, scope_tokens))

        ownership_category = "unknown"
        ownership_confidence = 0.35
        relevance_reason = "No strong tenant-scope match or dependency signature yet."

        if hostname and hostname in exact_hosts:
            ownership_category = "first_party"
            ownership_confidence = 0.99
            relevance_reason = "Matches a tenant seed or primary onboarding host."
        elif hostname and any(
            hostname == base or hostname.endswith(f".{base}")
            for base in base_domains
            if base
        ):
            ownership_category = "first_party"
            ownership_confidence = 0.92
            relevance_reason = "Shares the tenant base domain and behaves like a first-party surface."
        elif provider_edge and scope_token_match:
            ownership_category = "adjacent_dependency"
            ownership_confidence = 0.78
            relevance_reason = "Shared provider hostname still embeds tenant scope and likely represents an adjacent dependency."
        elif hostname and self._looks_like_provider_edge(hostname):
            ownership_category = "third_party_dependency"
            ownership_confidence = 0.84
            relevance_reason = "Hostname maps to shared provider or edge infrastructure."
        elif scope_token_match:
            ownership_category = "adjacent_dependency"
            ownership_confidence = 0.72
            relevance_reason = "Hostname carries tenant-specific scope markers outside the primary base domain."
        elif discovery_sources and set(discovery_sources) & self._DEPENDENCY_DISCOVERY_METHODS:
            ownership_category = "adjacent_dependency"
            ownership_confidence = 0.66
            relevance_reason = "Discovered through dependency-oriented methods rather than direct tenant scope."
        elif endpoint_base and endpoint_base in base_domains:
            ownership_category = "first_party"
            ownership_confidence = 0.88
            relevance_reason = "Registrable base domain overlaps with tenant onboarding scope."

        base_score = {
            "first_party": 0.78,
            "adjacent_dependency": 0.58,
            "third_party_dependency": 0.18,
            "unknown": 0.25,
        }.get(ownership_category, 0.25)

        score = base_score
        score += min(max(endpoint_confidence, 0.0), 1.0) * 0.10
        score += min(self._normalize_risk_score(guardian.get("severity")), 1.0) * 0.08
        if alert_count > 0:
            score += 0.05
        if endpoint.get("tls_version") or endpoint.get("ip"):
            score += 0.04
        if len(discovery_sources) >= 2:
            score += 0.03
        if (
            endpoint.get("shared_cert_cluster_id")
            or endpoint.get("lb_cluster_id")
            or endpoint.get("identity_cluster_id")
        ):
            score += 0.03
        if ownership_category == "third_party_dependency":
            score = min(score, 0.38)

        return (
            ownership_category,
            round(ownership_confidence, 4),
            round(min(score, 1.0), 4),
            relevance_reason,
        )

    def _extract_host(self, value: Any) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return ""
        if "://" in text:
            parsed = urlparse(text)
            host = str(parsed.hostname or "").strip().lower()
            return host.strip(".")

        host = text.split("/", 1)[0].strip()
        if host.count(":") == 1:
            maybe_host, maybe_port = host.rsplit(":", 1)
            if maybe_port.isdigit():
                host = maybe_host
        return host.strip("[]").strip(".")

    def _registrable_base_domain(self, hostname: str) -> str:
        return extract_registrable_base(hostname) or str(hostname or "").strip(".")

    def _looks_like_provider_edge(self, hostname: str) -> bool:
        host = str(hostname or "").strip().lower()
        if not host:
            return False
        return any(
            host == suffix or host.endswith(f".{suffix}")
            for suffix in self._PROVIDER_HOST_SUFFIXES
        )

    def _scope_tokens(self, scope_profile: Dict[str, set[str]]) -> set[str]:
        tokens: set[str] = set()
        for host in scope_profile.get("exact_hosts", set()):
            for label in str(host or "").split("."):
                token = self._normalize_scope_token(label)
                if token:
                    tokens.add(token)
        for base in scope_profile.get("base_domains", set()):
            token = self._normalize_scope_token(base)
            if token:
                tokens.add(token)
            for label in str(base or "").split("."):
                token = self._normalize_scope_token(label)
                if token:
                    tokens.add(token)
        return tokens

    @classmethod
    def _normalize_scope_token(cls, value: str) -> str:
        token = re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
        if len(token) < 4 or token in cls._COMMON_SCOPE_LABELS:
            return ""
        return token

    def _host_contains_scope_token(self, hostname: str, scope_tokens: set[str]) -> bool:
        host = self._normalize_scope_token(hostname)
        if not host:
            return False
        return any(token and token in host for token in scope_tokens)

    def _normalize_risk_score(self, value: Any) -> float:
        score = float(value or 0.0)
        if score <= 0:
            return 0.0
        return score / 10.0 if score > 1.0 else score

    def _build_workspace_status(self, tenant_config: Dict[str, Any]) -> Dict[str, Any]:
        cfg = tenant_config if isinstance(tenant_config, dict) else {}
        status = str(cfg.get("onboarding_status", "PENDING")).strip().upper() or "PENDING"
        main_url = str(cfg.get("main_url", "")).strip()
        name = str(cfg.get("name", "")).strip()
        seed_endpoints = cfg.get("seed_endpoints", [])
        seed_count = len(seed_endpoints) if isinstance(seed_endpoints, list) else 0
        onboarded_at = cfg.get("onboarded_at_unix_ms")
        registered_at = cfg.get("registered_at_unix_ms")
        return {
            "onboarding_status": status,
            "institution_name": name,
            "main_url": main_url,
            "seed_count": seed_count,
            "seed_endpoints": [str(row).strip() for row in seed_endpoints if str(row).strip()]
            if isinstance(seed_endpoints, list)
            else [],
            "registered_at_unix_ms": registered_at if isinstance(registered_at, int) else None,
            "onboarded_at_unix_ms": onboarded_at if isinstance(onboarded_at, int) else None,
        }
