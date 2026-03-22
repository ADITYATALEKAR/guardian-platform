from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, Dict, List, Optional, Set


SIGNAL_SCHEMA_VERSION = "v1"
FINDING_SCHEMA_VERSION = "v1"
REPORTING_SCHEMA_VERSION = "v1"
FINDING_LANGUAGE_MODE_DEFENSIVE = "defensive_posture"
CERT_VALIDATION_UNKNOWN = "UNKNOWN"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TriState(str, Enum):
    YES = "YES"
    NO = "NO"
    UNKNOWN = "UNKNOWN"


class CertValidationType(str, Enum):
    DV = "DV"
    OV = "OV"
    EV = "EV"
    UNKNOWN = CERT_VALIDATION_UNKNOWN


def classify_confidence(corroborating_signal_count: int) -> ConfidenceLevel:
    if corroborating_signal_count >= 3:
        return ConfidenceLevel.HIGH
    if corroborating_signal_count == 2:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


@dataclass(frozen=True)
class ReportingMetrics:
    schema_version: str = REPORTING_SCHEMA_VERSION
    total_discovered_domains: int = 0
    total_successful_observations: int = 0
    total_failed_observations: int = 0

    def __post_init__(self) -> None:
        if self.schema_version != REPORTING_SCHEMA_VERSION:
            raise ValueError("schema_version")
        if self.total_discovered_domains < 0:
            raise ValueError("total_discovered_domains")
        if self.total_successful_observations < 0:
            raise ValueError("total_successful_observations")
        if self.total_failed_observations < 0:
            raise ValueError("total_failed_observations")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "total_discovered_domains": self.total_discovered_domains,
            "total_successful_observations": self.total_successful_observations,
            "total_failed_observations": self.total_failed_observations,
        }


@dataclass(frozen=True)
class WAFPostureSignal:
    schema_version: str = SIGNAL_SCHEMA_VERSION
    endpoint_id: str = ""
    observed_at_unix_ms: int = 0
    http_status: Optional[int] = None
    waf_vendor: Optional[str] = None
    protection_tier_inferred: Optional[str] = None
    challenge_type: Optional[str] = None
    header_completeness: str = "UNKNOWN"
    classification_confidence: ConfidenceLevel = ConfidenceLevel.LOW
    confidence_rationale: List[str] = field(default_factory=list)
    edge_observed: bool = True
    origin_observed: bool = False
    finding_language_mode: str = FINDING_LANGUAGE_MODE_DEFENSIVE

    def __post_init__(self) -> None:
        if self.schema_version != SIGNAL_SCHEMA_VERSION:
            raise ValueError("schema_version")
        if not self.endpoint_id:
            raise ValueError("endpoint_id")
        if self.observed_at_unix_ms < 0:
            raise ValueError("observed_at_unix_ms")
        if self.http_status is not None and (self.http_status < 100 or self.http_status > 599):
            raise ValueError("http_status")
        if self.finding_language_mode != FINDING_LANGUAGE_MODE_DEFENSIVE:
            raise ValueError("finding_language_mode")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "endpoint_id": self.endpoint_id,
            "observed_at_unix_ms": self.observed_at_unix_ms,
            "http_status": self.http_status,
            "waf_vendor": self.waf_vendor,
            "protection_tier_inferred": self.protection_tier_inferred,
            "challenge_type": self.challenge_type,
            "header_completeness": self.header_completeness,
            "classification_confidence": self.classification_confidence.value,
            "confidence_rationale": sorted(set(self.confidence_rationale)),
            "edge_observed": self.edge_observed,
            "origin_observed": self.origin_observed,
            "finding_language_mode": self.finding_language_mode,
        }


@dataclass(frozen=True)
class TLSPostureSignal:
    schema_version: str = SIGNAL_SCHEMA_VERSION
    endpoint_id: str = ""
    observed_at_unix_ms: int = 0
    observation_success: bool = False
    negotiated_tls_version: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    alpn_protocol: Optional[str] = None
    sni_behavior: str = TriState.UNKNOWN.value
    certificate_issuer: Optional[str] = None
    certificate_subject_cn: Optional[str] = None
    certificate_san_list: List[str] = field(default_factory=list)
    certificate_not_before: Optional[str] = None
    certificate_not_after: Optional[str] = None
    certificate_validation_type: CertValidationType = CertValidationType.UNKNOWN
    certificate_key_algorithm: Optional[str] = None
    certificate_key_size_bits: Optional[int] = None
    ocsp_stapling_status: str = TriState.UNKNOWN.value
    must_staple_status: str = TriState.UNKNOWN.value
    hsts_present: str = TriState.UNKNOWN.value
    hsts_max_age_seconds: Optional[int] = None
    hsts_include_subdomains: str = TriState.UNKNOWN.value
    hsts_preload: str = TriState.UNKNOWN.value
    tls_downgrade_surface: str = TriState.UNKNOWN.value
    zero_rtt_status: str = TriState.UNKNOWN.value
    forward_secrecy_status: str = TriState.UNKNOWN.value
    key_exchange_family: Optional[str] = None
    quantum_ready: str = TriState.UNKNOWN.value
    edge_observed: bool = True
    origin_observed: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != SIGNAL_SCHEMA_VERSION:
            raise ValueError("schema_version")
        if not self.endpoint_id:
            raise ValueError("endpoint_id")
        if self.observed_at_unix_ms < 0:
            raise ValueError("observed_at_unix_ms")
        if self.certificate_key_size_bits is not None and self.certificate_key_size_bits <= 0:
            raise ValueError("certificate_key_size_bits")
        if self.hsts_max_age_seconds is not None and self.hsts_max_age_seconds < 0:
            raise ValueError("hsts_max_age_seconds")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "endpoint_id": self.endpoint_id,
            "observed_at_unix_ms": self.observed_at_unix_ms,
            "observation_success": self.observation_success,
            "negotiated_tls_version": self.negotiated_tls_version,
            "negotiated_cipher": self.negotiated_cipher,
            "alpn_protocol": self.alpn_protocol,
            "sni_behavior": self.sni_behavior,
            "certificate_issuer": self.certificate_issuer,
            "certificate_subject_cn": self.certificate_subject_cn,
            "certificate_san_list": sorted(set(self.certificate_san_list)),
            "certificate_not_before": self.certificate_not_before,
            "certificate_not_after": self.certificate_not_after,
            "certificate_validation_type": self.certificate_validation_type.value,
            "certificate_key_algorithm": self.certificate_key_algorithm,
            "certificate_key_size_bits": self.certificate_key_size_bits,
            "ocsp_stapling_status": self.ocsp_stapling_status,
            "must_staple_status": self.must_staple_status,
            "hsts_present": self.hsts_present,
            "hsts_max_age_seconds": self.hsts_max_age_seconds,
            "hsts_include_subdomains": self.hsts_include_subdomains,
            "hsts_preload": self.hsts_preload,
            "tls_downgrade_surface": self.tls_downgrade_surface,
            "zero_rtt_status": self.zero_rtt_status,
            "forward_secrecy_status": self.forward_secrecy_status,
            "key_exchange_family": self.key_exchange_family,
            "quantum_ready": self.quantum_ready,
            "edge_observed": self.edge_observed,
            "origin_observed": self.origin_observed,
        }


@dataclass(frozen=True)
class WAFFinding:
    schema_version: str = FINDING_SCHEMA_VERSION
    finding_id: str = ""
    endpoint_id: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    title: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    compliance_controls: List[str] = field(default_factory=list)
    recommendation: str = ""
    classification_confidence: ConfidenceLevel = ConfidenceLevel.LOW
    confidence_rationale: List[str] = field(default_factory=list)
    finding_language_mode: str = FINDING_LANGUAGE_MODE_DEFENSIVE

    def __post_init__(self) -> None:
        if self.schema_version != FINDING_SCHEMA_VERSION:
            raise ValueError("schema_version")
        if not self.finding_id:
            raise ValueError("finding_id")
        if not self.endpoint_id:
            raise ValueError("endpoint_id")
        if self.finding_language_mode != FINDING_LANGUAGE_MODE_DEFENSIVE:
            raise ValueError("finding_language_mode")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "endpoint_id": self.endpoint_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "compliance_controls": sorted(set(self.compliance_controls)),
            "recommendation": self.recommendation,
            "classification_confidence": self.classification_confidence.value,
            "confidence_rationale": sorted(set(self.confidence_rationale)),
            "finding_language_mode": self.finding_language_mode,
        }


@dataclass(frozen=True)
class TLSFinding:
    schema_version: str = FINDING_SCHEMA_VERSION
    finding_id: str = ""
    endpoint_id: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    title: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    compliance_controls: List[str] = field(default_factory=list)
    recommendation: str = ""
    finding_language_mode: str = FINDING_LANGUAGE_MODE_DEFENSIVE

    def __post_init__(self) -> None:
        if self.schema_version != FINDING_SCHEMA_VERSION:
            raise ValueError("schema_version")
        if not self.finding_id:
            raise ValueError("finding_id")
        if not self.endpoint_id:
            raise ValueError("endpoint_id")
        if self.finding_language_mode != FINDING_LANGUAGE_MODE_DEFENSIVE:
            raise ValueError("finding_language_mode")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "endpoint_id": self.endpoint_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "compliance_controls": sorted(set(self.compliance_controls)),
            "recommendation": self.recommendation,
            "finding_language_mode": self.finding_language_mode,
        }


PHASE45_COMPATIBILITY_TABLE: Dict[str, Dict[str, List[str]]] = {
    "WAFPostureSignal->WAFFinding.evidence": {
        "phase4_signal_fields": [
            "waf_vendor",
            "protection_tier_inferred",
            "challenge_type",
            "classification_confidence",
            "confidence_rationale",
            "header_completeness",
            "edge_observed",
            "origin_observed",
        ],
        "phase5_derived_fields": [],
    },
    "TLSPostureSignal->TLSFinding.evidence": {
        "phase4_signal_fields": [
            "negotiated_tls_version",
            "negotiated_cipher",
            "alpn_protocol",
            "sni_behavior",
            "certificate_issuer",
            "certificate_subject_cn",
            "certificate_san_list",
            "certificate_not_before",
            "certificate_not_after",
            "certificate_validation_type",
            "certificate_key_algorithm",
            "certificate_key_size_bits",
            "ocsp_stapling_status",
            "must_staple_status",
            "hsts_present",
            "hsts_max_age_seconds",
            "hsts_include_subdomains",
            "hsts_preload",
            "tls_downgrade_surface",
            "zero_rtt_status",
            "forward_secrecy_status",
            "key_exchange_family",
            "quantum_ready",
            "edge_observed",
            "origin_observed",
        ],
        "phase5_derived_fields": [
            "ct_history_summary",
            "hndl_risk_flag",
            "compliance_mapping",
            "protection_score",
            "cryptographic_health_score",
        ],
    },
}


def _dataclass_field_names(cls: Any) -> Set[str]:
    return {f.name for f in fields(cls)}


def validate_phase45_compatibility() -> List[str]:
    errors: List[str] = []

    waf_signal_fields = _dataclass_field_names(WAFPostureSignal)
    tls_signal_fields = _dataclass_field_names(TLSPostureSignal)

    waf_required = set(PHASE45_COMPATIBILITY_TABLE["WAFPostureSignal->WAFFinding.evidence"]["phase4_signal_fields"])
    tls_required = set(PHASE45_COMPATIBILITY_TABLE["TLSPostureSignal->TLSFinding.evidence"]["phase4_signal_fields"])

    missing_waf = sorted(waf_required - waf_signal_fields)
    missing_tls = sorted(tls_required - tls_signal_fields)

    if missing_waf:
        errors.append("missing_waf_signal_fields:" + ",".join(missing_waf))
    if missing_tls:
        errors.append("missing_tls_signal_fields:" + ",".join(missing_tls))

    return errors
