import json

import pytest

from infrastructure.posture.contracts_v1 import (
    FINDING_LANGUAGE_MODE_DEFENSIVE,
    FINDING_SCHEMA_VERSION,
    REPORTING_SCHEMA_VERSION,
    SIGNAL_SCHEMA_VERSION,
    CertValidationType,
    ConfidenceLevel,
    ReportingMetrics,
    TLSFinding,
    TLSPostureSignal,
    WAFFinding,
    WAFPostureSignal,
    classify_confidence,
    validate_phase45_compatibility,
)


def test_phase1_schema_versions_are_frozen() -> None:
    assert SIGNAL_SCHEMA_VERSION == "v1"
    assert FINDING_SCHEMA_VERSION == "v1"
    assert REPORTING_SCHEMA_VERSION == "v1"


@pytest.mark.parametrize(
    ("corroborating_signals", "expected"),
    [
        (0, ConfidenceLevel.LOW),
        (1, ConfidenceLevel.LOW),
        (2, ConfidenceLevel.MEDIUM),
        (3, ConfidenceLevel.HIGH),
        (5, ConfidenceLevel.HIGH),
    ],
)
def test_confidence_model_thresholds(
    corroborating_signals: int, expected: ConfidenceLevel
) -> None:
    assert classify_confidence(corroborating_signals) == expected


def test_reporting_metrics_are_validated_and_serializable() -> None:
    metrics = ReportingMetrics(
        total_discovered_domains=15,
        total_successful_observations=9,
        total_failed_observations=6,
    )
    payload = metrics.to_dict()

    assert payload["schema_version"] == "v1"
    assert payload["total_discovered_domains"] == 15
    assert payload["total_successful_observations"] == 9
    assert payload["total_failed_observations"] == 6
    json.dumps(payload, sort_keys=True)

    with pytest.raises(ValueError):
        ReportingMetrics(total_discovered_domains=-1)


def test_waf_signal_unknown_safe_and_defensive_language_guard() -> None:
    signal = WAFPostureSignal(
        endpoint_id="www.example.com:443",
        observed_at_unix_ms=123456,
        confidence_rationale=["header:server", "header:server"],
    )
    payload = signal.to_dict()

    assert payload["waf_vendor"] is None
    assert payload["classification_confidence"] == ConfidenceLevel.LOW.value
    assert payload["finding_language_mode"] == FINDING_LANGUAGE_MODE_DEFENSIVE
    assert payload["confidence_rationale"] == ["header:server"]
    json.dumps(payload, sort_keys=True)

    with pytest.raises(ValueError):
        WAFPostureSignal(
            endpoint_id="www.example.com:443",
            observed_at_unix_ms=1,
            finding_language_mode="bypass_mode",
        )


def test_tls_signal_unknown_safe_nullable_and_serializable() -> None:
    signal = TLSPostureSignal(
        endpoint_id="www.example.com:443",
        observed_at_unix_ms=123456,
        observation_success=False,
        certificate_validation_type=CertValidationType.UNKNOWN,
        certificate_san_list=["b.example.com", "a.example.com", "a.example.com"],
    )
    payload = signal.to_dict()

    assert payload["certificate_validation_type"] == CertValidationType.UNKNOWN.value
    assert payload["negotiated_tls_version"] is None
    assert payload["certificate_san_list"] == ["a.example.com", "b.example.com"]
    json.dumps(payload, sort_keys=True)

    with pytest.raises(ValueError):
        TLSPostureSignal(
            endpoint_id="www.example.com:443",
            observed_at_unix_ms=1,
            certificate_key_size_bits=0,
        )


def test_split_finding_schemas_are_independent() -> None:
    waf_finding = WAFFinding(
        finding_id="AVY-WAF-001",
        endpoint_id="www.example.com:443",
        title="WAF Signature Detection Gap",
        description="Control effectiveness finding",
        evidence={"waf_vendor": "Cloudflare"},
    )
    tls_finding = TLSFinding(
        finding_id="AVY-TLS-001",
        endpoint_id="www.example.com:443",
        title="Legacy TLS Accepted",
        description="Cryptographic finding",
        evidence={"negotiated_tls_version": "TLSv1.2"},
    )

    waf_payload = waf_finding.to_dict()
    tls_payload = tls_finding.to_dict()

    assert "classification_confidence" in waf_payload
    assert "classification_confidence" not in tls_payload
    assert waf_payload["finding_language_mode"] == FINDING_LANGUAGE_MODE_DEFENSIVE
    assert tls_payload["finding_language_mode"] == FINDING_LANGUAGE_MODE_DEFENSIVE
    json.dumps(waf_payload, sort_keys=True)
    json.dumps(tls_payload, sort_keys=True)


def test_phase45_contract_compatibility_table_matches_contracts() -> None:
    assert validate_phase45_compatibility() == []
