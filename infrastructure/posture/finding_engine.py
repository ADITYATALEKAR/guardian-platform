from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

from infrastructure.policy_integration.compliance import (
    map_tls_controls_for_frameworks,
    map_waf_controls_for_frameworks,
)

from .contracts_v1 import (
    FINDING_LANGUAGE_MODE_DEFENSIVE,
    ConfidenceLevel,
    FindingSeverity,
    TLSFinding,
    TriState,
    WAFFinding,
)
from .ct_longitudinal import CTLongitudinalAnalyzer


@dataclass(frozen=True)
class PostureFindingEvaluation:
    waf_findings: List[Dict[str, Any]]
    tls_findings: List[Dict[str, Any]]
    scores: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "waf_findings": self.waf_findings,
            "tls_findings": self.tls_findings,
            "scores": self.scores,
        }


class PostureFindingEngine:
    _DISALLOWED_LANGUAGE_TERMS = ("bypass", "evade", "circumvent", "exploit")

    def __init__(
        self,
        *,
        enable_ct_longitudinal: bool = False,
        ct_analyzer: Optional[CTLongitudinalAnalyzer] = None,
        max_ct_calls_per_cycle: int = 1,
    ) -> None:
        self._ct_analyzer = ct_analyzer or CTLongitudinalAnalyzer(
            enabled=enable_ct_longitudinal
        )
        self._max_ct_calls_per_cycle = max(0, int(max_ct_calls_per_cycle))
        self._ct_calls_remaining = self._max_ct_calls_per_cycle
        self._lock = threading.Lock()

    def begin_cycle(self, *, enable_ct_longitudinal: Optional[bool] = None) -> None:
        with self._lock:
            if enable_ct_longitudinal is not None:
                self._ct_analyzer.enabled = bool(enable_ct_longitudinal)
            self._ct_calls_remaining = self._max_ct_calls_per_cycle

    def evaluate_from_signal_dicts(
        self,
        posture_signals: Iterable[Dict[str, Any]],
        *,
        tenant_frameworks: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        waf_signal, tls_signal = self._split_signals(posture_signals)
        if not waf_signal and not tls_signal:
            return PostureFindingEvaluation(
                waf_findings=[],
                tls_findings=[],
                scores={
                    "cryptographic_health_score": 0,
                    "protection_posture_score": 0,
                    "hndl_risk_flag": False,
                    "quantum_ready": TriState.UNKNOWN.value,
                },
            ).to_dict()

        waf_findings = self._build_waf_findings(
            waf_signal,
            tenant_frameworks=tenant_frameworks,
        )
        tls_findings, tls_summary = self._build_tls_findings(
            tls_signal,
            tenant_frameworks=tenant_frameworks,
        )

        crypto_score = self._score_cryptographic_health(tls_signal)
        protection_score = self._score_protection_posture(waf_signal, crypto_score)

        return PostureFindingEvaluation(
            waf_findings=[f.to_dict() for f in waf_findings],
            tls_findings=[f.to_dict() for f in tls_findings],
            scores={
                "cryptographic_health_score": crypto_score,
                "protection_posture_score": protection_score,
                "hndl_risk_flag": bool(tls_summary.get("hndl_risk_flag", False)),
                "quantum_ready": str(
                    (tls_signal or {}).get("quantum_ready", TriState.UNKNOWN.value)
                ),
                "ct_history_summary": tls_summary.get("ct_history_summary", {}),
            },
        ).to_dict()

    def _split_signals(
        self,
        posture_signals: Iterable[Dict[str, Any]],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        waf_signal: Optional[Dict[str, Any]] = None
        tls_signal: Optional[Dict[str, Any]] = None
        for signal in posture_signals or []:
            if not isinstance(signal, dict):
                continue
            if "waf_vendor" in signal and "classification_confidence" in signal:
                waf_signal = signal
            if "negotiated_tls_version" in signal and "quantum_ready" in signal:
                tls_signal = signal
        return waf_signal, tls_signal

    def _build_waf_findings(
        self,
        waf_signal: Optional[Dict[str, Any]],
        *,
        tenant_frameworks: Optional[Iterable[str]],
    ) -> List[WAFFinding]:
        if not waf_signal:
            return []

        endpoint = str(waf_signal.get("endpoint_id", "")).strip()
        if not endpoint:
            return []

        confidence = self._parse_confidence(
            str(waf_signal.get("classification_confidence", ConfidenceLevel.LOW.value))
        )
        rationale = [
            str(item).strip()
            for item in (waf_signal.get("confidence_rationale") or [])
            if str(item).strip()
        ]
        vendor = waf_signal.get("waf_vendor")
        header_completeness = str(waf_signal.get("header_completeness", "UNKNOWN"))
        challenge_type = waf_signal.get("challenge_type")

        findings: List[WAFFinding] = []
        if vendor:
            title = "WAF posture observed"
            description = (
                "Edge protection signals were observed with confidence scoring for control-effectiveness assessment."
            )
            recommendation = (
                "Continue monitoring WAF telemetry and validate behavioral controls under production traffic patterns."
            )
            self._enforce_defensive_language(title, description, recommendation)
            findings.append(
                WAFFinding(
                    finding_id="WAF-POSTURE-001",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.INFO,
                    title=title,
                    description=description,
                    evidence={
                        "waf_vendor": vendor,
                        "protection_tier_inferred": waf_signal.get("protection_tier_inferred"),
                        "challenge_type": challenge_type,
                        "header_completeness": header_completeness,
                        "classification_confidence": confidence.value,
                        "confidence_rationale": sorted(set(rationale)),
                    },
                    compliance_controls=map_waf_controls_for_frameworks(
                        ["waf_observed"],
                        tenant_frameworks,
                    ),
                    recommendation=recommendation,
                    classification_confidence=confidence,
                    confidence_rationale=rationale,
                    finding_language_mode=FINDING_LANGUAGE_MODE_DEFENSIVE,
                )
            )

        if (
            vendor
            and challenge_type in {"forbidden_or_challenge", "rate_limited"}
            and header_completeness in {"FULL", "PARTIAL"}
        ):
            title = "WAF signature detection may be insufficient"
            description = (
                "The endpoint remained reachable for protocol-level analysis despite active challenge behavior, "
                "indicating potential reliance on signature-oriented controls."
            )
            recommendation = (
                "Prioritize behavioral bot scoring and request-sequence validation in addition to signature rules."
            )
            self._enforce_defensive_language(title, description, recommendation)
            findings.append(
                WAFFinding(
                    finding_id="WAF-CONTROL-002",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.MEDIUM,
                    title=title,
                    description=description,
                    evidence={
                        "waf_vendor": vendor,
                        "challenge_type": challenge_type,
                        "header_completeness": header_completeness,
                        "classification_confidence": confidence.value,
                    },
                    compliance_controls=map_waf_controls_for_frameworks(
                        ["waf_signature_gap"],
                        tenant_frameworks,
                    ),
                    recommendation=recommendation,
                    classification_confidence=confidence,
                    confidence_rationale=rationale,
                    finding_language_mode=FINDING_LANGUAGE_MODE_DEFENSIVE,
                )
            )

        return findings

    def _build_tls_findings(
        self,
        tls_signal: Optional[Dict[str, Any]],
        *,
        tenant_frameworks: Optional[Iterable[str]],
    ) -> Tuple[List[TLSFinding], Dict[str, Any]]:
        if not tls_signal:
            return [], {"hndl_risk_flag": False, "ct_history_summary": {}}

        endpoint = str(tls_signal.get("endpoint_id", "")).strip()
        if not endpoint:
            return [], {"hndl_risk_flag": False, "ct_history_summary": {}}

        ct_summary = self._summarize_ct_with_budget(self._endpoint_host(endpoint))
        findings: List[TLSFinding] = []
        issue_tags: List[str] = []
        hndl_risk_flag = self._is_hndl_risk(tls_signal)

        tls_version = str(tls_signal.get("negotiated_tls_version") or "")
        if tls_version.upper() in {"TLSV1", "TLSV1.0", "TLSV1.1"}:
            issue_tags.append("tls_legacy_version")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-PROTOCOL-001",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.CRITICAL,
                    title="Legacy TLS protocol negotiated",
                    description="Legacy TLS protocol versions were observed and increase cryptographic exposure.",
                    evidence={
                        "negotiated_tls_version": tls_version,
                        "tls_downgrade_surface": tls_signal.get("tls_downgrade_surface"),
                    },
                    recommendation="Disable TLS 1.0/1.1 and enforce modern protocol policy.",
                    tags=["tls_legacy_version"],
                    tenant_frameworks=tenant_frameworks,
                )
            )
        elif tls_version.upper() in {"TLSV1.2", "TLS 1.2"}:
            issue_tags.append("tls_downgrade_surface")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-PROTOCOL-002",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.MEDIUM,
                    title="TLS downgrade surface present",
                    description="TLS 1.2 negotiation indicates a downgrade surface relative to stricter TLS 1.3-only posture.",
                    evidence={
                        "negotiated_tls_version": tls_version,
                        "tls_downgrade_surface": tls_signal.get("tls_downgrade_surface"),
                    },
                    recommendation="Assess TLS 1.3-only policy where client compatibility permits.",
                    tags=["tls_downgrade_surface"],
                    tenant_frameworks=tenant_frameworks,
                )
            )

        if str(tls_signal.get("forward_secrecy_status")) == TriState.NO.value:
            issue_tags.append("forward_secrecy_absent")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-CRYPTO-003",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.HIGH,
                    title="Forward secrecy not observed",
                    description="Session key exchange does not indicate forward secrecy and increases retrospective decryption risk.",
                    evidence={
                        "forward_secrecy_status": tls_signal.get("forward_secrecy_status"),
                        "key_exchange_family": tls_signal.get("key_exchange_family"),
                    },
                    recommendation="Prefer ECDHE or TLS 1.3 key exchange suites with forward secrecy.",
                    tags=["forward_secrecy_absent"],
                    tenant_frameworks=tenant_frameworks,
                )
            )

        if str(tls_signal.get("quantum_ready")) == TriState.NO.value:
            issue_tags.append("quantum_not_ready")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-QUANTUM-004",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.HIGH,
                    title="Quantum readiness not observed",
                    description="Observed key exchange posture is not post-quantum capable under current signal set.",
                    evidence={
                        "quantum_ready": tls_signal.get("quantum_ready"),
                        "certificate_key_algorithm": tls_signal.get("certificate_key_algorithm"),
                        "key_exchange_family": tls_signal.get("key_exchange_family"),
                    },
                    recommendation="Establish a phased PQC readiness roadmap and monitor hybrid deployment options.",
                    tags=["quantum_not_ready"],
                    tenant_frameworks=tenant_frameworks,
                )
            )

        cert_type = str(tls_signal.get("certificate_validation_type") or "")
        if cert_type.upper() == "DV":
            issue_tags.append("dv_certificate")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-CERT-005",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.MEDIUM,
                    title="Domain-validated certificate observed",
                    description="Certificate validation indicates domain-only assurance without organization identity signals.",
                    evidence={
                        "certificate_validation_type": cert_type,
                        "certificate_issuer": tls_signal.get("certificate_issuer"),
                    },
                    recommendation="Use OV/EV certificates for high-assurance endpoints where policy requires stronger identity binding.",
                    tags=["dv_certificate"],
                    tenant_frameworks=tenant_frameworks,
                )
            )

        hsts_present = str(tls_signal.get("hsts_present"))
        hsts_age = tls_signal.get("hsts_max_age_seconds")
        if hsts_present == TriState.NO.value:
            issue_tags.append("hsts_missing")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-HSTS-006",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.HIGH,
                    title="HSTS policy missing",
                    description="Strict-Transport-Security policy was not observed in HTTP response headers.",
                    evidence={
                        "hsts_present": hsts_present,
                        "hsts_max_age_seconds": hsts_age,
                    },
                    recommendation="Enable HSTS with includeSubDomains and preload where applicable.",
                    tags=["hsts_missing"],
                    tenant_frameworks=tenant_frameworks,
                )
            )
        elif isinstance(hsts_age, int) and hsts_age < 31536000:
            issue_tags.append("hsts_weak")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-HSTS-007",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.MEDIUM,
                    title="HSTS max-age below long-term baseline",
                    description="HSTS max-age is below one-year baseline and may reduce long-term transport hardening.",
                    evidence={
                        "hsts_present": hsts_present,
                        "hsts_max_age_seconds": hsts_age,
                        "hsts_include_subdomains": tls_signal.get("hsts_include_subdomains"),
                        "hsts_preload": tls_signal.get("hsts_preload"),
                    },
                    recommendation="Increase HSTS max-age and align includeSubDomains/preload to policy requirements.",
                    tags=["hsts_weak"],
                    tenant_frameworks=tenant_frameworks,
                )
            )

        if (
            str(tls_signal.get("ocsp_stapling_status")) == TriState.NO.value
            and str(tls_signal.get("must_staple_status")) in {TriState.NO.value, TriState.UNKNOWN.value}
        ):
            issue_tags.append("ocsp_soft_fail")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-REVOCATION-008",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.MEDIUM,
                    title="Revocation hardening gap observed",
                    description="OCSP stapling hardening is not evident and revocation may depend on soft-fail client behavior.",
                    evidence={
                        "ocsp_stapling_status": tls_signal.get("ocsp_stapling_status"),
                        "must_staple_status": tls_signal.get("must_staple_status"),
                    },
                    recommendation="Enable OCSP stapling and evaluate Must-Staple policy for high-assurance endpoints.",
                    tags=["ocsp_soft_fail"],
                    tenant_frameworks=tenant_frameworks,
                )
            )

        if hndl_risk_flag:
            issue_tags.append("hndl_risk")
            findings.append(
                self._tls_finding(
                    finding_id="TLS-QUANTUM-009",
                    endpoint_id=endpoint,
                    severity=FindingSeverity.HIGH,
                    title="Harvest-now-decrypt-later risk elevated",
                    description=(
                        "Observed cryptographic posture can increase future decryption risk if adversaries archive traffic today."
                    ),
                    evidence={
                        "hndl_risk_flag": True,
                        "quantum_ready": tls_signal.get("quantum_ready"),
                        "forward_secrecy_status": tls_signal.get("forward_secrecy_status"),
                    },
                    recommendation="Prioritize PQC transition planning and forward-secrecy enforcement for sensitive traffic.",
                    tags=["hndl_risk"],
                    tenant_frameworks=tenant_frameworks,
                )
            )

        if findings:
            controls = map_tls_controls_for_frameworks(
                issue_tags,
                tenant_frameworks,
            )
            enriched: List[TLSFinding] = []
            for finding in findings:
                evidence = dict(finding.evidence)
                evidence["ct_history_summary"] = ct_summary
                enriched.append(
                    TLSFinding(
                        finding_id=finding.finding_id,
                        endpoint_id=finding.endpoint_id,
                        severity=finding.severity,
                        title=finding.title,
                        description=finding.description,
                        evidence=evidence,
                        compliance_controls=controls if not finding.compliance_controls else finding.compliance_controls,
                        recommendation=finding.recommendation,
                        finding_language_mode=finding.finding_language_mode,
                    )
                )
            findings = enriched

        return findings, {"hndl_risk_flag": hndl_risk_flag, "ct_history_summary": ct_summary}

    def _tls_finding(
        self,
        *,
        finding_id: str,
        endpoint_id: str,
        severity: FindingSeverity,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        recommendation: str,
        tags: List[str],
        tenant_frameworks: Optional[Iterable[str]],
    ) -> TLSFinding:
        self._enforce_defensive_language(title, description, recommendation)
        return TLSFinding(
            finding_id=finding_id,
            endpoint_id=endpoint_id,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            compliance_controls=map_tls_controls_for_frameworks(
                tags,
                tenant_frameworks,
            ),
            recommendation=recommendation,
            finding_language_mode=FINDING_LANGUAGE_MODE_DEFENSIVE,
        )

    def _summarize_ct_with_budget(self, domain: str) -> Dict[str, Any]:
        if not self._ct_analyzer.enabled:
            return self._ct_analyzer.summarize_domain(domain)

        with self._lock:
            if self._ct_calls_remaining <= 0:
                return {
                    "status": "deferred",
                    "domain": domain,
                    "reason": "ct_budget_exhausted",
                    "issuance_count": 0,
                    "shadow_subdomains": [],
                    "algorithm_timeline": [],
                }
            self._ct_calls_remaining -= 1
        return self._ct_analyzer.summarize_domain(domain)

    def _score_cryptographic_health(self, tls_signal: Optional[Dict[str, Any]]) -> int:
        if not tls_signal:
            return 0

        score = 100
        tls_version = str(tls_signal.get("negotiated_tls_version") or "").upper()
        if tls_version in {"TLSV1", "TLSV1.0", "TLSV1.1"}:
            score -= 40
        elif tls_version in {"TLSV1.2", "TLS 1.2"}:
            score -= 15

        if str(tls_signal.get("forward_secrecy_status")) == TriState.NO.value:
            score -= 20
        if str(tls_signal.get("quantum_ready")) == TriState.NO.value:
            score -= 25

        hsts_present = str(tls_signal.get("hsts_present"))
        hsts_age = tls_signal.get("hsts_max_age_seconds")
        if hsts_present == TriState.NO.value:
            score -= 15
        elif isinstance(hsts_age, int) and hsts_age < 31536000:
            score -= 8

        if str(tls_signal.get("certificate_validation_type", "")).upper() == "DV":
            score -= 10
        if str(tls_signal.get("ocsp_stapling_status")) == TriState.NO.value:
            score -= 5

        return max(0, min(100, int(score)))

    def _score_protection_posture(
        self,
        waf_signal: Optional[Dict[str, Any]],
        cryptographic_health_score: int,
    ) -> int:
        waf_score = 100
        if not waf_signal:
            waf_score -= 30
        else:
            if not waf_signal.get("waf_vendor"):
                waf_score -= 20
            challenge_type = str(waf_signal.get("challenge_type") or "")
            if not challenge_type:
                waf_score -= 10
            completeness = str(waf_signal.get("header_completeness") or "UNKNOWN")
            if completeness == "MINIMAL":
                waf_score -= 15
            elif completeness == "PARTIAL":
                waf_score -= 8
            confidence = self._parse_confidence(
                str(waf_signal.get("classification_confidence") or ConfidenceLevel.LOW.value)
            )
            if confidence == ConfidenceLevel.LOW:
                waf_score -= 10
            elif confidence == ConfidenceLevel.MEDIUM:
                waf_score -= 5

        waf_score = max(0, min(100, int(waf_score)))
        return max(0, min(100, int((waf_score + int(cryptographic_health_score)) / 2)))

    @staticmethod
    def _is_hndl_risk(tls_signal: Dict[str, Any]) -> bool:
        quantum_ready = str(tls_signal.get("quantum_ready", TriState.UNKNOWN.value))
        forward_secrecy = str(
            tls_signal.get("forward_secrecy_status", TriState.UNKNOWN.value)
        )
        return quantum_ready == TriState.NO.value and forward_secrecy != TriState.YES.value

    @staticmethod
    def _endpoint_host(endpoint_id: str) -> str:
        token = str(endpoint_id or "").strip().lower()
        if ":" in token:
            return token.rsplit(":", 1)[0]
        return token

    @staticmethod
    def _parse_confidence(value: str) -> ConfidenceLevel:
        token = str(value or "").strip().upper()
        for level in ConfidenceLevel:
            if level.value == token:
                return level
        return ConfidenceLevel.LOW

    def _enforce_defensive_language(self, *texts: str) -> None:
        lowered = " ".join(str(t or "").lower() for t in texts)
        for token in self._DISALLOWED_LANGUAGE_TERMS:
            if token in lowered:
                raise RuntimeError("finding language guard violation")
