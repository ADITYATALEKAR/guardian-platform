from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .contracts_v1 import (
    CertValidationType,
    ConfidenceLevel,
    TLSPostureSignal,
    TriState,
    WAFPostureSignal,
    classify_confidence,
)


class PostureSignalExtractor:
    """
    Extract WAF and TLS posture signals from protocol observer output.

    This extractor is intentionally conservative:
    - observed values are emitted directly
    - inferred values are confidence-scored
    - unknowns remain explicit (never silently converted)
    """

    _WAF_VENDOR_RULES: Dict[str, Tuple[str, ...]] = {
        "Cloudflare": ("cf-ray", "cf-cache-status", "server:cloudflare", "__cf", "cf-chl"),
        "Akamai": ("server:akamaighost", "x-akamai", "akamai"),
        "Imperva": ("x-iinfo", "incap_ses", "visid_incap", "incapsula"),
        "AWS": ("x-amz-cf-id", "cloudfront", "x-cache:error from cloudfront"),
        "F5": ("bigip", "ts01", "x-wa-info"),
    }

    _EDGE_HINTS: Tuple[str, ...] = (
        "cloudflare",
        "akamai",
        "incapsula",
        "imperva",
        "cloudfront",
        "fastly",
        "edgecast",
        "sucuri",
    )

    def extract_as_dicts(self, raw_observation: Any) -> List[Dict[str, Any]]:
        waf, tls = self.extract(raw_observation)
        return [waf.to_dict(), tls.to_dict()]

    def extract(self, raw_observation: Any) -> Tuple[WAFPostureSignal, TLSPostureSignal]:
        endpoint = str(
            getattr(raw_observation, "endpoint", "")
            or getattr(raw_observation, "endpoint_str", "")
            or ""
        ).strip()
        if not endpoint:
            raise RuntimeError("invalid observation endpoint")

        observed_at = int(
            getattr(raw_observation, "timestamp_ms", 0)
            or getattr(raw_observation, "observed_at_unix_ms", 0)
            or 0
        )
        if observed_at < 0:
            observed_at = 0

        http = getattr(raw_observation, "http", None)
        tls = getattr(raw_observation, "tls", None)

        headers = self._normalized_headers(http)
        http_status = self._http_status(http)

        waf_signal = self._build_waf_signal(
            endpoint=endpoint,
            observed_at_unix_ms=observed_at,
            headers=headers,
            http_status=http_status,
        )
        tls_signal = self._build_tls_signal(
            endpoint=endpoint,
            observed_at_unix_ms=observed_at,
            tls=tls,
            headers=headers,
            observation_success=bool(getattr(raw_observation, "success", False)),
            edge_observed=waf_signal.edge_observed,
        )
        return waf_signal, tls_signal

    def _build_waf_signal(
        self,
        *,
        endpoint: str,
        observed_at_unix_ms: int,
        headers: Dict[str, str],
        http_status: Optional[int],
    ) -> WAFPostureSignal:
        vendor, rationale = self._infer_waf_vendor(headers)
        confidence = classify_confidence(len(rationale))
        challenge_type = self._infer_challenge_type(http_status)
        tier = self._infer_protection_tier(http_status=http_status, vendor=vendor)
        header_completeness = self._header_completeness(headers)

        server = headers.get("server", "").lower()
        edge_observed = bool(
            vendor
            or any(hint in server for hint in self._EDGE_HINTS)
        )

        return WAFPostureSignal(
            endpoint_id=endpoint,
            observed_at_unix_ms=observed_at_unix_ms,
            http_status=http_status,
            waf_vendor=vendor,
            protection_tier_inferred=tier,
            challenge_type=challenge_type,
            header_completeness=header_completeness,
            classification_confidence=confidence,
            confidence_rationale=rationale,
            edge_observed=edge_observed,
            origin_observed=not edge_observed and http_status is not None,
        )

    def _build_tls_signal(
        self,
        *,
        endpoint: str,
        observed_at_unix_ms: int,
        tls: Any,
        headers: Dict[str, str],
        observation_success: bool,
        edge_observed: bool,
    ) -> TLSPostureSignal:
        tls_version = self._safe_str(getattr(tls, "tls_version", None))
        cipher = self._safe_str(getattr(tls, "cipher_suite", None))
        key_algorithm = self._safe_str(getattr(tls, "cert_public_key_algorithm", None))
        key_size = getattr(tls, "cert_public_key_size_bits", None)
        key_size_bits: Optional[int]
        if isinstance(key_size, int) and key_size > 0:
            key_size_bits = key_size
        else:
            key_size_bits = None

        cert_subject = self._safe_str(getattr(tls, "cert_subject", None))
        cert_issuer = self._safe_str(getattr(tls, "cert_issuer", None))
        cert_san = list(getattr(tls, "cert_san", []) or [])
        cert_validation = self._classify_certificate_validation(cert_subject)

        hsts_header = headers.get("strict-transport-security")
        hsts_present = TriState.UNKNOWN.value
        hsts_max_age: Optional[int] = None
        hsts_include_subdomains = TriState.UNKNOWN.value
        hsts_preload = TriState.UNKNOWN.value
        if headers:
            hsts_present = TriState.YES.value if hsts_header else TriState.NO.value
        if hsts_header:
            hsts_max_age = self._parse_hsts_max_age(hsts_header)
            hsts_include_subdomains = (
                TriState.YES.value
                if "includesubdomains" in hsts_header.lower()
                else TriState.NO.value
            )
            hsts_preload = (
                TriState.YES.value
                if "preload" in hsts_header.lower()
                else TriState.NO.value
            )

        sni_behavior = TriState.UNKNOWN.value
        sni_mismatch = getattr(tls, "sni_mismatch", None)
        if sni_mismatch is True:
            sni_behavior = TriState.NO.value
        elif sni_mismatch is False:
            sni_behavior = TriState.YES.value
        elif self._safe_str(getattr(tls, "error", None)).lower().find("hostname") >= 0:
            sni_behavior = TriState.NO.value

        ocsp_stapled = getattr(tls, "ocsp_stapled", None)
        if ocsp_stapled is True:
            ocsp_status = TriState.YES.value
        elif ocsp_stapled is False:
            ocsp_status = TriState.NO.value
        else:
            ocsp_status = TriState.UNKNOWN.value

        must_staple = getattr(tls, "cert_must_staple", None)
        if must_staple is True:
            must_staple_status = TriState.YES.value
        elif must_staple is False:
            must_staple_status = TriState.NO.value
        else:
            must_staple_status = TriState.UNKNOWN.value

        key_exchange_family = self._infer_key_exchange_family(tls_version=tls_version, cipher=cipher)
        forward_secrecy = self._forward_secrecy_status(key_exchange_family)
        downgrade_surface = self._downgrade_surface_status(tls_version)
        zero_rtt = self._zero_rtt_status(tls, headers)
        quantum_ready = self._quantum_ready_status(key_algorithm, cipher)

        return TLSPostureSignal(
            endpoint_id=endpoint,
            observed_at_unix_ms=observed_at_unix_ms,
            observation_success=observation_success,
            negotiated_tls_version=tls_version,
            negotiated_cipher=cipher,
            alpn_protocol=self._safe_str(getattr(tls, "alpn_protocol", None)),
            sni_behavior=sni_behavior,
            certificate_issuer=cert_issuer,
            certificate_subject_cn=self._extract_common_name(cert_subject),
            certificate_san_list=cert_san,
            certificate_not_before=self._safe_str(getattr(tls, "cert_not_before", None)),
            certificate_not_after=self._safe_str(getattr(tls, "cert_not_after", None)),
            certificate_validation_type=cert_validation,
            certificate_key_algorithm=key_algorithm,
            certificate_key_size_bits=key_size_bits,
            ocsp_stapling_status=ocsp_status,
            must_staple_status=must_staple_status,
            hsts_present=hsts_present,
            hsts_max_age_seconds=hsts_max_age,
            hsts_include_subdomains=hsts_include_subdomains,
            hsts_preload=hsts_preload,
            tls_downgrade_surface=downgrade_surface,
            zero_rtt_status=zero_rtt,
            forward_secrecy_status=forward_secrecy,
            key_exchange_family=key_exchange_family,
            quantum_ready=quantum_ready,
            edge_observed=edge_observed,
            origin_observed=not edge_observed and observation_success,
        )

    def _infer_waf_vendor(self, headers: Dict[str, str]) -> Tuple[Optional[str], List[str]]:
        header_pairs = [f"{k}:{v}".lower() for k, v in headers.items()]
        flat = " | ".join(header_pairs)
        best_vendor: Optional[str] = None
        best_hits: List[str] = []

        for vendor, patterns in self._WAF_VENDOR_RULES.items():
            hits: List[str] = []
            for pattern in patterns:
                pattern_l = pattern.lower()
                if ":" in pattern_l:
                    if pattern_l in flat:
                        hits.append(f"match:{pattern_l}")
                else:
                    if pattern_l in headers or any(pattern_l in pair for pair in header_pairs):
                        hits.append(f"match:{pattern_l}")
            if len(hits) > len(best_hits):
                best_vendor = vendor
                best_hits = hits

        return best_vendor, sorted(set(best_hits))

    @staticmethod
    def _infer_challenge_type(http_status: Optional[int]) -> Optional[str]:
        if http_status == 403:
            return "forbidden_or_challenge"
        if http_status == 429:
            return "rate_limited"
        if http_status == 503:
            return "challenge_or_upstream_block"
        if http_status in (401, 407):
            return "auth_gate"
        return None

    @staticmethod
    def _infer_protection_tier(*, http_status: Optional[int], vendor: Optional[str]) -> Optional[str]:
        if not vendor:
            return None
        if http_status in (403, 429, 503):
            return "managed_protection"
        if http_status in (200, 301, 302):
            return "edge_protected_pass_through"
        return "edge_protection_detected"

    @staticmethod
    def _header_completeness(headers: Dict[str, str]) -> str:
        if not headers:
            return "UNKNOWN"
        security_keys = {
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
        }
        total = len(headers)
        security_count = sum(1 for k in headers if k in security_keys)
        if total >= 12 and security_count >= 2:
            return "FULL"
        if total >= 6:
            return "PARTIAL"
        return "MINIMAL"

    @staticmethod
    def _normalized_headers(http: Any) -> Dict[str, str]:
        raw_headers = getattr(http, "headers", {}) if http is not None else {}
        if not isinstance(raw_headers, dict):
            return {}
        out: Dict[str, str] = {}
        for key, value in raw_headers.items():
            k = str(key or "").strip().lower()
            if not k:
                continue
            out[k] = str(value or "").strip()
        return out

    @staticmethod
    def _http_status(http: Any) -> Optional[int]:
        status = getattr(http, "status_code", None) if http is not None else None
        if isinstance(status, int):
            return status
        return None

    @staticmethod
    def _safe_str(value: Any) -> Optional[str]:
        if value is None:
            return None
        token = str(value).strip()
        return token if token else None

    @staticmethod
    def _extract_common_name(subject: Optional[str]) -> Optional[str]:
        if not subject:
            return None
        for part in subject.split(","):
            item = part.strip()
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            if key.strip().lower() in {"commonname", "cn"}:
                cn = value.strip()
                return cn or None
        return None

    @staticmethod
    def _classify_certificate_validation(subject: Optional[str]) -> CertValidationType:
        if not subject:
            return CertValidationType.UNKNOWN

        attrs: Dict[str, str] = {}
        for part in subject.split(","):
            item = part.strip()
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            attrs[key.strip().lower()] = value.strip()

        has_org = bool(attrs.get("organizationname") or attrs.get("o"))
        if not has_org:
            return CertValidationType.DV

        ev_markers = {
            "businesscategory",
            "serialnumber",
            "organizationidentifier",
            "jurisdictioncountryname",
            "jurisdictionstprovincename",
            "jurisdictionlocalityname",
        }
        if any(marker in attrs for marker in ev_markers):
            return CertValidationType.EV
        return CertValidationType.OV

    @staticmethod
    def _parse_hsts_max_age(hsts_value: str) -> Optional[int]:
        value = str(hsts_value or "").lower()
        parts = [p.strip() for p in value.split(";")]
        for part in parts:
            if part.startswith("max-age="):
                raw = part.split("=", 1)[1].strip()
                try:
                    n = int(raw)
                except Exception:
                    return None
                return n if n >= 0 else None
        return None

    @staticmethod
    def _infer_key_exchange_family(*, tls_version: Optional[str], cipher: Optional[str]) -> Optional[str]:
        c = str(cipher or "").upper()
        v = str(tls_version or "").upper()
        if not c and not v:
            return None
        if v in {"TLSV1.3", "TLS 1.3"}:
            return "TLS13_AEAD"
        if "ECDHE" in c:
            return "ECDHE"
        if "DHE" in c:
            return "DHE"
        if "RSA" in c:
            return "RSA"
        if "KYBER" in c or "MLKEM" in c:
            return "PQC_HYBRID"
        return "UNKNOWN"

    @staticmethod
    def _forward_secrecy_status(key_exchange_family: Optional[str]) -> str:
        k = str(key_exchange_family or "").upper()
        if k in {"ECDHE", "DHE", "TLS13_AEAD", "PQC_HYBRID"}:
            return TriState.YES.value
        if k == "RSA":
            return TriState.NO.value
        return TriState.UNKNOWN.value

    @staticmethod
    def _downgrade_surface_status(tls_version: Optional[str]) -> str:
        version = str(tls_version or "").upper()
        if version in {"TLSV1", "TLSV1.0", "TLSV1.1", "TLSV1.2", "TLS 1.2"}:
            return TriState.YES.value
        if version in {"TLSV1.3", "TLS 1.3"}:
            return TriState.UNKNOWN.value
        return TriState.UNKNOWN.value

    @staticmethod
    def _zero_rtt_status(tls: Any, headers: Dict[str, str]) -> str:
        # Python stdlib does not reliably expose 0-RTT acceptance per connection.
        # If an explicit early-data hint appears, mark YES; else UNKNOWN.
        hints: Iterable[str] = getattr(tls, "cert_extension_hints", []) or []
        hint_text = " ".join(str(h) for h in hints).lower()
        server_hint = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        if "early_data" in hint_text or "early-data" in server_hint:
            return TriState.YES.value
        return TriState.UNKNOWN.value

    @staticmethod
    def _quantum_ready_status(key_algorithm: Optional[str], cipher: Optional[str]) -> str:
        combined = f"{key_algorithm or ''} {cipher or ''}".upper()
        if any(tag in combined for tag in ("KYBER", "MLKEM", "DILITHIUM", "SPHINCS")):
            return TriState.YES.value
        if any(tag in combined for tag in ("RSA", "ECDSA", "ED25519", "ED448", "EC")):
            return TriState.NO.value
        return TriState.UNKNOWN.value
