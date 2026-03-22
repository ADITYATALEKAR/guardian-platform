# Phase 1 to Phase 5 Contract Compatibility (v1)

This document is the explicit producer-consumer compatibility table for:

- Phase 4 producers (`WAFPostureSignal`, `TLSPostureSignal`)
- Phase 5 consumers (`AVYAKTAWAFFinding.evidence`, `AVYAKTATLSFinding.evidence`)

## WAFPostureSignal -> AVYAKTAWAFFinding.evidence

Phase 4 signal fields required by Phase 5:

- `waf_vendor`
- `protection_tier_inferred`
- `challenge_type`
- `classification_confidence`
- `confidence_rationale`
- `header_completeness`
- `edge_observed`
- `origin_observed`

Phase 5 derived-only fields:

- none

## TLSPostureSignal -> AVYAKTATLSFinding.evidence

Phase 4 signal fields required by Phase 5:

- `negotiated_tls_version`
- `negotiated_cipher`
- `alpn_protocol`
- `sni_behavior`
- `certificate_issuer`
- `certificate_subject_cn`
- `certificate_san_list`
- `certificate_not_before`
- `certificate_not_after`
- `certificate_validation_type`
- `certificate_key_algorithm`
- `certificate_key_size_bits`
- `ocsp_stapling_status`
- `must_staple_status`
- `hsts_present`
- `hsts_max_age_seconds`
- `hsts_include_subdomains`
- `hsts_preload`
- `tls_downgrade_surface`
- `zero_rtt_status`
- `forward_secrecy_status`
- `key_exchange_family`
- `quantum_ready`
- `edge_observed`
- `origin_observed`

Phase 5 derived-only fields:

- `ct_history_summary`
- `hndl_risk_flag`
- `compliance_mapping`
- `protection_score`
- `cryptographic_health_score`

## Confidence Model

- `HIGH`: 3 or more corroborating signals
- `MEDIUM`: exactly 2 corroborating signals
- `LOW`: 0 or 1 corroborating signals

## Language Guard

- Findings must use `finding_language_mode = "defensive_posture"`.
