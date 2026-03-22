from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

from infrastructure.storage_manager.storage_manager import StorageManager

from ..policies.policy_store import PolicyStore


_TLS_CONTROL_MAP: Dict[str, List[str]] = {
    "tls_legacy_version": [
        "PCI-DSS v4.0 Req 4.2.1",
        "RBI Cybersecurity Framework Section 4",
        "SEBI CSCRF Annex II",
    ],
    "tls_downgrade_surface": [
        "PCI-DSS v4.0 Req 4.2.1",
        "RBI Cybersecurity Framework Section 4",
    ],
    "forward_secrecy_absent": [
        "PCI-DSS v4.0 Req 4.2.1",
        "RBI Cybersecurity Framework Section 4",
    ],
    "quantum_not_ready": [
        "NIST IR 8413",
        "G7 Fundamental Elements for Quantum Readiness",
        "RBI Quantum Risk Advisory",
    ],
    "hndl_risk": [
        "NIST IR 8413",
        "RBI Quantum Risk Advisory",
    ],
    "hsts_missing": [
        "PCI-DSS v4.0 Req 6.4",
        "SEBI CSCRF Annex II",
    ],
    "hsts_weak": [
        "PCI-DSS v4.0 Req 6.4",
        "SEBI CSCRF Annex II",
    ],
    "ocsp_soft_fail": [
        "PCI-DSS v4.0 Req 4.2.1",
        "RBI Cybersecurity Framework Section 4",
    ],
    "dv_certificate": [
        "PCI-DSS v4.0 Req 4.2.1",
        "RBI Cybersecurity Framework Section 4",
    ],
}

_WAF_CONTROL_MAP: Dict[str, List[str]] = {
    "waf_observed": [
        "PCI-DSS v4.0 Req 6.4.2",
        "RBI Cybersecurity Framework Section 4.2",
        "SEBI CSCRF Annex II",
    ],
    "waf_signature_gap": [
        "PCI-DSS v4.0 Req 6.4.2",
        "RBI Cybersecurity Framework Section 4.2",
        "SEBI CSCRF Annex II",
    ],
    "waf_low_confidence": [
        "PCI-DSS v4.0 Req 6.4.2",
    ],
}


def map_tls_controls(issue_tags: Iterable[str]) -> List[str]:
    return _map_controls(issue_tags, _TLS_CONTROL_MAP)


def map_waf_controls(issue_tags: Iterable[str]) -> List[str]:
    return _map_controls(issue_tags, _WAF_CONTROL_MAP)


def map_tls_controls_for_frameworks(
    issue_tags: Iterable[str],
    frameworks: Optional[Iterable[str]],
) -> List[str]:
    controls = _map_controls(issue_tags, _TLS_CONTROL_MAP)
    return _filter_controls_by_frameworks(controls, frameworks)


def map_waf_controls_for_frameworks(
    issue_tags: Iterable[str],
    frameworks: Optional[Iterable[str]],
) -> List[str]:
    controls = _map_controls(issue_tags, _WAF_CONTROL_MAP)
    return _filter_controls_by_frameworks(controls, frameworks)


def resolve_tenant_frameworks(
    storage_manager: StorageManager,
    tenant_id: str,
) -> List[str]:
    """
    Resolve tenant policy framework scope from canonical approved policies.

    Returns a deterministic subset of: ["PCI", "RBI", "SEBI"].
    Empty means "no tenant filter" (emit all mapped controls).
    """
    try:
        store = PolicyStore(storage_manager=storage_manager, tenant_id=tenant_id)
        approved = store.list_approved_policies()
    except Exception:
        return []

    tokens: Set[str] = set()
    for policy in approved:
        if not isinstance(policy, dict):
            continue
        fields = [
            str(policy.get("title", "")).upper(),
            str(policy.get("jurisdiction", "")).upper(),
        ]
        for tag in (policy.get("tags") or []):
            fields.append(str(tag).upper())
        blob = " | ".join(fields)
        if "PCI" in blob:
            tokens.add("PCI")
        if "RBI" in blob:
            tokens.add("RBI")
        if "SEBI" in blob:
            tokens.add("SEBI")
    return sorted(tokens)


def _map_controls(issue_tags: Iterable[str], mapping: Dict[str, List[str]]) -> List[str]:
    tags: Set[str] = {str(tag or "").strip().lower() for tag in issue_tags if str(tag or "").strip()}
    controls: Set[str] = set()
    for tag in tags:
        for control in mapping.get(tag, []):
            controls.add(control)
    return sorted(controls)


def _filter_controls_by_frameworks(
    controls: Iterable[str],
    frameworks: Optional[Iterable[str]],
) -> List[str]:
    allowed = {
        str(item or "").strip().upper()
        for item in (frameworks or [])
        if str(item or "").strip()
    }
    if not allowed:
        return sorted(set(controls))

    out: Set[str] = set()
    for control in controls:
        token = str(control or "")
        if "PCI" in allowed and token.startswith("PCI-DSS"):
            out.add(token)
        if "RBI" in allowed and token.startswith("RBI"):
            out.add(token)
        if "SEBI" in allowed and token.startswith("SEBI"):
            out.add(token)
    return sorted(out)
