"""
evidence_refs.py

Layer 2 — bounded, stable evidence reference helper.

Fixes included:
- Soft kind matching option to avoid Layer0 kind-string drift problems.
- Still deterministic ordering, bounded output, handshake-first preference.

NOTE:
We do NOT import Layer0 Fingerprint type: we accept any object with:
- kind, hash, fingerprint_id attributes
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .weakness_contracts import EvidenceAnchor, EvidenceRef


def _safe_str(x: Any, default: str = "") -> str:
    s = str(x or "").strip()
    return s if s else default


def _take_bounded_unique_sorted(values: Iterable[str], max_items: int) -> List[str]:
    out = sorted(set([_safe_str(v) for v in values if _safe_str(v)]))
    return out[: max(0, int(max_items))]


def _normalize_kind(kind: str) -> str:
    """
    Normalize kind strings for robust matching.

    Example:
      "transition_fp_v1" -> "transition_fp_v1"
      "transition_fp"    -> "transition_fp"
      "Transition_FP_V1" -> "transition_fp_v1"
    """
    return _safe_str(kind).lower()


def _kind_matches(kind: str, allow: Sequence[str]) -> bool:
    """
    Soft matching:
    - exact match OR substring match on normalized strings.
    This prevents evidence selection breaking when Layer0 kind naming evolves.
    """
    k = _normalize_kind(kind)
    if not k:
        return False
    allow_n = [_normalize_kind(a) for a in allow if _safe_str(a)]
    for a in allow_n:
        if not a:
            continue
        if k == a:
            return True
        # substring compatibility (transition_fp matches transition_fp_v1)
        if a in k or k in a:
            return True
    return False


@dataclass(frozen=True)
class EvidencePolicy:
    max_refs: int = 12
    max_fp_ids_per_ref: int = 8
    prefer_handshake_anchor: bool = True


def build_evidence_refs_from_fingerprints(
    fingerprints: Sequence[Any],
    *,
    policy: Optional[EvidencePolicy] = None,
) -> List[EvidenceRef]:
    pol = policy or EvidencePolicy()

    anchor_to_ids: Dict[Tuple[str, str], List[str]] = {}

    for fp in fingerprints or ():
        kind = _safe_str(_get(fp, "kind", ""))
        h = _safe_str(_get(fp, "hash", ""))
        fid = _safe_str(_get(fp, "fingerprint_id", ""))

        if not kind or not h:
            continue

        key = (kind, h)
        anchor_to_ids.setdefault(key, [])
        if fid:
            anchor_to_ids[key].append(fid)

    refs: List[EvidenceRef] = []
    for (kind, h), ids in anchor_to_ids.items():
        refs.append(
            EvidenceRef(
                anchor=EvidenceAnchor(kind=kind, hash=h),
                fingerprint_ids=_take_bounded_unique_sorted(ids, pol.max_fp_ids_per_ref),
            )
        )

    refs.sort(key=lambda r: (r.anchor.kind, r.anchor.hash))

    if pol.prefer_handshake_anchor:
        handshake = [r for r in refs if _normalize_kind(r.anchor.kind) == "handshake_fp_v1" or "handshake" in _normalize_kind(r.anchor.kind)]
        rest = [r for r in refs if r not in handshake]
        refs = handshake + rest

    return refs[: pol.max_refs]


def select_evidence_refs_for_axes(
    evidence_refs: Sequence[EvidenceRef],
    *,
    include_kinds: Sequence[str],
    max_refs: int = 8,
) -> List[EvidenceRef]:
    picked: List[EvidenceRef] = []
    for r in evidence_refs or ():
        if _kind_matches(r.anchor.kind, include_kinds):
            picked.append(r)

    picked.sort(key=lambda r: (r.anchor.kind, r.anchor.hash))
    return picked[: max(0, int(max_refs))]
def _get(fp: Any, key: str, default: Any = None) -> Any:
    if isinstance(fp, dict):
        return fp.get(key, default)
    return getattr(fp, key, default)
