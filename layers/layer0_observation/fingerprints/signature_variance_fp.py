"""
signature_variance_fp.py

Layer 0 structural fingerprint:
Signature / algorithm diversity (structural-only).

Note:
- Name is kept as signature_variance_fp for compatibility.
- Behavior is stable "diversity signature", not temporal variance.
  (Temporal variance would be handled by transition_fp / future delta fingerprints.)

Rules:
- Canonical Fingerprint only
- Bounded, deterministic
- No semantic interpretation

Behavioral micro-instability

One of your strongest signals
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, List, Tuple

from .fingerprint_types import Fingerprint


MAX_HEAD = 16
PRESENCE_BUCKETS = 32


def _require_nonempty(entity_id: str) -> str:
    v = str(entity_id or "").strip()
    if not v:
        raise ValueError("entity_id must be non-empty")
    return v


def _normalize_tokens(tokens: Iterable[Any]) -> Tuple[str, ...]:
    out: List[str] = []
    for t in tokens or ():
        s = str(t).strip()
        if s:
            out.append(s)
    # canonical: dedupe early + sorted
    return tuple(sorted(set(out)))


def _bucket_diversity(unique_count: int) -> int:
    if unique_count <= 0:
        return 0
    if unique_count == 1:
        return 1
    if unique_count <= 2:
        return 2
    if unique_count <= 4:
        return 3
    if unique_count <= 8:
        return 4
    return 5


def _bucket_index(token: str, *, buckets: int) -> int:
    h = hashlib.sha256(token.encode("utf-8")).digest()
    return int.from_bytes(h[:4], "big") % buckets


def compute_signature_variance_fingerprint(
    *,
    entity_id: str,
    signatures: Iterable[Any],
) -> Fingerprint:
    entity_id = _require_nonempty(entity_id)

    sigs = _normalize_tokens(signatures)
    unique_count = len(sigs)
    diversity_bucket = _bucket_diversity(unique_count)

    head = sigs[:MAX_HEAD]

    # Stable identity hash: coarse + bounded
    hash_payload = {
        "entity_id": entity_id,
        "diversity_bucket": diversity_bucket,
        "head": list(head),
    }
    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # Presence sketch vector (NOT hashed)
    presence = [0.0] * PRESENCE_BUCKETS
    for tok in sigs:
        presence[_bucket_index(tok, buckets=PRESENCE_BUCKETS)] = 1.0

    scalars = [
        float(diversity_bucket),
        float(min(unique_count, 64)),
    ]
    vector = Fingerprint.make_vector(scalars + presence, quantize_decimals=3)

    quality = Fingerprint.safe_quality(0.9 if unique_count > 0 else 0.2)

    source_fields = {
        "unique_signature_count": unique_count,
        "diversity_bucket": diversity_bucket,
        "head": head,
        "presence_buckets": PRESENCE_BUCKETS,
        "vector_dim": len(vector),
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="signature_variance_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
