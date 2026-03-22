"""
extension_vector_fp.py

Layer 0 structural fingerprint:
Protocol extension presence signature.

Goals:
- Stable identity hash (coarse): entity_id + count bucket + set_head
- Strong comparability vector: presence sketch across deterministic buckets

Rules:
- Do NOT encode ordering (order belongs in transition_fp)
- No semantic interpretation
- Bounded payload + bounded vector
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, List, Tuple

from .fingerprint_types import Fingerprint


MAX_SET_HEAD = 16
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
    # canonical: unique + sorted
    return tuple(sorted(set(out)))


def _bucket_count(n: int) -> int:
    if n <= 0:
        return 0
    if n <= 3:
        return 1
    if n <= 6:
        return 2
    if n <= 10:
        return 3
    if n <= 16:
        return 4
    return 5


def _bucket_index(token: str, *, buckets: int) -> int:
    """
    Deterministic stable bucket index for a token.
    Uses SHA256 for stability across Python runs (avoid built-in hash()).
    """
    h = hashlib.sha256(token.encode("utf-8")).digest()
    return int.from_bytes(h[:4], "big") % buckets


def compute_extension_vector_fingerprint(
    *,
    entity_id: str,
    extensions: Iterable[Any],
) -> Fingerprint:
    entity_id = _require_nonempty(entity_id)
    exts = _normalize_tokens(extensions)
    n = len(exts)

    n_bucket = _bucket_count(n)
    set_head = exts[:MAX_SET_HEAD]

    # Stable identity: coarse + bounded
    hash_payload = {
        "entity_id": entity_id,
        "n_bucket": n_bucket,
        "set_head": set_head,
    }
    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # Presence sketch vector (NOT hashed)
    presence = [0.0] * PRESENCE_BUCKETS
    for tok in exts:
        presence[_bucket_index(tok, buckets=PRESENCE_BUCKETS)] = 1.0

    # Add coarse scalars to the vector head for improved similarity
    scalars = [
        float(n_bucket),
        float(min(n, 64)),  # bounded count hint
    ]

    vector = Fingerprint.make_vector(scalars + presence, quantize_decimals=3)

    # Quality: purely structural completeness signal
    quality = Fingerprint.safe_quality(0.9 if n > 0 else 0.2)

    source_fields = {
        "extension_count": n,
        "n_bucket": n_bucket,
        "set_head": list(set_head),
        "presence_buckets": PRESENCE_BUCKETS,
        "vector_dim": len(vector),
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="extension_vector_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
