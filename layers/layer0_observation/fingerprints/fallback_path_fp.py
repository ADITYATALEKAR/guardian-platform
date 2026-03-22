"""
fallback_path_fp.py

Layer 0 structural fingerprint:
Attempt-path / downgrade-path signature fingerprint.

MERGE-SAFE REQUIREMENTS:
- Hash: stable & bounded (entity_id + attempt_bucket + path_head)
- Vector: must be richer than [attempt_bucket, head_len]
  Adds:
    - transition_count
    - unique_protocol_count
    - settle_flag (whether it stabilizes at end)
    - first/last class buckets

No semantics. No "risk". Pure structure.

Input is a sequence of protocol tokens across attempts.
"""

from __future__ import annotations

from typing import Iterable, List, Tuple

from .fingerprint_types import Fingerprint


MAX_PATH_HEAD = 8


def _require_nonempty(entity_id: str) -> str:
    v = str(entity_id or "").strip()
    if not v:
        raise ValueError("entity_id must be non-empty")
    return v


def _norm_token(t: str) -> str:
    """
    Canonicalize protocol-like tokens to reduce churn.
    This is intentionally conservative and does NOT interpret security meaning.
    """
    s = str(t or "").strip().upper()
    if not s:
        return ""

    # normalize common TLS representations
    s = s.replace("TLSV", "TLS")
    s = s.replace("TLS_", "TLS")
    s = s.replace("TLS-", "TLS")
    s = s.replace(" ", "")

    # very coarse family normalization (bounded identity space)
    if "TLS1.3" in s or "TLS13" in s:
        return "TLS1.3"
    if "TLS1.2" in s or "TLS12" in s:
        return "TLS1.2"
    if "TLS1.1" in s or "TLS11" in s:
        return "TLS1.1"
    if "TLS1.0" in s or "TLS10" in s:
        return "TLS1.0"

    if "QUIC" in s or "HTTP3" in s or "H3" == s:
        return "QUIC/H3"
    if "HTTP2" in s or s == "H2":
        return "HTTP/2"
    if "HTTP1.1" in s or "HTTP/1.1" in s:
        return "HTTP/1.1"

    return s[:32]  # bounded token length


def _normalize_path(tokens: Iterable[str]) -> Tuple[str, ...]:
    out: List[str] = []
    for t in tokens or ():
        nt = _norm_token(t)
        if nt:
            out.append(nt)
    return tuple(out)


def _bucket_attempts(n: int) -> int:
    if n <= 1:
        return 0
    if n == 2:
        return 1
    if n == 3:
        return 2
    if n <= 5:
        return 3
    return 4


def _bucket_small(n: int) -> int:
    if n <= 0:
        return 0
    if n == 1:
        return 1
    if n == 2:
        return 2
    if n <= 4:
        return 3
    if n <= 8:
        return 4
    return 5


def _class_bucket(tok: str) -> int:
    """
    Very coarse protocol class bucket for vector stability.
    """
    if tok.startswith("TLS"):
        return 1
    if tok.startswith("HTTP"):
        return 2
    if tok.startswith("QUIC"):
        return 3
    return 4 if tok else 0


def compute_fallback_path_fingerprint(
    *,
    entity_id: str,
    attempt_protocols: Iterable[str],
) -> Fingerprint:
    entity_id = _require_nonempty(entity_id)

    path = _normalize_path(attempt_protocols)
    n = len(path)

    attempt_bucket = _bucket_attempts(n)
    head = path[:MAX_PATH_HEAD]

    # transitions: count changes between adjacent attempts
    transitions = 0
    for i in range(1, n):
        if path[i] != path[i - 1]:
            transitions += 1

    unique_count = len(set(path))
    settle_flag = 0
    if n >= 2 and path[-1] == path[-2]:
        settle_flag = 1

    # Stable identity hash: coarse + bounded + head only
    hash_payload = {
        "entity_id": entity_id,
        "attempt_bucket": attempt_bucket,
        "path_head": head,
    }
    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # Vector: richer comparability sketch
    vector = Fingerprint.make_vector(
        [
            float(attempt_bucket),
            float(_bucket_small(transitions)),
            float(_bucket_small(unique_count)),
            float(settle_flag),
            float(_class_bucket(path[0]) if n > 0 else 0),
            float(_class_bucket(path[-1]) if n > 0 else 0),
        ],
        quantize_decimals=2,
    )

    quality = Fingerprint.safe_quality(0.9 if n > 1 else 0.3 if n == 1 else 0.1)

    source_fields = {
        "attempt_count": n,
        "attempt_bucket": attempt_bucket,
        "path_head": list(head),
        "transition_count": transitions,
        "unique_protocol_count": unique_count,
        "settle_flag": settle_flag,
        "first_token": path[0] if n > 0 else None,
        "last_token": path[-1] if n > 0 else None,
        "vector_dim": len(vector),
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="fallback_path_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
