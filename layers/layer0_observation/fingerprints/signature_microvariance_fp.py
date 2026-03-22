"""
signature_microvariance_fp.py

Layer 0 high-resolution structural+temporal fingerprint:
Signature micro-variance pattern over a window.

This fingerprint is meant to capture "micro-curve behavior":
- diversity (unique tokens)
- churn (how often changes occur)
- run stability (whether it stabilizes)
- transition energy (switch intensity)
- deterministic presence sketch for clustering

Rules:
- No semantics, no risk scoring
- Hash uses ONLY bucketized coarse metrics (stable identity)
- Vector provides richer similarity embedding (bounded, fixed dimension)
- Supports string tokens and numeric IDs (converted to strings)
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint


MAX_TOKENS = 256
MAX_HEAD = 16
PRESENCE_BUCKETS = 32


def _require_nonempty_str(name: str, value: Any) -> str:
    v = str(value or "").strip()
    if not v:
        raise ValueError(f"{name} must be non-empty")
    return v


def _safe_str(x: Any) -> str:
    s = str(x or "").strip()
    return s


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _bucketize01(x01: float, edges: Sequence[float]) -> int:
    x = _clamp01(float(x01))
    for i, e in enumerate(edges):
        if x <= e:
            return i
    return len(edges)


def _bucket_index(token: str, *, buckets: int) -> int:
    """
    Stable bucketing across runs.
    """
    h = hashlib.sha256(token.encode("utf-8")).digest()
    return int.from_bytes(h[:4], "big") % buckets


def _normalize_tokens(tokens: Iterable[Any]) -> Tuple[str, ...]:
    """
    Keep order (micro-variance is about sequence).
    Bounded token length.
    """
    out: List[str] = []
    for t in tokens or ():
        s = _safe_str(t)
        if not s:
            continue
        out.append(s[:64])
        if len(out) >= MAX_TOKENS:
            break
    return tuple(out)


def _compress_pos01(x: float) -> float:
    """
    Compress unbounded positive to [0..1).
    """
    ax = abs(float(x))
    return ax / (1.0 + ax)


def _run_lengths(seq: Sequence[str]) -> List[int]:
    if not seq:
        return []
    runs = []
    cur = seq[0]
    r = 1
    for i in range(1, len(seq)):
        if seq[i] == cur:
            r += 1
        else:
            runs.append(r)
            cur = seq[i]
            r = 1
    runs.append(r)
    return runs


def compute_signature_microvariance_fingerprint(
    *,
    entity_id: str,
    signature_tokens: Iterable[Any],
    window_ms: Optional[int] = None,
) -> Fingerprint:
    """
    Build signature micro-variance fingerprint from raw signature token stream.
    """
    entity_id = _require_nonempty_str("entity_id", entity_id)

    seq = _normalize_tokens(signature_tokens)
    n = len(seq)

    # diversity
    unique = set(seq)
    uniq_n = len(unique)
    diversity01 = _clamp01(uniq_n / max(1.0, min(64.0, float(n))))

    # churn: fraction of transitions (changes between adjacent tokens)
    transitions = 0
    for i in range(1, n):
        if seq[i] != seq[i - 1]:
            transitions += 1
    churn01 = _clamp01(transitions / max(1.0, float(n - 1))) if n >= 2 else 0.0

    # run stability: if last run is long, it's "settling"
    runs = _run_lengths(seq)
    last_run = runs[-1] if runs else 0
    run_stability01 = _clamp01(last_run / max(1.0, min(32.0, float(n))))

    # transition energy: penalize rapid switching
    # bounded scalar in [0..1)
    # - high churn & short runs => higher energy
    mean_run = (sum(runs) / len(runs)) if runs else 0.0
    mean_run_inv = 0.0 if mean_run <= 0 else (1.0 / mean_run)
    transition_energy01 = _compress_pos01(churn01 * (1.0 + mean_run_inv))

    # set head (stable bounded debug identity)
    head_unique = tuple(sorted(unique))[:MAX_HEAD]

    # window bucket stabilizer (keep int)
    w_bucket = 0
    if window_ms and int(window_ms) > 0:
        w = int(window_ms)
        if w <= 250:
            w_bucket = 1
        elif w <= 1000:
            w_bucket = 2
        elif w <= 5000:
            w_bucket = 3
        elif w <= 30000:
            w_bucket = 4
        else:
            w_bucket = 5

    # n bucket stabilizer
    if n <= 0:
        n_bucket = 0
    elif n < 8:
        n_bucket = 1
    elif n < 16:
        n_bucket = 2
    elif n < 32:
        n_bucket = 3
    elif n < 64:
        n_bucket = 4
    else:
        n_bucket = 5

    # identity buckets (stable)
    div_b = _bucketize01(diversity01, [0.05, 0.15, 0.30, 0.50, 0.70, 0.85, 0.95])
    churn_b = _bucketize01(churn01, [0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    stab_b = _bucketize01(run_stability01, [0.05, 0.15, 0.30, 0.50, 0.70, 0.85, 0.95])
    energy_b = _bucketize01(transition_energy01, [0.05, 0.15, 0.30, 0.50, 0.70, 0.85])

    hash_payload = {
        "entity_id": entity_id,
        "window_bucket": int(w_bucket),
        "n_bucket": int(n_bucket),
        "div_b": div_b,
        "churn_b": churn_b,
        "stab_b": stab_b,
        "energy_b": energy_b,
        "head_unique": head_unique,
    }
    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # presence sketch (vector only)
    presence = [0.0] * PRESENCE_BUCKETS
    for tok in unique:
        presence[_bucket_index(tok, buckets=PRESENCE_BUCKETS)] = 1.0

    # vector: fixed dimension
    vec = Fingerprint.make_vector(
        [
            diversity01,
            churn01,
            run_stability01,
            transition_energy01,
            float(n_bucket) / 5.0,
            float(w_bucket) / 5.0,
            float(uniq_n) / 64.0 if uniq_n <= 64 else 1.0,
        ]
        + presence,
        quantize_decimals=4,
    )

    # quality: depends on sample richness
    base_q = 0.9
    if n < 6:
        base_q = 0.35
    elif n < 16:
        base_q = 0.65
    quality = Fingerprint.safe_quality(base_q)

    source_fields = {
        "window_ms": int(window_ms) if window_ms is not None else None,
        "window_bucket": int(w_bucket),
        "n": n,
        "n_bucket": int(n_bucket),
        "unique_count": uniq_n,
        "transitions": transitions,
        "diversity01": float(diversity01),
        "churn01": float(churn01),
        "run_stability01": float(run_stability01),
        "transition_energy01": float(transition_energy01),
        "head_unique": head_unique,
        "presence_buckets": PRESENCE_BUCKETS,
        "vector_dim": len(vec),
    }

    return Fingerprint(
        entity_id=entity_id,
        kind="signature_microvariance_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vec,
        quality=quality,
        source_fields=source_fields,
    )
