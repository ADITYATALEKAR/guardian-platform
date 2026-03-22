"""
cert_field_shape_fp.py

Layer 0 structural fingerprint:
Certificate field SHAPE fingerprint (not interpretation).

What this captures (shape-only):
- presence of common certificate *fields* (no meaning / no validation)
- length buckets of text fields
- character-class composition buckets (digits/letters/symbols ratios)
- certificate encoding surface shape (PEM markers / base64-ish / raw bytes len)

What this explicitly does NOT do:
- parse X.509
- validate chains
- decode ASN.1
- interpret issuer/subject semantics
- label risk/trust/attack

Design goals:
- canonical Fingerprint output only
- stable hash payload (bucketized ints only)
- deterministic vectors with bounded dimensions
- safe source_fields for debugging (bounded + non-sensitive)
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint

# ----------------------------
# Constants / limits
# ----------------------------

# Hard caps to avoid payload blowups
_MAX_STR_LEN = 4096
_MAX_FIELDS = 32

# Presence sketch buckets for field names (stable hashing)
_FIELDNAME_BUCKETS = 32

# Character composition buckets (for string surfaces)
# vector dims = [len_bucket_norm, digits_ratio_bucket_norm, letters_ratio_bucket_norm, sym_ratio_bucket_norm]
# + fieldname_presence sketch + per-field length bucket sketch
_CHAR_BINS = 8

# We keep the output vector bounded and stable:
# 4 scalars + 32 presence + 16 length sketch = 52 dims (fixed)
_LEN_SKETCH_BUCKETS = 16


# ----------------------------
# Helpers
# ----------------------------

def _get(obj: Any, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _safe_str(x: Any) -> str:
    if x is None:
        return ""
    try:
        s = str(x)
    except Exception:
        return ""
    s = s.strip()
    if not s:
        return ""
    if len(s) > _MAX_STR_LEN:
        s = s[:_MAX_STR_LEN]
    return s


def _safe_bytes(x: Any) -> bytes:
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x[:_MAX_STR_LEN])
    s = _safe_str(x)
    if not s:
        return b""
    return s.encode("utf-8", errors="ignore")[:_MAX_STR_LEN]


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _sha_bucket(token: str, buckets: int) -> int:
    """
    Stable bucket index across Python runs.
    """
    if buckets <= 0:
        return 0
    b = hashlib.sha256(token.encode("utf-8", errors="ignore")).digest()
    return int.from_bytes(b[:4], "big") % buckets


def _bucket_len(n: int) -> int:
    """
    Bucketize lengths into stable coarse bins (ints only).
    """
    if n <= 0:
        return 0
    if n <= 8:
        return 1
    if n <= 16:
        return 2
    if n <= 32:
        return 3
    if n <= 64:
        return 4
    if n <= 128:
        return 5
    if n <= 256:
        return 6
    if n <= 512:
        return 7
    if n <= 1024:
        return 8
    return 9


def _bucket_ratio(r: float, bins: int = _CHAR_BINS) -> int:
    """
    r in [0,1] -> [0..bins-1]
    """
    if bins <= 1:
        return 0
    r = _clamp01(float(r))
    idx = int(r * bins)
    if idx >= bins:
        idx = bins - 1
    return idx


def _string_composition_buckets(s: str) -> Dict[str, int]:
    """
    Shape-only char composition:
    - digits ratio bucket
    - letters ratio bucket
    - symbol ratio bucket (includes punctuation/space/other)
    """
    if not s:
        return {
            "len_bucket": 0,
            "digits_bucket": 0,
            "letters_bucket": 0,
            "symbols_bucket": 0,
        }

    total = len(s)
    digits = 0
    letters = 0
    symbols = 0

    for ch in s:
        o = ord(ch)
        if 48 <= o <= 57:
            digits += 1
        elif (65 <= o <= 90) or (97 <= o <= 122):
            letters += 1
        else:
            symbols += 1

    digits_r = digits / total
    letters_r = letters / total
    symbols_r = symbols / total

    return {
        "len_bucket": _bucket_len(total),
        "digits_bucket": _bucket_ratio(digits_r),
        "letters_bucket": _bucket_ratio(letters_r),
        "symbols_bucket": _bucket_ratio(symbols_r),
    }


def _detect_surface_shape(cert_raw: str) -> Dict[str, int]:
    """
    Raw encoding surface shape detection, purely structural.
    """
    s = cert_raw.strip()
    if not s:
        return {
            "has_pem_markers": 0,
            "looks_base64ish": 0,
            "line_count_bucket": 0,
        }

    has_pem = 1 if ("BEGIN CERTIFICATE" in s and "END CERTIFICATE" in s) else 0

    # Base64-ish check: ratio of base64 chars among non-whitespace
    non_ws = [c for c in s if c not in "\r\n\t "]
    if not non_ws:
        base64ish = 0
    else:
        b64chars = 0
        for c in non_ws[:2048]:
            o = ord(c)
            # A-Z a-z 0-9 + / =
            if (65 <= o <= 90) or (97 <= o <= 122) or (48 <= o <= 57) or c in "+/=":
                b64chars += 1
        ratio = b64chars / max(1, len(non_ws[:2048]))
        base64ish = 1 if ratio >= 0.95 else 0

    lines = s.splitlines()
    lc = len(lines)
    if lc <= 0:
        line_bucket = 0
    elif lc <= 2:
        line_bucket = 1
    elif lc <= 8:
        line_bucket = 2
    elif lc <= 32:
        line_bucket = 3
    else:
        line_bucket = 4

    return {
        "has_pem_markers": has_pem,
        "looks_base64ish": base64ish,
        "line_count_bucket": line_bucket,
    }


def _normalize_field_name(k: Any) -> str:
    """
    Conservative normalization:
    - uppercase
    - strip spaces
    - bound length
    """
    s = _safe_str(k)
    if not s:
        return ""
    s = s.replace(" ", "").upper()
    return s[:48]


def _iter_fields(cert_fields: Any) -> Sequence[Tuple[str, str]]:
    """
    Accept:
    - dict-like {field: value}
    - list/tuple of (k,v)
    - object with __dict__ (best effort)
    """
    if cert_fields is None:
        return []

    if isinstance(cert_fields, Mapping):
        items = list(cert_fields.items())
    elif isinstance(cert_fields, (list, tuple)):
        items = []
        for it in cert_fields:
            if isinstance(it, (list, tuple)) and len(it) == 2:
                items.append((it[0], it[1]))
    else:
        # last resort: __dict__
        d = getattr(cert_fields, "__dict__", None)
        if isinstance(d, dict):
            items = list(d.items())
        else:
            items = []

    out: list[Tuple[str, str]] = []
    for k, v in items[:_MAX_FIELDS]:
        nk = _normalize_field_name(k)
        if not nk:
            continue
        nv = _safe_str(v)
        out.append((nk, nv))
    return out


def _length_sketch_for_fields(fields: Sequence[Tuple[str, str]]) -> Tuple[int, ...]:
    """
    Build a deterministic length sketch of values across fields:
    - 16 buckets
    - each bucket stores max bucket-value seen (0/1-ish) to avoid churn
    """
    sketch = [0] * _LEN_SKETCH_BUCKETS
    for k, v in fields:
        lb = _bucket_len(len(v))
        idx = _sha_bucket(k, _LEN_SKETCH_BUCKETS)
        # store max to keep stable with duplicates/ordering
        if lb > sketch[idx]:
            sketch[idx] = lb
    return tuple(sketch)


# ----------------------------
# Main fingerprint function
# ----------------------------

def compute_cert_field_shape_fingerprint(
    *,
    entity_id: str,
    observation: Any = None,
    cert_fields: Any = None,
    cert_raw: Optional[Any] = None,
) -> Fingerprint:
    """
    Compute a certificate field-shape fingerprint.

    Inputs (any combination):
      - observation: dict/object that may contain "cert_fields" or "certificate" fields
      - cert_fields: explicit cert field mapping/list
      - cert_raw: raw certificate string/bytes (PEM/base64-ish), used only for surface shape

    Preferred path:
      - provide cert_fields from your collector if available (best shape signal)
    """
    entity_id_s = str(entity_id or "").strip()
    if not entity_id_s:
        raise ValueError("entity_id must be non-empty")

    # Resolve fields from observation if not passed
    if cert_fields is None and observation is not None:
        cert_fields = _get(observation, "cert_fields", None) or _get(observation, "certificate_fields", None)

    # Resolve raw cert surface from observation if not passed
    if cert_raw is None and observation is not None:
        cert_raw = _get(observation, "certificate", None) or _get(observation, "cert_raw", None)

    fields = _iter_fields(cert_fields)
    field_names = tuple(sorted({k for k, _ in fields}))

    # Presence sketch for field names (NOT hashed directly as full list; hashed as bounded head)
    presence = [0.0] * _FIELDNAME_BUCKETS
    for fn in field_names:
        presence[_sha_bucket(fn, _FIELDNAME_BUCKETS)] = 1.0

    # Field-count bucket (stable identity)
    field_count = len(field_names)
    field_count_bucket = _bucket_len(field_count)

    # Composition buckets from concatenated values (bounded)
    # This is shape of text only; it does not interpret meaning.
    concat = ""
    if fields:
        # keep bounded to avoid leaking large cert bodies
        parts = []
        for _, v in fields[:_MAX_FIELDS]:
            if v:
                parts.append(v[:128])
        concat = "|".join(parts)[:1024]

    comp = _string_composition_buckets(concat)

    # Surface shape from raw string/bytes (optional)
    cert_raw_s = _safe_str(cert_raw)
    surface = _detect_surface_shape(cert_raw_s)

    # Length sketch across fields
    len_sketch = _length_sketch_for_fields(fields)

    # -------- Identity hash (bucketized, bounded, stable) --------
    # Important:
    # - Never hash raw cert bytes
    # - Never hash full subject/issuer strings
    # - Only hash coarse shape signals + bounded head
    head = field_names[:16]

    hash_payload: Dict[str, Any] = {
        "entity_id": entity_id_s,
        "field_count_bucket": field_count_bucket,
        "field_head": head,
        "len_bucket": int(comp["len_bucket"]),
        "digits_bucket": int(comp["digits_bucket"]),
        "letters_bucket": int(comp["letters_bucket"]),
        "symbols_bucket": int(comp["symbols_bucket"]),
        "pem": int(surface["has_pem_markers"]),
        "b64": int(surface["looks_base64ish"]),
        "lines_b": int(surface["line_count_bucket"]),
        # include a coarse sketch signature (ints only, bounded)
        "len_sketch_head": len_sketch[:8],
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    # -------- Vector (richer similarity sketch) --------
    # Fixed dimension vector:
    #  - 4 composition scalars normalized
    #  - 32 presence bits
    #  - 16 length sketch normalized
    #
    # Normalize buckets into 0..1 so downstream similarity behaves
    len_bucket_norm = float(comp["len_bucket"]) / 9.0
    digits_norm = float(comp["digits_bucket"]) / float(max(1, _CHAR_BINS - 1))
    letters_norm = float(comp["letters_bucket"]) / float(max(1, _CHAR_BINS - 1))
    symbols_norm = float(comp["symbols_bucket"]) / float(max(1, _CHAR_BINS - 1))

    # Length sketch normalized
    len_sketch_norm = [float(min(v, 9)) / 9.0 for v in len_sketch]

    vector_raw = [
        _clamp01(len_bucket_norm),
        _clamp01(digits_norm),
        _clamp01(letters_norm),
        _clamp01(symbols_norm),
    ] + presence + len_sketch_norm

    vector = Fingerprint.make_vector(vector_raw, quantize_decimals=4)

    # -------- Quality (data richness only; not "risk") --------
    # We consider quality higher when:
    # - fields exist
    # - field_count not tiny
    # - composition non-empty
    quality = 0.1
    if field_count > 0:
        quality = 0.45
    if field_count >= 4:
        quality = 0.7
    if field_count >= 8:
        quality = 0.85

    quality = Fingerprint.safe_quality(quality)

    # -------- Bounded debug fields --------
    source_fields: Dict[str, Any] = {
        "field_count": field_count,
        "field_count_bucket": field_count_bucket,
        "field_head": head,
        "presence_buckets": _FIELDNAME_BUCKETS,
        "len_sketch_buckets": _LEN_SKETCH_BUCKETS,
        "composition_len_bucket": int(comp["len_bucket"]),
        "composition_digits_bucket": int(comp["digits_bucket"]),
        "composition_letters_bucket": int(comp["letters_bucket"]),
        "composition_symbols_bucket": int(comp["symbols_bucket"]),
        "surface_has_pem_markers": int(surface["has_pem_markers"]),
        "surface_looks_base64ish": int(surface["looks_base64ish"]),
        "surface_line_count_bucket": int(surface["line_count_bucket"]),
        "vector_dim": len(vector),
    }

    return Fingerprint(
        entity_id=entity_id_s,
        kind="cert_field_shape_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
