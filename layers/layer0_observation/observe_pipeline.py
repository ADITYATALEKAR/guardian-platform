"""
observe.py (Layer 0) — Bank/Prod Grade Orchestrator

Layer0 entrypoint:
    observe_timing_batch(...)

What Layer0 must guarantee
--------------------------
- Emit canonical Fingerprint objects only.
- Deterministic + bounded identity hashing (no float churn).
- Robust to missing modules, signature mismatches, or partial corruption.
- No filesystem writes.
- No Layer 1–4 imports.
- "Physics-first" when available, fallback-safe when not.

Fingerprints expected by tests / product posture
------------------------------------------------
Core mandatory:
- handshake_fp_v1
- drift_fp_v1
- jitter_fp_v1
- oscillation_fp_v1 OR correlation_shock_fp_v1

Bank-grade / stealth-ready (structural detection):
- coherence_fp_v1
- coupling_fp_v1
- meta_fp_v1

Nice-to-have:
- entropy_histogram_fp_v1
- fallback_path_fp_v1
- cert_field_shape_fp_v1



Importance: 🧠 Orchestrator

What it does

Wires the full pipeline:

collect → validate → normalize → calibrate → fingerprint


Guarantees deterministic flow

Defines the only legal entry point

What’s special

No branching logic

No business rules

No thresholds

This is pipeline physics, not orchestration chaos.

Metaphor

This is the wind tunnel.
Everything flows through the same controlled conditions.

"""

from __future__ import annotations

import logging
import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from core_utils.safety import (
    clamp01 as _clamp01,
    is_nonempty_str as _is_nonempty_str,
    safe_float as _safe_float,
    safe_int as _safe_int,
    safe_str as _safe_str,
)
from .fingerprints.fingerprint_types import Fingerprint
from .normalization.timing_normalizer import TimingNormalizer

logger = logging.getLogger(__name__)


# =============================================================================
# Small utilities (pure)
# =============================================================================
def _get_field(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _bounded_list(xs: Any, max_n: int) -> List[Any]:
    if xs is None:
        return []
    if not isinstance(xs, (list, tuple)):
        return []
    return list(xs[: max(0, int(max_n))])


# =============================================================================
# JSON-safe source_fields sanitization (Fingerprint is frozen)
# =============================================================================
def _json_safe_value(v: Any, *, depth: int = 0, max_depth: int = 4) -> Any:
    if depth > max_depth:
        return _safe_str(v, default="")

    if v is None:
        return None
    if isinstance(v, (bool, int, float, str)):
        if isinstance(v, float):
            fv = _safe_float(v)
            return fv if fv is not None else None
        return v

    if isinstance(v, (tuple, set)):
        v = list(v)

    if isinstance(v, list):
        out: List[Any] = []
        for x in v[:64]:
            out.append(_json_safe_value(x, depth=depth + 1, max_depth=max_depth))
        return out

    if isinstance(v, dict):
        out: Dict[str, Any] = {}
        i = 0
        for k, x in v.items():
            if i >= 64:
                break
            sk = _safe_str(k, default="")
            if not sk:
                continue
            out[sk] = _json_safe_value(x, depth=depth + 1, max_depth=max_depth)
            i += 1
        return out

    return _safe_str(v, default="")


def _sanitize_fingerprint(fp: Fingerprint) -> Fingerprint:
    sf = fp.source_fields or None
    if not sf:
        return fp

    safe_sf = _json_safe_value(sf)
    if safe_sf == sf:
        return fp

    return Fingerprint(
        fingerprint_id=fp.fingerprint_id,
        entity_id=fp.entity_id,
        kind=fp.kind,
        version=fp.version,
        created_ms=fp.created_ms,
        hash=fp.hash,
        vector=fp.vector,
        quality=fp.quality,
        source_fields=safe_sf,
    )


def _deterministic_created_ms(timestamps_ms: Sequence[int]) -> int:
    if not timestamps_ms:
        return 0
    try:
        return int(max(int(t) for t in timestamps_ms if isinstance(t, int)))
    except Exception:
        return 0


def _is_default_fp_id(fp_id: str) -> bool:
    # default id format: "fp_" + 12 hex chars
    if not isinstance(fp_id, str):
        return False
    if not fp_id.startswith("fp_"):
        return False
    tail = fp_id[3:]
    if len(tail) != 12:
        return False
    for ch in tail:
        if ch not in "0123456789abcdef":
            return False
    return True


def _deterministic_fp_id(fp: Fingerprint, created_ms: int) -> str:
    payload = {
        "kind": fp.kind,
        "entity_id": fp.entity_id,
        "hash": fp.hash,
        "created_ms": int(created_ms),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "fp_" + hashlib.sha256(encoded).hexdigest()[:12]


def _force_entity_id(fp: Fingerprint, entity_id: str) -> Fingerprint:
    eid = _safe_str(entity_id, default="")
    if not eid:
        return fp
    if _safe_str(fp.entity_id, default="") == eid:
        return fp

    return Fingerprint(
        fingerprint_id=fp.fingerprint_id,
        entity_id=eid,
        kind=fp.kind,
        version=fp.version,
        created_ms=fp.created_ms,
        hash=fp.hash,
        vector=fp.vector,
        quality=fp.quality,
        source_fields=fp.source_fields,
    )


# =============================================================================
# Import adapters (schema/validator)
# =============================================================================
def _import_schema_builder():
    """
    Return builder(raw_dict)-> observation
    Works even if schema module not present.
    """
    try:
        from .schemas.timing_schema import timing_observation_from_dict  # type: ignore

        def _builder(raw: Mapping[str, Any]) -> Any:
            return timing_observation_from_dict(raw)

        return _builder
    except Exception:
        pass

    def _builder(raw: Mapping[str, Any]) -> Any:
        return dict(raw)

    return _builder


def _import_validator():
    validate_fn = None
    repair_fn = None

    try:
        from .validation.timing_validation import validate_timing_observation  # type: ignore

        validate_fn = validate_timing_observation
    except Exception:
        validate_fn = None

    try:
        from .validation.timing_validation import repair_unit_mismatch_if_obvious  # type: ignore

        repair_fn = repair_unit_mismatch_if_obvious
    except Exception:
        repair_fn = None

    def _validate(obs: Any) -> Any:
        if validate_fn is None:
            return obs
        return validate_fn(obs)

    def _repair(obs: Any) -> Any:
        if repair_fn is None:
            return obs
        return repair_fn(obs)

    return _validate, _repair


# =============================================================================
# Import adapters (physics + fingerprints)
# =============================================================================
def _import_physics_compute() -> Dict[str, Any]:
    """
    Best-effort import of physics compute functions.
    """
    out: Dict[str, Any] = {}

    def _get_callable(mod: Any, names: Sequence[str]) -> Optional[Any]:
        for n in names:
            if hasattr(mod, n) and callable(getattr(mod, n)):
                return getattr(mod, n)
        return None

    # existing physics
    try:
        from .physics import drift as drift_mod  # type: ignore

        fn = _get_callable(drift_mod, ["compute_drift_signals", "compute_drift"])
        if fn:
            out["drift"] = fn
    except Exception:
        pass

    try:
        from .physics import jitter as jitter_mod  # type: ignore

        fn = _get_callable(jitter_mod, ["compute_jitter_signals", "compute_jitter"])
        if fn:
            out["jitter"] = fn
    except Exception:
        pass

    try:
        from .physics import oscillation as osc_mod  # type: ignore

        fn = _get_callable(osc_mod, ["compute_oscillation_signals", "compute_oscillation"])
        if fn:
            out["oscillation"] = fn
    except Exception:
        pass

    try:
        from .physics import correlation as corr_mod  # type: ignore

        fn = _get_callable(corr_mod, ["compute_correlation_shock", "compute_correlation_signals", "compute_correlation"])
        if fn:
            out["correlation"] = fn
    except Exception:
        pass

    # NEW: stealth structural physics
    try:
        from .physics import coherence as coh_mod  # type: ignore

        fn = _get_callable(coh_mod, ["compute_coherence_signals", "compute_coherence"])
        if fn:
            out["coherence"] = fn
    except Exception:
        pass

    try:
        from .physics import coupling as cpl_mod  # type: ignore

        fn = _get_callable(cpl_mod, ["compute_coupling_signals", "compute_coupling"])
        if fn:
            out["coupling"] = fn
    except Exception:
        pass

    try:
        from .physics import meta as meta_mod  # type: ignore

        fn = _get_callable(meta_mod, ["compute_meta_physics", "compute_meta_signals", "compute_meta"])
        if fn:
            out["meta"] = fn
    except Exception:
        pass

    try:
        from .physics import momentum as mom_mod  # type: ignore

        fn = _get_callable(mom_mod, ["compute_momentum"])
        if fn:
            out["momentum"] = fn
    except Exception:
        pass

    try:
        from .physics import decay as dec_mod  # type: ignore

        fn = _get_callable(dec_mod, ["compute_decay"])
        if fn:
            out["decay"] = fn
    except Exception:
        pass

    try:
        from .physics import resonance as res_mod  # type: ignore

        fn = _get_callable(res_mod, ["compute_resonance"])
        if fn:
            out["resonance"] = fn
    except Exception:
        pass

    return out


def _import_fingerprints() -> Dict[str, Any]:
    fps: Dict[str, Any] = {}

    def _safe_add_any(mod_path: str, candidates: Sequence[str], key: str) -> None:
        try:
            mod = __import__(mod_path, fromlist=["*"])
        except Exception:
            return
        for fn_name in candidates:
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                fps[key] = fn
                return

    # core
    _safe_add_any(
        "layers.layer0_observation.fingerprints.handshake_fp",
        ["build_handshake_fingerprint", "compute_handshake_fingerprint"],
        "handshake",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.fallback_path_fp",
        ["compute_fallback_path_fingerprint"],
        "fallback_path",
    )

    # required plugin fps
    _safe_add_any(
        "layers.layer0_observation.fingerprints.drift_fp",
        ["compute_drift_fingerprint", "build_drift_fingerprint"],
        "drift_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.jitter_fp",
        ["compute_jitter_fingerprint", "build_jitter_fingerprint"],
        "jitter_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.oscillation_fp",
        ["compute_oscillation_fingerprint"],
        "oscillation_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.correlation_shock_fp",
        ["compute_correlation_shock_fingerprint"],
        "correlation_shock_fp",
    )

    # NEW: coherence/coupling/meta fps
    _safe_add_any(
        "layers.layer0_observation.fingerprints.coherence_fp",
        ["compute_coherence_fingerprint"],
        "coherence_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.coupling_fp",
        ["compute_coupling_fingerprint"],
        "coupling_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.meta_fp",
        ["compute_meta_fingerprint"],
        "meta_fp",
    )

    # additional temporal/structural fingerprints
    _safe_add_any(
        "layers.layer0_observation.fingerprints.transition_fp",
        ["compute_transition_fingerprint", "build_transition_fingerprint"],
        "transition_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.momentum_fp",
        ["compute_momentum_fingerprint", "build_momentum_fingerprint"],
        "momentum_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.decay_fp",
        ["compute_decay_fingerprint"],
        "decay_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.resonance_fp",
        ["compute_resonance_fingerprint", "build_resonance_fingerprint"],
        "resonance_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.curvature_fp",
        ["compute_curvature_fingerprint"],
        "curvature_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.drift_acceleration_fp",
        ["compute_drift_acceleration_fingerprint"],
        "drift_acceleration_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.entropy_decay_slope_fp",
        ["compute_entropy_decay_slope_fingerprint"],
        "entropy_decay_slope_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.extension_vector_fp",
        ["compute_extension_vector_fingerprint"],
        "extension_vector_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.fallback_periodicity_fp",
        ["compute_fallback_periodicity_fingerprint"],
        "fallback_periodicity_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.retry_curve_fp",
        ["compute_retry_curve_fingerprint"],
        "retry_curve_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.signature_variance_fp",
        ["compute_signature_variance_fingerprint"],
        "signature_variance_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.signature_microvariance_fp",
        ["compute_signature_microvariance_fingerprint"],
        "signature_microvariance_fp",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.subms_jitter_fp",
        ["compute_subms_jitter_fingerprint"],
        "subms_jitter_fp",
    )

    # optional
    _safe_add_any(
        "layers.layer0_observation.fingerprints.entropy_histogram_fp",
        ["compute_entropy_histogram_fingerprint"],
        "entropy_histogram",
    )
    _safe_add_any(
        "layers.layer0_observation.fingerprints.cert_field_shape_fp",
        ["compute_cert_field_shape_fingerprint"],
        "cert_field_shape",
    )

    return fps


# =============================================================================
# Series extraction
# =============================================================================
def _extract_series(observations: Sequence[Any], field_name: str, *, max_n: int = 512) -> List[float]:
    out: List[float] = []
    for obs in observations:
        v = _get_field(obs, field_name, None)
        fv = _safe_float(v)
        if fv is None:
            continue
        out.append(float(fv))
        if len(out) >= max_n:
            break
    return out


def _extract_series_int(observations: Sequence[Any], field_name: str, *, max_n: int = 512) -> List[int]:
    out: List[int] = []
    for obs in observations:
        v = _get_field(obs, field_name, None)
        iv = _safe_int(v)
        if iv is None:
            continue
        out.append(int(iv))
        if len(out) >= max_n:
            break
    return out


def _flatten_series_list(observations: Sequence[Any], field_name: str, *, max_n: int = 2048) -> List[float]:
    out: List[float] = []
    for obs in observations:
        v = _get_field(obs, field_name, None)
        if not isinstance(v, (list, tuple)):
            continue
        for x in v:
            fv = _safe_float(x)
            if fv is None:
                continue
            out.append(float(fv))
            if len(out) >= max_n:
                return out
    return out


def _normalize_series01(values: Sequence[float]) -> List[float]:
    if not values:
        return []
    lo = min(values)
    hi = max(values)
    if hi - lo <= 1e-9:
        return [0.5 for _ in values]
    return [(v - lo) / (hi - lo) for v in values]


def _mean(values: Sequence[float]) -> float:
    return sum(values) / float(len(values)) if values else 0.0


def _std(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    m = _mean(values)
    var = sum((v - m) ** 2 for v in values) / max(1, len(values))
    return var ** 0.5


def _zscore(values: Sequence[float]) -> List[float]:
    if not values:
        return []
    m = _mean(values)
    s = _std(values) or 1e-9
    return [(v - m) / s for v in values]


def _extract_entropy_series(observations: Sequence[Any], *, max_n: int = 512) -> List[float]:
    candidates = ("entropy", "entropy_level", "signature_entropy", "key_entropy", "entropy_values")
    out: List[float] = []
    for obs in observations:
        v = None
        for k in candidates:
            vv = _get_field(obs, k, None)
            if vv is None:
                continue
            if isinstance(vv, (list, tuple)) and vv:
                vv = vv[-1]
            v = vv
            break
        fv = _safe_float(v)
        if fv is None:
            continue
        out.append(_clamp01(float(fv)))
        if len(out) >= max_n:
            break
    return out


def _extract_attempt_path_tokens_from_raw_events(raw_events: List[Mapping[str, Any]]) -> List[str]:
    for ev in raw_events:
        if not isinstance(ev, Mapping):
            continue
        val = ev.get("attempt_path") or ev.get("attempt_protocols") or ev.get("attempts")
        if isinstance(val, (list, tuple)) and val:
            toks: List[str] = []
            for x in val[:32]:
                sx = _safe_str(x, default="")
                if sx:
                    toks.append(sx)
            if toks:
                return toks
    return []


# =============================================================================
# Built-in guaranteed fingerprints (fallbacks)
# =============================================================================
def _robust_bucket(x: float) -> float:
    """
    Coarse quantizer for fallback identity hashing.
    """
    if x <= 0.0:
        return 0.0
    if x <= 1.0:
        return 1.0
    if x <= 2.0:
        return 2.0
    if x <= 5.0:
        return 3.0
    if x <= 10.0:
        return 4.0
    return 5.0


def _compute_drift_simple(values: List[float]) -> Dict[str, float]:
    if len(values) < 4:
        return {"drift": 0.0, "spread": 0.0}
    n = len(values)
    q = max(1, n // 4)
    a = sum(values[:q]) / q
    b = sum(values[-q:]) / q
    drift = b - a
    spread = max(values) - min(values)
    return {"drift": float(drift), "spread": float(spread)}


def _compute_jitter_simple(values: List[float]) -> Dict[str, float]:
    if len(values) < 3:
        return {"jitter": 0.0}
    ds = [abs(values[i] - values[i - 1]) for i in range(1, len(values))]
    jitter = sum(ds) / max(1, len(ds))
    return {"jitter": float(jitter)}


def _compute_oscillation_simple(values: List[float]) -> Dict[str, float]:
    if len(values) < 5:
        return {"oscillation": 0.0}
    deltas = [values[i] - values[i - 1] for i in range(1, len(values))]
    signs = [1 if d > 0 else -1 if d < 0 else 0 for d in deltas]
    changes = 0
    prev = signs[0]
    for s in signs[1:]:
        if s == 0:
            continue
        if prev != 0 and s != prev:
            changes += 1
        prev = s
    rate = changes / max(1, len(signs))
    return {"oscillation": float(rate)}


def _emit_builtin_drift_fp(entity_id: str, values: List[float]) -> Fingerprint:
    stats = _compute_drift_simple(values)
    drift = stats["drift"]
    spread = stats["spread"]

    payload = {"entity_id": entity_id, "kind": "drift_fp_v1", "bucket": float(_robust_bucket(abs(drift)))}
    fp_hash = Fingerprint.stable_hash_from_payload(payload)

    vector = Fingerprint.make_vector(
        [
            float(_robust_bucket(abs(drift))),
            float(_robust_bucket(spread / 10.0 if spread > 0 else 0.0)),
            float(_robust_bucket(len(values) / 64.0)),
        ],
        quantize_decimals=2,
    )

    return Fingerprint(
        entity_id=entity_id,
        kind="drift_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=Fingerprint.safe_quality(0.85 if len(values) >= 10 else 0.50),
        source_fields={"n": len(values), "drift": float(drift), "spread": float(spread)},
    )


def _emit_builtin_jitter_fp(entity_id: str, values: List[float]) -> Fingerprint:
    stats = _compute_jitter_simple(values)
    jitter = stats["jitter"]

    payload = {"entity_id": entity_id, "kind": "jitter_fp_v1", "bucket": float(_robust_bucket(jitter))}
    fp_hash = Fingerprint.stable_hash_from_payload(payload)

    vector = Fingerprint.make_vector(
        [
            float(_robust_bucket(jitter)),
            float(_robust_bucket(len(values) / 64.0)),
        ],
        quantize_decimals=2,
    )

    return Fingerprint(
        entity_id=entity_id,
        kind="jitter_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=Fingerprint.safe_quality(0.85 if len(values) >= 10 else 0.50),
        source_fields={"n": len(values), "jitter": float(jitter)},
    )


def _emit_builtin_oscillation_fp(entity_id: str, values: List[float]) -> Fingerprint:
    stats = _compute_oscillation_simple(values)
    osc = stats["oscillation"]

    payload = {"entity_id": entity_id, "kind": "oscillation_fp_v1", "bucket": float(_robust_bucket(osc * 10.0))}
    fp_hash = Fingerprint.stable_hash_from_payload(payload)

    vector = Fingerprint.make_vector(
        [
            float(_robust_bucket(osc * 10.0)),
            float(_robust_bucket(len(values) / 64.0)),
        ],
        quantize_decimals=2,
    )

    return Fingerprint(
        entity_id=entity_id,
        kind="oscillation_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=Fingerprint.safe_quality(0.80 if len(values) >= 12 else 0.45),
        source_fields={"n": len(values), "oscillation": float(osc)},
    )


# =============================================================================
# Main entrypoint
# =============================================================================
def observe_timing_batch(
    raw_events: Iterable[Mapping[str, Any]],
    *,
    entity_id: Optional[str] = None,
    window_ms: Optional[int] = None,
    prior_calibration: Any = None,  # API stability placeholder
) -> List[Fingerprint]:
    raw_list: List[Mapping[str, Any]] = []
    for ev in raw_events or []:
        if isinstance(ev, Mapping):
            raw_list.append(dict(ev))
    if not raw_list:
        return []

    # Allow forcing entity_id at callsite (tests / integration)
    if _is_nonempty_str(entity_id):
        forced = str(entity_id).strip()
        raw_list = [dict(ev, entity_id=forced) for ev in raw_list]

    build_obs = _import_schema_builder()
    validate_obs, repair_obs = _import_validator()
    physics_fns = _import_physics_compute()
    fp_fns = _import_fingerprints()

    parsed: List[Any] = []
    validation_failures = 0
    for ev in raw_list:
        if not _is_nonempty_str(ev.get("entity_id", "")):
            continue
        try:
            obs = build_obs(ev)
        except Exception:
            validation_failures += 1
            logger.warning(
                "layer0_observe.schema_error",
                extra={"entity_id": ev.get("entity_id"), "stage": "schema"},
            )
            continue
        try:
            obs = repair_obs(obs)
        except Exception:
            pass
        try:
            obs = validate_obs(obs)
        except Exception:
            validation_failures += 1
            logger.warning(
                "layer0_observe.validation_error",
                extra={"entity_id": ev.get("entity_id"), "stage": "validation"},
            )
            continue
        parsed.append(obs)

    if not parsed:
        return []

    eid = _safe_str(_get_field(parsed[0], "entity_id", ""), default="")
    if not eid:
        eid = _safe_str(entity_id, default="")
    if not eid:
        return []

    last = parsed[-1]

    # Normalization (series copy only; raw events preserved)
    normalizer = TimingNormalizer()
    normalized: List[Any] = []
    for obs in parsed:
        try:
            normalized.append(normalizer.normalize(obs, calibration=prior_calibration))
        except Exception:
            normalized.append(None)
    timestamps_ms = _extract_series_int(parsed, "event_time_ms", max_n=512)
    if not timestamps_ms:
        timestamps_ms = _extract_series_int(parsed, "timestamp_ms", max_n=512)

    if window_ms is None and len(timestamps_ms) >= 2:
        window_ms = max(0, timestamps_ms[-1] - timestamps_ms[0])

    rtt_series_raw = _extract_series(parsed, "rtt_ms", max_n=512)
    if not rtt_series_raw:
        rtt_series_raw = _extract_series(parsed, "tls_time_ms", max_n=512)
    if not rtt_series_raw:
        rtt_series_raw = _extract_series(parsed, "handshake_ms", max_n=512)

    rtt_series_norm = _extract_series(normalized, "rtt_norm", max_n=512)
    if not rtt_series_norm:
        rtt_series_norm = _extract_series(normalized, "rtt_ms", max_n=512)
    rtt_series_phys = rtt_series_norm or rtt_series_raw

    dns_series = _extract_series(parsed, "dns_time_ms", max_n=512)
    tcp_series = _extract_series(parsed, "tcp_time_ms", max_n=512)
    tls_series = _extract_series(parsed, "tls_time_ms", max_n=512)

    packet_spacing_ms = _flatten_series_list(parsed, "packet_spacing_ms", max_n=2048)
    if not packet_spacing_ms:
        packet_gaps_us = _flatten_series_list(parsed, "packet_gaps_us", max_n=2048)
        if packet_gaps_us:
            packet_spacing_ms = [v / 1000.0 for v in packet_gaps_us]

    entropy_series = _extract_entropy_series(parsed, max_n=512)
    if not entropy_series and rtt_series_raw:
        entropy_series = _normalize_series01(rtt_series_raw)

    # Signature tokens: prefer raw event fields, else derive from TLS fields
    signature_tokens: List[str] = []
    for ev in raw_list:
        if not isinstance(ev, Mapping):
            continue
        toks = ev.get("signature_tokens", None)
        if isinstance(toks, (list, tuple)):
            for t in toks:
                st = _safe_str(t, default="")
                if st:
                    signature_tokens.append(st)
            continue
        tls_v = _safe_str(ev.get("tls_version", ""), default="")
        cipher = _safe_str(ev.get("cipher", ""), default="")
        alpn = _safe_str(ev.get("alpn", ""), default="")
        if tls_v or cipher or alpn:
            signature_tokens.append(":".join([x for x in (tls_v, cipher, alpn) if x]))

    signature_tokens = sorted(set(signature_tokens))

    extensions = []
    if raw_list and isinstance(raw_list[-1], Mapping):
        extensions = (
            raw_list[-1].get("extensions")
            or raw_list[-1].get("tls_extensions")
            or raw_list[-1].get("cert_extension_hints")
            or []
        )
    if extensions:
        try:
            extensions = sorted(set(extensions))
        except Exception:
            pass

    # Attempt-path tokens fallback: use explicit tokens if provided, else TLS version sequence
    attempt_tokens = _extract_attempt_path_tokens_from_raw_events(raw_list)
    if not attempt_tokens and tls_series:
        attempt_tokens = [_safe_str(_get_field(obs, "tls_version", ""), default="") for obs in parsed]
        attempt_tokens = [t for t in attempt_tokens if t]

    fps_out: List[Fingerprint] = []

    # ============================================================
    # Physics Signals (activate full physics module set)
    # ============================================================
    physics_signals: Dict[str, Any] = {}

    drift_series: List[float] = []
    if rtt_series_phys and len(rtt_series_phys) >= 2:
        drift_fn = physics_fns.get("drift")
        for i in range(1, len(rtt_series_phys)):
            dt = 1.0
            if len(timestamps_ms) >= i + 1:
                delta_ms = max(1, timestamps_ms[i] - timestamps_ms[i - 1])
                dt = delta_ms / 1000.0
            if callable(drift_fn):
                drift_series.append(float(drift_fn(rtt_series_phys[i - 1], rtt_series_phys[i], dt)))
            else:
                drift_series.append(float(rtt_series_phys[i] - rtt_series_phys[i - 1]))

    momentum_series: List[float] = []
    if drift_series and len(drift_series) >= 2:
        mom_fn = physics_fns.get("momentum")
        for i in range(1, len(drift_series)):
            dt = 1.0
            if len(timestamps_ms) >= i + 2:
                delta_ms = max(1, timestamps_ms[i + 1] - timestamps_ms[i])
                dt = delta_ms / 1000.0
            if callable(mom_fn):
                momentum_series.append(float(mom_fn(drift_series[i - 1], drift_series[i], dt)))
            else:
                momentum_series.append(float(drift_series[i] - drift_series[i - 1]))

    jitter_value = 0.0
    jitter_fn = physics_fns.get("jitter")
    if packet_spacing_ms and callable(jitter_fn):
        try:
            jitter_value = float(jitter_fn(packet_spacing_ms))
        except Exception:
            jitter_value = 0.0

    oscillation_value = 0.0
    osc_fn = physics_fns.get("oscillation")
    if drift_series and callable(osc_fn):
        try:
            oscillation_value = float(osc_fn(drift_series))
        except Exception:
            oscillation_value = 0.0

    coherence_score = None
    coh_fn = physics_fns.get("coherence")
    if rtt_series_phys and callable(coh_fn):
        try:
            coherence_score = float(coh_fn(rtt_series_phys))
        except Exception:
            coherence_score = None

    decay_metrics: Dict[str, Any] = {}
    decay_fn = physics_fns.get("decay")
    if rtt_series_phys and callable(decay_fn):
        try:
            decay_metrics = dict(decay_fn(rtt_series_phys))
        except Exception:
            decay_metrics = {}

    corr_fn = physics_fns.get("correlation")
    a_series = rtt_series_phys
    b_series = tls_series or tcp_series
    if a_series and b_series and callable(corr_fn):
        n = min(len(a_series), len(b_series))
        try:
            _ = dict(corr_fn(a_series[:n], b_series[:n]))
        except Exception:
            pass

    coupling_metrics: Dict[str, Any] = {}
    cpl_fn = physics_fns.get("coupling")
    if a_series and b_series and callable(cpl_fn):
        n = min(len(a_series), len(b_series))
        try:
            coupling_metrics = dict(cpl_fn(a_values=a_series[:n], b_values=b_series[:n]))
        except Exception:
            coupling_metrics = {}

    meta_metrics: Dict[str, Any] = {}
    meta_fn = physics_fns.get("meta")
    if rtt_series_phys and callable(meta_fn):
        try:
            meta_metrics = dict(meta_fn(values=rtt_series_phys, window_ms=window_ms))
        except Exception:
            meta_metrics = {}

    resonance_metrics: Dict[str, Any] = {}
    res_fn = physics_fns.get("resonance")
    if callable(res_fn):
        signals: Dict[str, List[float]] = {}
        if rtt_series_phys:
            signals["rtt"] = _zscore(rtt_series_phys)
        if tls_series:
            signals["tls"] = _zscore(tls_series)
        if packet_spacing_ms:
            signals["jitter"] = _zscore(packet_spacing_ms)
        if signals:
            try:
                resonance_metrics = dict(res_fn(signals, threshold=2.0))
            except Exception:
                resonance_metrics = {}

    def _emit(fp: Optional[Fingerprint]) -> None:
        if fp is None or not isinstance(fp, Fingerprint):
            return
        fp2 = _force_entity_id(fp, eid)
        fp2 = _sanitize_fingerprint(fp2)
        created_ms = _deterministic_created_ms(timestamps_ms)
        fp_id = fp2.fingerprint_id
        if _is_default_fp_id(fp_id) or not fp_id:
            fp_id = _deterministic_fp_id(fp2, created_ms)
        fp2 = Fingerprint(
            fingerprint_id=fp_id,
            entity_id=fp2.entity_id,
            kind=fp2.kind,
            version=fp2.version,
            created_ms=created_ms,
            hash=fp2.hash,
            vector=fp2.vector,
            quality=fp2.quality,
            source_fields=fp2.source_fields,
        )
        fps_out.append(fp2)

    # -------------------------------------------------------------------------
    # 1) handshake_fp_v1 (mandatory)
    # -------------------------------------------------------------------------
    try:
        hb = fp_fns.get("handshake")
        if hb is None:
            raise RuntimeError("handshake builder missing")

        handshake_payload = raw_list[-1] if raw_list else last
        try:
            fp = hb(entity_id=eid, observation=handshake_payload)  # type: ignore
        except TypeError:
            fp = hb(observation=handshake_payload)  # type: ignore
        _emit(fp)
    except Exception as e:
        payload = {"entity_id": eid, "kind": "handshake_fp_v1", "fallback": 1}
        _emit(
            Fingerprint(
                entity_id=eid,
                kind="handshake_fp_v1",
                version=1,
                hash=Fingerprint.stable_hash_from_payload(payload),
                vector=Fingerprint.make_vector([0.0]),
                quality=Fingerprint.safe_quality(0.1),
                source_fields={"fallback": 1, "error": _safe_str(e)[:160]},
            )
        )

    # -------------------------------------------------------------------------
    # 2) fallback_path_fp_v1 (attempt-path behavior)
    # -------------------------------------------------------------------------
    if attempt_tokens:
        try:
            fb = fp_fns.get("fallback_path")
            if fb is not None:
                _emit(fb(entity_id=eid, attempt_protocols=attempt_tokens))  # type: ignore
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 3) Optional: entropy histogram / cert
    # -------------------------------------------------------------------------
    if entropy_series:
        try:
            eh = fp_fns.get("entropy_histogram")
            if eh is not None:
                _emit(eh(entity_id=eid, entropy_values=entropy_series))  # type: ignore
        except Exception:
            pass

    try:
        cf = fp_fns.get("cert_field_shape")
        if cf is not None:
            cert_fields = _get_field(last, "cert_fields", None)
            if cert_fields is None and raw_list and isinstance(raw_list[-1], dict):
                cert_fields = raw_list[-1].get("cert_fields", None)
            if cert_fields is not None:
                _emit(cf(entity_id=eid, cert_fields=cert_fields))  # type: ignore
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 4) drift_fp_v1 (required)
    # -------------------------------------------------------------------------
    if rtt_series_raw:
        emitted = False
        try:
            drift_builder = fp_fns.get("drift_fp")
            if drift_builder is not None:
                drift_mean = _mean(drift_series) if drift_series else 0.0
                drift_z = _mean(_zscore(drift_series)) if drift_series else 0.0
                drift_std = _std(drift_series)
                _emit(
                    drift_builder(
                        entity_id=eid,
                        physics_signals={
                            "drift_rate": drift_mean,
                            "drift_zscore": drift_z,
                            "baseline_drift_std": drift_std,
                            "coherence_drop": (1.0 - float(coherence_score)) if coherence_score is not None else 0.0,
                            "window_size": len(rtt_series_raw),
                        },
                    )
                )
                emitted = True
        except Exception:
            emitted = False

        if not emitted:
            _emit(_emit_builtin_drift_fp(eid, rtt_series_raw))

    # -------------------------------------------------------------------------
    # 5) jitter_fp_v1 (required)
    # -------------------------------------------------------------------------
    if packet_spacing_ms:
        emitted = False
        try:
            jitter_builder = fp_fns.get("jitter_fp")
            if jitter_builder is not None:
                _emit(
                    jitter_builder(
                        entity_id=eid,
                        jitter_samples_ms=packet_spacing_ms,
                        physics_signals={"jitter_score": jitter_value},
                        window_ms=window_ms,
                    )
                )
                emitted = True
        except Exception:
            emitted = False

        if not emitted and rtt_series_raw:
            _emit(_emit_builtin_jitter_fp(eid, rtt_series_raw))

    # -------------------------------------------------------------------------
    # 6) oscillation_fp_v1 OR correlation_shock_fp_v1 (required)
    # -------------------------------------------------------------------------
    if rtt_series_raw:
        emitted_any = False

        try:
            osc_builder = fp_fns.get("oscillation_fp")
            if osc_builder is not None:
                _emit(
                    osc_builder(
                        entity_id=eid,
                        signal_name="rtt_ms",
                        signal_values=rtt_series_raw,
                        physics_signals={
                            "oscillation_energy": oscillation_value,
                            "oscillation_flip_rate": oscillation_value,
                        },
                        window_ms=window_ms,
                    )
                )
                emitted_any = True
        except Exception:
            pass

        try:
            corr_builder = fp_fns.get("correlation_shock_fp")
            if corr_builder is not None and not emitted_any and a_series and b_series:
                n = min(len(a_series), len(b_series))
                mid = n // 2
                early_corr = 0.0
                late_corr = 0.0
                if mid >= 2:
                    try:
                        early_corr = float(corr_fn(a_series[:mid], b_series[:mid]).get("correlation", 0.0)) if callable(corr_fn) else 0.0
                        late_corr = float(corr_fn(a_series[mid:n], b_series[mid:n]).get("correlation", 0.0)) if callable(corr_fn) else 0.0
                    except Exception:
                        early_corr = 0.0
                        late_corr = 0.0
                shock = abs(late_corr - early_corr)
                _emit(
                    corr_builder(
                        entity_id=eid,
                        a_values=a_series[:n],
                        b_values=b_series[:n],
                        physics_signals={
                            "early_corr": early_corr,
                            "late_corr": late_corr,
                            "correlation_shock": shock,
                        },
                        window_ms=window_ms,
                    )
                )
                emitted_any = True
        except Exception:
            pass

        if not emitted_any:
            _emit(_emit_builtin_oscillation_fp(eid, rtt_series_raw))

    # -------------------------------------------------------------------------
    # 7) NEW: coherence_fp_v1 (structural stability)
    # -------------------------------------------------------------------------
    try:
        coh_builder = fp_fns.get("coherence_fp")
        if coh_builder is not None:
            _emit(
                coh_builder(
                    entity_id=eid,
                    signal_name="rtt_ms",
                    signal_values=rtt_series_raw,
                    physics_signals={
                        "coherence_score": coherence_score if coherence_score is not None else 0.0,
                        "coherence_dispersion": 1.0 - float(coherence_score) if coherence_score is not None else 0.0,
                    },
                    window_ms=window_ms,
                )
            )
    except Exception:
        # coherence is optional; never break pipeline
        pass

    # -------------------------------------------------------------------------
    # 8) NEW: coupling_fp_v1 (second-order structure)
    # -------------------------------------------------------------------------
    try:
        cpl_builder = fp_fns.get("coupling_fp")
        if cpl_builder is not None:
            _emit(cpl_builder(entity_id=eid, physics_signals=coupling_metrics or {}))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 9) NEW: meta_fp_v1 (third-order structure)
    # -------------------------------------------------------------------------
    try:
        meta_builder = fp_fns.get("meta_fp")
        if meta_builder is not None:
            _emit(meta_builder(entity_id=eid, physics_signals=meta_metrics or {}))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 10) transition_fp_v1 (change dynamics)
    # -------------------------------------------------------------------------
    try:
        tr_builder = fp_fns.get("transition_fp")
        if tr_builder is not None and rtt_series_raw:
            norm_series = _normalize_series01(rtt_series_raw)
            _emit(tr_builder(entity_id=eid, signal_name="rtt_ms", signal_values=norm_series, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 11) momentum_fp_v1 (second-order)
    # -------------------------------------------------------------------------
    try:
        mom_builder = fp_fns.get("momentum_fp")
        if mom_builder is not None:
            mom_mean = _mean(momentum_series) if momentum_series else 0.0
            mom_z = _mean(_zscore(momentum_series)) if momentum_series else 0.0
            acc = momentum_series[-1] if momentum_series else 0.0
            _emit(
                mom_builder(
                    entity_id=eid,
                    physics_signals={
                        "momentum": mom_mean,
                        "momentum_zscore": mom_z,
                        "acceleration": acc,
                        "window_size": len(rtt_series_raw),
                    },
                )
            )
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 12) decay_fp_v1 (slow degradation)
    # -------------------------------------------------------------------------
    try:
        dec_builder = fp_fns.get("decay_fp")
        if dec_builder is not None and rtt_series_raw:
            _emit(dec_builder(entity_id=eid, signal_name="rtt_ms", signal_values=rtt_series_raw, physics_signals=decay_metrics, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 13) resonance_fp_v1 (multi-signal amplification)
    # -------------------------------------------------------------------------
    try:
        res_builder = fp_fns.get("resonance_fp")
        if res_builder is not None:
            _emit(res_builder(entity_id=eid, physics_signals=resonance_metrics or {}, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 13) curvature_fp_v1 (second derivative / jerkiness)
    # -------------------------------------------------------------------------
    try:
        curv_builder = fp_fns.get("curvature_fp")
        if curv_builder is not None and drift_series:
            _emit(curv_builder(entity_id=eid, signal_name="drift", signal_values=drift_series, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 14) drift_acceleration_fp_v1 (drift curvature)
    # -------------------------------------------------------------------------
    try:
        da_builder = fp_fns.get("drift_acceleration_fp")
        if da_builder is not None and drift_series:
            _emit(da_builder(entity_id=eid, drift_values=drift_series, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 15) entropy_decay_slope_fp_v1 (entropy-like slope)
    # -------------------------------------------------------------------------
    try:
        ed_builder = fp_fns.get("entropy_decay_slope_fp")
        if ed_builder is not None and entropy_series:
            _emit(ed_builder(entity_id=eid, entropy_values=entropy_series, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 16) extension_vector_fp_v1
    # -------------------------------------------------------------------------
    try:
        ext_builder = fp_fns.get("extension_vector_fp")
        if ext_builder is not None:
            _emit(ext_builder(entity_id=eid, extensions=extensions or []))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 17) fallback_periodicity_fp_v1
    # -------------------------------------------------------------------------
    try:
        fp_builder = fp_fns.get("fallback_periodicity_fp")
        if fp_builder is not None and timestamps_ms:
            _emit(fp_builder(entity_id=eid, event_times_ms=timestamps_ms, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 18) retry_curve_fp_v1
    # -------------------------------------------------------------------------
    try:
        rc_builder = fp_fns.get("retry_curve_fp")
        if rc_builder is not None and timestamps_ms:
            _emit(rc_builder(entity_id=eid, attempt_times_ms=timestamps_ms, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 19) signature_variance_fp_v1
    # -------------------------------------------------------------------------
    try:
        sv_builder = fp_fns.get("signature_variance_fp")
        if sv_builder is not None:
            _emit(sv_builder(entity_id=eid, signatures=signature_tokens))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 20) signature_microvariance_fp_v1
    # -------------------------------------------------------------------------
    try:
        sm_builder = fp_fns.get("signature_microvariance_fp")
        if sm_builder is not None:
            _emit(sm_builder(entity_id=eid, signature_tokens=signature_tokens, window_ms=window_ms))
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 21) subms_jitter_fp_v1
    # -------------------------------------------------------------------------
    try:
        sj_builder = fp_fns.get("subms_jitter_fp")
        if sj_builder is not None and packet_spacing_ms:
            _emit(sj_builder(entity_id=eid, jitter_values_ms=packet_spacing_ms, window_ms=window_ms))
    except Exception:
        pass

    if validation_failures > 0 and fps_out:
        fp0 = fps_out[0]
        sf = dict(fp0.source_fields or {})
        sf["_validation_failures"] = int(validation_failures)
        fps_out[0] = Fingerprint(
            fingerprint_id=fp0.fingerprint_id,
            entity_id=fp0.entity_id,
            kind=fp0.kind,
            version=fp0.version,
            created_ms=fp0.created_ms,
            hash=fp0.hash,
            vector=fp0.vector,
            quality=fp0.quality,
            source_fields=sf,
        )
    return fps_out
