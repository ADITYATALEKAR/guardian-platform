"""
handshake_schema.py

Layer 0 schema for raw handshake/network/crypto observables.

Design goals:
- Raw observables only (no semantics/risk/interpretation)
- Deterministic, bounded, JSON-safe
- Flexible enough to transport handshake + timing + crypto structural signals
- Token-safe: supports strings/ints/lists from collectors

This schema is deliberately "flat-ish" and transport-focused.
Validation happens in validation/ modules (not here).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _safe_str(x: Any, default: str = "") -> str:
    s = str(x or "").strip()
    return s if s else default


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        v = int(x)
        return v
    except Exception:
        return default


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        f = float(x)
        if f != f:  # NaN
            return default
        if f == float("inf") or f == float("-inf"):
            return default
        return f
    except Exception:
        return default


def _bounded_list_str(values: Any, *, max_items: int, max_len: int = 64) -> Tuple[str, ...]:
    """
    Canonicalize a token list into a bounded tuple[str,...].
    - preserves order (raw ordering is meaningful for negotiation patterns)
    - trims blanks
    - bounds count and token length
    """
    out: List[str] = []
    if values is None:
        return tuple()
    if isinstance(values, (list, tuple)):
        src = values
    else:
        src = [values]

    for t in src:
        s = _safe_str(t, default="")
        if not s:
            continue
        s = s[:max_len]
        out.append(s)
        if len(out) >= max_items:
            break
    return tuple(out)


def _bounded_series(values: Any, *, max_items: int) -> Tuple[float, ...]:
    """
    Bounded numeric series transport. Non-finite -> dropped.
    """
    out: List[float] = []
    if values is None:
        return tuple()
    if isinstance(values, (list, tuple)):
        src = values
    else:
        src = [values]

    for v in src:
        f = _safe_float(v, default=None)  # type: ignore[arg-type]
        if f is None:
            continue
        out.append(float(f))
        if len(out) >= max_items:
            break
    return tuple(out)


@dataclass(frozen=True)
class HandshakeObservation:
    """
    Transport object for raw Layer-0 handshake observables.

    Key principle:
    This object is not an interpretation of anything.
    It's simply a canonical container for raw observed features.

    entity_id: stable identity (IP:port, client-id, endpoint key, etc.)
    """
    entity_id: str

    # Optional signal routing name (if you want to treat this as multi-signal)
    signal_name: str = "handshake"

    # Timing anchors (ms or epoch-ms depending on collector discipline)
    t_start_ms: Optional[int] = None
    t_end_ms: Optional[int] = None

    # Derived raw duration (transport convenience; not interpretation)
    rtt_ms: Optional[float] = None
    convergence_ms: Optional[float] = None

    # Retry/fallback attempt series (protocol tokens)
    attempt_protocols: Tuple[str, ...] = field(default_factory=tuple)

    # TLS handshake structures (raw tokens)
    sni: str = ""
    alpn: Tuple[str, ...] = field(default_factory=tuple)
    tls_version: str = ""

    cipher_suites: Tuple[str, ...] = field(default_factory=tuple)
    extensions: Tuple[str, ...] = field(default_factory=tuple)
    supported_groups: Tuple[str, ...] = field(default_factory=tuple)
    signature_algorithms: Tuple[str, ...] = field(default_factory=tuple)

    # “Structure bytes” transported safely as shape-only, not raw bytes dump.
    # Collector can fill these with:
    # - length
    # - coarse byte histogram sketch
    # - presence sketch
    clienthello_shape: Tuple[float, ...] = field(default_factory=tuple)
    serverhello_shape: Tuple[float, ...] = field(default_factory=tuple)

    # High-res timing raw samples (bounded)
    packet_gaps_us: Tuple[float, ...] = field(default_factory=tuple)
    subms_jitter_samples: Tuple[float, ...] = field(default_factory=tuple)

    # Crypto structural signals (raw numeric windows or scalar hints)
    entropy_values: Tuple[float, ...] = field(default_factory=tuple)
    signature_tokens: Tuple[str, ...] = field(default_factory=tuple)

    # Shape-only certificate field descriptors (collector-safe)
    cert_fields: Dict[str, Any] = field(default_factory=dict)

    # Load/context (raw, numeric-only preferred)
    cpu_load_norm: Optional[float] = None
    queue_depth: Optional[int] = None
    concurrency: Optional[int] = None
    request_rate_hint: Optional[float] = None

    # Extra raw metadata (bounded in validation layer; left flexible here)
    meta: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_raw(payload: Dict[str, Any]) -> "HandshakeObservation":
        """
        Factory from raw dict payloads.

        Strictly transport: only canonicalize + bound sizes.
        No semantics.
        """
        entity_id = _safe_str(payload.get("entity_id"), default="")
        if not entity_id:
            raise ValueError("HandshakeObservation.entity_id must be non-empty")

        signal_name = _safe_str(payload.get("signal_name"), default="handshake")

        t_start_ms = payload.get("t_start_ms", None)
        t_end_ms = payload.get("t_end_ms", None)
        if t_start_ms is not None:
            t_start_ms = _safe_int(t_start_ms, default=0)
        if t_end_ms is not None:
            t_end_ms = _safe_int(t_end_ms, default=0)

        rtt_ms = payload.get("rtt_ms", None)
        convergence_ms = payload.get("convergence_ms", None)
        if rtt_ms is not None:
            rtt_ms = _safe_float(rtt_ms, default=0.0)
        if convergence_ms is not None:
            convergence_ms = _safe_float(convergence_ms, default=0.0)

        obs = HandshakeObservation(
            entity_id=entity_id,
            signal_name=signal_name,
            t_start_ms=t_start_ms,
            t_end_ms=t_end_ms,
            rtt_ms=rtt_ms,
            convergence_ms=convergence_ms,
            attempt_protocols=_bounded_list_str(payload.get("attempt_protocols"), max_items=16, max_len=32),
            sni=_safe_str(payload.get("sni"), default="")[:128],
            alpn=_bounded_list_str(payload.get("alpn"), max_items=8, max_len=32),
            tls_version=_safe_str(payload.get("tls_version"), default="")[:32],
            cipher_suites=_bounded_list_str(payload.get("cipher_suites"), max_items=64, max_len=64),
            extensions=_bounded_list_str(payload.get("extensions"), max_items=128, max_len=64),
            supported_groups=_bounded_list_str(payload.get("supported_groups"), max_items=32, max_len=64),
            signature_algorithms=_bounded_list_str(payload.get("signature_algorithms"), max_items=64, max_len=64),
            clienthello_shape=_bounded_series(payload.get("clienthello_shape"), max_items=64),
            serverhello_shape=_bounded_series(payload.get("serverhello_shape"), max_items=64),
            packet_gaps_us=_bounded_series(payload.get("packet_gaps_us"), max_items=512),
            subms_jitter_samples=_bounded_series(payload.get("subms_jitter_samples"), max_items=512),
            entropy_values=_bounded_series(payload.get("entropy_values"), max_items=256),
            signature_tokens=_bounded_list_str(payload.get("signature_tokens"), max_items=256, max_len=64),
            cert_fields=dict(payload.get("cert_fields") or {}),
            cpu_load_norm=_safe_float(payload.get("cpu_load_norm"), default=None) if payload.get("cpu_load_norm") is not None else None,
            queue_depth=_safe_int(payload.get("queue_depth"), default=0) if payload.get("queue_depth") is not None else None,
            concurrency=_safe_int(payload.get("concurrency"), default=0) if payload.get("concurrency") is not None else None,
            request_rate_hint=_safe_float(payload.get("request_rate_hint"), default=None) if payload.get("request_rate_hint") is not None else None,
            meta=dict(payload.get("meta") or {}),
        )
        return obs
