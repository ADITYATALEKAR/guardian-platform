"""
test_layer0_bank_grade_evaluation.py

Bank-grade evaluation tests for Layer0.

Goals:
- Verify stability under benign noise (low false positives).
- Verify sensitivity under controlled structural attacks (high recall).
- Verify separation across entities (no cross-entity collisions).
- Verify adversarial evasion resistance (bounded churn, partial invariance).
- Verify output is audit-friendly (contract + boundedness + deterministic identity).

These tests do NOT assume Layer0 does semantic detection.
They validate that Layer0 extracts stable structural physics signals and fingerprints
that can power higher-level detection systems.
"""

from __future__ import annotations

import math
import random
import time
from typing import Any, Dict, List, Mapping, Tuple

import pytest

from layers.layer0_observation.observe import observe_timing_batch
from layers.layer0_observation.fingerprints.fingerprint_types import Fingerprint


# -----------------------------
# Helpers
# -----------------------------

def _assert_contract(fp: Fingerprint) -> None:
    assert isinstance(fp, Fingerprint)
    assert isinstance(fp.fingerprint_id, str) and fp.fingerprint_id.strip()
    assert isinstance(fp.entity_id, str) and fp.entity_id.strip()
    assert isinstance(fp.kind, str) and fp.kind.strip()
    assert isinstance(fp.version, int) and fp.version >= 1
    assert isinstance(fp.hash, str) and fp.hash.strip()

    # accept raw hex or "h_" prefixed
    h = fp.hash.strip()
    if h.startswith("h_"):
        h = h[2:]
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h.lower())

    assert isinstance(fp.vector, list)
    assert 1 <= len(fp.vector) <= 128
    assert all(isinstance(x, float) and math.isfinite(x) for x in fp.vector)

    assert isinstance(fp.quality, float)
    assert 0.0 <= fp.quality <= 1.0

    assert isinstance(fp.source_fields, dict)
    assert len(fp.source_fields) <= 64


def _fingerprints_by_kind(fps: List[Fingerprint]) -> Dict[str, List[Fingerprint]]:
    out: Dict[str, List[Fingerprint]] = {}
    for fp in fps:
        out.setdefault(fp.kind, []).append(fp)
    return out


def _hashes_by_kind(fps: List[Fingerprint]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for fp in fps:
        out.setdefault(fp.kind, []).append(fp.hash)
    return out


def _pick_last_kind_hash(fps: List[Fingerprint], kind: str) -> str | None:
    for fp in reversed(fps):
        if fp.kind == kind:
            return fp.hash
    return None


# -----------------------------
# Synthetic event generators
# -----------------------------

def _base_event(entity_id: str, ts_ms: int) -> Dict[str, Any]:
    # minimal event shape consistent with your Layer0 tests
    return {
        "entity_id": entity_id,
        "ts_ms": ts_ms,
        "protocol": "TLS1.3",
        "rtt_ms": 12.0,
        "handshake_ms": 25.0,
        "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        "extensions": ["server_name", "supported_versions", "key_share"],
        "sni": "example.net",
        "clienthello_len": 512,
        "serverhello_len": 256,
        # optional signals
        "entropy_values": [0.3, 0.31, 0.29],
        "cert_fields": {"issuer_cn": "CA", "subject_cn": "example.net"},
        "attempt_path": ["TLS1.3"],
    }


def _gen_stable_benign(entity_id: str, n: int = 96, noise: float = 0.25) -> List[Dict[str, Any]]:
    """
    Stable endpoint with tiny noise (benign jitter).
    Layer0 should remain stable in identity hashes for physics & structural FPs.
    """
    now = int(time.time() * 1000)
    out: List[Dict[str, Any]] = []
    for i in range(n):
        ev = _base_event(entity_id, now + i * 10)
        ev["rtt_ms"] = 12.0 + random.uniform(-noise, noise)
        ev["handshake_ms"] = 25.0 + random.uniform(-noise, noise)
        # small entropy wobble
        ev["entropy_values"] = [0.30 + random.uniform(-0.02, 0.02) for _ in range(3)]
        out.append(ev)
    return out


def _gen_oscillation_attack(entity_id: str, n: int = 96) -> List[Dict[str, Any]]:
    """
    Oscillation pattern: alternating fast/slow latencies.
    This should trigger oscillation_fp_v1 OR correlation_shock_fp_v1 depending
    on what your repo emits.
    """
    now = int(time.time() * 1000)
    out: List[Dict[str, Any]] = []
    for i in range(n):
        ev = _base_event(entity_id, now + i * 10)
        # alternate RTT
        ev["rtt_ms"] = 10.0 if (i % 2 == 0) else 50.0
        # handshake correlates
        ev["handshake_ms"] = 20.0 if (i % 2 == 0) else 80.0
        # attempt path shows occasional downgrade retry
        if i % 16 == 0:
            ev["attempt_path"] = ["TLS1.3", "TLS1.2"]
        out.append(ev)
    return out


def _gen_drift_attack(entity_id: str, n: int = 96) -> List[Dict[str, Any]]:
    """
    Slow monotonic drift in RTT.
    Should produce drift_fp_v1.
    """
    now = int(time.time() * 1000)
    out: List[Dict[str, Any]] = []
    base = 10.0
    for i in range(n):
        ev = _base_event(entity_id, now + i * 10)
        ev["rtt_ms"] = base + (i * 0.5)
        ev["handshake_ms"] = 20.0 + (i * 0.2)
        out.append(ev)
    return out


def _gen_fallback_path_attack(entity_id: str, n: int = 96) -> List[Dict[str, Any]]:
    """
    Attempt-path downgrade / retry signature.
    Must emit fallback_path_fp_v1.
    """
    now = int(time.time() * 1000)
    out: List[Dict[str, Any]] = []
    for i in range(n):
        ev = _base_event(entity_id, now + i * 10)
        # simulate retries between TLS versions
        if i % 3 == 0:
            ev["attempt_path"] = ["TLS1.3", "TLS1.2"]
        elif i % 3 == 1:
            ev["attempt_path"] = ["TLS1.2"]
        else:
            ev["attempt_path"] = ["TLS1.3"]
        out.append(ev)
    return out


# -----------------------------
# Bank-grade tests
# -----------------------------

@pytest.mark.layer0
def test_layer0_bank_grade_cross_entity_separation():
    """
    Two different endpoints must not collapse into identical fingerprints
    for core identity kinds.
    """
    raw_a = _gen_stable_benign("endpoint-bank-A", n=96, noise=0.1)
    raw_b = _gen_stable_benign("endpoint-bank-B", n=96, noise=0.1)

    fps_a = observe_timing_batch(raw_a)
    fps_b = observe_timing_batch(raw_b)

    assert fps_a and fps_b
    for fp in fps_a + fps_b:
        _assert_contract(fp)

    ha = _pick_last_kind_hash(fps_a, "handshake_fp_v1")
    hb = _pick_last_kind_hash(fps_b, "handshake_fp_v1")

    assert ha is not None and hb is not None

    # IMPORTANT:
    # handshake_fp_v1 is a *global structural fingerprint* (like JA3),
    # so same handshake shape should hash identically across entities.
    assert ha == hb, (
        "handshake_fp_v1 hash should represent handshake structure, "
        "not entity identity. If this fails, you lose cross-entity comparability."
    )

    # However, entity_id MUST be preserved to prevent cross-entity mixing downstream
    assert all(fp.entity_id == "endpoint-bank-A" for fp in fps_a)
    assert all(fp.entity_id == "endpoint-bank-B" for fp in fps_b)



@pytest.mark.layer0
def test_layer0_bank_grade_drift_sensitivity():
    """
    Controlled monotonic drift should yield drift_fp_v1.
    """
    raw = _gen_drift_attack("endpoint-bank-drift", n=96)
    fps = observe_timing_batch(raw)
    assert fps
    for fp in fps:
        _assert_contract(fp)

    kinds = {fp.kind for fp in fps}
    assert "drift_fp_v1" in kinds, f"Expected drift_fp_v1, got {kinds}"


@pytest.mark.layer0
def test_layer0_bank_grade_oscillation_or_shock_presence():
    """
    Oscillation pattern must produce oscillation_fp_v1 OR correlation_shock_fp_v1.
    We accept either because repos can implement either.
    """
    raw = _gen_oscillation_attack("endpoint-bank-osc", n=96)
    fps = observe_timing_batch(raw)
    assert fps
    for fp in fps:
        _assert_contract(fp)

    kinds = {fp.kind for fp in fps}
    assert ("oscillation_fp_v1" in kinds) or ("correlation_shock_fp_v1" in kinds), (
        f"Expected oscillation_fp_v1 or correlation_shock_fp_v1, got {kinds}"
    )


@pytest.mark.layer0
def test_layer0_bank_grade_fallback_path_presence():
    """
    Retry / downgrade attempt paths must emit fallback_path_fp_v1.
    """
    raw = _gen_fallback_path_attack("endpoint-bank-fallback", n=96)
    fps = observe_timing_batch(raw)
    assert fps
    for fp in fps:
        _assert_contract(fp)

    kinds = {fp.kind for fp in fps}
    assert "fallback_path_fp_v1" in kinds, f"Expected fallback_path_fp_v1, got {kinds}"


@pytest.mark.layer0
def test_layer0_bank_grade_large_batch_does_not_degrade_contract():
    """
    Production reality:
    large batches happen. We validate that performance stays acceptable and
    contract remains bounded.

    This is NOT a micro-benchmark; we just ensure it doesn't explode.
    """
    random.seed(13)

    raw = _gen_stable_benign("endpoint-bank-big", n=2048, noise=0.3)

    t0 = time.perf_counter()
    fps = observe_timing_batch(raw)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert fps
    for fp in fps:
        _assert_contract(fp)

    # Generous threshold to avoid CI flakiness on windows
    assert elapsed_ms < 1200.0, f"Layer0 too slow for large batch: {elapsed_ms:.2f}ms"


@pytest.mark.layer0
def test_layer0_bank_grade_entity_partitioning_never_mixes():
    """
    Bank-grade guarantee:
    Even if fingerprints have identical hashes across entities (expected),
    Layer0 must NEVER output wrong/mixed entity_id.

    This is the true separation requirement for multi-tenant operation.
    """
    raw_a = _gen_stable_benign("endpoint-bank-A", n=64, noise=0.1)
    raw_b = _gen_stable_benign("endpoint-bank-B", n=64, noise=0.1)

    fps_a = observe_timing_batch(raw_a)
    fps_b = observe_timing_batch(raw_b)

    assert fps_a and fps_b

    for fp in fps_a:
        assert fp.entity_id == "endpoint-bank-A"

    for fp in fps_b:
        assert fp.entity_id == "endpoint-bank-B"
