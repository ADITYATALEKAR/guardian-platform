from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple, ClassVar
import math

from core_utils.safety import clamp01 as _clamp01
from core_utils.safety import safe_float as _safe_float
from core_utils.safety import safe_int as _safe_int
from core_utils.safety import safe_str as _safe_str

# Hard caps
MAX_KINDS = 24
MAX_PERSISTENCE = 20
MAX_CO_OCCURRENCE = MAX_KINDS * MAX_KINDS

# Temporal constants (from spec)
ALPHA_S = 0.30
ALPHA_C = 0.30
ABSENCE_DECAY = 0.85
CO_ALPHA = 0.20
CO_DECAY = 0.90
PERSISTENCE_THRESHOLD = 0.35

def _assert_finite_01(name: str, v: float) -> None:
    if not isinstance(v, (int, float)):
        raise ValueError(f"{name} not numeric")
    if not math.isfinite(float(v)):
        raise ValueError(f"{name} not finite")
    if v < 0.0 or v > 1.0:
        raise ValueError(f"{name} out of [0,1]")


def _assert_non_negative_int(name: str, v: int, max_v: int) -> None:
    if not isinstance(v, int):
        raise ValueError(f"{name} not int")
    if v < 0 or v > max_v:
        raise ValueError(f"{name} out of bounds")


def _sorted_keys(keys: Iterable[str]) -> List[str]:
    return sorted({_safe_str(k) for k in keys if _safe_str(k)})


def _assert_no_wall_clock() -> None:
    # Hard guard: Layer3 must not rely on wall-clock time
    if "time" in globals() or "datetime" in globals():
        raise RuntimeError("Layer3 wall-clock usage is forbidden")


@dataclass(frozen=True, slots=True)
class AxisState:
    ewma_severity: float = 0.0
    ewma_confidence: float = 0.0
    reliability_ewma: float = 0.0
    volatility_ewma: float = 0.0
    peak_severity_recent: float = 0.0
    velocity: float = 0.0
    persistence: int = 0

    def __post_init__(self) -> None:
        es = _clamp01(self.ewma_severity)
        ec = _clamp01(self.ewma_confidence)
        rel = _clamp01(self.reliability_ewma)
        vol = _clamp01(self.volatility_ewma)
        peak = _clamp01(self.peak_severity_recent)
        v = max(-1.0, min(1.0, _safe_float(self.velocity, 0.0)))
        p = max(0, min(MAX_PERSISTENCE, int(self.persistence)))

        _assert_finite_01("ewma_severity", es)
        _assert_finite_01("ewma_confidence", ec)
        _assert_finite_01("reliability_ewma", rel)
        _assert_finite_01("volatility_ewma", vol)
        _assert_finite_01("peak_severity_recent", peak)
        if not math.isfinite(float(v)):
            raise ValueError("velocity not finite")
        _assert_non_negative_int("persistence", p, MAX_PERSISTENCE)

        object.__setattr__(self, "ewma_severity", float(es))
        object.__setattr__(self, "ewma_confidence", float(ec))
        object.__setattr__(self, "reliability_ewma", float(rel))
        object.__setattr__(self, "volatility_ewma", float(vol))
        object.__setattr__(self, "peak_severity_recent", float(peak))
        object.__setattr__(self, "velocity", float(v))
        object.__setattr__(self, "persistence", int(p))


@dataclass(frozen=True, slots=True)
class LearningState:
    SNAPSHOT_VERSION: ClassVar[int] = 1
    version: int = 3
    entity_id: str = "unknown"
    last_ts_ms: int = 0

    axis_state: Dict[str, AxisState] = field(default_factory=dict)
    co_occurrence: Dict[str, float] = field(default_factory=dict)

    propagation_persistence: int = 0
    structural_reinforcement_score: float = 0.0

    def __post_init__(self) -> None:
        eid = _safe_str(self.entity_id, "unknown")
        ts = max(0, _safe_int(self.last_ts_ms, 0))
        if int(self.version) != 3:
            raise ValueError("LearningState version mismatch")
        if len(self.axis_state) > MAX_KINDS:
            raise ValueError("axis_state exceeds MAX_KINDS")
        if len(self.co_occurrence) > MAX_CO_OCCURRENCE:
            raise ValueError("co_occurrence exceeds MAX_CO_OCCURRENCE")

        # deterministic ordering for axis_state
        axis_out: Dict[str, AxisState] = {}
        for k in _sorted_keys(self.axis_state.keys()):
            if len(axis_out) >= MAX_KINDS:
                break
            st = self.axis_state.get(k)
            if isinstance(st, AxisState):
                axis_out[k] = st

        # deterministic ordering for co_occurrence
        co_out: Dict[str, float] = {}
        for k in sorted(self.co_occurrence.keys()):
            if len(co_out) >= MAX_CO_OCCURRENCE:
                break
            v = _clamp01(self.co_occurrence.get(k, 0.0))
            _assert_finite_01("co_occurrence", v)
            parts = k.split("|")
            if len(parts) == 2:
                if parts[0] >= parts[1]:
                    raise ValueError("co_occurrence key not ordered")
            co_out[k] = float(v)

        pp = max(0, min(MAX_PERSISTENCE, int(self.propagation_persistence)))
        rs = _clamp01(self.structural_reinforcement_score)
        _assert_non_negative_int("propagation_persistence", pp, MAX_PERSISTENCE)
        _assert_finite_01("structural_reinforcement_score", rs)

        object.__setattr__(self, "entity_id", eid)
        object.__setattr__(self, "last_ts_ms", int(ts))
        object.__setattr__(self, "axis_state", axis_out)
        object.__setattr__(self, "co_occurrence", co_out)
        object.__setattr__(self, "propagation_persistence", int(pp))
        object.__setattr__(self, "structural_reinforcement_score", float(rs))

    @staticmethod
    def empty(entity_id: str) -> "LearningState":
        return LearningState(version=3, entity_id=_safe_str(entity_id, "unknown"))

    @staticmethod
    def from_dict(payload: Dict[str, Any]) -> "LearningState":
        if not isinstance(payload, dict):
            raise ValueError("LearningState payload invalid")

        version = int(payload.get("version", 1) or 1)
        if version not in (1, 2, 3):
            raise ValueError("LearningState version mismatch")

        axis_raw = payload.get("axis_state", {})
        axis_state: Dict[str, AxisState] = {}
        if isinstance(axis_raw, dict):
            for k in _sorted_keys(axis_raw.keys()):
                if len(axis_state) >= MAX_KINDS:
                    break
                v = axis_raw.get(k, {})
                if not isinstance(v, dict):
                    continue
                axis_state[k] = AxisState(
                    ewma_severity=_safe_float(v.get("ewma_severity", 0.0), 0.0),
                    ewma_confidence=_safe_float(v.get("ewma_confidence", 0.0), 0.0),
                    reliability_ewma=_safe_float(v.get("reliability_ewma", 0.0), 0.0),
                    volatility_ewma=_safe_float(v.get("volatility_ewma", 0.0), 0.0),
                    peak_severity_recent=_safe_float(v.get("peak_severity_recent", 0.0), 0.0),
                    velocity=_safe_float(v.get("velocity", 0.0), 0.0),
                    persistence=_safe_int(v.get("persistence", 0), 0),
                )

        co_raw = payload.get("co_occurrence", {})
        co_occurrence: Dict[str, float] = {}
        if isinstance(co_raw, dict):
            for k in sorted(co_raw.keys()):
                if len(co_occurrence) >= MAX_CO_OCCURRENCE:
                    break
                co_occurrence[k] = _clamp01(co_raw.get(k, 0.0))

        return LearningState(
            version=3,
            entity_id=_safe_str(payload.get("entity_id", "unknown")),
            last_ts_ms=_safe_int(payload.get("last_ts_ms", 0), 0),
            axis_state=axis_state,
            co_occurrence=co_occurrence,
            propagation_persistence=_safe_int(payload.get("propagation_persistence", 0), 0),
            structural_reinforcement_score=_safe_float(payload.get("structural_reinforcement_score", 0.0), 0.0),
        )

    def to_dict(self) -> Dict[str, Any]:
        axis_out: Dict[str, Any] = {}
        for k in _sorted_keys(self.axis_state.keys()):
            st = self.axis_state.get(k)
            if not isinstance(st, AxisState):
                continue
            axis_out[k] = {
                "ewma_severity": float(st.ewma_severity),
                "ewma_confidence": float(st.ewma_confidence),
                "reliability_ewma": float(st.reliability_ewma),
                "volatility_ewma": float(st.volatility_ewma),
                "peak_severity_recent": float(st.peak_severity_recent),
                "velocity": float(st.velocity),
                "persistence": int(st.persistence),
            }

        co_out: Dict[str, float] = {}
        for k in sorted(self.co_occurrence.keys()):
            v = _clamp01(self.co_occurrence.get(k, 0.0))
            co_out[k] = float(v)

        return {
            "version": 3,
            "entity_id": self.entity_id,
            "last_ts_ms": int(self.last_ts_ms),
            "axis_state": axis_out,
            "co_occurrence": co_out,
            "propagation_persistence": int(self.propagation_persistence),
            "structural_reinforcement_score": float(self.structural_reinforcement_score),
        }


    @staticmethod
    def from_snapshot(snapshot: Dict[str, Any], *, tenant_id: str) -> Dict[str, 'LearningState']:
        if not isinstance(snapshot, dict):
            raise RuntimeError("Corrupt layer3 snapshot")
        if int(snapshot.get('version', 0) or 0) != LearningState.SNAPSHOT_VERSION:
            raise RuntimeError("Corrupt layer3 snapshot")
        entities = snapshot.get('entities', {})
        if not isinstance(entities, dict):
            raise RuntimeError("Corrupt layer3 snapshot")
        out: Dict[str, LearningState] = {}
        for eid in sorted(entities.keys()):
            if len(out) >= 1000000:
                raise RuntimeError("Corrupt layer3 snapshot")
            payload = entities.get(eid)
            if not isinstance(payload, dict):
                raise RuntimeError("Corrupt layer3 snapshot")
            st = LearningState.from_dict(payload)
            out[_safe_str(eid, 'unknown')] = st
        return out

    @staticmethod
    def to_snapshot(state_map: Dict[str, 'LearningState'], *, tenant_id: str) -> Dict[str, Any]:
        entities: Dict[str, Any] = {}
        for eid in sorted(state_map.keys()):
            st = state_map.get(eid)
            if not isinstance(st, LearningState):
                continue
            entities[_safe_str(eid, 'unknown')] = st.to_dict()
        return {
            'version': LearningState.SNAPSHOT_VERSION,
            'tenant_id': _safe_str(tenant_id, ''),
            'entities': entities,
        }

    def update_from_signals(
        self,
        signals: List[Dict[str, Any]],
        *,
        ts_ms: int,
        propagation_flag: int,
    ) -> "LearningState":
        _assert_no_wall_clock()
        # map to current axis values (use max severity, then max confidence)
        current: Dict[str, Tuple[float, float]] = {}
        for s in signals:
            if not isinstance(s, dict):
                continue
            k = _safe_str(s.get("weakness_kind", "")).lower()
            if not k:
                continue
            sev = _clamp01(s.get("severity_01", 0.0))
            conf = _clamp01(s.get("confidence_01", 0.0))
            prev = current.get(k)
            if prev is None or sev > prev[0] or (sev == prev[0] and conf > prev[1]):
                current[k] = (sev, conf)

        active_kinds = _sorted_keys(current.keys())
        # ensure active kinds are kept within MAX_KINDS
        keys: List[str] = list(active_kinds)
        for k in _sorted_keys(self.axis_state.keys()):
            if k not in current:
                keys.append(k)
        keys = _sorted_keys(keys)[:MAX_KINDS]

        axis_out: Dict[str, AxisState] = {}
        for k in keys:
            prev = self.axis_state.get(k, AxisState())
            if k in current:
                s_t, c_t = current[k]
                ewma_s = ALPHA_S * s_t + (1.0 - ALPHA_S) * prev.ewma_severity
                ewma_c = ALPHA_C * c_t + (1.0 - ALPHA_C) * prev.ewma_confidence
                if s_t >= PERSISTENCE_THRESHOLD:
                    p = min(MAX_PERSISTENCE, prev.persistence + 1)
                else:
                    p = max(0, prev.persistence - 1)
            else:
                ewma_s = ABSENCE_DECAY * prev.ewma_severity
                ewma_c = ABSENCE_DECAY * prev.ewma_confidence
                p = max(0, prev.persistence - 1)

            v = max(-1.0, min(1.0, ewma_s - prev.ewma_severity))
            if k in current:
                diff = abs(s_t - ewma_s)
                rel = ALPHA_S * diff + (1.0 - ALPHA_S) * prev.reliability_ewma
                vol = ALPHA_S * abs(v) + (1.0 - ALPHA_S) * prev.volatility_ewma
                if s_t > prev.peak_severity_recent:
                    peak = s_t
                else:
                    peak = max(ABSENCE_DECAY * prev.peak_severity_recent, ewma_s)
            else:
                rel = ABSENCE_DECAY * prev.reliability_ewma
                vol = ABSENCE_DECAY * prev.volatility_ewma
                peak = max(ABSENCE_DECAY * prev.peak_severity_recent, ewma_s)

            axis_out[k] = AxisState(
                ewma_severity=ewma_s,
                ewma_confidence=ewma_c,
                reliability_ewma=rel,
                volatility_ewma=vol,
                peak_severity_recent=peak,
                velocity=v,
                persistence=p,
            )

        # co-occurrence update (bounded, deterministic)
        severity_by_kind: Dict[str, float] = {k: float(current[k][0]) for k in active_kinds if k in current}
        co_out: Dict[str, float] = {}
        key_list = _sorted_keys(axis_out.keys())
        for i in range(len(key_list)):
            for j in range(i + 1, len(key_list)):
                a = key_list[i]
                b = key_list[j]
                pair_key = f"{a}|{b}"
                prev_val = _clamp01(self.co_occurrence.get(pair_key, 0.0))
                if a in severity_by_kind and b in severity_by_kind:
                    x = min(severity_by_kind[a], severity_by_kind[b])
                    val = CO_ALPHA * x + (1.0 - CO_ALPHA) * prev_val
                else:
                    val = CO_DECAY * prev_val
                co_out[pair_key] = _clamp01(val)
                if len(co_out) >= MAX_CO_OCCURRENCE:
                    break
            if len(co_out) >= MAX_CO_OCCURRENCE:
                break

        if co_out:
            co_mean = sum(co_out.values()) / max(1, len(co_out))
        else:
            co_mean = 0.0
        co_mean = _clamp01(co_mean)

        # propagation persistence
        if int(propagation_flag) >= 1:
            prop_p = min(MAX_PERSISTENCE, self.propagation_persistence + 1)
        else:
            prop_p = max(0, self.propagation_persistence - 1)

        active_set = set(current.keys())
        recurrence_density = _clamp01(len(active_set) / float(MAX_KINDS))
        reinforcement = _clamp01(
            0.40 * (prop_p / float(MAX_PERSISTENCE))
            + 0.30 * co_mean
            + 0.30 * recurrence_density
        )

        # assertions
        if len(axis_out) > MAX_KINDS:
            raise ValueError("axis_state exceeds MAX_KINDS")
        if len(co_out) > MAX_CO_OCCURRENCE:
            raise ValueError("co_occurrence exceeds MAX_CO_OCCURRENCE")
        for key in co_out.keys():
            parts = key.split("|")
            if len(parts) != 2 or parts[0] >= parts[1]:
                raise ValueError("co_occurrence key not ordered")
        _assert_finite_01("co_mean", co_mean)
        _assert_finite_01("reinforcement", reinforcement)
        _assert_non_negative_int("propagation_persistence", prop_p, MAX_PERSISTENCE)

        return LearningState(
            version=3,
            entity_id=self.entity_id,
            last_ts_ms=max(0, int(ts_ms)),
            axis_state=axis_out,
            co_occurrence=co_out,
            propagation_persistence=prop_p,
            structural_reinforcement_score=reinforcement,
        )
