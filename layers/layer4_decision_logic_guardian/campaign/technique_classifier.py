"""
Layer 4 - Technique classifier (deterministic, conditional).

Rules are loaded from a versioned JSON contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def _clamp01(x: Any) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


@dataclass(frozen=True, slots=True)
class TechniqueLabel:
    label: str
    description: str
    supporting_kinds: List[str]


@dataclass(frozen=True, slots=True)
class _TechniqueRule:
    label: str
    description: str
    thresholds: Tuple[Tuple[str, float], ...]
    max_horizon_days: Optional[int]


_RULES_PATH = Path(__file__).with_name("technique_rules.v1.json")
_RULES_CACHE: Optional[List[_TechniqueRule]] = None


def _load_rules() -> List[_TechniqueRule]:
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    if not _RULES_PATH.exists():
        raise RuntimeError(f"Technique rules missing: {_RULES_PATH}")
    try:
        payload = json.loads(_RULES_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Technique rules invalid JSON: {_RULES_PATH}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Technique rules payload must be object")
    if str(payload.get("schema_version", "")).strip() != "v1":
        raise RuntimeError("Unsupported technique rules schema_version")
    rows = payload.get("rules")
    if not isinstance(rows, list):
        raise RuntimeError("Technique rules missing rules[]")

    compiled: List[_TechniqueRule] = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("Technique rule row must be object")
        label = str(row.get("label", "")).strip()
        description = str(row.get("description", "")).strip()
        thresholds_raw = row.get("thresholds")
        max_horizon_raw = row.get("max_horizon_days")
        if not label or not description:
            raise RuntimeError("Technique rule missing label/description")
        if not isinstance(thresholds_raw, dict) or not thresholds_raw:
            raise RuntimeError(f"Technique rule {label} missing thresholds")
        thresholds: List[Tuple[str, float]] = []
        for metric_key, threshold in thresholds_raw.items():
            metric = str(metric_key).strip()
            if not metric:
                raise RuntimeError(f"Technique rule {label} has empty metric key")
            thresholds.append((metric, _clamp01(threshold)))
        max_horizon = None
        if max_horizon_raw is not None:
            try:
                max_horizon = max(0, int(max_horizon_raw))
            except Exception as exc:
                raise RuntimeError(f"Technique rule {label} has invalid max_horizon_days") from exc
        compiled.append(
            _TechniqueRule(
                label=label,
                description=description,
                thresholds=tuple(sorted(thresholds)),
                max_horizon_days=max_horizon,
            )
        )
    compiled.sort(key=lambda r: r.label)
    _RULES_CACHE = compiled
    return compiled


def classify_techniques(signals: Iterable[Dict[str, Any]]) -> List[TechniqueLabel]:
    rules = _load_rules()
    labels: List[TechniqueLabel] = []

    for s in signals or []:
        if not isinstance(s, dict):
            continue
        kind = str(s.get("prediction_kind", "")).strip()
        metrics = s.get("metrics", {})
        if not isinstance(metrics, dict):
            continue

        horizon: Optional[int] = None
        if "horizon_days" in s:
            try:
                horizon = int(s.get("horizon_days", 0))
            except Exception:
                horizon = 0

        for rule in rules:
            if rule.max_horizon_days is not None:
                if horizon is None or int(horizon) > int(rule.max_horizon_days):
                    continue
            matched = True
            for metric_name, threshold in rule.thresholds:
                if metric_name not in metrics:
                    matched = False
                    break
                if _clamp01(metrics.get(metric_name)) < threshold:
                    matched = False
                    break
            if not matched:
                continue
            labels.append(
                TechniqueLabel(
                    label=rule.label,
                    description=rule.description,
                    supporting_kinds=[kind],
                )
            )

    seen: Dict[Tuple[str, str], TechniqueLabel] = {}
    for lbl in labels:
        seen[(lbl.label, lbl.description)] = lbl
    return [seen[key] for key in sorted(seen.keys())]
