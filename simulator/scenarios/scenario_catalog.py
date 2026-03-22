"""
Scenario Catalog
================

Deterministic baseline attack scenarios loaded from a versioned JSON catalog.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass(frozen=True, slots=True)
class AttackScenario:
    id: str
    injection_type: str
    target_selector: Dict[str, Any]
    injection_payload: Dict[str, Any]
    description: str


_DEFAULT_CATALOG_PATH = Path(__file__).with_name("scenario_catalog.v1.json")
_ENV_OVERRIDE = "GUARDIAN_SCENARIO_CATALOG_PATH"


def _resolve_catalog_path() -> Path:
    override = str(os.getenv(_ENV_OVERRIDE, "")).strip()
    return Path(override) if override else _DEFAULT_CATALOG_PATH


def _load_catalog_payload() -> Dict[str, Any]:
    path = _resolve_catalog_path()
    if not path.exists():
        raise RuntimeError(f"Scenario catalog missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Scenario catalog is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Scenario catalog must be an object: {path}")
    version = str(payload.get("schema_version", "")).strip()
    if version != "v1":
        raise RuntimeError(f"Unsupported scenario catalog schema_version: {version or '<missing>'}")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        raise RuntimeError("Scenario catalog missing scenarios[]")
    return payload


def get_default_scenarios() -> List[AttackScenario]:
    """
    Return deterministic baseline scenarios from the JSON catalog.
    """
    payload = _load_catalog_payload()
    scenarios = payload.get("scenarios", [])
    out: List[AttackScenario] = []
    for row in scenarios:
        if not isinstance(row, dict):
            raise RuntimeError("Scenario catalog row must be object")
        scenario_id = str(row.get("id", "")).strip()
        injection_type = str(row.get("injection_type", "")).strip()
        description = str(row.get("description", "")).strip()
        target_selector = row.get("target_selector", {})
        injection_payload = row.get("injection_payload", {})
        if not scenario_id or not injection_type or not description:
            raise RuntimeError("Scenario catalog row missing required fields")
        if not isinstance(target_selector, dict):
            raise RuntimeError(f"Scenario {scenario_id}: target_selector must be object")
        if not isinstance(injection_payload, dict):
            raise RuntimeError(f"Scenario {scenario_id}: injection_payload must be object")
        out.append(
            AttackScenario(
                id=scenario_id,
                injection_type=injection_type,
                target_selector=dict(target_selector),
                injection_payload=dict(injection_payload),
                description=description,
            )
        )
    out.sort(key=lambda s: s.id)
    return out
