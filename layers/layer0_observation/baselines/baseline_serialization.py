from typing import Dict
from layers.layer0_observation.baselines.baseline_types import (
    EntityBaseline,
    BaselineStats,
)


# ------------------------------------------------------------
# Serialization
# ------------------------------------------------------------

def serialize_baseline_store(
    snapshot: Dict[str, EntityBaseline],
) -> Dict[str, Dict]:
    """
    Convert BaselineStore.snapshot() to JSON-safe dict.
    """
    out: Dict[str, Dict] = {}

    for entity_id, baseline in snapshot.items():
        metrics_dict: Dict[str, Dict] = {}

        for metric_name, stats in baseline.metrics.items():
            metrics_dict[metric_name] = {
                "mean": stats.mean,
                "mad": stats.mad,
                "ewma": stats.ewma,
                "min_v": stats.min_v,
                "max_v": stats.max_v,
                "maturity": stats.maturity,
                "n_bucket": stats.n_bucket,
            }

        out[entity_id] = {
            "entity_id": baseline.entity_id,
            "updated_at_ms": baseline.updated_at_ms,
            "metrics": metrics_dict,
        }

    return out


# ------------------------------------------------------------
# Hydration
# ------------------------------------------------------------

def hydrate_baseline_store(
    raw: Dict[str, Dict],
) -> Dict[str, EntityBaseline]:
    """
    Convert persisted dict back into EntityBaseline objects.
    """
    result: Dict[str, EntityBaseline] = {}

    for entity_id, data in raw.items():
        metrics_raw = data.get("metrics", {})
        metrics: Dict[str, BaselineStats] = {}

        for metric_name, stats in metrics_raw.items():
            metrics[metric_name] = BaselineStats(
                mean=float(stats.get("mean", 0.0)),
                mad=float(stats.get("mad", 0.0)),
                ewma=float(stats.get("ewma", 0.0)),
                min_v=float(stats.get("min_v", 0.0)),
                max_v=float(stats.get("max_v", 0.0)),
                maturity=float(stats.get("maturity", 0.0)),
                n_bucket=int(stats.get("n_bucket", 0)),
            )

        result[entity_id] = EntityBaseline(
            entity_id=entity_id,
            updated_at_ms=data.get("updated_at_ms"),
            metrics=metrics,
        )

    return result