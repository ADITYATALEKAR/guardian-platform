from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

from infrastructure.layer5_api.bootstrap import (
    Layer5BootstrapConfig,
    build_layer5_runtime_bundle,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guardian cycle worker")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--cycle-id")
    parser.add_argument("--cycle-number", type=int)
    parser.add_argument("--storage-root", required=True)
    parser.add_argument("--operator-storage-root", required=True)
    parser.add_argument("--simulation-root", required=True)
    parser.add_argument("--master-env", default="OPERATOR_MASTER_PASSWORD")
    parser.add_argument("--layer2-mode", default="hybrid")
    parser.add_argument("--discovery-max-workers", type=int, default=10)
    parser.add_argument("--discovery-max-endpoints", type=int, default=5000)
    parser.add_argument("--discovery-samples-per-endpoint", type=int, default=8)
    parser.add_argument("--discovery-max-san-recursion", type=int, default=5)
    parser.add_argument("--discovery-max-dns-recursion", type=int, default=5)
    parser.add_argument("--discovery-max-spf-recursion", type=int, default=5)
    parser.add_argument("--discovery-max-ct-calls-per-cycle", type=int, default=5)
    parser.add_argument("--discovery-category-a-time-budget-seconds", type=int, default=300)
    parser.add_argument("--discovery-bcde-time-budget-seconds", type=int, default=300)
    parser.add_argument("--cycle-time-budget-seconds", type=int, default=1200)
    parser.add_argument("--discovery-exploration-budget-seconds", type=int, default=600)
    parser.add_argument("--discovery-exploitation-budget-seconds", type=int, default=600)
    parser.add_argument("--discovery-module-time-slice-seconds", type=int, default=60)
    parser.add_argument("--scheduler-cadence-seconds", type=int, default=7200)
    parser.add_argument("--scheduler-tick-seconds", type=int, default=5)
    parser.add_argument("--allow-insecure-tls", default="false")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger = logging.getLogger(__name__)

    bundle = build_layer5_runtime_bundle(
        Layer5BootstrapConfig(
            storage_root=str(args.storage_root),
            operator_storage_root=str(args.operator_storage_root),
            simulation_root=str(args.simulation_root),
            master_env=str(args.master_env),
            layer2_mode=str(args.layer2_mode),
            discovery_max_workers=int(args.discovery_max_workers),
            discovery_max_endpoints=int(args.discovery_max_endpoints),
            discovery_samples_per_endpoint=int(args.discovery_samples_per_endpoint),
            discovery_max_san_recursion=int(args.discovery_max_san_recursion),
            discovery_max_dns_recursion=int(args.discovery_max_dns_recursion),
            discovery_max_spf_recursion=int(args.discovery_max_spf_recursion),
            discovery_max_ct_calls_per_cycle=int(args.discovery_max_ct_calls_per_cycle),
            discovery_category_a_time_budget_seconds=int(
                args.discovery_category_a_time_budget_seconds
            ),
            discovery_bcde_time_budget_seconds=int(
                args.discovery_bcde_time_budget_seconds
            ),
            cycle_time_budget_seconds=int(args.cycle_time_budget_seconds),
            discovery_exploration_budget_seconds=int(
                args.discovery_exploration_budget_seconds
            ),
            discovery_exploitation_budget_seconds=int(
                args.discovery_exploitation_budget_seconds
            ),
            discovery_module_time_slice_seconds=int(
                args.discovery_module_time_slice_seconds
            ),
            scheduler_cadence_seconds=int(args.scheduler_cadence_seconds),
            scheduler_tick_seconds=int(args.scheduler_tick_seconds),
            discovery_allow_insecure_tls=str(args.allow_insecure_tls).strip().lower()
            in {"1", "true", "yes", "on"},
            enable_background_scheduler=False,
        )
    )

    tenant_id = str(args.tenant_id)
    cycle_id = str(args.cycle_id).strip() if args.cycle_id else None
    cycle_number = int(args.cycle_number) if args.cycle_number else None
    scheduler_sync = getattr(
        getattr(bundle, "operator_service", None),
        "sync_scheduler_state_from_cycle_result",
        None,
    )
    try:
        logger.info(
            "cycle_worker_started tenant_id=%s cycle_id=%s cycle_number=%s",
            tenant_id,
            cycle_id or "-",
            cycle_number or "-",
        )
        bundle.orchestrator.run_cycle(
            tenant_id,
            cycle_id=cycle_id,
            cycle_number=cycle_number,
        )
        bundle.operator_service._tenant_lifecycle.mark_tenant_onboarding_completed(
            tenant_id
        )
        if callable(scheduler_sync):
            scheduler_sync(
                tenant_id=tenant_id,
                cycle_id=cycle_id,
                cycle_number=cycle_number,
                status="completed",
            )
        logger.info("cycle_worker_completed tenant_id=%s", tenant_id)
        return 0
    except Exception as exc:
        try:
            if callable(scheduler_sync):
                scheduler_sync(
                    tenant_id=tenant_id,
                    cycle_id=cycle_id,
                    cycle_number=cycle_number,
                    status="failed",
                    error_message=str(exc),
                )
        except Exception:
            logger.exception("cycle_worker_scheduler_sync_failed tenant_id=%s", tenant_id)
        logger.exception("cycle_worker_failed tenant_id=%s", tenant_id)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
