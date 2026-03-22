from __future__ import annotations

from pathlib import Path

from infrastructure.aggregation.aggregation_engine import AggregationEngine
from infrastructure.discovery.discovery_engine import DiscoveryEngine
from infrastructure.storage_manager.storage_manager import StorageManager


def _new_storage(tmp_path: Path) -> StorageManager:
    storage = StorageManager(str(tmp_path / "storage_root"))
    storage.create_tenant("tenant_a")
    storage.save_tenant_config(
        "tenant_a",
        {
            "tenant_id": "tenant_a",
            "name": "Example Bank",
            "main_url": "https://www.banconal.com.pa/",
            "seed_endpoints": ["www.banconal.com.pa:443"],
            "onboarding_status": "COMPLETED",
        },
    )
    return storage


def test_phase9_observation_surface_prioritizes_tenant_scope_before_provider_noise(
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    engine = DiscoveryEngine(storage=storage, max_endpoints=100, max_workers=1)

    roots = ["www.banconal.com.pa:443"]
    scope_profile = engine._build_scope_profile(roots)
    expanded = {
        "api.banconal.com.pa:443",
        "admin.banconal.com.pa:443",
        "banconal-com-pa.mail.protection.outlook.com:25",
        "104.20.37.21:443",
        "104.20.37.21:8080",
        "cloudflare.com:443",
        "www.cloudflare.com:443",
        "mailcontrol.com:443",
        "3labs.mailcontrol.com:443",
        "sync.mailcontrol.com:443",
        "mss.mailcontrol.com:443",
        "cluster-b.mailcontrol.com:443",
        "forcepoint.net:443",
        "pki.forcepoint.net:443",
        "websense.com:443",
        "www.websense.com:443",
        "amazonses.com:443",
        "www.amazonses.com:443",
        "1.aws-lbr.amazonaws.com:443",
        "www.amazonaws-china.com:443",
        "unknown-example.net:443",
        "another-unknown.example.org:443",
    }

    selected, summary = engine._select_observation_targets(
        roots=roots,
        expanded_candidates=expanded,
        scope_profile=scope_profile,
        max_targets=100,
    )

    selected_set = set(selected)
    assert "www.banconal.com.pa:443" in selected_set
    assert "api.banconal.com.pa:443" in selected_set
    assert "admin.banconal.com.pa:443" in selected_set
    assert "banconal-com-pa.mail.protection.outlook.com:25" in selected_set
    assert engine._should_expand_runtime_candidate(
        "api.banconal.com.pa:443",
        scope_profile=scope_profile,
    )
    assert engine._should_expand_runtime_candidate(
        "banconal-com-pa.mail.protection.outlook.com:443",
        scope_profile=scope_profile,
    )
    assert not engine._should_expand_runtime_candidate(
        "cloudflare.com:443",
        scope_profile=scope_profile,
    )

    provider_only_selected = [
        endpoint
        for endpoint in selected
        if any(
            token in endpoint
            for token in (
                "cloudflare",
                "mailcontrol",
                "forcepoint",
                "websense",
                "amazonses",
                "amazonaws",
            )
        )
        and "banconal-com-pa" not in endpoint
    ]
    assert len(selected) < len(set(roots) | expanded)
    assert len(provider_only_selected) <= summary["provider_edge_budget"]


def test_phase9_relevance_classifier_demotes_shared_provider_hosts_but_keeps_tenant_embedded_dependencies(
    tmp_path: Path,
) -> None:
    storage = _new_storage(tmp_path)
    engine = AggregationEngine(storage=storage)
    scope_profile = {
        "exact_hosts": {"www.banconal.com.pa"},
        "base_domains": {"banconal.com.pa"},
    }

    adjacent = engine._classify_endpoint_relevance(
        endpoint={"hostname": "banconal-com-pa.mail.protection.outlook.com", "port": 25},
        guardian={},
        discovery_sources=[],
        endpoint_confidence=1.0,
        alert_count=0,
        scope_profile=scope_profile,
    )
    pure_provider = engine._classify_endpoint_relevance(
        endpoint={"hostname": "cloudflare.com", "port": 443},
        guardian={"severity": 1.0},
        discovery_sources=[],
        endpoint_confidence=1.0,
        alert_count=1,
        scope_profile=scope_profile,
    )

    assert adjacent[0] == "adjacent_dependency"
    assert adjacent[1] >= 0.78
    assert "tenant scope" in adjacent[3].lower()

    assert pure_provider[0] == "third_party_dependency"
    assert pure_provider[2] <= 0.38
    assert pure_provider[2] < adjacent[2]
