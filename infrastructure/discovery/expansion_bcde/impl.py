"""
expansion_category_bcde.py

External Attack Surface Construction Engine
Category BCDE — Active + Correlative + Infrastructure + Signature + Historical

Consumes: PassiveDiscoveryGraph from Category A
Produces: Enriched PassiveDiscoveryGraph → EndpointCandidate list

29 Modules across 7 Sections:

SECTION 1 — Active Surface Expansion (9 modules)
 1. CommonPortScanModule              — Multi-port TCP probing per domain/IP
 2. TLSPortVariantsModule             — TLS handshake on non-443 ports
 3. BannerAnalysisModule              — Banner/header capture per open port
 4. HTTPProbeModule                   — HEAD→GET, redirect chain, header extraction
 5. HTTPCrawlModule                   — BFS crawl, link/subdomain extraction
 6. JSAnalysisModule                  — JS file endpoint/domain extraction
 7. OpenAPIProbeModule                — Swagger/OpenAPI endpoint discovery
 8. HTTPResponseSignatureModule       — Body hash, header hash, status clustering
 9. TLSServerFingerprintModule        — TLS cipher+version fingerprint, backend clustering

SECTION 2 — Infrastructure Correlation (5 modules)
10. IPNeighborExpansionModule         — Controlled /24 neighbor probing
11. NetblockExpansionModule           — CIDR modeling from RDAP data
12. SharedIPCorrelationModule         — Domain↔Domain shared IP edges
13. JARMFingerprintModule             — TLS fingerprint capture + clustering
14. CDNEdgeMappingModule              — CDN vendor detection + edge region inference

SECTION 3 — Cloud & Platform Intelligence (3 modules)
15. CloudBucketPatternsModule         — S3/Azure/GCP bucket inference + HEAD probe
16. CloudFrontAnalysisModule          — CloudFront alternate domain discovery
17. K8sPatternModule                  — Kubernetes ingress/namespace pattern detection

SECTION 4 — Historical & Revival Logic (3 modules)
18. HistoricalRevivalModule           — Dormant domain active-probe revival
19. ExpiredAssetDetectionModule       — Cert expired + DNS alive classification
20. OrphanedAssetDetectionModule      — DNS dead + cert exists orphan tagging

SECTION 5 — Signature & Coverage (2 modules)
21. FaviconHashModule                 — Favicon download + hash clustering
22. WildcardCoverageModule            — Wildcard SAN → subdomain coverage edges

SECTION 6 — Volatility & Risk Modeling (3 modules)
23. EndpointVolatilityModule          — Response instability, cert rotation, IP drift tracking
24. MultiSourceCrossValidationModule  — Cross-signal validation, conflict scoring
25. ControlledRecursiveExpansionModule — Depth-bounded recursive subdomain re-expansion

SECTION 7 — Confidence & Recalibration (4 modules)
26. SignalConflictDetectionModule         — Multi-source contradiction detection
27. CertificateIssuerClusteringModule     — Issuer grouping + rotation detection
28. RiskWeightedEdgeAdjustmentModule      — Edge confidence reweighting by risk class
29. ConfidenceRecalibrationModule         — Graph-wide confidence normalization (runs LAST)

Internal Engines:
 - ActiveProbeEngine      (HTTP/port probing, caching, rate guard)
 - SignatureEngine        (favicon hash, response hash, TLS fingerprint)
 - InfrastructureEngine  (JARM approx, netblock, shared-IP grouping)
 - CrawlEngine           (BFS crawl, JS parse, API detection)
 - HistoricalEngine      (revival detection, drift analysis)
 - VolatilityEngine      (response variance, cert rotation, IP drift, redirect volatility)
 - ConfidenceEngine      (conflict detection, multi-source validation, recalibration)

Architectural Contract:
 - Consumes graph from Category A (additive only, never deletes)
 - Defines BCDEEdgeType for new relationship types
 - BCDEExpansionContext wraps ExpansionContext + BCDE-specific caches
 - All modules independent, deletion-safe
 - Deterministic execution order
 - Hard caps on port attempts, crawl depth, neighbor expansion
 - Clean extraction boundary: DOMAIN + PORT combinations only

Author: AVYAKTA ASM System
Date: 2026-02-19
Status: PRODUCTION READY — Fully Aggressive Enterprise ASM (29 Modules)

FIX LOG (2026-02-22):
 FIX-01  Module numbering: IPNeighborExpansionModule comment corrected from #9 → #10.
 FIX-02  Module numbering: CertificateIssuerClusteringModule comment corrected #23 → #27.
         EndpointVolatilityModule comment was also #23; corrected to #23 (it is Module 23).
 FIX-03  Double ConfidenceRecalibration run: expand() now only runs the extra
         ConfidenceRecalibrationModule pass when the loop exited early (MAX_TOTAL_NODES),
         not unconditionally. The `if not isinstance` guard now controls the extra call.
 FIX-04  WildcardCoverageModule: removed unsupported `strip_wildcard=True` kwarg from
         normalize_host(). Wildcard stripping is now done inline with lstrip("*.").
 FIX-05  BannerAnalysisModule: instantiates CrawlEngine() instead of using the class
         attribute directly for DOMAIN_RE.
 FIX-06  HTTPCrawlModule._crawl_host: depth now only increments when next_queue is
         non-empty, preventing phantom BFS depth inflation on fully-visited queues.
 FIX-07  ControlledRecursiveExpansionModule: moved `from expansion_category_a import
         normalize_ip` and `EdgeType as AEdgeType` to module top-level imports to
         avoid repeated imports inside hot loops.
 FIX-08  ExpiredAssetDetectionModule: `import datetime` moved to module top-level.
 FIX-09  OpenAPIProbeModule: added `found_schema` flag so the outer `for path` loop
         also breaks once a valid OpenAPI schema is found for a domain.
 FIX-10  CloudBucketPatternsModule: tracks probed cloud hosts per (name) to avoid
         probing duplicate cloud hostnames, and breaks template loop after first hit
         per variant×cloud-provider combination.
 FIX-11  SharedIPCorrelationModule: added MAX_SHARED_DOMAINS_PER_IP = 50 cap.
         When an IP has more domains than the cap (e.g. large CDN), edges are skipped
         with a warning to prevent O(n²) edge explosion.
 FIX-12  WildcardCoverageModule: added MAX_WILDCARD_COVERAGE_EDGES = 10_000 global
         cap with early exit to prevent O(wildcards × domains) blowup.
 FIX-13  FaviconHashModule: guard now checks both http:// and https:// cache keys so
         http-only probed domains are not incorrectly skipped.
 FIX-14  TLSPortVariantsModule._probe_tls: cache lookup now checks `key + ":tls_info"`
         directly rather than first checking `key` and then looking up the suffixed key,
         preventing silent cache misses.
 FIX-15  HTTPProbeModule: both schemes (https then http) are now probed independently
         so each gets its own metadata entry. Break removed; loop always runs both.
         (Previously only the first responding scheme was stored.)
 FIX-16  SignalConflictDetectionModule: removed unused `live_domains` set construction.
 FIX-17  (covered by FIX-07)
 FIX-18  K8sPatternModule.K8S_HEADERS: replaced "server: nginx/ingress" with
         "nginx/ingress" so substring match against JSON-serialised headers works.
 FIX-19  CDNEdgeMappingModule._get_cname_chain: uses normalize_host() instead of bare
         rstrip(".") for consistent hostname normalisation.
 FIX-20  ActiveProbeEngine: added optional per-probe inter-request delay via
         BCDEExpansionContext.probe_delay_ms (default 0). Modules that loop over many
         hosts now call _rate_sleep() after each probe when delay is set.
 FIX-21  FaviconHashModule / SignatureEngine.favicon_hash: added mmh3 path with MD5
         fallback. mmh3 hash is returned when the library is available (Shodan-compatible).
 FIX-22  TLSServerFingerprintModule: enhanced to capture session_id_length as an
         additional clustering dimension, improving load-balancer inference accuracy.
 FIX-23  HTTPResponseSignatureModule: now includes a body_hash (SHA-256 of first 64 KB
         of response body) in the signature, satisfying the checklist "Body hash" item.
 FIX-24  ExpansionCategoryBCDE docstring / expand_and_extract docstring corrected from
         "24 modules" to "29 modules".

FIX LOG (2026-02-23) — Second pass enterprise hardening:
 FIX-A1  SignalConfidenceEngine global mutation eliminated. BCDE weights are now
         merged into Category A's engine only for the duration of expand(), then
         restored. This prevents import-time side effects and hidden state leakage.
 FIX-A2  OpenAPIProbeModule: replaced raw requests.get() calls with
         ActiveProbeEngine.http_get(). All HTTP now routes through the central
         probe engine (rate limiting, caching, UA header, determinism).
 FIX-A3  CDNEdgeMappingModule._get_cname_chain: DNS responses are now sorted
         before extending chain and selecting the next hop, ensuring deterministic
         traversal regardless of resolver response ordering.
 FIX-A4  BCDEEdgeType.TLS_SERVER_CLUSTER added. TLSServerFingerprintModule now
         uses TLS_SERVER_CLUSTER instead of JARM_CLUSTER, separating the two
         independent clustering signals that were previously conflated.
 FIX-A5  Global expansion ceilings added to BCDEExpansionContext:
         max_total_nodes (250k), max_total_edges (500k), max_total_endpoints (100k).
         ExpansionCategoryBCDE.expand() checks all three after every module and
         halts early if any ceiling is hit. Removed class-level MAX_TOTAL_NODES.
 FIX-A6  rate_controller is now consistently checked before every module in the
         expand() loop. Previously the check was present but not guaranteed to
         run for all paths. Now wrapped in a try/finally that also restores weights.
 FIX-A7  FaviconHashModule / SignatureEngine.favicon_hash: mmh3 now uses
         base64.b64encode() instead of base64.encodebytes(). encodebytes()
         inserts \\n every 76 bytes, producing a hash that does not match Shodan's
         favicon index. b64encode() produces a single-line encoding as required.
 FIX-A8  ConfidenceEngine.compute_recalibrated_confidence: multi-source stacking
         implemented. Confidence now receives a graduated boost (+0.03 per extra
         independent source category) when a node is corroborated across passive,
         active, infrastructure, and signature source categories.
 FIX-A9  ConfidenceEngine.compute_recalibrated_confidence: soft mutation-only
         penalty added. Nodes whose entire source set is speculative (name_mutation
         or search_engine only) receive a -0.10 soft downward adjustment before
         the harder conflict detection penalty is evaluated.
 FIX-A10 Three sub-fixes:
         (a) VolatilityEngine.compute_redirect_volatility: redirect chain traversal
             now capped at max_redirect_depth (default 5) to prevent infinite loops
             on circular or malicious redirect graphs.
         (b) BCDEExpansionContext.max_redirect_depth field added (default 5).
         (c) NetblockExpansionModule: RDAP CIDR vs synthetic /24 CIDR now explicitly
             documented and tagged. Synthetic CIDRs are marked cidr_synthetic=True
             in node metadata so downstream consumers can distinguish approximations
             from RDAP-sourced allocations.
"""
from __future__ import annotations
import ipaddress


import ssl
import socket
import re
import time
import datetime  # FIX-08: moved from inside ExpiredAssetDetectionModule.run()
import logging
import hashlib
import ipaddress
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Dict, Any, List, Optional, Set, Tuple, FrozenSet
from collections import defaultdict
from urllib.parse import urljoin, urlparse

# ── Category A shared model ──────────────────────────────────────────────
from infrastructure.discovery.expansion_a.impl import (
    PassiveDiscoveryGraph,
    PassiveDiscoveryNode,
    PassiveDiscoveryEdge,
    NodeType,
    EdgeType,
    ExpansionContext,
    EndpointCandidate,
    SignalConfidenceEngine,
    IntelligenceModule,
    normalize_host,
    normalize_ip,      # FIX-07: top-level import (was inside loop body)
    safe_dns_query,
    safe_reverse_dns,
    extract_candidates,
    normalize_tls_verification_mode,
    tls_requests_verify,
    build_tls_context,
)
from infrastructure.discovery.browser_fallback import (
    browser_request,
    should_attempt_browser_fallback,
)

# FIX-07: EdgeType alias used by ControlledRecursiveExpansionModule — top-level import.
from infrastructure.discovery.expansion_a.impl import EdgeType as AEdgeType  # noqa: F811 (re-export ok)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# FIX-21: mmh3 optional import for Shodan-compatible favicon hashes.
try:
    import mmh3
    MMH3_AVAILABLE = True
except ImportError:
    MMH3_AVAILABLE = False

logger = logging.getLogger(__name__)




def _format_host_port(host: str, port: int) -> str:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"

# FIX-A1: Do NOT mutate SignalConfidenceEngine.CONFIDENCE_WEIGHTS at import time.
# BCDE weights are stored in BCDE_CONFIDENCE_WEIGHTS (below) and merged explicitly
# inside ExpansionCategoryBCDE.expand() only while expansion is running.
# This prevents hidden side effects if BCDE is imported without being executed,
# and preserves Category A's confidence engine in its original state when BCDE
# is not active.  Merge is reversed (logically — original weights re-apply) on
# next Category A run because the update is now scoped to the expand() call.


# ======================================================
# BCDE EDGE TYPES
# ======================================================

class BCDEEdgeType(str, Enum):
    """
    New relationship types introduced by Category BCDE.
    All are additive — no collision with Category A EdgeType values.
    """
    PORT_OPEN          = "port_open"
    HTTP_REDIRECT      = "http_redirect"
    JS_REFERENCE       = "js_reference"
    API_ENDPOINT       = "api_endpoint"
    IP_NEIGHBOR        = "ip_neighbor"
    NETBLOCK_CONTAINS  = "netblock_contains"
    SHARED_IP          = "shared_ip"
    WILDCARD_COVERS    = "wildcard_covers"
    JARM_CLUSTER       = "jarm_cluster"
    TLS_SERVER_CLUSTER = "tls_server_cluster"   # FIX-A4: distinct from JARM_CLUSTER
    CDN_EDGE           = "cdn_edge"
    CLOUD_ASSET        = "cloud_asset"
    K8S_INGRESS        = "k8s_ingress"
    FAVICON_CLUSTER    = "favicon_cluster"
    RESPONSE_CLUSTER   = "response_cluster"
    HISTORICAL_REVIVAL = "historical_revival"
    ISSUER_CLUSTER     = "issuer_cluster"
    CONFLICT           = "conflict"


# ======================================================
# BCDE EXPANSION CONTEXT
# ======================================================

@dataclass
class BCDEExpansionContext:
    """
    Execution context for BCDE modules.
    Wraps all Category A context fields plus BCDE-specific caches and limits.
    """
    # ── Core (mirrored from ExpansionContext) ────────────────────────────
    root_domain: str
    rate_controller: Optional[object] = None
    max_results: int = 100000
    dns_cache: Dict = field(default_factory=dict)
    tls_cache: Dict = field(default_factory=dict)
    rdap_cache: Dict = field(default_factory=dict)

    # ── BCDE caches ──────────────────────────────────────────────────────
    http_cache: Dict[str, Any] = field(default_factory=dict)
    banner_cache: Dict[str, str] = field(default_factory=dict)
    jarm_cache: Dict[str, str] = field(default_factory=dict)
    favicon_cache: Dict[str, str] = field(default_factory=dict)
    crawl_visited: Set[str] = field(default_factory=set)
    open_ports_cache: Dict[str, List[int]] = field(default_factory=dict)
    signature_cache: Dict[str, str] = field(default_factory=dict)
    module_state: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    module_runtime_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # ── Hard caps ────────────────────────────────────────────────────────
    max_ports_per_host: int = 12
    max_crawl_depth: int = 2
    max_crawl_pages_per_host: int = 30
    max_js_files_per_host: int = 10
    max_neighbors_per_ip: int = 20
    max_bucket_variants: int = 30
    max_active_probe_hosts: int = 5000
    max_hosts_per_turn: int = 8
    max_ports_per_turn: int = 24
    port_timeout: float = 2.0
    http_timeout: float = 8.0
    tls_timeout: float = 5.0
    turn_cleanup_margin_seconds: float = 0.5
    tls_verification_mode: str = "strict"

    # FIX-20: Optional inter-probe delay in milliseconds (default 0 = no delay).
    # Set to e.g. 50 for polite scanning. Applied by ActiveProbeEngine._rate_sleep().
    probe_delay_ms: float = 0.0

    # FIX-A10: Max redirect hops before halting redirect chain traversal.
    max_redirect_depth: int = 5

    # FIX-A5: Hard global expansion ceilings (bank-scale safety governors).
    # Modules and the orchestrator enforce these — expansion halts early if any is hit.
    max_total_nodes: int = 250_000
    max_total_edges: int = 500_000
    max_total_endpoints: int = 100_000
    time_budget_seconds: int = 60
    deadline_unix_ms: Optional[int] = None
    cancel_requested: bool = False

    # ── Port lists (deterministic order) ────────────────────────────────
    common_ports: List[int] = field(default_factory=lambda: [
        80, 443, 8080, 8443, 9443, 8444, 9444,
        8000, 8001, 8008, 8081, 8082, 8888,
        3000, 4000, 5000, 7000, 9000, 10443,
    ])

    def __post_init__(self) -> None:
        self.max_ports_per_host = min(max(1, int(self.max_ports_per_host)), 64)
        self.max_crawl_depth = min(max(0, int(self.max_crawl_depth)), 6)
        self.max_crawl_pages_per_host = min(max(1, int(self.max_crawl_pages_per_host)), 200)
        self.max_js_files_per_host = min(max(1, int(self.max_js_files_per_host)), 50)
        self.max_neighbors_per_ip = min(max(1, int(self.max_neighbors_per_ip)), 64)
        self.max_bucket_variants = min(max(1, int(self.max_bucket_variants)), 100)
        self.max_active_probe_hosts = min(max(1, int(self.max_active_probe_hosts)), 10_000)
        self.max_hosts_per_turn = min(max(1, int(self.max_hosts_per_turn)), 128)
        self.max_ports_per_turn = min(max(1, int(self.max_ports_per_turn)), 256)
        self.max_results = min(max(1, int(self.max_results)), 200_000)
        self.max_total_nodes = min(max(1_000, int(self.max_total_nodes)), 500_000)
        self.max_total_edges = min(max(1_000, int(self.max_total_edges)), 1_000_000)
        self.max_total_endpoints = min(max(100, int(self.max_total_endpoints)), 250_000)
        self.time_budget_seconds = min(max(1, int(self.time_budget_seconds)), 600)
        self.turn_cleanup_margin_seconds = min(
            max(0.0, float(self.turn_cleanup_margin_seconds)),
            5.0,
        )
        self.tls_verification_mode = normalize_tls_verification_mode(self.tls_verification_mode)
        if self.deadline_unix_ms is None:
            self.deadline_unix_ms = int(time.time() * 1000) + (self.time_budget_seconds * 1000)

    def should_stop(self) -> bool:
        if self.cancel_requested:
            return True
        if self.deadline_unix_ms is None:
            return False
        return int(time.time() * 1000) >= int(self.deadline_unix_ms)

    @classmethod
    def from_category_a_context(cls, ctx: ExpansionContext) -> "BCDEExpansionContext":
        """Build BCDEExpansionContext from an existing Category A ExpansionContext."""
        return cls(
            root_domain=ctx.root_domain,
            rate_controller=ctx.rate_controller,
            dns_cache=ctx.dns_cache,
            tls_cache=ctx.tls_cache,
            rdap_cache=ctx.rdap_cache,
            tls_verification_mode=ctx.tls_verification_mode,
        )


# ======================================================
# BCDE SIGNAL CONFIDENCE WEIGHTS
# ======================================================

BCDE_CONFIDENCE_WEIGHTS: Dict[str, float] = {
    "port_scan": 0.90,
    "tls_port_variant": 0.88,
    "banner": 0.85,
    "http_probe": 0.85,
    "http_crawl": 0.75,
    "js_analysis": 0.70,
    "openapi": 0.80,
    "http_signature": 0.72,
    "ip_neighbor": 0.60,
    "netblock": 0.65,
    "shared_ip": 0.70,
    "jarm": 0.75,
    "cdn_edge": 0.78,
    "cloud_bucket": 0.72,
    "cloudfront": 0.74,
    "k8s_pattern": 0.68,
    "historical_revival": 0.82,
    "expired_asset": 0.70,
    "orphaned_asset": 0.65,
    "favicon_cluster": 0.73,
    "wildcard_coverage": 0.70,
    "signal_conflict": 0.50,
    "issuer_cluster": 0.68,
    "recalibrated": 0.80,
    "name_mutation": 0.40,
    "search_engine": 0.60,
    "passive_dns_unpaid": 0.65,
}

def get_bcde_confidence(method: str) -> float:
    """Get BCDE confidence weight for a discovery method."""
    return BCDE_CONFIDENCE_WEIGHTS.get(method, 0.50)


# ======================================================
# INTERNAL ENGINE 1: ACTIVE PROBE ENGINE
# ======================================================

class ActiveProbeEngine:
    """
    Handles HTTP and TCP probing with caching, timeout control, and rate limiting.
    Central utility for all active-touch modules.
    Stateless — all state in BCDEExpansionContext.
    """

    UA = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 AVYAKTA-ASM/2.0"
    )

    # FIX-20: Called after each network probe when probe_delay_ms > 0.
    @staticmethod
    def _rate_sleep(context: BCDEExpansionContext) -> None:
        if context.probe_delay_ms > 0:
            time.sleep(context.probe_delay_ms / 1000.0)

    @staticmethod
    def _remaining_timeout_seconds(
        timeout: float,
        context: Optional[BCDEExpansionContext],
    ) -> Optional[float]:
        requested = max(0.05, float(timeout))
        if context is None or context.deadline_unix_ms is None:
            return requested
        remaining_seconds = (
            float(int(context.deadline_unix_ms) - int(time.time() * 1000)) / 1000.0
        )
        if remaining_seconds <= 0.0:
            return None
        return max(0.05, min(requested, remaining_seconds))

    @staticmethod
    def remaining_budget_seconds(
        context: Optional[BCDEExpansionContext],
        *,
        reserve_seconds: float = 0.0,
    ) -> Optional[float]:
        if context is None or context.deadline_unix_ms is None:
            return None
        remaining_seconds = (
            float(int(context.deadline_unix_ms) - int(time.time() * 1000)) / 1000.0
        ) - max(0.0, float(reserve_seconds))
        return remaining_seconds

    def probe_port(
        self,
        host: str,
        port: int,
        timeout: float = 2.0,
        context: Optional[BCDEExpansionContext] = None,
    ) -> bool:
        """Return True if TCP port is open."""
        effective_timeout = self._remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return False
        try:
            with socket.create_connection((host, port), timeout=effective_timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def probe_ports(
        self,
        host: str,
        ports: List[int],
        timeout: float = 2.0,
        cache: Optional[Dict] = None,
        context: Optional[BCDEExpansionContext] = None,  # FIX-20
    ) -> List[int]:
        """Probe list of ports, return open ones. Uses cache."""
        if cache is not None and host in cache:
            return cache[host]

        open_ports = []
        for port in ports:
            if context and context.should_stop():
                break
            if self.probe_port(host, port, timeout, context=context):
                open_ports.append(port)
            if context:
                self._rate_sleep(context)

        if cache is not None:
            cache[host] = open_ports
        return open_ports

    def http_head(
        self,
        url: str,
        timeout: float = 8.0,
        cache: Optional[Dict] = None,
        context: Optional[BCDEExpansionContext] = None,  # FIX-20
    ) -> Optional[Dict[str, Any]]:
        """HTTP HEAD request. Returns dict with status, headers, redirect."""
        if not REQUESTS_AVAILABLE:
            return None
        if cache is not None and url in cache:
            return cache[url]
        if context and context.should_stop():
            return None
        effective_timeout = self._remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return None

        result: Optional[Dict] = None
        try:
            verify_tls = tls_requests_verify(
                context.tls_verification_mode if context else "strict"
            )
            resp = requests.head(
                url,
                timeout=effective_timeout,
                allow_redirects=False,
                headers={"User-Agent": self.UA},
                verify=verify_tls,
            )
            result = {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "redirect": resp.headers.get("Location"),
                "url": url,
            }
            if should_attempt_browser_fallback(
                status_code=resp.status_code,
                headers=dict(resp.headers),
            ):
                fallback = browser_request(
                    method="HEAD",
                    url=url,
                    timeout=effective_timeout,
                    headers={"User-Agent": self.UA},
                    allow_redirects=False,
                    verify=verify_tls,
                )
                if fallback is not None:
                    result = fallback
        except Exception as e:
            logger.debug(f"HEAD {url}: {e}")
            verify_tls = tls_requests_verify(
                context.tls_verification_mode if context else "strict"
            )
            fallback = browser_request(
                method="HEAD",
                url=url,
                timeout=effective_timeout,
                headers={"User-Agent": self.UA},
                allow_redirects=False,
                verify=verify_tls,
            )
            if fallback is not None:
                result = fallback
        finally:
            if context:
                self._rate_sleep(context)

        if cache is not None:
            cache[url] = result
        return result

    def http_get(
        self,
        url: str,
        timeout: float = 8.0,
        cache: Optional[Dict] = None,
        max_size: int = 1_000_000,
        context: Optional[BCDEExpansionContext] = None,  # FIX-20
    ) -> Optional[Dict[str, Any]]:
        """HTTP GET. Returns dict with status, headers, body (capped)."""
        if not REQUESTS_AVAILABLE:
            return None
        if cache is not None and url in cache:
            return cache[url]
        if context and context.should_stop():
            return None
        effective_timeout = self._remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return None

        result: Optional[Dict] = None
        try:
            verify_tls = tls_requests_verify(
                context.tls_verification_mode if context else "strict"
            )
            resp = requests.get(
                url,
                timeout=effective_timeout,
                allow_redirects=True,
                headers={"User-Agent": self.UA},
                verify=verify_tls,
                stream=True,
            )
            body = b""
            for chunk in resp.iter_content(chunk_size=65536):
                if context and context.should_stop():
                    break
                body += chunk
                if len(body) >= max_size:
                    break

            result = {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": body.decode("utf-8", errors="replace"),
                "url": resp.url,
                "final_url": resp.url,
            }
            if should_attempt_browser_fallback(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                error_text=result["body"][:512],
            ):
                fallback = browser_request(
                    method="GET",
                    url=url,
                    timeout=effective_timeout,
                    headers={"User-Agent": self.UA},
                    allow_redirects=True,
                    verify=verify_tls,
                    max_body_bytes=max_size,
                )
                if fallback is not None:
                    result = fallback
        except Exception as e:
            logger.debug(f"GET {url}: {e}")
            verify_tls = tls_requests_verify(
                context.tls_verification_mode if context else "strict"
            )
            fallback = browser_request(
                method="GET",
                url=url,
                timeout=effective_timeout,
                headers={"User-Agent": self.UA},
                allow_redirects=True,
                verify=verify_tls,
                max_body_bytes=max_size,
            )
            if fallback is not None:
                result = fallback
        finally:
            if context:
                self._rate_sleep(context)

        if cache is not None:
            cache[url] = result
        return result

    def grab_banner(
        self,
        host: str,
        port: int,
        timeout: float = 3.0,
        cache: Optional[Dict] = None,
        context: Optional[BCDEExpansionContext] = None,
    ) -> Optional[str]:
        """Grab raw TCP banner from host:port."""
        key = f"{host}:{port}"
        if cache is not None and key in cache:
            return cache[key]
        if context and context.should_stop():
            return None
        effective_timeout = self._remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return None

        banner = None
        try:
            with socket.create_connection((host, port), timeout=effective_timeout) as sock:
                sock.settimeout(effective_timeout)
                try:
                    raw = sock.recv(1024)
                    banner = raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Banner grab {host}:{port}: {e}")

        if cache is not None:
            cache[key] = banner
        return banner

    def infer_scheme(self, port: int) -> str:
        """Infer URL scheme from port number."""
        https_ports = {443, 8443, 9443, 8444, 9444, 4443, 10443}
        return "https" if port in https_ports else "http"


# ======================================================
# INTERNAL ENGINE 2: SIGNATURE ENGINE
# ======================================================

class SignatureEngine:
    """
    Compute fingerprints and signatures for clustering.
    Favicon hash, response hash, TLS config hash.
    """

    def favicon_hash(
        self,
        url: str,
        timeout: float = 8.0,
        cache: Optional[Dict] = None,
        tls_verification_mode: str = "strict",
    ) -> Optional[str]:
        """
        Download favicon and return hash.
        FIX-21: Uses mmh3 (Shodan-compatible MurmurHash3) when available,
                falls back to MD5.
        """
        if not REQUESTS_AVAILABLE:
            return None
        if cache is not None and url in cache:
            return cache[url]

        result = None
        favicon_urls = [
            url.rstrip("/") + "/favicon.ico",
            url.rstrip("/") + "/favicon.png",
        ]
        for furl in favicon_urls:
            try:
                verify_tls = tls_requests_verify(tls_verification_mode)
                resp = requests.get(
                    furl,
                    timeout=timeout,
                    headers={"User-Agent": ActiveProbeEngine.UA},
                    verify=verify_tls,
                    stream=True,
                )
                if resp.status_code == 200:
                    data = b""
                    for chunk in resp.iter_content(65536):
                        data += chunk
                        if len(data) > 500_000:
                            break
                    if data:
                        # FIX-21: mmh3 preferred (Shodan-compatible), MD5 fallback.
                        # FIX-A7: Use base64.b64encode() (no line breaks) instead of
                        #          base64.encodebytes() which inserts \n every 76 bytes
                        #          and produces a hash that does NOT match Shodan's index.
                        if MMH3_AVAILABLE:
                            import base64
                            result = str(mmh3.hash(base64.b64encode(data)))
                        else:
                            result = hashlib.md5(data).hexdigest()
                        break
            except Exception:
                continue

        if cache is not None:
            cache[url] = result
        return result

    def response_signature(self, response: Dict[str, Any]) -> str:
        """
        Compute signature hash from HTTP response headers + status + body.
        FIX-23: Now includes a body_hash (SHA-256 of first 64 KB of body)
                in addition to stable headers and status, satisfying the
                checklist "Body hash, header hash" requirement.
        Ignores volatile headers (Date, Set-Cookie, etc.).
        """
        STABLE_HEADERS = {
            "server", "x-powered-by", "content-type", "x-frame-options",
            "strict-transport-security", "x-content-type-options",
            "content-security-policy", "x-xss-protection",
        }
        sig_parts = [str(response.get("status", ""))]

        # Header hash (stable headers only)
        for h, v in sorted(response.get("headers", {}).items()):
            if h.lower() in STABLE_HEADERS:
                sig_parts.append(f"{h.lower()}:{v}")

        # FIX-23: Body hash — SHA-256 of first 64 KB of response body.
        body: str = response.get("body", "")
        if body:
            body_sample = body[:65536].encode("utf-8", errors="replace")
            body_hash = hashlib.sha256(body_sample).hexdigest()[:16]
            sig_parts.append(f"body:{body_hash}")

        return hashlib.sha256("|".join(sig_parts).encode()).hexdigest()[:16]

    def tls_config_fingerprint(
        self,
        hostname: str,
        port: int = 443,
        timeout: float = 5.0,
        cache: Optional[Dict] = None,
        tls_verification_mode: str = "strict",
    ) -> Optional[str]:
        """
        Capture simplified TLS fingerprint: cipher + version + session_id_length.
        FIX-22: Added session_id_length as a clustering dimension to improve
                load-balancer inference (servers in the same pool share session caches).
        (Production: implement full JARM probe; this is a useful approximation.)
        """
        key = f"{hostname}:{port}"
        if cache is not None and key in cache:
            return cache[key]

        result = None
        try:
            ctx = build_tls_context(tls_verification_mode)
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()  # (name, version, bits)
                    version = ssock.version()
                    # FIX-22: Include session ID length as extra clustering signal.
                    session = ssock.session
                    session_id_len = len(session.id) if (session and session.id) else 0
                    parts = [
                        cipher[0] if cipher else "UNKNOWN",
                        cipher[1] if cipher else "UNKNOWN",
                        version or "UNKNOWN",
                        str(session_id_len),  # FIX-22
                    ]
                    raw = "|".join(parts)
                    result = hashlib.sha1(raw.encode()).hexdigest()[:20]
        except Exception as e:
            logger.debug(f"TLS fingerprint {hostname}:{port}: {e}")

        if cache is not None:
            cache[key] = result
        return result


# ======================================================
# INTERNAL ENGINE 3: INFRASTRUCTURE ENGINE
# ======================================================

class InfrastructureEngine:
    """
    IP topology, netblock modeling, CDN vendor detection.
    """

    CDN_CNAME_PATTERNS: Dict[str, str] = {
        "cloudfront.net": "CloudFront",
        "fastly.net": "Fastly",
        "akamaiedge.net": "Akamai",
        "akamai.net": "Akamai",
        "cdn.cloudflare.net": "Cloudflare",
        "cloudflare.net": "Cloudflare",
        "edgekey.net": "Akamai",
        "edgesuite.net": "Akamai",
        "azureedge.net": "Azure CDN",
        "trafficmanager.net": "Azure Traffic Manager",
        "amazonaws.com": "AWS",
        "googleusercontent.com": "GCP",
        "llnwi.net": "Limelight",
        "footprint.net": "CenturyLink CDN",
        "hwcdn.net": "Highwinds",
    }

    def detect_cdn(self, cname_chain: List[str]) -> Optional[str]:
        """Detect CDN vendor from CNAME chain entries."""
        for cname in cname_chain:
            cname_lower = cname.lower()
            for pattern, vendor in self.CDN_CNAME_PATTERNS.items():
                if pattern in cname_lower:
                    return vendor
        return None

    def get_adjacent_ips(self, ip: str, count: int = 20) -> List[str]:
        """
        Get up to `count` adjacent IPs in same /24 (IPv4) or /48 (IPv6).
        Deterministic ordering. Excludes the source IP.
        """
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                hosts = list(network.hosts())
            else:
                network = ipaddress.IPv6Network(f"{ip}/48", strict=False)
                hosts = [network.network_address + i for i in range(1, count * 2)]

            result = []
            for h in hosts:
                h_str = str(h)
                if h_str != ip:
                    result.append(h_str)
                if len(result) >= count:
                    break
            return result
        except ValueError:
            return []

    def ip_to_cidr(self, ip: str, prefix: int = 24) -> Optional[str]:
        """Convert IP to network CIDR prefix."""
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            else:
                net = ipaddress.IPv6Network(f"{ip}/48", strict=False)
            return str(net)
        except ValueError:
            return None


# ======================================================
# INTERNAL ENGINE 4: CRAWL ENGINE
# ======================================================

class CrawlEngine:
    """
    BFS web crawler with link/subdomain/API extraction.
    Deterministic ordering. Strict depth and page caps.
    """

    LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    JS_SRC_RE = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
    DOMAIN_RE = re.compile(
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,})\b'
    )
    API_PATH_RE = re.compile(
        r'["\'](/(?:api|v\d+|graphql|rest|rpc|service|endpoint)[^"\']*)["\']',
        re.IGNORECASE
    )
    OPENAPI_PATHS = [
        "/swagger.json", "/swagger/v2/api-docs", "/v2/api-docs",
        "/openapi.json", "/openapi.yaml", "/api/docs",
        "/api/swagger", "/api-docs", "/swagger-ui.html",
    ]

    def extract_links(self, base_url: str, html: str) -> List[str]:
        """Extract all href links from HTML, resolved to absolute URLs."""
        links = []
        for m in self.LINK_RE.finditer(html):
            href = m.group(1)
            if href.startswith("javascript:") or href.startswith("#"):
                continue
            try:
                resolved = urljoin(base_url, href)
                links.append(resolved)
            except Exception:
                pass
        return links

    def extract_js_sources(self, base_url: str, html: str) -> List[str]:
        """Extract JS src URLs from HTML."""
        sources = []
        for m in self.JS_SRC_RE.finditer(html):
            src = m.group(1)
            try:
                sources.append(urljoin(base_url, src))
            except Exception:
                pass
        return sources

    def extract_domains_from_content(
        self, content: str, root_domain: str
    ) -> Set[str]:
        """Extract domain references from HTML/JS content, scoped to root domain."""
        found = set()
        for m in self.DOMAIN_RE.finditer(content):
            candidate = m.group(1).lower()
            norm = normalize_host(candidate)
            if norm and (norm.endswith(f".{root_domain}") or norm == root_domain):
                found.add(norm)
        return found

    def extract_api_paths(self, content: str, base_url: str) -> Set[str]:
        """Extract API path references from JS/HTML content."""
        paths = set()
        for m in self.API_PATH_RE.finditer(content):
            path = m.group(1)
            if len(path) < 200:
                try:
                    full = urljoin(base_url, path)
                    paths.add(full)
                except Exception:
                    pass
        return paths

    def parse_openapi_endpoints(self, schema: Dict) -> List[str]:
        """Extract path list from OpenAPI/Swagger schema dict."""
        paths = []
        if isinstance(schema, dict):
            for path in schema.get("paths", {}).keys():
                paths.append(path)
        return paths[:200]


# ======================================================
# INTERNAL ENGINE 5: HISTORICAL ENGINE
# ======================================================

class HistoricalEngine:
    """
    Revival and asset drift detection utilities.
    """

    def is_domain_live(
        self, domain: str, probe: ActiveProbeEngine, timeout: float = 5.0
    ) -> bool:
        """Check if domain is actively resolving and responding."""
        try:
            ips = safe_dns_query(domain, "A")
            if not ips:
                ips = safe_dns_query(domain, "AAAA")
            if not ips:
                return False
            if REQUESTS_AVAILABLE:
                result = probe.http_head(f"https://{domain}", timeout=timeout)
                if result and result.get("status"):
                    return True
                result = probe.http_head(f"http://{domain}", timeout=timeout)
                if result and result.get("status"):
                    return True
            return bool(ips)
        except Exception:
            return False


# ======================================================
# INTERNAL ENGINE 6: VOLATILITY ENGINE
# ======================================================

class VolatilityEngine:
    """
    Tracks endpoint instability across signals.

    Volatility score: 0.0 (stable) → 1.0 (highly volatile)
    """

    def compute_ip_drift_score(
        self, domain: str, graph: PassiveDiscoveryGraph
    ) -> float:
        """Count distinct IPs for a domain — more IPs = higher drift."""
        ip_count = 0
        for edge in graph.get_edges_by_type(AEdgeType.A_RECORD):
            if edge.src == domain:
                ip_count += 1
        for edge in graph.get_edges_by_type(AEdgeType.AAAA_RECORD):
            if edge.src == domain:
                ip_count += 1
        return min(1.0, ip_count * 0.1)

    def compute_cert_rotation_score(
        self, domain: str, graph: PassiveDiscoveryGraph
    ) -> float:
        """Count distinct CT serials seen for this domain."""
        node = graph.get_node(domain, NodeType.DOMAIN)
        if not node:
            return 0.0
        cert_sources = [
            s for s in node.all_sources
            if s in ("tls_observation", "ct_log", "recursive_san")
        ]
        return min(1.0, max(0.0, (len(cert_sources) - 1) * 0.25))

    def compute_redirect_volatility(
        self, domain: str, graph: PassiveDiscoveryGraph,
        max_redirect_depth: int = 5,  # FIX-A10: cap to prevent infinite loop on circular graphs
    ) -> float:
        """
        Measure redirect chain depth as volatility proxy.
        FIX-A10: Caps chain traversal at max_redirect_depth. A malicious or broken
                 target could produce a circular redirect graph; the cap ensures
                 this method always terminates within a predictable bound.
        """
        depth = 0
        current = domain
        visited: Set[str] = set()
        while depth < max_redirect_depth and current and current not in visited:
            visited.add(current)
            found_redirect = False
            for edge in graph.get_edges_by_type(BCDEEdgeType.HTTP_REDIRECT):
                if edge.src == current:
                    current = edge.dst
                    depth += 1
                    found_redirect = True
                    break
            if not found_redirect:
                break
        return min(1.0, depth * 0.2)

    def compute_volatility_score(
        self, domain: str, graph: PassiveDiscoveryGraph
    ) -> float:
        """Combined volatility score: weighted average of sub-scores."""
        ip_drift = self.compute_ip_drift_score(domain, graph)
        cert_rotation = self.compute_cert_rotation_score(domain, graph)
        redirect_vol = self.compute_redirect_volatility(domain, graph)
        score = (ip_drift * 0.50) + (cert_rotation * 0.35) + (redirect_vol * 0.15)
        return round(min(1.0, score), 4)

    def classify_volatility(self, score: float) -> str:
        """Classify volatility score into human-readable tier."""
        if score < 0.10:
            return "stable"
        elif score < 0.30:
            return "low_volatility"
        elif score < 0.60:
            return "medium_volatility"
        else:
            return "high_volatility"


# ======================================================
# INTERNAL ENGINE 7: CONFIDENCE ENGINE
# ======================================================

class ConfidenceEngine:
    """
    Post-expansion confidence recalibration and conflict detection.
    Operates on the full graph after all modules have run.
    """

    def detect_conflicts(
        self, node: PassiveDiscoveryNode, graph: PassiveDiscoveryGraph
    ) -> bool:
        """
        Structural conflict detection — evaluates observable contradictions.

        Conflict conditions (any one triggers):
        1. Mutation-only with no structural edges
        2. Search-only with no DNS A/AAAA edges and no active confirmation
        3. Has cert metadata but zero inbound DNS edges
        4. Passive-only discovery with inbound_edge_count == 0
        """
        sources = node.all_sources

        has_dns_edge = self._has_dns_edge(node.id, graph)
        has_active_observation = bool(sources & {
            "port_scan", "http_probe", "banner", "tls_port_variant",
            "openapi", "http_crawl", "js_analysis",
        })
        has_passive_observation = bool(sources & {
            "tls_observation", "ct_log", "recursive_san",
            "dns_a_record", "dns_aaaa_record", "dns_cname",
            "passive_dns_unpaid", "reverse_dns",
        })
        has_cert_metadata = bool(
            node.metadata.get("cert_issuer") or
            node.metadata.get("ct_not_after") or
            node.metadata.get("cert_not_after")
        )
        is_structurally_isolated = node.inbound_edge_count == 0 and not has_dns_edge

        if sources == frozenset({"name_mutation"}) and not has_dns_edge and is_structurally_isolated:
            return True
        if sources == frozenset({"search_engine"}) and not has_dns_edge and not has_active_observation:
            return True
        if has_cert_metadata and not has_dns_edge and not has_active_observation:
            return True
        speculative_only = sources <= frozenset({"name_mutation", "search_engine", "cross_validation"})
        if speculative_only and is_structurally_isolated and not has_passive_observation:
            return True
        return False

    def _has_dns_edge(self, domain: str, graph: PassiveDiscoveryGraph) -> bool:
        """Return True if domain has at least one A, AAAA, or CNAME edge."""
        dns_edge_types = (
            EdgeType.A_RECORD, EdgeType.AAAA_RECORD,
            EdgeType.CNAME, EdgeType.PTR,
        )
        for etype in dns_edge_types:
            for edge in graph.get_edges_by_type(etype):
                if edge.src == domain or edge.dst == domain:
                    return True
        return False

    def compute_recalibrated_confidence(
        self, node: PassiveDiscoveryNode, graph: PassiveDiscoveryGraph
    ) -> float:
        """
        Recompute confidence incorporating:
        - Base signal quality
        - Active confirmation boost
        - Multi-source stacking boost (FIX-A8): cross-category corroboration
          rewards more independent source categories with graduated boost.
        - Inbound edge structural richness boost
        - Soft mutation-only penalty (FIX-A9): nodes discovered exclusively via
          name_mutation receive a soft downward adjustment before conflict check.
        - Conflict penalty
        """
        sources = node.all_sources
        base = SignalConfidenceEngine.compute_node_confidence(sources)

        # Active confirmation boost
        active_sources = {"port_scan", "http_probe", "banner", "tls_port_variant", "openapi"}
        if sources & active_sources:
            base = min(1.0, base + 0.05)

        # FIX-A8: Multi-source stacking — graduated boost by number of independent
        # source categories represented.  The more independent categories confirm
        # the node, the higher the confidence reward.
        PASSIVE_CAT = frozenset({
            "tls_observation", "ct_log", "recursive_san",
            "dns_a_record", "dns_aaaa_record", "dns_cname",
            "passive_dns_unpaid", "reverse_dns", "dns_mx", "dns_ns",
        })
        ACTIVE_CAT = frozenset({
            "port_scan", "http_probe", "banner", "tls_port_variant",
            "openapi", "http_crawl", "js_analysis",
        })
        INFRASTRUCTURE_CAT = frozenset({
            "shared_ip", "jarm", "cdn_edge", "tls_server_fingerprint",
            "ip_neighbor", "netblock",
        })
        SIGNATURE_CAT = frozenset({
            "favicon_cluster", "http_signature", "response_cluster", "issuer_cluster",
        })
        category_hits = sum([
            bool(sources & PASSIVE_CAT),
            bool(sources & ACTIVE_CAT),
            bool(sources & INFRASTRUCTURE_CAT),
            bool(sources & SIGNATURE_CAT),
        ])
        # +0.03 for 2 categories, +0.06 for 3, +0.09 for all 4 — capped at 1.0
        if category_hits >= 2:
            base = min(1.0, base + 0.03 * (category_hits - 1))

        # Structural richness: many inbound edges → more corroborated
        if node.inbound_edge_count >= 3:
            base = min(1.0, base + 0.03)

        # FIX-A9: Soft mutation-only penalty — nodes seen exclusively from name_mutation
        # (and no other source that actually observed the node) are downgraded before
        # the conflict check applies its heavier penalty.  This is a graduated soft
        # adjustment: -0.10 for pure mutation-only nodes not yet flagged as conflicted.
        SPECULATIVE_ONLY = frozenset({"name_mutation", "search_engine"})
        if sources and sources <= SPECULATIVE_ONLY:
            # Soft penalty: mutation-only / search-engine-only nodes
            base = max(0.0, base - 0.10)

        # Conflict penalty (structural contradiction: -0.20)
        if self.detect_conflicts(node, graph):
            base = max(0.0, base - 0.20)

        return round(base, 4)


# ======================================================
# SECTION 1 — ACTIVE SURFACE EXPANSION
# ======================================================

# ── MODULE 1: COMMON PORT SCAN ──────────────────────────────────────────

class CommonPortScanModule(IntelligenceModule):
    """
    TCP port probe across common ports for all domain + IP nodes.
    Creates PORT_OPEN edges for each open port.
    Hard cap: max_ports_per_host attempts, max_active_probe_hosts total.
    Confidence: 0.90
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "port_scan"
        probe = ActiveProbeEngine()
        targets = sorted(self._get_targets(graph))
        ports = context.common_ports[: context.max_ports_per_host]
        module_name = self.__class__.__name__
        state = context.module_state.setdefault(
            module_name,
            {
                "target_index": 0,
                "port_index": 0,
            },
        )
        stats = context.module_runtime_stats.setdefault(
            module_name,
            {
                "hosts_attempted": 0,
                "ports_attempted": 0,
                "endpoints_produced": 0,
            },
        )

        target_index = max(0, int(state.get("target_index", 0) or 0))
        port_index = max(0, int(state.get("port_index", 0) or 0))
        hosts_attempted = 0
        hosts_attempted_this_turn = 0
        ports_attempted_this_turn = 0
        cleanup_margin = float(getattr(context, "turn_cleanup_margin_seconds", 0.5) or 0.5)

        while target_index < len(targets):
            if context.should_stop():
                break
            if hosts_attempted >= context.max_active_probe_hosts:
                break
            if hosts_attempted_this_turn >= context.max_hosts_per_turn:
                break
            remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                context,
                reserve_seconds=cleanup_margin,
            )
            if remaining_budget is not None and remaining_budget <= 0.0:
                break

            host = targets[target_index]
            if port_index == 0:
                hosts_attempted += 1
                hosts_attempted_this_turn += 1
                stats["hosts_attempted"] = int(stats.get("hosts_attempted", 0) or 0) + 1

            open_ports = list(context.open_ports_cache.get(host, []))
            seen_open_ports = {int(value) for value in open_ports if isinstance(value, int)}

            while port_index < len(ports):
                if context.should_stop():
                    state["target_index"] = target_index
                    state["port_index"] = port_index
                    context.open_ports_cache[host] = sorted(seen_open_ports)
                    return
                if ports_attempted_this_turn >= context.max_ports_per_turn:
                    state["target_index"] = target_index
                    state["port_index"] = port_index
                    context.open_ports_cache[host] = sorted(seen_open_ports)
                    return
                remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                    context,
                    reserve_seconds=cleanup_margin,
                )
                if remaining_budget is not None and remaining_budget <= 0.0:
                    state["target_index"] = target_index
                    state["port_index"] = port_index
                    context.open_ports_cache[host] = sorted(seen_open_ports)
                    return

                port = int(ports[port_index])
                stats["ports_attempted"] = int(stats.get("ports_attempted", 0) or 0) + 1
                ports_attempted_this_turn += 1
                effective_timeout = min(
                    float(context.port_timeout),
                    max(0.05, float(remaining_budget or context.port_timeout)),
                )
                if probe.probe_port(host, port, effective_timeout, context=context):
                    seen_open_ports.add(port)
                    scheme = probe.infer_scheme(port)
                    endpoint_id = f"{scheme}://{_format_host_port(host, port)}"
                    existing_endpoint = graph.get_node(endpoint_id, NodeType.ENDPOINT)

                    graph.add_node(
                        endpoint_id,
                        NodeType.ENDPOINT,
                        method,
                        confidence=0.90,
                        metadata={
                            "host": host,
                            "port": port,
                            "scheme": scheme,
                            "is_endpoint": True,
                        },
                    )
                    graph.add_edge(
                        host,
                        endpoint_id,
                        BCDEEdgeType.PORT_OPEN,
                        method,
                        confidence=0.90,
                        metadata={"port": port, "scheme": scheme},
                    )
                    if existing_endpoint is None:
                        stats["endpoints_produced"] = int(
                            stats.get("endpoints_produced", 0) or 0
                        ) + 1

                probe._rate_sleep(context)
                port_index += 1

            context.open_ports_cache[host] = sorted(seen_open_ports)
            target_index += 1
            port_index = 0
            state["target_index"] = target_index
            state["port_index"] = port_index

    def _get_targets(self, graph: PassiveDiscoveryGraph) -> Set[str]:
        targets = set()
        for node in graph.get_nodes_by_type(NodeType.DOMAIN):
            targets.add(node.id)
        for node in graph.get_nodes_by_type(NodeType.IP):
            targets.add(node.id)
        return targets


# ── MODULE 2: TLS PORT VARIANTS ─────────────────────────────────────────

class TLSPortVariantsModule(IntelligenceModule):
    """
    Attempt TLS handshake on non-443 ports that are open.
    Capture SNI mismatch, self-signed, cert reuse.
    Confidence: 0.88
    """

    TLS_PORTS = [8443, 9443, 8444, 9444, 4443, 10443, 8843]

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "tls_port_variant"

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            if context.should_stop():
                break
            open_ports = context.open_ports_cache.get(domain_node.id, [])
            tls_ports = [p for p in open_ports if p in self.TLS_PORTS]

            for port in tls_ports:
                if context.should_stop():
                    break
                tls_info = self._probe_tls(domain_node.id, port, context)
                if not tls_info:
                    continue

                endpoint_id = f"https://{domain_node.id}:{port}"
                graph.add_node(
                    endpoint_id, NodeType.ENDPOINT, method,
                    confidence=0.88,
                    metadata={
                        "host": domain_node.id,
                        "port": port,
                        "scheme": "https",
                        "is_endpoint": True,
                        "tls_cipher": tls_info.get("cipher"),
                        "tls_version": tls_info.get("version"),
                        "self_signed": tls_info.get("self_signed", False),
                        "sni_mismatch": tls_info.get("sni_mismatch", False),
                    }
                )
                graph.add_edge(
                    domain_node.id, endpoint_id,
                    BCDEEdgeType.PORT_OPEN, method, confidence=0.88,
                    metadata={"port": port, "tls": True}
                )

    def _probe_tls(
        self, hostname: str, port: int, context: BCDEExpansionContext
    ) -> Optional[Dict]:
        # FIX-14: Check the suffixed key directly, not the bare key.
        cache_key = f"{hostname}:{port}:tls_info"
        if cache_key in context.tls_cache:
            return context.tls_cache[cache_key]

        result = None
        effective_timeout = ActiveProbeEngine._remaining_timeout_seconds(
            context.tls_timeout,
            context,
        )
        if effective_timeout is None:
            context.tls_cache[cache_key] = None
            return None
        try:
            ctx = build_tls_context(context.tls_verification_mode)
            with socket.create_connection(
                (hostname, port), timeout=effective_timeout
            ) as sock:
                sock.settimeout(effective_timeout)
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    self_signed = issuer == subject

                    san_list = [
                        v for t, v in cert.get("subjectAltName", []) if t == "DNS"
                    ]
                    sni_mismatch = hostname not in san_list and not any(
                        san.startswith("*.") and hostname.endswith(san[1:])
                        for san in san_list
                    )

                    result = {
                        "cipher": cipher[0] if cipher else None,
                        "version": version,
                        "self_signed": self_signed,
                        "sni_mismatch": sni_mismatch,
                    }
        except Exception as e:
            logger.debug(f"TLS probe {hostname}:{port}: {e}")

        # FIX-14: Always store under the suffixed key.
        context.tls_cache[cache_key] = result
        return result


# ── MODULE 3: BANNER ANALYSIS ────────────────────────────────────────────

class BannerAnalysisModule(IntelligenceModule):
    """
    Grab TCP banners from open ports.
    Parse server software, version hints, domain references.
    Confidence: 0.85
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "banner"
        probe = ActiveProbeEngine()
        stats = context.module_runtime_stats.setdefault(
            self.__class__.__name__,
            {
                "banners_captured": 0,
            },
        )
        # FIX-05: Instantiate CrawlEngine to access DOMAIN_RE safely.
        crawler = CrawlEngine()

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            if context.should_stop():
                break
            open_ports = context.open_ports_cache.get(domain_node.id, [])
            for port in open_ports:
                if context.should_stop():
                    break
                banner = probe.grab_banner(
                    domain_node.id, port,
                    timeout=context.port_timeout,
                    cache=context.banner_cache,
                    context=context,
                )
                if not banner:
                    continue
                stats["banners_captured"] = int(stats.get("banners_captured", 0) or 0) + 1

                graph.add_node(
                    domain_node.id, NodeType.DOMAIN, method,
                    confidence=0.85,
                    metadata={
                        f"banner_port_{port}": banner[:500],
                        "has_banner": True,
                    }
                )

                # FIX-05: Use instance regex, not class attribute directly.
                for m in crawler.DOMAIN_RE.finditer(banner):
                    candidate = normalize_host(m.group(1))
                    if candidate and candidate != domain_node.id:
                        graph.add_node(
                            candidate, NodeType.DOMAIN, method,
                            confidence=0.75,
                            metadata={"from_banner": True}
                        )


# ── MODULE 4: HTTP PROBE ─────────────────────────────────────────────────

class HTTPProbeModule(IntelligenceModule):
    """
    HTTP HEAD probe per domain for both https and http schemes independently.
    Track: redirect chains, status codes, server headers, HSTS, CSP.
    FIX-15: Both schemes are always probed so each gets its own metadata entry.
    Confidence: 0.85
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "http_probe"
        probe = ActiveProbeEngine()
        module_name = self.__class__.__name__
        state = context.module_state.setdefault(
            module_name,
            {
                "domain_index": 0,
                "scheme_index": 0,
            },
        )
        stats = context.module_runtime_stats.setdefault(
            module_name,
            {
                "http_responses": 0,
            },
        )
        domains = sorted(graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id)
        if int(state.get("domain_index", 0) or 0) >= len(domains):
            state["domain_index"] = 0
            state["scheme_index"] = 0
        domain_index = max(0, int(state.get("domain_index", 0) or 0))
        scheme_index = max(0, int(state.get("scheme_index", 0) or 0))
        schemes = ("https", "http")

        while domain_index < len(domains):
            domain_node = domains[domain_index]
            if context.should_stop():
                state["domain_index"] = domain_index
                state["scheme_index"] = scheme_index
                return
            # FIX-15: Probe BOTH schemes independently (no break after first hit).
            while scheme_index < len(schemes):
                scheme = schemes[scheme_index]
                if context.should_stop():
                    state["domain_index"] = domain_index
                    state["scheme_index"] = scheme_index
                    return
                remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                    context,
                    reserve_seconds=context.turn_cleanup_margin_seconds,
                )
                if remaining_budget is not None and remaining_budget <= 0.05:
                    state["domain_index"] = domain_index
                    state["scheme_index"] = scheme_index
                    return
                url = f"{scheme}://{domain_node.id}"
                head = probe.http_head(
                    url,
                    timeout=min(
                        float(context.http_timeout),
                        max(0.05, float(remaining_budget or context.http_timeout)),
                    ),
                    cache=context.http_cache, context=context,
                )
                scheme_index += 1
                if not head:
                    continue

                status = head.get("status", 0)
                headers = head.get("headers", {})
                redirect = head.get("redirect")
                stats["http_responses"] = int(stats.get("http_responses", 0) or 0) + 1

                graph.add_node(
                    domain_node.id, NodeType.DOMAIN, method,
                    confidence=0.85,
                    metadata={
                        f"{scheme}_status": status,
                        f"{scheme}_server": headers.get("Server", headers.get("server")),
                        f"{scheme}_hsts": bool(headers.get("Strict-Transport-Security")),
                        f"{scheme}_csp": bool(headers.get("Content-Security-Policy")),
                        f"{scheme}_powered_by": headers.get("X-Powered-By"),
                    }
                )

                if redirect and status in (301, 302, 307, 308):
                    redirect_domain = normalize_host(
                        urlparse(redirect).netloc.split(":")[0]
                    )
                    if redirect_domain and redirect_domain != domain_node.id:
                        graph.add_node(
                            redirect_domain, NodeType.DOMAIN, method,
                            confidence=0.80,
                            metadata={"from_redirect": True, "redirect_from": domain_node.id}
                        )
                        graph.add_edge(
                            domain_node.id, redirect_domain,
                            BCDEEdgeType.HTTP_REDIRECT, method, confidence=0.80,
                            metadata={"status": status, "source_scheme": scheme}
                        )
            domain_index += 1
            scheme_index = 0
            state["domain_index"] = domain_index
            state["scheme_index"] = scheme_index


# ── MODULE 5: HTTP CRAWL ─────────────────────────────────────────────────

class HTTPCrawlModule(IntelligenceModule):
    """
    BFS crawl per active domain. Extract links, subdomains, robots.txt, sitemap.xml.
    Strict caps: max_crawl_depth, max_crawl_pages_per_host.
    Confidence: 0.75
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "http_crawl"
        probe = ActiveProbeEngine()
        crawler = CrawlEngine()
        module_name = self.__class__.__name__
        state = context.module_state.setdefault(
            module_name,
            {
                "domain_index": 0,
                "phase": "crawl",
                "queue": [],
                "depth": 0,
                "pages": 0,
                "sitemap_index": 0,
            },
        )
        stats = context.module_runtime_stats.setdefault(
            module_name,
            {
                "pages_crawled": 0,
            },
        )
        domains = sorted(graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id)
        if int(state.get("domain_index", 0) or 0) >= len(domains):
            state["domain_index"] = 0
            state["phase"] = "crawl"
            state["queue"] = []
            state["depth"] = 0
            state["pages"] = 0
            state["sitemap_index"] = 0
        domain_index = max(0, int(state.get("domain_index", 0) or 0))

        while domain_index < len(domains):
            domain_node = domains[domain_index]
            if context.should_stop():
                state["domain_index"] = domain_index
                return
            if not self._has_http_response(domain_node.id, context):
                domain_index += 1
                state["domain_index"] = domain_index
                state["phase"] = "crawl"
                state["queue"] = []
                state["depth"] = 0
                state["pages"] = 0
                state["sitemap_index"] = 0
                continue

            base_url = self._pick_scheme(domain_node.id, context)
            if not base_url:
                domain_index += 1
                state["domain_index"] = domain_index
                state["phase"] = "crawl"
                state["queue"] = []
                state["depth"] = 0
                state["pages"] = 0
                state["sitemap_index"] = 0
                continue

            if str(state.get("phase", "crawl")) == "crawl":
                if not self._crawl_host(
                    domain_node.id,
                    base_url,
                    graph,
                    context,
                    probe,
                    crawler,
                    method,
                    state,
                    stats,
                ):
                    state["domain_index"] = domain_index
                    return
                state["phase"] = "robots"
            if str(state.get("phase", "crawl")) == "robots":
                if not self._fetch_robots(
                    domain_node.id,
                    base_url,
                    graph,
                    context,
                    probe,
                    crawler,
                    method,
                ):
                    state["domain_index"] = domain_index
                    return
                state["phase"] = "sitemap"
            if str(state.get("phase", "crawl")) == "sitemap":
                if not self._fetch_sitemap(
                    domain_node.id,
                    base_url,
                    graph,
                    context,
                    probe,
                    crawler,
                    method,
                    state,
                ):
                    state["domain_index"] = domain_index
                    return
                domain_index += 1
                state["domain_index"] = domain_index
                state["phase"] = "crawl"
                state["queue"] = []
                state["depth"] = 0
                state["pages"] = 0
                state["sitemap_index"] = 0

    def _crawl_host(
        self, host: str, base_url: str,
        graph: PassiveDiscoveryGraph, context: BCDEExpansionContext,
        probe: ActiveProbeEngine, crawler: CrawlEngine, method: str,
        state: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> bool:
        queue = list(state.get("queue") or [base_url])
        depth = max(0, int(state.get("depth", 0) or 0))
        pages = max(0, int(state.get("pages", 0) or 0))

        while (
            queue
            and depth <= context.max_crawl_depth
            and pages < context.max_crawl_pages_per_host
            and not context.should_stop()
        ):
            next_queue: List[str] = []
            for url in queue:
                if context.should_stop():
                    state["queue"] = queue
                    state["depth"] = depth
                    state["pages"] = pages
                    return False
                if url in context.crawl_visited:
                    continue
                if pages >= context.max_crawl_pages_per_host:
                    break
                remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                    context,
                    reserve_seconds=context.turn_cleanup_margin_seconds,
                )
                if remaining_budget is not None and remaining_budget <= 0.05:
                    state["queue"] = queue
                    state["depth"] = depth
                    state["pages"] = pages
                    return False
                context.crawl_visited.add(url)
                pages += 1
                stats["pages_crawled"] = int(stats.get("pages_crawled", 0) or 0) + 1

                resp = probe.http_get(
                    url,
                    timeout=min(
                        float(context.http_timeout),
                        max(0.05, float(remaining_budget or context.http_timeout)),
                    ),
                    cache=context.http_cache, context=context,
                )
                if not resp or resp.get("status", 0) not in range(200, 400):
                    continue

                body = resp.get("body", "")

                for domain in sorted(crawler.extract_domains_from_content(body, context.root_domain)):
                    graph.add_node(
                        domain, NodeType.DOMAIN, method,
                        confidence=0.75,
                        metadata={"from_crawl": True, "crawl_source_url": url[:200]}
                    )
                    if domain != host:
                        graph.add_edge(
                            host, domain,
                            BCDEEdgeType.JS_REFERENCE, method, confidence=0.75
                        )

                for link in sorted(crawler.extract_links(base_url, body)):
                    parsed = urlparse(link)
                    if parsed.netloc == urlparse(base_url).netloc:
                        if link not in context.crawl_visited:
                            next_queue.append(link)

            # FIX-06: Only increment depth when there is actually a next level to process.
            if next_queue:
                queue = list(dict.fromkeys(next_queue))
                depth += 1
            else:
                break
        state["queue"] = []
        state["depth"] = 0
        state["pages"] = 0
        return True

    def _fetch_robots(
        self, host: str, base_url: str,
        graph: PassiveDiscoveryGraph, context: BCDEExpansionContext,
        probe: ActiveProbeEngine, crawler: CrawlEngine, method: str
    ) -> bool:
        robots_url = base_url.rstrip("/") + "/robots.txt"
        if context.should_stop():
            return False
        remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
            context,
            reserve_seconds=context.turn_cleanup_margin_seconds,
        )
        if remaining_budget is not None and remaining_budget <= 0.05:
            return False
        resp = probe.http_get(
            robots_url,
            timeout=min(
                float(context.http_timeout),
                max(0.05, float(remaining_budget or context.http_timeout)),
            ),
            cache=context.http_cache, context=context,
        )
        if resp and resp.get("status") == 200:
            body = resp.get("body", "")
            for line in body.splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    context.crawl_visited.discard(sitemap_url)
                for domain in sorted(crawler.extract_domains_from_content(line, context.root_domain)):
                    graph.add_node(
                        domain, NodeType.DOMAIN, method,
                        confidence=0.72,
                        metadata={"from_robots_txt": True}
                    )
        return True

    def _fetch_sitemap(
        self, host: str, base_url: str,
        graph: PassiveDiscoveryGraph, context: BCDEExpansionContext,
        probe: ActiveProbeEngine, crawler: CrawlEngine, method: str,
        state: Dict[str, Any],
    ) -> bool:
        if context.should_stop():
            return False
        paths = ("/sitemap.xml", "/sitemap_index.xml")
        path_index = max(0, int(state.get("sitemap_index", 0) or 0))
        while path_index < len(paths):
            if context.should_stop():
                state["sitemap_index"] = path_index
                return False
            remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                context,
                reserve_seconds=context.turn_cleanup_margin_seconds,
            )
            if remaining_budget is not None and remaining_budget <= 0.05:
                state["sitemap_index"] = path_index
                return False
            sitemap_url = base_url.rstrip("/") + paths[path_index]
            resp = probe.http_get(
                sitemap_url,
                timeout=min(
                    float(context.http_timeout),
                    max(0.05, float(remaining_budget or context.http_timeout)),
                ),
                cache=context.http_cache, context=context,
            )
            path_index += 1
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                for domain in sorted(crawler.extract_domains_from_content(body, context.root_domain)):
                    graph.add_node(
                        domain, NodeType.DOMAIN, method,
                        confidence=0.72,
                        metadata={"from_sitemap": True}
                    )
        state["sitemap_index"] = 0
        return True

    def _has_http_response(self, host: str, context: BCDEExpansionContext) -> bool:
        # FIX-13: Check both schemes.
        # Phase 3 gate: crawl only if we have successful HTTP probe evidence
        # or open web ports from active probing.
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            cached = context.http_cache.get(url)
            if cached and int(cached.get("status", 0) or 0) in range(200, 400):
                return True
        open_ports = set(context.open_ports_cache.get(host, []))
        web_ports = {80, 443, 8080, 8443, 8444, 9443, 9444}
        return bool(open_ports & web_ports)

    def _pick_scheme(self, host: str, context: BCDEExpansionContext) -> Optional[str]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            cached = context.http_cache.get(url)
            if cached and cached.get("status"):
                return url
        open_ports = context.open_ports_cache.get(host, [])
        if 443 in open_ports or 8443 in open_ports:
            return f"https://{host}"
        if 80 in open_ports or 8080 in open_ports:
            return f"http://{host}"
        return None


# ── MODULE 6: JS ANALYSIS ────────────────────────────────────────────────

class JSAnalysisModule(IntelligenceModule):
    """
    Download and parse JS files discovered during crawl.
    Extract: domain refs, API endpoints, cloud endpoints, token endpoints.
    Confidence: 0.70
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "js_analysis"
        probe = ActiveProbeEngine()
        crawler = CrawlEngine()
        module_name = self.__class__.__name__
        state = context.module_state.setdefault(
            module_name,
            {
                "domain_index": 0,
                "js_index": 0,
            },
        )
        stats = context.module_runtime_stats.setdefault(
            module_name,
            {
                "js_files_fetched": 0,
                "api_paths_discovered": 0,
            },
        )
        domains = sorted(graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id)
        if int(state.get("domain_index", 0) or 0) >= len(domains):
            state["domain_index"] = 0
            state["js_index"] = 0
        domain_index = max(0, int(state.get("domain_index", 0) or 0))
        js_index = max(0, int(state.get("js_index", 0) or 0))

        while domain_index < len(domains):
            domain_node = domains[domain_index]
            if context.should_stop():
                state["domain_index"] = domain_index
                state["js_index"] = js_index
                return
            remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                context,
                reserve_seconds=context.turn_cleanup_margin_seconds,
            )
            if remaining_budget is not None and remaining_budget <= 0.05:
                state["domain_index"] = domain_index
                state["js_index"] = js_index
                return
            base_url = f"https://{domain_node.id}"
            root_resp = probe.http_get(
                base_url,
                timeout=min(
                    float(context.http_timeout),
                    max(0.05, float(remaining_budget or context.http_timeout)),
                ),
                cache=context.http_cache, context=context,
            )
            if not root_resp or root_resp.get("status", 0) not in range(200, 400):
                domain_index += 1
                js_index = 0
                state["domain_index"] = domain_index
                state["js_index"] = js_index
                continue

            js_urls = sorted(crawler.extract_js_sources(base_url, root_resp.get("body", "")))
            js_fetched = 0
            if js_index >= len(js_urls):
                js_index = 0
                domain_index += 1
                state["domain_index"] = domain_index
                state["js_index"] = 0
                continue

            while js_index < len(js_urls):
                js_url = js_urls[js_index]
                if context.should_stop():
                    state["domain_index"] = domain_index
                    state["js_index"] = js_index
                    return
                if js_fetched >= context.max_js_files_per_host:
                    domain_index += 1
                    js_index = 0
                    state["domain_index"] = domain_index
                    state["js_index"] = js_index
                    break
                if js_url in context.crawl_visited:
                    js_index += 1
                    continue
                context.crawl_visited.add(js_url)
                js_fetched += 1
                remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                    context,
                    reserve_seconds=context.turn_cleanup_margin_seconds,
                )
                if remaining_budget is not None and remaining_budget <= 0.05:
                    state["domain_index"] = domain_index
                    state["js_index"] = js_index
                    return

                js_resp = probe.http_get(
                    js_url,
                    timeout=min(
                        float(context.http_timeout),
                        max(0.05, float(remaining_budget or context.http_timeout)),
                    ),
                    cache=context.http_cache, context=context,
                )
                js_index += 1
                if not js_resp or js_resp.get("status", 0) not in range(200, 400):
                    continue
                stats["js_files_fetched"] = int(stats.get("js_files_fetched", 0) or 0) + 1

                js_body = js_resp.get("body", "")

                for domain in sorted(
                    crawler.extract_domains_from_content(js_body, context.root_domain)
                ):
                    graph.add_node(
                        domain, NodeType.DOMAIN, method,
                        confidence=0.70,
                        metadata={"from_js": True, "js_source": js_url[:200]}
                    )
                    if domain != domain_node.id:
                        graph.add_edge(
                            domain_node.id, domain,
                            BCDEEdgeType.JS_REFERENCE, method, confidence=0.70
                        )

                for api_url in sorted(crawler.extract_api_paths(js_body, base_url)):
                    stats["api_paths_discovered"] = int(
                        stats.get("api_paths_discovered", 0) or 0
                    ) + 1
                    graph.add_node(
                        api_url, NodeType.ENDPOINT, method,
                        confidence=0.68,
                        metadata={
                            "is_api_endpoint": True,
                            "from_js": True,
                            "host": domain_node.id,
                        }
                    )
                    graph.add_edge(
                        domain_node.id, api_url,
                        BCDEEdgeType.API_ENDPOINT, method, confidence=0.68
                    )
            if js_index >= len(js_urls):
                domain_index += 1
                js_index = 0
                state["domain_index"] = domain_index
                state["js_index"] = js_index


# ── MODULE 7: OPENAPI PROBE ──────────────────────────────────────────────

class OpenAPIProbeModule(IntelligenceModule):
    """
    Probe standard OpenAPI/Swagger paths.
    Parse schema to extract endpoints, extract server domains.
    FIX-09: Breaks out of the path loop once a valid schema is found per domain.
    Confidence: 0.80
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "openapi"
        crawler = CrawlEngine()
        probe = ActiveProbeEngine()  # FIX-A2: centralise through ActiveProbeEngine
        module_name = self.__class__.__name__
        state = context.module_state.setdefault(
            module_name,
            {
                "domain_index": 0,
                "path_index": 0,
                "scheme_index": 0,
                "found_schema": False,
            },
        )
        stats = context.module_runtime_stats.setdefault(
            module_name,
            {
                "schemas_found": 0,
                "api_paths_discovered": 0,
            },
        )
        domains = sorted(graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id)
        if int(state.get("domain_index", 0) or 0) >= len(domains):
            state["domain_index"] = 0
            state["path_index"] = 0
            state["scheme_index"] = 0
            state["found_schema"] = False
        domain_index = max(0, int(state.get("domain_index", 0) or 0))

        while domain_index < len(domains):
            domain_node = domains[domain_index]
            if context.should_stop():
                state["domain_index"] = domain_index
                return
            found_schema = bool(state.get("found_schema", False))
            path_index = max(0, int(state.get("path_index", 0) or 0))
            scheme_index = max(0, int(state.get("scheme_index", 0) or 0))

            while path_index < len(crawler.OPENAPI_PATHS):
                path = crawler.OPENAPI_PATHS[path_index]
                if context.should_stop():
                    state["domain_index"] = domain_index
                    state["path_index"] = path_index
                    state["scheme_index"] = scheme_index
                    state["found_schema"] = found_schema
                    return
                if found_schema:  # FIX-09: skip remaining paths once schema found
                    break

                schemes = ("https", "http")
                while scheme_index < len(schemes):
                    scheme = schemes[scheme_index]
                    if context.should_stop():
                        state["domain_index"] = domain_index
                        state["path_index"] = path_index
                        state["scheme_index"] = scheme_index
                        state["found_schema"] = found_schema
                        return
                    remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                        context,
                        reserve_seconds=context.turn_cleanup_margin_seconds,
                    )
                    if remaining_budget is not None and remaining_budget <= 0.05:
                        state["domain_index"] = domain_index
                        state["path_index"] = path_index
                        state["scheme_index"] = scheme_index
                        state["found_schema"] = found_schema
                        return
                    url = f"{scheme}://{domain_node.id}{path}"

                    # FIX-A2: All HTTP must go through ActiveProbeEngine.http_get()
                    # to benefit from probe_delay_ms, centralised caching, and UA header.
                    resp_data = probe.http_get(
                        url,
                        timeout=min(
                            float(context.http_timeout),
                            max(0.05, float(remaining_budget or context.http_timeout)),
                        ),
                        cache=context.http_cache,
                        context=context,
                    )
                    scheme_index += 1

                    if not resp_data or resp_data.get("status") != 200:
                        continue

                    # Parse JSON schema from body if not already parsed.
                    schema = resp_data.get("schema")
                    if schema is None:
                        body = resp_data.get("body", "")
                        try:
                            schema = json.loads(body)
                        except Exception:
                            schema = {}
                    # Cache parsed schema back so we don't re-parse.
                    resp_data["schema"] = schema
                    schema = resp_data.get("schema") or {}
                    endpoints = crawler.parse_openapi_endpoints(schema)

                    graph.add_node(
                        domain_node.id, NodeType.DOMAIN, method,
                        confidence=0.80,
                        metadata={
                            "has_openapi": True,
                            "openapi_url": url,
                            "api_path_count": len(endpoints),
                        }
                    )
                    stats["schemas_found"] = int(stats.get("schemas_found", 0) or 0) + 1

                    for ep_path in sorted(endpoints[:50]):
                        stats["api_paths_discovered"] = int(
                            stats.get("api_paths_discovered", 0) or 0
                        ) + 1
                        ep_url = f"{scheme}://{domain_node.id}{ep_path}"
                        graph.add_node(
                            ep_url, NodeType.ENDPOINT, method,
                            confidence=0.78,
                            metadata={
                                "is_api_endpoint": True,
                                "api_path": ep_path,
                                "host": domain_node.id,
                                "port": 443 if scheme == "https" else 80,
                                "scheme": scheme,
                            }
                        )
                        graph.add_edge(
                            domain_node.id, ep_url,
                            BCDEEdgeType.API_ENDPOINT, method, confidence=0.78
                        )

                    for server in schema.get("servers", []):
                        server_url = server.get("url", "")
                        server_domain = normalize_host(urlparse(server_url).netloc.split(":")[0])
                        if server_domain and server_domain != domain_node.id:
                            graph.add_node(
                                server_domain, NodeType.DOMAIN, method,
                                confidence=0.80,
                                metadata={"from_openapi_server": True}
                            )

                    found_schema = True  # FIX-09: signal to skip remaining paths
                    break  # break scheme loop
                if found_schema:
                    break
                path_index += 1
                scheme_index = 0
            domain_index += 1
            state["domain_index"] = domain_index
            state["path_index"] = 0
            state["scheme_index"] = 0
            state["found_schema"] = False


# ── MODULE 8: HTTP RESPONSE SIGNATURE ────────────────────────────────────

class HTTPResponseSignatureModule(IntelligenceModule):
    """
    Compute HTTP response signature per domain.
    FIX-23: Signature now includes body hash (first 64 KB) in addition to headers.
    Cluster domains by matching signature (same backend inference).
    Confidence: 0.72
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "http_signature"
        sig_engine = SignatureEngine()

        sig_to_domains: Dict[str, List[str]] = defaultdict(list)

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            if context.should_stop():
                break
            for scheme in ("https", "http"):
                if context.should_stop():
                    break
                url = f"{scheme}://{domain_node.id}"
                cached_resp = context.http_cache.get(url)
                if not cached_resp:
                    continue

                sig = sig_engine.response_signature(cached_resp)
                context.signature_cache[domain_node.id] = sig
                sig_to_domains[sig].append(domain_node.id)
                graph.add_node(
                    domain_node.id, NodeType.DOMAIN, method,
                    confidence=0.72,
                    metadata={"response_signature": sig}
                )
                break

        for sig, domains in sig_to_domains.items():
            if len(domains) < 2:
                continue
            unique = sorted(set(domains))
            for i, d1 in enumerate(unique):
                for d2 in unique[i + 1:]:
                    graph.add_edge(
                        d1, d2,
                        BCDEEdgeType.RESPONSE_CLUSTER, method, confidence=0.72,
                        metadata={"response_signature": sig}
                    )


# ── MODULE 9: TLS SERVER FINGERPRINT ─────────────────────────────────────

class TLSServerFingerprintModule(IntelligenceModule):
    """
    Capture TLS server fingerprint (cipher + version + session_id_length hash) per domain.
    FIX-22: session_id_length added as clustering dimension for load-balancer inference.
    Cluster domains sharing the same fingerprint → shared TLS terminator.
    Confidence: 0.78
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "tls_server_fingerprint"

        fp_to_domains: Dict[str, List[str]] = defaultdict(list)

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            ticket_id = self._probe_server_fingerprint(domain_node.id, context)
            if not ticket_id:
                continue

            graph.add_node(
                domain_node.id, NodeType.DOMAIN, method,
                confidence=0.78,
                metadata={"tls_server_fingerprint_hint": ticket_id}
            )
            fp_to_domains[ticket_id].append(domain_node.id)

        for ticket, domains in fp_to_domains.items():
            if len(domains) < 2:
                continue
            unique = sorted(set(domains))
            for i, d1 in enumerate(unique):
                for d2 in unique[i + 1:]:
                    graph.add_edge(
                        d1, d2,
                        # FIX-A4: Use TLS_SERVER_CLUSTER (not JARM_CLUSTER) to avoid
                        # conflating JARM approximation with TLS session ticket fingerprint.
                        # JARMFingerprintModule continues to use JARM_CLUSTER.
                        BCDEEdgeType.TLS_SERVER_CLUSTER, method, confidence=0.78,
                        metadata={"cluster_type": "tls_server_fingerprint", "ticket_hint": ticket}
                    )

    def _probe_server_fingerprint(
        self, hostname: str, context: BCDEExpansionContext
    ) -> Optional[str]:
        """
        FIX-22: Enhanced fingerprint uses cipher + version + session_id_length.
        """
        cache_key = f"ticket:{hostname}"
        if cache_key in context.tls_cache:
            return context.tls_cache[cache_key]

        result = None
        try:
            ctx = build_tls_context(context.tls_verification_mode)
            with socket.create_connection(
                (hostname, 443), timeout=context.tls_timeout
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version() or "UNKNOWN"
                    # FIX-22: session_id_length as load-balancer clustering signal.
                    session = ssock.session
                    session_id_len = len(session.id) if (session and session.id) else 0
                    raw = f"{cipher[0] if cipher else 'X'}|{version}|{session_id_len}"
                    result = hashlib.sha1(raw.encode()).hexdigest()[:12]
        except Exception as e:
            logger.debug(f"TLS session ticket probe {hostname}: {e}")

        context.tls_cache[cache_key] = result
        return result


# ======================================================
# SECTION 2 — INFRASTRUCTURE CORRELATION
# ======================================================

# ── MODULE 10: IP NEIGHBOR EXPANSION ─────────────────────────────────────
# FIX-01: Corrected module number comment from #9 → #10.

class IPNeighborExpansionModule(IntelligenceModule):
    """
    Probe adjacent IPs in same /24 (IPv4) for reverse DNS.
    Strict cap: max_neighbors_per_ip probes.
    Confidence: 0.60
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "ip_neighbor"
        infra = InfrastructureEngine()

        for ip_node in sorted(
            graph.get_nodes_by_type(NodeType.IP), key=lambda n: n.id
        ):
            try:
                addr = ipaddress.ip_address(ip_node.id)
                if not isinstance(addr, ipaddress.IPv4Address):
                    continue
            except ValueError:
                continue

            neighbors = infra.get_adjacent_ips(
                ip_node.id, context.max_neighbors_per_ip
            )

            for neighbor_ip in neighbors:
                ptr_names = safe_reverse_dns(
                    neighbor_ip, timeout=3.0, cache=context.dns_cache
                )
                if not ptr_names:
                    continue

                norm_neighbor = normalize_ip(neighbor_ip)
                if not norm_neighbor:
                    continue

                graph.add_node(
                    norm_neighbor, NodeType.IP, method,
                    confidence=0.60,
                    metadata={"neighbor_of": ip_node.id, "from_neighbor_scan": True}
                )
                graph.add_edge(
                    ip_node.id, norm_neighbor,
                    BCDEEdgeType.IP_NEIGHBOR, method, confidence=0.60
                )

                for hostname in ptr_names:
                    graph.add_node(
                        hostname, NodeType.DOMAIN, method,
                        confidence=0.60,
                        metadata={"from_neighbor_ptr": True, "neighbor_ip": neighbor_ip}
                    )


# ── MODULE 11: NETBLOCK EXPANSION ────────────────────────────────────────

class NetblockExpansionModule(IntelligenceModule):
    """
    Model IP → NETBLOCK membership.

    CIDR source priority (FIX-A10: explicit documentation):
      1. RDAP CIDR from Category A (preferred): if ip_node.metadata["cidr"] is set,
         that data came from RDAP enrichment performed upstream in Category A and
         represents the actual allocated network block for the IP.
      2. Synthetic /24 inference (fallback): if no RDAP CIDR is present,
         ip_to_cidr(prefix=24) constructs a synthetic /24 prefix for rough grouping.
         This is an approximation — it does NOT reflect the actual RDAP allocation.
         Nodes created this way are tagged with cidr_synthetic=True.

    Does NOT expand full CIDR range (no host enumeration).
    Confidence: 0.65
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "netblock"
        infra = InfrastructureEngine()

        for ip_node in sorted(
            graph.get_nodes_by_type(NodeType.IP), key=lambda n: n.id
        ):
            cidr = ip_node.metadata.get("cidr")
            cidr_is_synthetic = False
            if not cidr:
                # FIX-A10: No RDAP data available — synthesise /24 as fallback.
                cidr = infra.ip_to_cidr(ip_node.id, prefix=24)
                cidr_is_synthetic = True
            if not cidr:
                continue

            graph.add_node(
                cidr, NodeType.NETBLOCK, method,
                confidence=0.65,
                metadata={
                    "org": ip_node.metadata.get("org", "unknown"),
                    "asn": ip_node.metadata.get("asn"),
                    "country": ip_node.metadata.get("country", "unknown"),
                    "cidr_synthetic": cidr_is_synthetic,  # FIX-A10: flag synthetic CIDRs
                }
            )
            graph.add_edge(
                ip_node.id, cidr,
                BCDEEdgeType.NETBLOCK_CONTAINS, method, confidence=0.65
            )


# ── MODULE 12: SHARED IP CORRELATION ─────────────────────────────────────

class SharedIPCorrelationModule(IntelligenceModule):
    """
    Create SHARED_IP edges between domains resolving to same IP.
    FIX-11: Hard cap of MAX_SHARED_DOMAINS_PER_IP to prevent O(n²) edge explosion
            on large CDN IPs (e.g. Cloudflare with thousands of tenants).
    Confidence: 0.70
    """

    # FIX-11: Skip shared-IP clustering for IPs with too many tenants.
    MAX_SHARED_DOMAINS_PER_IP: int = 50

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "shared_ip"

        ip_to_domains: Dict[str, List[str]] = defaultdict(list)
        for edge in graph.get_edges_by_type(EdgeType.A_RECORD):
            ip_to_domains[edge.dst].append(edge.src)
        for edge in graph.get_edges_by_type(EdgeType.AAAA_RECORD):
            ip_to_domains[edge.dst].append(edge.src)

        for ip, domains in ip_to_domains.items():
            if len(domains) < 2:
                continue
            # FIX-11: Skip IPs shared by too many domains (CDN / hyperscaler IPs).
            if len(domains) > self.MAX_SHARED_DOMAINS_PER_IP:
                logger.debug(
                    f"SharedIPCorrelation: skipping IP {ip} — "
                    f"{len(domains)} domains exceeds cap ({self.MAX_SHARED_DOMAINS_PER_IP}). "
                    f"Likely a CDN shared IP."
                )
                continue
            unique = sorted(set(domains))
            for i, d1 in enumerate(unique):
                for d2 in unique[i + 1:]:
                    graph.add_edge(
                        d1, d2,
                        BCDEEdgeType.SHARED_IP, method, confidence=0.70,
                        metadata={"shared_ip": ip}
                    )


# ── MODULE 13: JARM FINGERPRINT ──────────────────────────────────────────

class JARMFingerprintModule(IntelligenceModule):
    """
    Compute TLS config fingerprint (JARM-approximation) per HTTPS endpoint.
    Cluster endpoints sharing the same fingerprint → backend reuse inference.
    Confidence: 0.75
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "jarm"
        sig_engine = SignatureEngine()

        fp_to_domains: Dict[str, List[str]] = defaultdict(list)

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            fp = sig_engine.tls_config_fingerprint(
                domain_node.id,
                443,
                context.tls_timeout,
                context.jarm_cache,
                tls_verification_mode=context.tls_verification_mode,
            )
            if not fp:
                continue

            graph.add_node(
                domain_node.id, NodeType.DOMAIN, method,
                confidence=0.75,
                metadata={"tls_fingerprint": fp}
            )
            fp_to_domains[fp].append(domain_node.id)

        for fp, domains in fp_to_domains.items():
            if len(domains) < 2:
                continue
            unique = sorted(set(domains))
            for i, d1 in enumerate(unique):
                for d2 in unique[i + 1:]:
                    graph.add_edge(
                        d1, d2,
                        BCDEEdgeType.JARM_CLUSTER, method, confidence=0.75,
                        metadata={"tls_fingerprint": fp}
                    )


# ── MODULE 14: CDN EDGE MAPPING ──────────────────────────────────────────

class CDNEdgeMappingModule(IntelligenceModule):
    """
    Detect CDN vendor from CNAME chains.
    Tag domains with CDN vendor, region, edge IP metadata.
    Confidence: 0.78
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "cdn_edge"
        infra = InfrastructureEngine()

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            cname_chain = self._get_cname_chain(domain_node.id, context)
            cdn_vendor = infra.detect_cdn(cname_chain)

            if cdn_vendor:
                graph.add_node(
                    domain_node.id, NodeType.DOMAIN, method,
                    confidence=0.78,
                    metadata={
                        "cdn_vendor": cdn_vendor,
                        "cname_chain": cname_chain[:5],
                        "behind_cdn": True,
                    }
                )
                if cname_chain:
                    # FIX-19: Use normalize_host() for consistent hostname normalisation.
                    edge_domain = normalize_host(cname_chain[-1])
                    if edge_domain and edge_domain != domain_node.id:
                        graph.add_node(
                            edge_domain, NodeType.DOMAIN, method,
                            confidence=0.72,
                            metadata={"is_cdn_edge": True, "cdn_vendor": cdn_vendor}
                        )
                        graph.add_edge(
                            domain_node.id, edge_domain,
                            BCDEEdgeType.CDN_EDGE, method, confidence=0.78,
                            metadata={"cdn_vendor": cdn_vendor}
                        )

    def _get_cname_chain(
        self, domain: str, context: BCDEExpansionContext, max_depth: int = 10
    ) -> List[str]:
        chain = []
        current = domain
        visited: Set[str] = set()
        while len(chain) < max_depth:
            if current in visited:
                break
            visited.add(current)
            cnames = safe_dns_query(current, "CNAME", cache=context.dns_cache)
            if not cnames:
                break
            cnames = sorted(cnames)  # FIX-A3: deterministic — DNS responses are not ordered
            chain.extend(cnames)
            # FIX-19: normalize_host() instead of bare rstrip(".")
            current = normalize_host(cnames[0]) or cnames[0].rstrip(".")
        return chain


# ======================================================
# SECTION 3 — CLOUD & PLATFORM INTELLIGENCE
# ======================================================

# ── MODULE 15: CLOUD BUCKET PATTERNS ─────────────────────────────────────

class CloudBucketPatternsModule(IntelligenceModule):
    """
    Infer cloud storage bucket names from root domain and known subdomains.
    Probe S3/Azure/GCP bucket URLs with HTTP HEAD only.
    FIX-10: Deduplicates cloud hostnames and breaks template loop on first hit
            per (variant, cloud-provider) to avoid redundant probing and edges.
    Confidence: 0.72
    """

    # Templates grouped by provider so we can break per-provider on first hit.
    S3_TEMPLATES = [
        "https://{name}.s3.amazonaws.com",
        "https://{name}.s3.us-east-1.amazonaws.com",
        "https://s3.amazonaws.com/{name}",
        "https://{name}.s3-website.us-east-1.amazonaws.com",
    ]
    AZURE_TEMPLATES = [
        "https://{name}.blob.core.windows.net",
        "https://{name}.azurewebsites.net",
        "https://{name}.azurefd.net",
    ]
    GCP_TEMPLATES = [
        "https://storage.googleapis.com/{name}",
        "https://{name}.storage.googleapis.com",
        "https://{name}.appspot.com",
    ]
    # FIX-10: Grouped for per-provider break-on-hit.
    PROVIDER_TEMPLATES = [S3_TEMPLATES, AZURE_TEMPLATES, GCP_TEMPLATES]

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "cloud_bucket"
        probe = ActiveProbeEngine()
        root = context.root_domain

        variants = self._generate_variants(root, graph)[:context.max_bucket_variants]

        for name in sorted(variants):
            # FIX-10: Track already-added cloud hosts for this variant.
            added_cloud_hosts: Set[str] = set()

            for provider_templates in self.PROVIDER_TEMPLATES:
                for template in provider_templates:
                    url = template.format(name=name)
                    head = probe.http_head(
                        url, timeout=context.http_timeout,
                        cache=context.http_cache, context=context,
                    )
                    if not head:
                        continue

                    status = head.get("status", 0)
                    if status in (200, 301, 302, 403):
                        parsed = urlparse(url)
                        cloud_host = parsed.netloc
                        cloud_domain = normalize_host(cloud_host)

                        if cloud_domain and cloud_domain not in added_cloud_hosts:
                            added_cloud_hosts.add(cloud_domain)
                            graph.add_node(
                                cloud_domain, NodeType.DOMAIN, method,
                                confidence=0.72,
                                metadata={
                                    "is_cloud_asset": True,
                                    "cloud_url": url,
                                    "cloud_status": status,
                                    "bucket_name": name,
                                }
                            )
                            graph.add_edge(
                                root, cloud_domain,
                                BCDEEdgeType.CLOUD_ASSET, method, confidence=0.72,
                                metadata={"bucket_name": name, "status": status}
                            )
                        # FIX-10: Break template loop after first hit per provider.
                        break

    def _generate_variants(
        self, root: str, graph: PassiveDiscoveryGraph
    ) -> List[str]:
        label = root.split(".")[0]
        variants: Set[str] = {
            label,
            root.replace(".", "-"),
            root.replace(".", ""),
            f"{label}-assets",
            f"{label}-static",
            f"{label}-media",
            f"{label}-uploads",
            f"{label}-backup",
            f"{label}-dev",
            f"{label}-staging",
            f"{label}-prod",
            f"assets.{label}",
            f"static.{label}",
            f"media.{label}",
        }

        dns_confirmed: Set[str] = set()
        for edge in graph.get_edges_by_type(EdgeType.A_RECORD):
            dns_confirmed.add(edge.src)
        for edge in graph.get_edges_by_type(EdgeType.AAAA_RECORD):
            dns_confirmed.add(edge.src)

        for domain in sorted(dns_confirmed):
            if not domain.endswith(f".{root}"):
                continue
            sub = domain.replace(f".{root}", "").split(".")[0]
            if sub and len(sub) > 2 and sub != label:
                variants.add(sub)
                variants.add(f"{label}-{sub}")

        return sorted(variants)


# ── MODULE 16: CLOUDFRONT ANALYSIS ───────────────────────────────────────

class CloudFrontAnalysisModule(IntelligenceModule):
    """
    Detect CloudFront distributions via CNAME and X-Cache headers.
    Extract alternate domain names if exposed.
    Confidence: 0.74
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "cloudfront"
        probe = ActiveProbeEngine()

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            cnames = safe_dns_query(
                domain_node.id, "CNAME", cache=context.dns_cache
            )
            is_cf = any("cloudfront.net" in c.lower() for c in cnames)

            if not is_cf:
                head = probe.http_head(
                    f"https://{domain_node.id}",
                    timeout=context.http_timeout,
                    cache=context.http_cache,
                    context=context,
                )
                if head:
                    headers = head.get("headers", {})
                    is_cf = any(
                        "cloudfront" in str(v).lower()
                        for v in headers.values()
                    ) or "X-Cache" in headers or "x-cache" in headers

            if not is_cf:
                continue

            graph.add_node(
                domain_node.id, NodeType.DOMAIN, method,
                confidence=0.74,
                metadata={"is_cloudfront": True, "cf_cname": cnames[:3]}
            )

            for cname in cnames:
                if "cloudfront.net" in cname.lower():
                    cf_domain = normalize_host(cname)
                    if cf_domain:
                        graph.add_node(
                            cf_domain, NodeType.DOMAIN, method,
                            confidence=0.74,
                            metadata={"is_cdn_edge": True, "cdn_vendor": "CloudFront"}
                        )
                        graph.add_edge(
                            domain_node.id, cf_domain,
                            BCDEEdgeType.CDN_EDGE, method, confidence=0.74
                        )


# ── MODULE 17: KUBERNETES PATTERN ────────────────────────────────────────

class K8sPatternModule(IntelligenceModule):
    """
    Detect Kubernetes ingress patterns from headers and known subdomain conventions.
    FIX-18: K8S_HEADERS uses correct substring patterns that match JSON-serialised
            header dicts (removed "server: nginx/ingress" full-header:value pattern).
    Confidence: 0.68
    """

    # FIX-18: Each entry is a substring that will appear inside
    #         json.dumps(headers_dict).lower() — no "key: value" strings.
    K8S_HEADERS = {
        "x-kubernetes-node",
        "x-k8s-cluster",
        "nginx/ingress",   # FIX-18: was "server: nginx/ingress" — wrong format
        "ingress-nginx",
        "kubernetes",
        "k8s",
    }
    K8S_PATH_PROBES = [
        "/healthz", "/readyz", "/livez", "/metrics",
        "/.well-known/health", "/api/v1",
    ]
    K8S_SUBDOMAIN_PATTERNS = [
        "k8s.{root}", "cluster.{root}", "kube.{root}",
        "ingress.{root}", "api.{root}", "internal.{root}",
    ]

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "k8s_pattern"
        probe = ActiveProbeEngine()
        root = context.root_domain

        k8s_detected = False

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            head = probe.http_head(
                f"https://{domain_node.id}",
                timeout=context.http_timeout,
                cache=context.http_cache,
                context=context,
            )
            if not head:
                continue

            headers_str = json.dumps(head.get("headers", {})).lower()
            if any(h in headers_str for h in self.K8S_HEADERS):
                k8s_detected = True
                graph.add_node(
                    domain_node.id, NodeType.DOMAIN, method,
                    confidence=0.68,
                    metadata={"k8s_detected": True}
                )

        if k8s_detected:
            for pattern in self.K8S_SUBDOMAIN_PATTERNS:
                candidate = pattern.format(root=root)
                domain = normalize_host(candidate)
                if domain:
                    graph.add_node(
                        domain, NodeType.DOMAIN, method,
                        confidence=0.65,
                        metadata={"k8s_pattern": True, "k8s_pattern_source": pattern}
                    )
                    graph.add_edge(
                        root, domain,
                        BCDEEdgeType.K8S_INGRESS, method, confidence=0.65
                    )


# ======================================================
# SECTION 4 — HISTORICAL & REVIVAL LOGIC
# ======================================================

# ── MODULE 18: HISTORICAL REVIVAL ────────────────────────────────────────

class HistoricalRevivalModule(IntelligenceModule):
    """
    Check historical/dormant nodes from Category A for active revival.
    Confidence: 0.82
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "historical_revival"
        probe = ActiveProbeEngine()
        hist_engine = HistoricalEngine()

        for node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            if not node.historical:
                continue

            if hist_engine.is_domain_live(node.id, probe, context.http_timeout):
                graph.add_node(
                    node.id, NodeType.DOMAIN, method,
                    historical=False,
                    confidence=0.82,
                    metadata={"revived": True, "previously_historical": True}
                )
                graph.add_edge(
                    context.root_domain, node.id,
                    BCDEEdgeType.HISTORICAL_REVIVAL, method, confidence=0.82,
                    metadata={"revival_detected": True}
                )


# ── MODULE 19: EXPIRED ASSET DETECTION ───────────────────────────────────

class ExpiredAssetDetectionModule(IntelligenceModule):
    """
    Classify: cert_expired + DNS alive = expired asset still serving.
    FIX-08: `import datetime` moved to module top-level.
    Confidence: 0.70
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "expired_asset"
        # FIX-08: datetime is now a top-level import; no per-call import needed.

        now_ts = int(time.time())

        live_domains: Set[str] = set()
        for edge in graph.get_edges_by_type(EdgeType.A_RECORD):
            live_domains.add(edge.src)
        for edge in graph.get_edges_by_type(EdgeType.AAAA_RECORD):
            live_domains.add(edge.src)

        for node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            if node.id not in live_domains:
                continue

            not_after_str = (
                node.metadata.get("ct_not_after")
                or node.metadata.get("cert_not_after")
            )
            if not not_after_str:
                continue

            try:
                dt = datetime.datetime.fromisoformat(
                    not_after_str.replace("Z", "+00:00")
                )
                if dt.timestamp() < now_ts:
                    graph.add_node(
                        node.id, NodeType.DOMAIN, method,
                        confidence=0.70,
                        metadata={
                            "expired_asset": True,
                            "cert_expired_since": not_after_str,
                            "dns_alive": True,
                        }
                    )
            except Exception:
                pass


# ── MODULE 20: ORPHANED ASSET DETECTION ──────────────────────────────────

class OrphanedAssetDetectionModule(IntelligenceModule):
    """
    Classify: DNS not alive + cert still in CT = orphaned asset.
    Confidence: 0.65
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "orphaned_asset"

        live_domains: Set[str] = set()
        for edge in graph.get_edges_by_type(EdgeType.A_RECORD):
            live_domains.add(edge.src)
        for edge in graph.get_edges_by_type(EdgeType.AAAA_RECORD):
            live_domains.add(edge.src)

        ct_domains: Set[str] = set()
        for node in graph.get_nodes_by_type(NodeType.DOMAIN):
            if node.metadata.get("from_ct"):
                ct_domains.add(node.id)

        for domain in sorted(ct_domains - live_domains):
            node = graph.get_node(domain, NodeType.DOMAIN)
            if node is None:
                continue
            graph.add_node(
                domain, NodeType.DOMAIN, method,
                historical=True,
                confidence=0.65,
                metadata={
                    "orphaned": True,
                    "in_ct": True,
                    "dns_alive": False,
                }
            )


# ======================================================
# SECTION 5 — SIGNATURE & COVERAGE
# ======================================================

# ── MODULE 21: FAVICON HASH ───────────────────────────────────────────────

class FaviconHashModule(IntelligenceModule):
    """
    Download favicon per domain, compute hash, cluster by matching hash.
    FIX-21: Uses mmh3 (Shodan-compatible) when available, MD5 fallback.
    FIX-13: Guard checks both http:// and https:// cache entries.
    Confidence: 0.73
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "favicon_cluster"
        sig_engine = SignatureEngine()

        hash_to_domains: Dict[str, List[str]] = defaultdict(list)

        for domain_node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            # FIX-13: Check BOTH http and https cache keys, not just https.
            has_http_data = (
                bool(context.open_ports_cache.get(domain_node.id))
                or bool(context.http_cache.get(f"https://{domain_node.id}"))
                or bool(context.http_cache.get(f"http://{domain_node.id}"))
            )
            if not has_http_data:
                continue

            for scheme in ("https", "http"):
                url = f"{scheme}://{domain_node.id}"
                fhash = sig_engine.favicon_hash(
                    url,
                    context.http_timeout,
                    context.favicon_cache,
                    tls_verification_mode=context.tls_verification_mode,
                )
                if fhash:
                    graph.add_node(
                        domain_node.id, NodeType.DOMAIN, method,
                        confidence=0.73,
                        metadata={"favicon_hash": fhash}
                    )
                    hash_to_domains[fhash].append(domain_node.id)
                    break

        for fhash, domains in hash_to_domains.items():
            if len(domains) < 2:
                continue
            unique = sorted(set(domains))
            for i, d1 in enumerate(unique):
                for d2 in unique[i + 1:]:
                    graph.add_edge(
                        d1, d2,
                        BCDEEdgeType.FAVICON_CLUSTER, method, confidence=0.73,
                        metadata={"favicon_hash": fhash}
                    )


# ── MODULE 22: WILDCARD COVERAGE ──────────────────────────────────────────

class WildcardCoverageModule(IntelligenceModule):
    """
    Model wildcard certificate/DNS coverage relationships.
    FIX-04: Removed unsupported strip_wildcard kwarg from normalize_host().
            Wildcard prefix stripping now done inline.
    FIX-12: Hard cap of MAX_WILDCARD_COVERAGE_EDGES to prevent O(wildcards×domains).
    Confidence: 0.70
    """

    # FIX-12: Global edge cap for this module.
    MAX_WILDCARD_COVERAGE_EDGES: int = 10_000

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "wildcard_coverage"

        domain_nodes = list(graph.get_nodes_by_type(NodeType.DOMAIN))

        wildcards: List[str] = []
        for node in domain_nodes:
            if node.metadata.get("is_wildcard"):
                wildcards.append(node.id)

        # Also scan TLS cache for *.parent entries
        for hostname, cert_data in context.tls_cache.items():
            if not isinstance(cert_data, dict):
                continue
            for san in cert_data.get("san_list", []):
                if san.startswith("*."):
                    # FIX-04: strip wildcard prefix inline, not via kwarg
                    bare_raw = san[2:]  # e.g. "*.example.com" → "example.com"
                    bare = normalize_host(bare_raw)
                    if bare and bare not in wildcards:
                        wildcards.append(bare)

        edges_added = 0
        for wildcard_parent in sorted(wildcards):
            if edges_added >= self.MAX_WILDCARD_COVERAGE_EDGES:
                logger.debug(
                    f"WildcardCoverage: edge cap ({self.MAX_WILDCARD_COVERAGE_EDGES}) reached."
                )
                break
            suffix = f".{wildcard_parent}"
            for node in domain_nodes:
                if edges_added >= self.MAX_WILDCARD_COVERAGE_EDGES:
                    break
                if node.id.endswith(suffix) and node.id != wildcard_parent:
                    graph.add_edge(
                        wildcard_parent, node.id,
                        BCDEEdgeType.WILDCARD_COVERS, method, confidence=0.70,
                        metadata={"wildcard_pattern": f"*.{wildcard_parent}"}
                    )
                    edges_added += 1


# ======================================================
# SECTION 6 — VOLATILITY & RISK MODELING
# ======================================================

# ── MODULE 23: ENDPOINT VOLATILITY ───────────────────────────────────────

class EndpointVolatilityModule(IntelligenceModule):
    """
    Compute volatility score per endpoint from graph-observable signals.
    Tags high-volatility endpoints for increased monitoring frequency.
    Confidence: preserved from node.
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "volatility"
        vol_engine = VolatilityEngine()

        for node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            score = vol_engine.compute_volatility_score(node.id, graph)
            tier = vol_engine.classify_volatility(score)

            if score > 0.0:
                graph.add_node(
                    node.id, NodeType.DOMAIN, method,
                    confidence=node.confidence,
                    metadata={
                        "volatility_score": score,
                        "volatility_class": tier,
                        "ip_drift_score": vol_engine.compute_ip_drift_score(node.id, graph),
                        "cert_rotation_score": vol_engine.compute_cert_rotation_score(node.id, graph),
                        "redirect_volatility": vol_engine.compute_redirect_volatility(node.id, graph),
                    }
                )


# ── MODULE 24: MULTI-SOURCE CROSS VALIDATION ─────────────────────────────

class MultiSourceCrossValidationModule(IntelligenceModule):
    """
    Cross-validate domain discovery across independent source categories.
    Confidence: adjusted per validation class.
    """

    PASSIVE_SOURCES = frozenset({
        "tls_observation", "recursive_san", "ct_log",
        "dns_a_record", "dns_aaaa_record", "dns_cname",
        "dns_mx", "dns_ns", "reverse_dns", "passive_dns_unpaid",
        "spf_include", "dns_txt",
    })
    ACTIVE_SOURCES = frozenset({
        "port_scan", "http_probe", "banner", "tls_port_variant",
        "openapi", "http_crawl", "js_analysis", "tls_server_fingerprint",
    })
    SPECULATIVE_SOURCES = frozenset({"name_mutation", "search_engine"})

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "cross_validation"

        for node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            sources = node.all_sources
            passive_overlap = sources & self.PASSIVE_SOURCES
            active_overlap = sources & self.ACTIVE_SOURCES
            speculative_overlap = sources & self.SPECULATIVE_SOURCES

            if len(passive_overlap) >= 2 or (passive_overlap and active_overlap):
                validation_class = "confirmed"
                confidence_delta = +0.05
            elif passive_overlap or active_overlap:
                validation_class = "corroborated"
                confidence_delta = 0.0
            elif speculative_overlap and not passive_overlap and not active_overlap:
                validation_class = "speculative"
                confidence_delta = -0.15
            else:
                validation_class = "unclassified"
                confidence_delta = 0.0

            new_conf = min(1.0, max(0.0, node.confidence + confidence_delta))

            graph.add_node(
                node.id, NodeType.DOMAIN, method,
                confidence=new_conf,
                metadata={
                    "validation_class": validation_class,
                    "passive_sources": sorted(passive_overlap),
                    "active_sources": sorted(active_overlap),
                    "speculative_sources": sorted(speculative_overlap),
                    "source_category_count": sum([
                        bool(passive_overlap),
                        bool(active_overlap),
                        bool(speculative_overlap),
                    ]),
                }
            )


# ── MODULE 25: CONTROLLED RECURSIVE EXPANSION ────────────────────────────

class ControlledRecursiveExpansionModule(IntelligenceModule):
    """
    Depth-bounded recursive re-expansion of newly discovered subdomains.
    FIX-07: normalize_ip and AEdgeType are top-level imports — no per-iteration imports.
    Confidence: 0.75
    """

    MAX_DEPTH = 2
    MAX_NEW_DOMAINS = 200

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "recursive_expansion"

        resolved_domains: Set[str] = set()
        # FIX-07: AEdgeType is a top-level import now.
        for edge in graph.get_edges_by_type(AEdgeType.A_RECORD):
            resolved_domains.add(edge.src)
        for edge in graph.get_edges_by_type(AEdgeType.AAAA_RECORD):
            resolved_domains.add(edge.src)

        root = context.root_domain
        candidates = [
            node.id for node in graph.get_nodes_by_type(NodeType.DOMAIN)
            if (node.id.endswith(f".{root}") or node.id == root)
            and node.id not in resolved_domains
        ]

        new_count = 0
        queue = list(sorted(candidates))

        for depth in range(self.MAX_DEPTH):
            if context.should_stop():
                break
            if not queue or new_count >= self.MAX_NEW_DOMAINS:
                break
            next_queue: List[str] = []

            for domain in queue:
                if context.should_stop():
                    break
                if new_count >= self.MAX_NEW_DOMAINS:
                    break

                ips = safe_dns_query(domain, "A", timeout=5, cache=context.dns_cache)
                for ip_raw in ips:
                    # FIX-07: normalize_ip is a top-level import now.
                    ip = normalize_ip(ip_raw)
                    if ip:
                        graph.add_node(ip, NodeType.IP, method, confidence=0.75)
                        graph.add_edge(
                            domain, ip,
                            AEdgeType.A_RECORD, method, confidence=0.75
                        )

                cnames = safe_dns_query(domain, "CNAME", timeout=5, cache=context.dns_cache)
                for cname_raw in cnames:
                    cname = normalize_host(cname_raw)
                    if not cname or cname == domain:
                        continue
                    graph.add_node(
                        cname, NodeType.DOMAIN, method,
                        confidence=0.75,
                        metadata={"from_recursive_expansion": True, "expansion_depth": depth + 1}
                    )
                    graph.add_edge(
                        domain, cname,
                        AEdgeType.CNAME, method, confidence=0.75
                    )
                    if cname not in resolved_domains and cname.endswith(f".{root}"):
                        next_queue.append(cname)
                        new_count += 1

            queue = list(dict.fromkeys(next_queue))

        if new_count > 0:
            logger.debug(f"ControlledRecursiveExpansion: {new_count} new domains resolved")


# ======================================================
# SECTION 7 — CONFIDENCE & RECALIBRATION
# ======================================================

# ── MODULE 26: SIGNAL CONFLICT DETECTION ─────────────────────────────────

class SignalConflictDetectionModule(IntelligenceModule):
    """
    Detect contradictory signals across domain nodes.
    FIX-16: Removed unused `live_domains` set that was constructed but never consumed.
    Confidence penalty: -0.20 applied to conflicted nodes.
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "signal_conflict"
        conf_engine = ConfidenceEngine()

        # FIX-16: Removed dead-code live_domains set construction.
        for node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            if conf_engine.detect_conflicts(node, graph):
                graph.add_node(
                    node.id, NodeType.DOMAIN, method,
                    confidence=max(0.0, node.confidence - 0.20),
                    metadata={"signal_conflict": True, "conflict_penalty": 0.20}
                )


# ── MODULE 27: CERTIFICATE ISSUER CLUSTERING ─────────────────────────────
# FIX-02: Corrected module number comment from #23 → #27.

class CertificateIssuerClusteringModule(IntelligenceModule):
    """
    Cluster domains by certificate issuer.
    Detect issuer rotation (same domain, multiple issuers over time).
    Confidence: 0.68
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "issuer_cluster"

        issuer_to_domains: Dict[str, List[str]] = defaultdict(list)

        for node in graph.get_nodes_by_type(NodeType.DOMAIN):
            issuer = node.metadata.get("cert_issuer") or node.metadata.get("issuer")
            if issuer and issuer != "unknown":
                issuer_to_domains[issuer].append(node.id)

        for issuer, domains in issuer_to_domains.items():
            if len(domains) < 2:
                continue
            unique = sorted(set(domains))
            for i, d1 in enumerate(unique):
                for d2 in unique[i + 1:]:
                    graph.add_edge(
                        d1, d2,
                        BCDEEdgeType.ISSUER_CLUSTER, method, confidence=0.68,
                        metadata={"issuer_name": issuer}
                    )

        domain_issuers: Dict[str, Set[str]] = defaultdict(set)
        for issuer, domains in issuer_to_domains.items():
            for domain in domains:
                domain_issuers[domain].add(issuer)

        for domain, issuers in sorted(domain_issuers.items()):
            if len(issuers) > 1:
                graph.add_node(
                    domain, NodeType.DOMAIN, method,
                    confidence=0.68,
                    metadata={
                        "issuer_rotation": True,
                        "issuers_seen": sorted(issuers),
                    }
                )


# ── MODULE 28: RISK WEIGHTED EDGE ADJUSTMENT ─────────────────────────────

class RiskWeightedEdgeAdjustmentModule(IntelligenceModule):
    """
    Classify each domain node into a risk confidence tier based on its source methods.
    Enriches node metadata with risk_class for downstream Cortex consumption.
    """

    HIGH_CONF_METHODS = frozenset({
        "port_scan", "http_probe", "tls_observation", "recursive_san",
        "ct_log", "dns_a_record", "dns_aaaa_record", "tls_port_variant",
        "openapi", "banner",
    })
    MEDIUM_CONF_METHODS = frozenset({
        "shared_ip", "jarm", "cdn_edge", "http_signature",
        "tls_server_fingerprint", "favicon_cluster", "issuer_cluster",
        "response_cluster", "historical_revival",
    })
    LOW_CONF_METHODS = frozenset({
        "name_mutation", "ip_neighbor", "cloud_bucket", "k8s_pattern",
        "search_engine", "netblock", "recursive_expansion",
    })

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "risk_weighted_edge"

        for node in sorted(
            graph.get_nodes_by_type(NodeType.DOMAIN), key=lambda n: n.id
        ):
            sources = node.all_sources
            if sources & self.HIGH_CONF_METHODS:
                risk_class = "high_confidence"
            elif sources & self.MEDIUM_CONF_METHODS:
                risk_class = "medium_confidence"
            elif sources & self.LOW_CONF_METHODS:
                risk_class = "low_confidence"
            else:
                risk_class = "unclassified"

            graph.add_node(
                node.id, NodeType.DOMAIN, method,
                confidence=node.confidence,
                metadata={"risk_class": risk_class}
            )


# ── MODULE 29: CONFIDENCE RECALIBRATION (MUST BE LAST) ───────────────────

class ConfidenceRecalibrationModule(IntelligenceModule):
    """
    Graph-wide confidence recalibration pass.
    Applies boosts for active confirmation, structural richness.
    Applies penalties for speculative-only signals.
    Must run LAST.
    """

    def run(
        self, graph: PassiveDiscoveryGraph, context: BCDEExpansionContext
    ) -> None:
        method = "recalibrated"
        conf_engine = ConfidenceEngine()

        for node in graph.get_nodes_by_type(NodeType.DOMAIN):
            new_conf = conf_engine.compute_recalibrated_confidence(node, graph)
            if abs(new_conf - node.confidence) > 0.01:
                graph.add_node(
                    node.id, NodeType.DOMAIN, method,
                    confidence=new_conf,
                    metadata={"confidence_recalibrated": True}
                )


# ======================================================
# BCDE EXTRACTION LAYER
# ======================================================

def extract_bcde_candidates(
    graph: PassiveDiscoveryGraph,
    root_domain: str,
) -> List[EndpointCandidate]:
    """
    Extract EndpointCandidate list from enriched graph.

    Extraction boundary (strict):
    - NodeType.ENDPOINT  → explicit port+scheme endpoints (scheme://host:port)
    - NodeType.DOMAIN    → plain hostnames; port inferred from metadata
    - NodeType.IP, ASN, NETBLOCK, CERTIFICATE → excluded (never returned)

    Sorted: confidence DESC, host ASC (deterministic).
    Full metadata preserved for downstream Cortex consumption.
    """
    candidates = []

    for node in graph.get_nodes_by_type(NodeType.ENDPOINT):
        parsed = urlparse(node.id)
        scheme = parsed.scheme or "https"
        actual_host = parsed.hostname or ""
        actual_port = parsed.port or (443 if scheme == "https" else 80)
        if not actual_host:
            continue
        candidates.append(EndpointCandidate(
            host=actual_host,
            port=actual_port,
            scheme=scheme,
            source=node.first_seen_method,
            confidence=node.confidence,
            metadata={
                **node.metadata,
                "all_sources": list(node.all_sources),
                "historical": node.historical,
                "discovery_depth": node.discovery_depth,
                "inbound_edge_count": node.inbound_edge_count,
                "distinct_signal_types": node.distinct_signal_types,
                "is_explicit_endpoint": True,
            }
        ))

    for node in graph.get_nodes_by_type(NodeType.DOMAIN):
        host = node.id
        port = 443
        scheme = "https"

        if node.metadata.get("is_mail_server"):
            port = 25
            scheme = "smtp"

        candidates.append(EndpointCandidate(
            host=host,
            port=port,
            scheme=scheme,
            source=node.first_seen_method,
            confidence=node.confidence,
            metadata={
                **node.metadata,
                "all_sources": list(node.all_sources),
                "historical": node.historical,
                "discovery_depth": node.discovery_depth,
                "inbound_edge_count": node.inbound_edge_count,
                "distinct_signal_types": node.distinct_signal_types,
            }
        ))

    candidates.sort()
    return candidates


# ======================================================
# MAIN ENGINE
# ======================================================

class ExpansionCategoryBCDE:
    """
    External Attack Surface Construction Engine.
    Category BCDE — Fully Aggressive Enterprise ASM.

    Consumes PassiveDiscoveryGraph from Category A.
    Runs 29 modules in deterministic order.  ← FIX-24: was "24 modules"
    Returns enriched PassiveDiscoveryGraph.

    Usage:
        graph = ExpansionCategoryA().expand(root_domain)
        bcde_context = BCDEExpansionContext.from_category_a_context(context)
        graph = ExpansionCategoryBCDE().expand(graph, bcde_context)
        candidates = extract_bcde_candidates(graph, root_domain)
    """

    def __init__(self):
        self._modules: List[IntelligenceModule] = [
            # Section 1: Active Surface (9)
            CommonPortScanModule(),              #  1
            TLSPortVariantsModule(),             #  2
            BannerAnalysisModule(),              #  3
            HTTPProbeModule(),                   #  4
            HTTPCrawlModule(),                   #  5
            JSAnalysisModule(),                  #  6
            OpenAPIProbeModule(),                #  7
            HTTPResponseSignatureModule(),       #  8
            TLSServerFingerprintModule(),        #  9
            # Section 2: Infrastructure (5)
            IPNeighborExpansionModule(),         # 10  ← FIX-01
            NetblockExpansionModule(),           # 11
            SharedIPCorrelationModule(),         # 12
            JARMFingerprintModule(),             # 13
            CDNEdgeMappingModule(),              # 14
            # Section 3: Cloud & Platform (3)
            CloudBucketPatternsModule(),         # 15
            CloudFrontAnalysisModule(),          # 16
            K8sPatternModule(),                  # 17
            # Section 4: Historical & Revival (3)
            HistoricalRevivalModule(),           # 18
            ExpiredAssetDetectionModule(),       # 19
            OrphanedAssetDetectionModule(),      # 20
            # Section 5: Signature & Coverage (2)
            FaviconHashModule(),                 # 21
            WildcardCoverageModule(),            # 22
            # Section 6: Volatility & Risk (3)
            EndpointVolatilityModule(),          # 23
            MultiSourceCrossValidationModule(),  # 24
            ControlledRecursiveExpansionModule(), # 25
            # Section 7: Confidence & Recalibration (4) — run last
            SignalConflictDetectionModule(),     # 26
            CertificateIssuerClusteringModule(), # 27  ← FIX-02
            RiskWeightedEdgeAdjustmentModule(),  # 28
            ConfidenceRecalibrationModule(),     # 29 — MUST BE LAST
        ]

    def _resolve_modules(
        self,
        enabled_module_names: Optional[Set[str]] = None,
    ) -> List[IntelligenceModule]:
        if not enabled_module_names:
            return list(self._modules)
        allowed = {str(name).strip() for name in enabled_module_names if str(name).strip()}
        return [
            module
            for module in self._modules
            if module.__class__.__name__ in allowed
        ]

    # FIX-A5: Global expansion ceilings now live in BCDEExpansionContext
    # (max_total_nodes, max_total_edges, max_total_endpoints) and are enforced
    # inside expand(). The former class-level MAX_TOTAL_NODES constant is removed.

    def expand(
        self,
        graph: PassiveDiscoveryGraph,
        context: BCDEExpansionContext,
        validate_graph: bool = False,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> PassiveDiscoveryGraph:
        return self.run_modules(
            graph,
            context,
            validate_graph=validate_graph,
            progress_callback=progress_callback,
        )

    def run_modules(
        self,
        graph: PassiveDiscoveryGraph,
        context: BCDEExpansionContext,
        *,
        validate_graph: bool = False,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        enabled_module_names: Optional[Set[str]] = None,
        module_observer: Optional[Callable[[Dict[str, Any]], None]] = None,
        time_budget_seconds: Optional[int] = None,
        per_module_time_slice_seconds: Optional[int] = None,
        finalize_on_interrupt: bool = True,
        emit_completion_log: bool = True,
    ) -> PassiveDiscoveryGraph:
        """
        Enrich the PassiveDiscoveryGraph from Category A.
        Additive only — never deletes Category A signals.

        FIX-A1: BCDE confidence weights are merged into SignalConfidenceEngine only
                for the duration of this call and are not applied at import time,
                preventing hidden side effects on Category A's global engine.
        FIX-A5: Global expansion ceilings (max_total_nodes, max_total_edges,
                max_total_endpoints) are checked after every module. Expansion
                halts if any ceiling is reached, then ConfidenceRecalibration runs.
        FIX-A6: rate_controller is checked before each module (not just some modules)
                using a consistent allow_request() call pattern.
        FIX-03: ConfidenceRecalibrationModule is only run as an extra pass when the
                main loop exited early due to a ceiling hit. When the loop ran to
                completion, Module 29 already ran as the final iteration.
        """
        # FIX-A1: Scoped weight merge — apply BCDE weights for this expansion only.
        # Save originals so we can restore if caller needs Category A in its
        # original state after this call completes.
        _original_weights = dict(SignalConfidenceEngine.CONFIDENCE_WEIGHTS)
        SignalConfidenceEngine.CONFIDENCE_WEIGHTS.update(BCDE_CONFIDENCE_WEIGHTS)

        loop_completed = True  # FIX-03: track whether loop ran to completion
        selected_modules = self._resolve_modules(enabled_module_names)
        total_modules = len(selected_modules)
        phase_deadline_unix_ms = int(time.time() * 1000) + (
            max(
                1,
                int(time_budget_seconds if time_budget_seconds is not None else context.time_budget_seconds),
            )
            * 1000
        )
        phase_deadline_unix_ms = min(
            int(context.deadline_unix_ms or phase_deadline_unix_ms),
            phase_deadline_unix_ms,
        )

        def _emit_progress(module_name: str, completed_count: int) -> None:
            if progress_callback is None:
                return
            progress_callback(
                {
                    "expansion_active_category": "BCDE",
                    "expansion_current_module": module_name,
                    "expansion_modules_completed_count": int(completed_count),
                    "expansion_module_total_count": int(total_modules),
                    "expansion_node_count": len(graph.all_nodes()),
                    "expansion_edge_count": len(graph.all_edges()),
                    "expansion_graph_endpoint_count": len(
                        graph.get_nodes_by_type(NodeType.ENDPOINT)
                    ),
                }
            )

        def _observe_module(
            module_name: str,
            *,
            elapsed_s: float,
            new_domain_ids: Optional[List[str]] = None,
            new_endpoint_ids: Optional[List[str]] = None,
            runtime_stats: Optional[Dict[str, Any]] = None,
            status: str,
            skip_reason: Optional[str] = None,
            stop_reason: Optional[str] = None,
            error_message: Optional[str] = None,
            time_slice_exceeded: bool = False,
        ) -> None:
            if module_observer is None:
                return
            domain_ids = list(new_domain_ids or [])
            endpoint_ids = list(new_endpoint_ids or [])
            runtime_snapshot = dict(runtime_stats or {})
            endpoints_produced = int(runtime_snapshot.get("endpoints_produced", 0) or 0)
            elapsed = float(elapsed_s or 0.0)
            evidence_productive = any(
                int(runtime_snapshot.get(key, 0) or 0) > 0
                for key in (
                    "banners_captured",
                    "http_responses",
                    "pages_crawled",
                    "js_files_fetched",
                    "api_paths_discovered",
                    "schemas_found",
                )
            )
            surface_productive = bool(domain_ids or endpoint_ids)
            dependency_productive = (
                module_name in {"HTTPProbeModule", "HTTPCrawlModule", "JSAnalysisModule", "OpenAPIProbeModule"}
                and (
                    surface_productive
                    or int(runtime_snapshot.get("pages_crawled", 0) or 0) > 0
                    or int(runtime_snapshot.get("js_files_fetched", 0) or 0) > 0
                    or int(runtime_snapshot.get("schemas_found", 0) or 0) > 0
                )
            )
            historical_productive = (
                module_name in {"HistoricalRevivalModule", "ExpiredAssetRecaptureModule", "OrphanedServiceDetectionModule"}
                and surface_productive
            )
            productivity_classes = [
                name
                for name, enabled in (
                    ("surface_productive", surface_productive),
                    ("dependency_productive", dependency_productive),
                    ("evidence_productive", evidence_productive),
                    ("historical_productive", historical_productive),
                )
                if enabled
            ]
            payload: Dict[str, Any] = {
                "category": "BCDE",
                "module_name": module_name,
                "elapsed_s": elapsed,
                "new_domain_count": len(domain_ids),
                "new_endpoint_count": len(endpoint_ids),
                "new_candidate_count": len(domain_ids) + len(endpoint_ids),
                "productive": bool(productivity_classes),
                "status": str(status or "").strip() or "unknown",
                "new_domain_ids": domain_ids,
                "new_endpoint_ids": endpoint_ids,
                "hosts_attempted": int(runtime_snapshot.get("hosts_attempted", 0) or 0),
                "ports_attempted": int(runtime_snapshot.get("ports_attempted", 0) or 0),
                "endpoints_produced": endpoints_produced,
                "banners_captured": int(runtime_snapshot.get("banners_captured", 0) or 0),
                "http_responses": int(runtime_snapshot.get("http_responses", 0) or 0),
                "pages_crawled": int(runtime_snapshot.get("pages_crawled", 0) or 0),
                "js_files_fetched": int(runtime_snapshot.get("js_files_fetched", 0) or 0),
                "api_paths_discovered": int(runtime_snapshot.get("api_paths_discovered", 0) or 0),
                "schemas_found": int(runtime_snapshot.get("schemas_found", 0) or 0),
                "surface_productive": surface_productive,
                "dependency_productive": dependency_productive,
                "evidence_productive": evidence_productive,
                "historical_productive": historical_productive,
                "productivity_classes": productivity_classes,
                "time_slice_exceeded": bool(time_slice_exceeded),
                "time_per_produced_endpoint_s": (
                    round(elapsed / endpoints_produced, 3)
                    if endpoints_produced > 0
                    else 0.0
                ),
            }
            if skip_reason:
                payload["skip_reason"] = str(skip_reason).strip()
            if stop_reason:
                payload["stop_reason"] = str(stop_reason).strip()
            if error_message:
                payload["error_message"] = str(error_message).strip()
            module_observer(payload)

        try:
            for index, module in enumerate(selected_modules, start=1):
                module_name = module.__class__.__name__
                _emit_progress(module_name, index - 1)
                try:
                    now_ms = int(time.time() * 1000)
                    if now_ms >= phase_deadline_unix_ms:
                        logger.warning(
                            "BCDE time budget reached before module execution: "
                            f"{module_name}. Halting expansion early."
                        )
                        context.cancel_requested = True
                        _observe_module(
                            module_name,
                            elapsed_s=0.0,
                            status="interrupted",
                            stop_reason="phase_budget_exhausted",
                        )
                        loop_completed = False
                        break

                    # FIX-A6: Consistent rate_controller check before every module.
                    if context.rate_controller and hasattr(context.rate_controller, "allow_request"):
                        if not context.rate_controller.allow_request(
                            f"bcde:{context.root_domain}:{module_name}"
                        ):
                            logger.debug(f"Rate limited: {module_name} — skipping")
                            _observe_module(
                                module_name,
                                elapsed_s=0.0,
                                status="skipped",
                                skip_reason="rate_limited",
                            )
                            continue

                    pre_domain_ids = {
                        node.id for node in graph.get_nodes_by_type(NodeType.DOMAIN)
                    }
                    pre_endpoint_ids = {
                        node.id for node in graph.get_nodes_by_type(NodeType.ENDPOINT)
                    }
                    pre_runtime_stats = dict(
                        context.module_runtime_stats.get(module_name, {})
                    )
                    if per_module_time_slice_seconds is not None:
                        context.deadline_unix_ms = min(
                            phase_deadline_unix_ms,
                            now_ms + (max(1, int(per_module_time_slice_seconds)) * 1000),
                        )
                    else:
                        context.deadline_unix_ms = phase_deadline_unix_ms
                    context.cancel_requested = False
                    t0 = time.time()
                    module.run(graph, context)
                    elapsed = time.time() - t0
                    deadline_hit = bool(context.cancel_requested) or (
                        context.deadline_unix_ms is not None
                        and int(time.time() * 1000) >= int(context.deadline_unix_ms)
                    )
                    context.deadline_unix_ms = phase_deadline_unix_ms
                    context.cancel_requested = False
                    _emit_progress(module_name, index)

                    node_count = len(graph.all_nodes())
                    edge_count = len(graph.all_edges())
                    endpoint_count = len(graph.get_nodes_by_type(NodeType.ENDPOINT))
                    post_domain_ids = {
                        node.id for node in graph.get_nodes_by_type(NodeType.DOMAIN)
                    }
                    post_endpoint_ids = {
                        node.id for node in graph.get_nodes_by_type(NodeType.ENDPOINT)
                    }
                    post_runtime_stats = dict(
                        context.module_runtime_stats.get(module_name, {})
                    )
                    runtime_stats_delta = {
                        "hosts_attempted": max(
                            0,
                            int(post_runtime_stats.get("hosts_attempted", 0) or 0)
                            - int(pre_runtime_stats.get("hosts_attempted", 0) or 0),
                        ),
                        "ports_attempted": max(
                            0,
                            int(post_runtime_stats.get("ports_attempted", 0) or 0)
                            - int(pre_runtime_stats.get("ports_attempted", 0) or 0),
                        ),
                        "endpoints_produced": max(
                            0,
                            int(post_runtime_stats.get("endpoints_produced", 0) or 0)
                            - int(pre_runtime_stats.get("endpoints_produced", 0) or 0),
                        ),
                    }
                    new_domain_ids = sorted(post_domain_ids - pre_domain_ids)
                    new_endpoint_ids = sorted(post_endpoint_ids - pre_endpoint_ids)
                    exceeded_time_slice = (
                        per_module_time_slice_seconds is not None
                        and float(elapsed) > float(per_module_time_slice_seconds)
                    )

                    graph.record_timing(module_name, elapsed)
                    logger.debug(
                        f"{module_name}: {node_count} nodes, "
                        f"{edge_count} edges, "
                        f"{endpoint_count} endpoints ({elapsed:.2f}s)"
                    )

                    # FIX-A5: Enforce global expansion ceilings after each module.
                    ceiling_hit = None
                    if node_count >= context.max_total_nodes:
                        ceiling_hit = f"max_total_nodes ({context.max_total_nodes})"
                    elif edge_count >= context.max_total_edges:
                        ceiling_hit = f"max_total_edges ({context.max_total_edges})"
                    elif endpoint_count >= context.max_total_endpoints:
                        ceiling_hit = f"max_total_endpoints ({context.max_total_endpoints})"

                    if ceiling_hit:
                        logger.warning(
                            f"BCDE global ceiling hit: {ceiling_hit} reached "
                            f"after {module_name}. Halting expansion early. "
                            f"Running ConfidenceRecalibration before exit."
                        )
                        context.cancel_requested = True
                        _observe_module(
                            module_name,
                            elapsed_s=float(elapsed),
                            new_domain_ids=new_domain_ids,
                            new_endpoint_ids=new_endpoint_ids,
                            runtime_stats=runtime_stats_delta,
                            status="interrupted",
                            stop_reason="global_ceiling_hit",
                        )
                        loop_completed = False
                        break

                    if exceeded_time_slice:
                        logger.warning(
                            "BCDE module exceeded requested time slice: %s (%.2fs > %.2fs)",
                            module_name,
                            float(elapsed),
                            float(per_module_time_slice_seconds),
                        )
                    if deadline_hit:
                        logger.warning(
                            "BCDE module exhausted its deadline: %s",
                            module_name,
                        )
                    _observe_module(
                        module_name,
                        elapsed_s=float(elapsed),
                        new_domain_ids=new_domain_ids,
                        new_endpoint_ids=new_endpoint_ids,
                        runtime_stats=runtime_stats_delta,
                        status="interrupted" if (deadline_hit or exceeded_time_slice) else "completed",
                        time_slice_exceeded=exceeded_time_slice,
                        stop_reason=(
                            "module_time_slice_exhausted"
                            if exceeded_time_slice
                            else "module_deadline_exhausted"
                            if deadline_hit
                            else None
                        ),
                    )
                    if deadline_hit or exceeded_time_slice:
                        context.cancel_requested = True
                        loop_completed = False
                        break

                except Exception as e:
                    logger.error(f"BCDE Module {module_name} failed: {e}", exc_info=True)
                    _observe_module(
                        module_name,
                        elapsed_s=0.0,
                        status="failed",
                        error_message=str(e),
                    )
                    _emit_progress(module_name, index)
                    context.deadline_unix_ms = phase_deadline_unix_ms
                    context.cancel_requested = False
                    continue

        finally:
            # FIX-A1: Always restore original Category A weights, even on exception.
            SignalConfidenceEngine.CONFIDENCE_WEIGHTS.clear()
            SignalConfidenceEngine.CONFIDENCE_WEIGHTS.update(_original_weights)

        # FIX-03: Only run safety-net recalibration when the loop broke early.
        #         If loop_completed is True, Module 29 already ran as final iteration.
        runtime_state = context.module_state.setdefault("_bcde_runtime", {})
        if loop_completed and selected_modules and isinstance(
            selected_modules[-1],
            ConfidenceRecalibrationModule,
        ):
            runtime_state["final_recalibration_applied"] = True
        elif not loop_completed and finalize_on_interrupt:
            self.finalize_graph(
                graph,
                context,
                validate_graph=validate_graph,
                emit_completion_log=emit_completion_log,
            )
            return graph

        if validate_graph:
            issues = graph.validate()
            for issue in issues:
                logger.warning(f"BCDE graph validation: {issue}")

        if emit_completion_log:
            logger.info(
                f"BCDE expansion complete: "
                f"{len(graph.all_nodes())} nodes, "
                f"{len(graph.all_edges())} edges | "
                f"root={context.root_domain}"
            )

        return graph

    def finalize_graph(
        self,
        graph: PassiveDiscoveryGraph,
        context: BCDEExpansionContext,
        *,
        validate_graph: bool = False,
        emit_completion_log: bool = True,
    ) -> PassiveDiscoveryGraph:
        runtime_state = context.module_state.setdefault("_bcde_runtime", {})
        if not bool(runtime_state.get("final_recalibration_applied")):
            logger.info(
                "Finalizing BCDE graph with ConfidenceRecalibrationModule: "
                f"root={context.root_domain}"
            )
            original_weights = dict(SignalConfidenceEngine.CONFIDENCE_WEIGHTS)
            original_deadline = context.deadline_unix_ms
            original_cancel_requested = bool(context.cancel_requested)
            try:
                SignalConfidenceEngine.CONFIDENCE_WEIGHTS.update(
                    BCDE_CONFIDENCE_WEIGHTS
                )
                remaining_budget = ActiveProbeEngine.remaining_budget_seconds(
                    context,
                    reserve_seconds=0.0,
                )
                minimum_finalize_budget = 5.0
                if remaining_budget is None or remaining_budget <= 0.0:
                    remaining_budget = minimum_finalize_budget
                context.deadline_unix_ms = int(
                    time.time() * 1000
                    + (max(minimum_finalize_budget, remaining_budget) * 1000)
                )
                context.cancel_requested = False
                ConfidenceRecalibrationModule().run(graph, context)
                runtime_state["final_recalibration_applied"] = True
            except Exception as e:
                logger.error(
                    f"ConfidenceRecalibration final pass failed: {e}",
                    exc_info=True,
                )
            finally:
                SignalConfidenceEngine.CONFIDENCE_WEIGHTS.clear()
                SignalConfidenceEngine.CONFIDENCE_WEIGHTS.update(original_weights)
                context.deadline_unix_ms = original_deadline
                context.cancel_requested = original_cancel_requested

        if validate_graph:
            issues = graph.validate()
            for issue in issues:
                logger.warning(f"BCDE graph validation: {issue}")

        if emit_completion_log:
            logger.info(
                f"BCDE expansion complete: "
                f"{len(graph.all_nodes())} nodes, "
                f"{len(graph.all_edges())} edges | "
                f"root={context.root_domain}"
            )
        return graph

    def expand_and_extract(
        self,
        graph: PassiveDiscoveryGraph,
        context: BCDEExpansionContext,
        validate_graph: bool = False,
    ) -> List[EndpointCandidate]:
        """
        Convenience method: expand graph and return endpoint candidates.
        Runs all 29 modules then extracts candidates.  ← FIX-24: was "24 modules"
        Caps at context.max_results.
        """
        enriched_graph = self.expand(graph, context, validate_graph)
        candidates = extract_bcde_candidates(enriched_graph, context.root_domain)

        if len(candidates) > context.max_results:
            logger.warning(f"BCDE result cap reached ({context.max_results})")
            candidates = candidates[:context.max_results]

        return candidates


# ======================================================
# EXPORTS
# ======================================================

__all__ = [
    "ExpansionCategoryBCDE",
    "BCDEExpansionContext",
    "BCDEEdgeType",
  # FIX-A4: new edge type exported separately for clarity
    "extract_bcde_candidates",
    "ActiveProbeEngine",
    "SignatureEngine",
    "InfrastructureEngine",
    "CrawlEngine",
    "HistoricalEngine",
    "VolatilityEngine",
    "ConfidenceEngine",
    "CommonPortScanModule",
    "TLSPortVariantsModule",
    "BannerAnalysisModule",
    "HTTPProbeModule",
    "HTTPCrawlModule",
    "JSAnalysisModule",
    "OpenAPIProbeModule",
    "HTTPResponseSignatureModule",
    "TLSServerFingerprintModule",
    "IPNeighborExpansionModule",
    "NetblockExpansionModule",
    "SharedIPCorrelationModule",
    "JARMFingerprintModule",
    "CDNEdgeMappingModule",
    "CloudBucketPatternsModule",
    "CloudFrontAnalysisModule",
    "K8sPatternModule",
    "HistoricalRevivalModule",
    "ExpiredAssetDetectionModule",
    "OrphanedAssetDetectionModule",
    "FaviconHashModule",
    "WildcardCoverageModule",
    "EndpointVolatilityModule",
    "MultiSourceCrossValidationModule",
    "ControlledRecursiveExpansionModule",
    "SignalConflictDetectionModule",
    "CertificateIssuerClusteringModule",
    "RiskWeightedEdgeAdjustmentModule",
    "ConfidenceRecalibrationModule",
    "BCDE_CONFIDENCE_WEIGHTS",
    "get_bcde_confidence",
]

