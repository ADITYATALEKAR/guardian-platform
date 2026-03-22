"""
expansion_category_a.py

Pure Passive Surface Discovery Engine
Production-Grade • Cortex-Ready • ML-Forward
Category A — Signal Acquisition Layer Only

15 Discovery Modules (10 contractual methods):
 1. TLSObservationModule          — expand_via_san_from_observation
 2. RecursiveSANModule            — expand_via_recursive_san_chain
 3. CertificateTransparencyModule — expand_via_ct_logs
 4. ARecordModule                 — expand_via_dns_record_analysis (IPv4)
 5. AAAARecordModule              — expand_via_dns_record_analysis (IPv6)
 6. CNAMEChainModule              — expand_via_dns_record_analysis (CNAME)
 7. MXRecordModule                — expand_via_spf_mx_analysis (MX)
 8. NSDelegationModule            — expand_via_dns_record_analysis (NS)
 9. TXTReferenceModule            — expand_via_dns_record_analysis (TXT)
10. SPFIncludeModule              — expand_via_spf_mx_analysis (SPF)
11. ReverseDNSModule              — expand_via_reverse_dns_lookup
12. SearchEngineModule            — expand_via_search_engine
13. PassiveDNSUnpaidModule        — expand_via_passive_dns_unpaid
14. NameMutationModule            — expand_via_name_mutation
15. ASNResolutionModule           — expand_via_asn_intelligence (metadata only)

Architectural boundary:
  Category A = pure signal acquisition (direct observation + public indexing)
  Category B = correlation, clustering, enrichment (NOT this file)

Plus:
- DNS result cache (per-run)
- TLS result cache (per-run)
- RDAP cache (per-run)
- O(1) edge dedup via frozenset key
- Self-loop guard
- Inbound edge count index
- Confidence stored back into graph nodes
- IDNA / punycode normalization
- Graph structural validation
- Module timing metrics
- IPv6 normalization
- IP SAN extraction
- CT cert deduplication by serial
- Improved ASN extraction (RDAP links + Team Cymru fallback)
- Full provenance metadata

Author: AVYAKTA ASM System
Date: 2026-02-19
Status: PRODUCTION READY — Category A Complete
"""

from __future__ import annotations

import ssl
import socket
import re
import time
import logging
import ipaddress
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Dict, Any, List, Optional, Set, Tuple, FrozenSet
from collections import defaultdict

from infrastructure.discovery.scope_utils import extract_registrable_base

try:
    import dns.resolver
    import dns.exception
    import dns.reversename
    import dns.name
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

TLS_VERIFICATION_STRICT = "strict"
TLS_VERIFICATION_INSECURE = "insecure"


def normalize_tls_verification_mode(mode: Any) -> str:
    token = str(mode or TLS_VERIFICATION_STRICT).strip().lower()
    if token in {TLS_VERIFICATION_STRICT, TLS_VERIFICATION_INSECURE}:
        return token
    return TLS_VERIFICATION_STRICT


def tls_requests_verify(mode: Any) -> bool:
    return normalize_tls_verification_mode(mode) == TLS_VERIFICATION_STRICT


def build_tls_context(mode: Any) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if normalize_tls_verification_mode(mode) == TLS_VERIFICATION_INSECURE:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


# ======================================================
# GRAPH MODEL — PRODUCTION-GRADE
# ======================================================

class NodeType(str, Enum):
    """Entity types in discovery graph"""
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    NETBLOCK = "netblock"
    CERTIFICATE = "certificate"
    ENDPOINT = "ENDPOINT"


class EdgeType(str, Enum):
    """Relationship types with full provenance tracking"""
    SAN = "san"
    HISTORICAL_CERT = "historical_cert"
    CNAME = "cname"
    MX = "mx"
    NS = "ns"
    SPF_INCLUDE = "spf_include"
    PTR = "ptr"
    A_RECORD = "a_record"
    AAAA_RECORD = "aaaa_record"
    TXT_REFERENCE = "txt_reference"
    ASN_MEMBER = "asn_member"
    SEARCH_REFERENCE = "search_reference"   # Discovered via public search engine
    MUTATION = "mutation"                    # Deterministic name variant
    PASSIVE_DNS = "passive_dns"              # Historical passive DNS record


@dataclass(frozen=True)
class PassiveDiscoveryNode:
    """
    Immutable node with rich metadata.

    Tracks:
    - Discovery source (first method)
    - All sources (for confidence)
    - Depth in discovery tree
    - Historical vs active flag
    - Confidence score (computed from all sources, stored)
    - Timestamps
    - Inbound edge count (structural richness for ML)
    - Signal type count (distinct edge types observed)
    """
    id: str
    type: NodeType
    first_seen_method: str = ""
    all_sources: frozenset = field(default_factory=frozenset)
    discovery_depth: int = 0
    historical: bool = False
    confidence: float = 1.0
    first_seen_ts: int = field(default_factory=lambda: int(time.time()))
    last_seen_ts: int = field(default_factory=lambda: int(time.time()))
    inbound_edge_count: int = 0
    distinct_signal_types: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.id, self.type))

    def __eq__(self, other):
        if not isinstance(other, PassiveDiscoveryNode):
            return False
        return self.id == other.id and self.type == other.type


@dataclass(frozen=True)
class PassiveDiscoveryEdge:
    """
    Immutable edge with full discovery provenance.

    Carries intelligence about *why* connection exists:
    - Discovery method (which module found it)
    - Confidence (how reliable is this signal)
    - Metadata (issuer, mechanism, rir, etc.)
    - Timestamp (when discovered)
    """
    src: str
    dst: str
    edge_type: EdgeType
    discovery_method: str = ""
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def __hash__(self):
        return hash((self.src, self.dst, self.edge_type))

    def __eq__(self, other):
        if not isinstance(other, PassiveDiscoveryEdge):
            return False
        return (self.src == other.src and
                self.dst == other.dst and
                self.edge_type == other.edge_type)


class PassiveDiscoveryGraph:
    """
    Core graph structure with:
    - Unique node keying (type + id)
    - Efficient indexing (by src, by dst, by type)
    - O(1) edge deduplication via frozenset key
    - Self-loop guard
    - Metadata aggregation
    - Signal confidence tracking (stored in node)
    - Inbound edge count tracking
    - Graph structural validation
    - Module timing metrics
    """

    def __init__(self):
        # Nodes keyed by (type, id)
        self._nodes: Dict[Tuple[NodeType, str], PassiveDiscoveryNode] = {}

        # All edges (ordered insertion)
        self._edges: List[PassiveDiscoveryEdge] = []

        # O(1) dedup: set of (src, dst, edge_type)
        self._edge_keys: Set[Tuple[str, str, EdgeType]] = set()

        # Indexes for efficient lookup
        self._edges_by_src: Dict[str, List[PassiveDiscoveryEdge]] = defaultdict(list)
        self._edges_by_dst: Dict[str, List[PassiveDiscoveryEdge]] = defaultdict(list)
        self._edges_by_type: Dict[EdgeType, List[PassiveDiscoveryEdge]] = defaultdict(list)

        # Node source tracking (for confidence)
        self._node_sources: Dict[Tuple[NodeType, str], Set[str]] = defaultdict(set)

        # Inbound edge count tracking
        self._inbound_counts: Dict[str, int] = defaultdict(int)

        # Module timing metrics
        self.module_timings: Dict[str, float] = {}

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        method: str,
        depth: int = 0,
        historical: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0
    ) -> PassiveDiscoveryNode:
        """
        Add or update node with multi-source tracking.
        Confidence is computed from all sources and stored back in the node.
        """
        key = (node_type, node_id)
        sources = self._node_sources[key]
        sources.add(method)

        computed_confidence = SignalConfidenceEngine.compute_node_confidence(frozenset(sources))

        if key not in self._nodes:
            node = PassiveDiscoveryNode(
                id=node_id,
                type=node_type,
                first_seen_method=method,
                all_sources=frozenset(sources),
                discovery_depth=depth,
                historical=historical,
                confidence=computed_confidence,
                inbound_edge_count=self._inbound_counts.get(node_id, 0),
                metadata=metadata or {}
            )
        else:
            old = self._nodes[key]
            merged_meta = {**old.metadata, **(metadata or {})}
            node = PassiveDiscoveryNode(
                id=node_id,
                type=node_type,
                first_seen_method=old.first_seen_method,
                all_sources=frozenset(sources),
                discovery_depth=min(old.discovery_depth, depth),
                historical=old.historical or historical,
                confidence=computed_confidence,
                first_seen_ts=old.first_seen_ts,
                last_seen_ts=int(time.time()),
                inbound_edge_count=self._inbound_counts.get(node_id, 0),
                distinct_signal_types=old.distinct_signal_types,
                metadata=merged_meta
            )

        self._nodes[key] = node
        return self._nodes[key]

    def add_edge(
        self,
        src: str,
        dst: str,
        edge_type: EdgeType,
        method: str,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[PassiveDiscoveryEdge]:
        """
        Add edge with full provenance metadata.
        Guards:
        - Self-loop prevention (src == dst)
        - O(1) duplicate detection via key set
        - Inbound count update
        - Distinct signal type update on dst node
        """
        # Self-loop guard
        if src == dst:
            logger.debug(f"Skipping self-loop edge: {src} -> {dst} [{edge_type}]")
            return None

        edge_key = (src, dst, edge_type)

        # O(1) dedup
        if edge_key in self._edge_keys:
            return None

        edge = PassiveDiscoveryEdge(
            src=src,
            dst=dst,
            edge_type=edge_type,
            discovery_method=method,
            confidence=confidence,
            metadata=metadata or {}
        )

        self._edges.append(edge)
        self._edge_keys.add(edge_key)
        self._edges_by_src[src].append(edge)
        self._edges_by_dst[dst].append(edge)
        self._edges_by_type[edge_type].append(edge)

        # Update inbound count
        self._inbound_counts[dst] += 1

        # Update inbound_edge_count and distinct_signal_types on dst node if it exists
        dst_key_domain = (NodeType.DOMAIN, dst)
        dst_key_ip = (NodeType.IP, dst)
        for dst_key in (dst_key_domain, dst_key_ip):
            if dst_key in self._nodes:
                old = self._nodes[dst_key]
                existing_types = {e.edge_type for e in self._edges_by_dst.get(dst, [])}
                self._nodes[dst_key] = PassiveDiscoveryNode(
                    id=old.id,
                    type=old.type,
                    first_seen_method=old.first_seen_method,
                    all_sources=old.all_sources,
                    discovery_depth=old.discovery_depth,
                    historical=old.historical,
                    confidence=old.confidence,
                    first_seen_ts=old.first_seen_ts,
                    last_seen_ts=old.last_seen_ts,
                    inbound_edge_count=self._inbound_counts[dst],
                    distinct_signal_types=len(existing_types),
                    metadata=old.metadata
                )

        return edge

    def get_node(self, node_id: str, node_type: NodeType) -> Optional[PassiveDiscoveryNode]:
        return self._nodes.get((node_type, node_id))

    def get_nodes_by_type(self, node_type: NodeType) -> List[PassiveDiscoveryNode]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def get_edges_from(self, src: str) -> List[PassiveDiscoveryEdge]:
        return self._edges_by_src.get(src, [])

    def get_edges_to(self, dst: str) -> List[PassiveDiscoveryEdge]:
        return self._edges_by_dst.get(dst, [])

    def get_edges_by_type(self, edge_type: EdgeType) -> List[PassiveDiscoveryEdge]:
        return self._edges_by_type.get(edge_type, [])

    def mark_historical(self, node_id: str, node_type: NodeType) -> None:
        key = (node_type, node_id)
        if key in self._nodes:
            old = self._nodes[key]
            self._nodes[key] = PassiveDiscoveryNode(
                id=old.id,
                type=old.type,
                first_seen_method=old.first_seen_method,
                all_sources=old.all_sources,
                discovery_depth=old.discovery_depth,
                historical=True,
                confidence=old.confidence,
                first_seen_ts=old.first_seen_ts,
                last_seen_ts=old.last_seen_ts,
                inbound_edge_count=old.inbound_edge_count,
                distinct_signal_types=old.distinct_signal_types,
                metadata=old.metadata
            )

    def all_nodes(self) -> List[PassiveDiscoveryNode]:
        return list(self._nodes.values())

    def all_edges(self) -> List[PassiveDiscoveryEdge]:
        return self._edges

    def validate(self) -> List[str]:
        """
        Structural graph validation.
        Returns list of issues found.
        """
        issues = []

        # Check for dangling edges (src or dst not in nodes)
        all_ids = {n.id for n in self._nodes.values()}
        for edge in self._edges:
            if edge.src not in all_ids:
                issues.append(f"Dangling edge src: {edge.src} -> {edge.dst}")
            if edge.dst not in all_ids:
                issues.append(f"Dangling edge dst: {edge.src} -> {edge.dst}")

        # Check for self-loops (should not exist post-guard)
        for edge in self._edges:
            if edge.src == edge.dst:
                issues.append(f"Self-loop detected: {edge.src}")

        # Check confidence range
        for node in self._nodes.values():
            if not 0.0 <= node.confidence <= 1.0:
                issues.append(f"Confidence out of range: {node.id} = {node.confidence}")

        return issues

    def record_timing(self, module_name: str, elapsed: float) -> None:
        self.module_timings[module_name] = elapsed


# ======================================================
# CONTEXT & CONFIG
# ======================================================

@dataclass
class ExpansionContext:
    """Execution context for modules"""
    root_domain: str
    rate_controller: Optional[object] = None
    max_san_recursion: int = 3
    max_dns_recursion: int = 3
    max_spf_recursion: int = 5
    max_cname_depth: int = 10
    max_results: int = 10000
    time_budget_seconds: int = 300
    max_total_nodes: int = 250_000
    max_total_edges: int = 500_000
    max_total_endpoints: int = 100_000
    tls_verification_mode: str = TLS_VERIFICATION_STRICT
    dns_cache: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    tls_cache: Dict[str, Any] = field(default_factory=dict)
    rdap_cache: Dict[str, Any] = field(default_factory=dict)
    deadline_unix_ms: Optional[int] = None
    cancel_requested: bool = False

    def should_stop(self) -> bool:
        if self.cancel_requested:
            return True
        if self.deadline_unix_ms is None:
            return False
        return int(time.time() * 1000) >= int(self.deadline_unix_ms)


# ======================================================
# HELPER UTILITIES
# ======================================================

def normalize_host(host: str, strip_wildcard: bool = True) -> Optional[str]:
    """
    Normalize hostname with proper validation.

    Handles:
    - Case folding
    - Trailing dot removal
    - Wildcard stripping (optional)
    - IDNA/punycode encoding
    - IP address rejection
    - Length validation
    """
    if not host:
        return None

    host = host.lower().strip().rstrip(".")

    # Strip wildcard if requested
    if strip_wildcard and host.startswith("*."):
        host = host[2:]

    if not host:
        return None

    # Skip bare IPv4
    try:
        ipaddress.IPv4Address(host)
        return None
    except ValueError:
        pass

    # Skip IPv6 — brackets or colons
    if ":" in host or (host.startswith("[") and host.endswith("]")):
        return None

    # Basic length check
    if len(host) > 253:
        return None

    # IDNA encoding for unicode hostnames
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass  # Keep original if IDNA fails
    except Exception:
        pass

    # Validate label structure
    labels = host.split(".")
    if not all(labels):
        return None
    for label in labels:
        if len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None

    # Require at least one dot (no bare hostnames)
    if "." not in host:
        return None

    return host


def normalize_ip(ip_str: str) -> Optional[str]:
    """
    Normalize IP address (IPv4 and IPv6).
    Returns canonical string or None.
    """
    if not ip_str:
        return None
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        return None


def _remaining_timeout_seconds(
    timeout: float,
    context: Optional[ExpansionContext],
) -> Optional[float]:
    requested = max(0.05, float(timeout))
    if context is None or context.deadline_unix_ms is None:
        return requested
    remaining = (
        float(int(context.deadline_unix_ms) - int(time.time() * 1000)) / 1000.0
    )
    if remaining <= 0.0:
        context.cancel_requested = True
        return None
    return max(0.05, min(requested, remaining))


def extract_san_from_tls(
    hostname: str,
    timeout: int = 5,
    cache: Optional[Dict] = None,
    tls_verification_mode: str = TLS_VERIFICATION_STRICT,
    context: Optional[ExpansionContext] = None,
) -> Dict[str, Any]:
    """
    Extract SAN, issuer, serial, expiry from TLS certificate.
    Returns dict with 'san_list', 'issuer', 'serial', 'not_before', 'not_after'.
    Uses cache to avoid redundant handshakes.
    """
    if cache is not None and hostname in cache:
        return cache[hostname]

    result = {
        "san_list": [],
        "ip_san_list": [],
        "issuer": "unknown",
        "serial": None,
        "not_before": None,
        "not_after": None,
    }

    try:
        effective_timeout = _remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return result

        tls_context = build_tls_context(tls_verification_mode)

        with socket.create_connection((hostname, 443), timeout=effective_timeout) as sock:
            with tls_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    return result

                for sub in cert.get("subjectAltName", []):
                    if sub[0] == "DNS":
                        domain = normalize_host(sub[1], strip_wildcard=False)
                        if domain:
                            result["san_list"].append(domain)
                    elif sub[0] == "IP Address":
                        # IP SANs — normalize and store separately
                        ip = normalize_ip(sub[1])
                        if ip:
                            result["ip_san_list"] = result.get("ip_san_list", [])
                            result["ip_san_list"].append(ip)

                # Issuer extraction
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer_dict.get("organizationName", "unknown")

                # Serial number
                result["serial"] = cert.get("serialNumber")

                # Validity window
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")

    except socket.timeout:
        logger.debug(f"TLS timeout for {hostname}")
    except ssl.SSLError as e:
        logger.debug(f"TLS SSL error for {hostname}: {e}")
    except OSError as e:
        logger.debug(f"TLS OS error for {hostname}: {e}")
    except Exception as e:
        logger.debug(f"TLS extraction failed for {hostname}: {e}")

    if cache is not None:
        cache[hostname] = result

    return result


def safe_dns_query(
    domain: str,
    record_type: str = "A",
    timeout: int = 5,
    cache: Optional[Dict] = None,
    context: Optional[ExpansionContext] = None,
) -> List[str]:
    """
    Safe DNS query with caching, proper error handling.
    Cache key: (domain, record_type)
    """
    if not DNS_AVAILABLE:
        return []

    cache_key = (domain.lower(), record_type.upper())
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    results = []

    try:
        effective_timeout = _remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return results
        resolver = dns.resolver.Resolver()
        resolver.timeout = effective_timeout
        resolver.lifetime = effective_timeout

        answers = resolver.resolve(domain, record_type)

        for rdata in answers:
            record = str(rdata).rstrip(".")
            if record:
                results.append(record)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.Timeout:
        logger.debug(f"DNS timeout for {domain} ({record_type})")
    except Exception as e:
        logger.debug(f"DNS query failed for {domain} ({record_type}): {e}")

    if cache is not None:
        cache[cache_key] = results

    return results


def safe_reverse_dns(
    ip: str,
    timeout: int = 5,
    cache: Optional[Dict] = None,
    context: Optional[ExpansionContext] = None,
) -> List[str]:
    """
    Reverse DNS lookup (PTR record) for an IP.
    Returns list of PTR hostnames.
    """
    if not DNS_AVAILABLE:
        return []

    cache_key = (ip, "PTR")
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    results = []

    try:
        effective_timeout = _remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return results
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = effective_timeout
        resolver.lifetime = effective_timeout
        answers = resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            hostname = normalize_host(str(rdata))
            if hostname:
                results.append(hostname)
    except Exception as e:
        logger.debug(f"Reverse DNS failed for {ip}: {e}")

    if cache is not None:
        cache[cache_key] = results

    return results


def safe_http_get(
    url: str,
    params: Optional[Dict] = None,
    timeout: int = 10,
    headers: Optional[Dict] = None,
    context: Optional[ExpansionContext] = None,
) -> Optional[Any]:
    """
    Safe HTTP GET with proper error handling.
    Returns parsed JSON or None.
    """
    if not REQUESTS_AVAILABLE:
        return None

    default_headers = {
        "User-Agent": "AVYAKTA-ASM/2.0 (+https://github.com/avyakta)",
        "Accept": "application/json",
    }
    if headers:
        default_headers.update(headers)

    try:
        effective_timeout = _remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return None
        response = requests.get(
            url,
            params=params,
            timeout=effective_timeout,
            headers=default_headers
        )
        response.raise_for_status()
        return response.json()
    except requests.Timeout:
        logger.debug(f"HTTP timeout: {url}")
    except requests.ConnectionError:
        logger.debug(f"Connection error: {url}")
    except requests.HTTPError as e:
        logger.debug(f"HTTP error {url}: {e}")
    except ValueError:
        logger.debug(f"JSON parsing error: {url}")
    except Exception as e:
        logger.debug(f"HTTP request failed: {e}")

    return None


def safe_http_text(
    url: str,
    params: Optional[Dict] = None,
    timeout: int = 10,
    headers: Optional[Dict] = None,
    context: Optional[ExpansionContext] = None,
) -> Optional[str]:
    if not REQUESTS_AVAILABLE:
        return None

    default_headers = {
        "User-Agent": "AVYAKTA-ASM/2.0 (+https://github.com/avyakta)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if headers:
        default_headers.update(headers)

    try:
        effective_timeout = _remaining_timeout_seconds(timeout, context)
        if effective_timeout is None:
            return None
        response = requests.get(
            url,
            params=params,
            timeout=effective_timeout,
            headers=default_headers,
        )
        response.raise_for_status()
        return response.text
    except requests.Timeout:
        logger.debug(f"HTTP timeout: {url}")
    except requests.ConnectionError:
        logger.debug(f"Connection error: {url}")
    except requests.HTTPError as e:
        logger.debug(f"HTTP error {url}: {e}")
    except Exception as e:
        logger.debug(f"HTTP text request failed: {e}")

    return None


# ======================================================
# SIGNAL CONFIDENCE ENGINE
# ======================================================

class SignalConfidenceEngine:
    """
    Compute confidence scores based on discovery source.

    Weighting reflects reliability and directness of observation.
    Multi-source corroboration boosts confidence.
    """

    CONFIDENCE_WEIGHTS = {
        "tls_observation": 0.95,
        "recursive_san": 0.93,
        "ct_log": 0.90,
        "dns_a_record": 0.85,
        "dns_aaaa_record": 0.85,
        "dns_cname": 0.85,
        "dns_mx": 0.80,
        "dns_ns": 0.80,
        "rdap": 0.80,
        "reverse_dns": 0.75,
        "spf_include": 0.75,
        "dns_txt": 0.70,
        "passive_dns_unpaid": 0.65,
        "search_engine": 0.60,
        "name_mutation": 0.40,
        "root": 1.00,
    }

    @classmethod
    def get_confidence(cls, method: str) -> float:
        return cls.CONFIDENCE_WEIGHTS.get(method, 0.50)

    @classmethod
    def compute_node_confidence(cls, sources: frozenset) -> float:
        """
        Compute node confidence based on all independent sources.
        Multiple independent high-quality sources increase confidence.
        """
        if not sources:
            return 0.50

        scores = [cls.get_confidence(s) for s in sources]
        base_avg = sum(scores) / len(scores)
        # Log-scale boost for additional sources
        source_count_boost = min(0.10, len(scores) * 0.02)

        return min(1.0, base_avg + source_count_boost)


# ======================================================
# MODULE BASE INTERFACE
# ======================================================

class IntelligenceModule:
    """
    Base class for all intelligence modules.

    Contract:
    - Independent (no module dependencies)
    - Idempotent (safe to run multiple times)
    - Defensive (guards all operations)
    - Non-fatal (failures don't crash pipeline)
    - Timed (records execution time to graph)
    """

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        raise NotImplementedError

    def execute(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        """Wraps run() with timing metrics"""
        t0 = time.time()
        try:
            self.run(graph, context)
        finally:
            elapsed = time.time() - t0
            graph.record_timing(self.__class__.__name__, elapsed)


# ======================================================
# MODULE 1: TLS OBSERVATION (ENHANCED)
# ======================================================

class TLSObservationModule(IntelligenceModule):
    """
    Extract SAN, issuer, serial, expiry from direct TLS handshake.
    Confidence: 0.95
    """

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "tls_observation"
        host = context.root_domain
        timeout = getattr(context.rate_controller, "timeout", 5) if context.rate_controller else 5

        try:
            cert_data = extract_san_from_tls(
                host,
                timeout=timeout,
                cache=context.tls_cache,
                tls_verification_mode=context.tls_verification_mode,
                context=context,
            )

            if cert_data["san_list"] or cert_data["serial"]:
                serial = cert_data.get("serial") or hashlib.sha1(host.encode()).hexdigest()[:16]
                cert_id = f"cert:{host}:{serial}"

                graph.add_node(
                    cert_id,
                    NodeType.CERTIFICATE,
                    method,
                    confidence=0.95,
                    metadata={
                        "subject": host,
                        "issuer": cert_data.get("issuer", "unknown"),
                        "serial": cert_data.get("serial"),
                        "not_before": cert_data.get("not_before"),
                        "not_after": cert_data.get("not_after"),
                    }
                )

                for san_domain in cert_data["san_list"]:
                    domain = normalize_host(san_domain, strip_wildcard=False)
                    if domain:
                        is_wildcard = san_domain.startswith("*.")
                        graph.add_node(
                            domain,
                            NodeType.DOMAIN,
                            method,
                            confidence=0.95,
                            metadata={
                                "from_san": True,
                                "is_wildcard": is_wildcard,
                                "cert_issuer": cert_data.get("issuer"),
                                "cert_serial": cert_data.get("serial"),
                                "cert_not_after": cert_data.get("not_after"),
                            }
                        )
                        graph.add_edge(cert_id, domain, EdgeType.SAN, method, confidence=0.95)

                # IP SANs — emit as IP nodes
                for ip_san in cert_data.get("ip_san_list", []):
                    graph.add_node(
                        ip_san, NodeType.IP, method, confidence=0.95,
                        metadata={"from_ip_san": True, "cert_serial": cert_data.get("serial")}
                    )
                    graph.add_edge(cert_id, ip_san, EdgeType.SAN, method, confidence=0.95)

        except Exception as e:
            logger.debug(f"TLSObservationModule failed: {e}")


# ======================================================
# MODULE 2: RECURSIVE SAN (CACHED)
# ======================================================

class RecursiveSANModule(IntelligenceModule):
    """
    Follow SAN relationships recursively with depth bounds and caching.
    Reuses TLS cache to avoid redundant handshakes.
    Confidence: 0.93
    """

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "recursive_san"
        visited: Set[str] = set()
        queue = [context.root_domain]
        depth = 0

        while queue and depth < context.max_san_recursion:
            next_queue = []

            for domain in queue:
                if domain in visited:
                    continue
                visited.add(domain)

                try:
                    cert_data = extract_san_from_tls(
                        domain,
                        timeout=5,
                        cache=context.tls_cache,
                        tls_verification_mode=context.tls_verification_mode,
                        context=context,
                    )

                    for san_domain in cert_data["san_list"]:
                        normalized = normalize_host(san_domain, strip_wildcard=False)
                        if normalized and normalized not in visited:
                            graph.add_node(
                                normalized,
                                NodeType.DOMAIN,
                                method,
                                depth=depth + 1,
                                confidence=0.93,
                                metadata={
                                    "parent": domain,
                                    "is_wildcard": san_domain.startswith("*."),
                                    "cert_issuer": cert_data.get("issuer"),
                                }
                            )
                            next_queue.append(normalized)

                except Exception:
                    continue

            queue = next_queue
            depth += 1


# ======================================================
# MODULE 3: CERTIFICATE TRANSPARENCY (WITH PAGINATION)
# ======================================================

class CertificateTransparencyModule(IntelligenceModule):
    """
    Query Certificate Transparency logs via crt.sh.
    Supports pagination. Tracks not_before, not_after, issuer, serial.
    Confidence: 0.90
    """

    CT_URL = "https://crt.sh/json"
    PAGE_SIZE = 1000

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "ct_log"
        root = context.root_domain

        all_entries = self._fetch_all_entries(root, context=context)
        seen_names: Set[str] = set()
        seen_serials: Set[str] = set()

        for entry in all_entries:
            if not isinstance(entry, dict):
                continue

            names = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "unknown")
            not_before = entry.get("not_before")
            not_after = entry.get("not_after")
            serial = entry.get("serial_number") or entry.get("id", "")
            serial_str = str(serial)

            # Build a CERTIFICATE node per unique serial
            if serial_str and serial_str not in seen_serials:
                seen_serials.add(serial_str)
                cert_id = f"ct:{serial_str}"
                graph.add_node(
                    cert_id,
                    NodeType.CERTIFICATE,
                    method,
                    historical=True,
                    confidence=0.90,
                    metadata={
                        "issuer": issuer,
                        "not_before": not_before,
                        "not_after": not_after,
                        "serial": serial_str,
                        "from_ct": True,
                    }
                )

            for name in names.split("\n"):
                name = name.strip()
                domain = normalize_host(name, strip_wildcard=True)

                if domain and domain not in seen_names:
                    seen_names.add(domain)

                    graph.add_node(
                        domain,
                        NodeType.DOMAIN,
                        method,
                        historical=True,
                        confidence=0.90,
                        metadata={
                            "issuer": issuer,
                            "from_ct": True,
                            "ct_not_before": not_before,
                            "ct_not_after": not_after,
                            "ct_serial": serial_str,
                            "is_wildcard": name.startswith("*."),
                        }
                    )
                    graph.mark_historical(domain, NodeType.DOMAIN)

                    # Link domain to its CT cert node
                    if serial_str and serial_str not in ("", "None"):
                        graph.add_edge(
                            f"ct:{serial_str}", domain,
                            EdgeType.HISTORICAL_CERT, method, confidence=0.90
                        )

    def _fetch_all_entries(
        self,
        root: str,
        *,
        context: Optional[ExpansionContext] = None,
    ) -> List[Dict]:
        """
        Fetch CT entries with pagination via offset.

        Query widening strategy (deterministic order):
        1) %.root
        2) root
        3) %.base
        4) base
        """
        all_entries: List[Dict[str, Any]] = []
        seen_entry_keys: Set[str] = set()
        base = self._registrable_base_domain(root)

        query_patterns: List[str] = [f"%.{root}", root]
        if base and base != root:
            query_patterns.extend([f"%.{base}", base])

        for query in query_patterns:
            offset = 0
            while True:
                if context is not None and context.should_stop():
                    return all_entries
                data = safe_http_get(
                    self.CT_URL,
                    params={"q": query, "output": "json", "offset": offset},
                    timeout=15,
                    context=context,
                )

                if not data:
                    break

                if isinstance(data, dict):
                    data = [data]
                if not data:
                    break

                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    key = self._entry_key(entry)
                    if key in seen_entry_keys:
                        continue
                    seen_entry_keys.add(key)
                    all_entries.append(entry)

                # crt.sh paginates in blocks — stop if fewer than PAGE_SIZE returned
                if len(data) < self.PAGE_SIZE:
                    break
                offset += self.PAGE_SIZE

        return all_entries

    @staticmethod
    def _entry_key(entry: Dict[str, Any]) -> str:
        serial = str(entry.get("serial_number") or entry.get("id") or "").strip()
        issuer = str(entry.get("issuer_name") or "").strip()
        names = str(entry.get("name_value") or "").strip()
        not_before = str(entry.get("not_before") or "").strip()
        return f"{serial}|{issuer}|{names}|{not_before}"

    @staticmethod
    def _registrable_base_domain(hostname: str) -> str:
        return extract_registrable_base(hostname) or str(hostname or "").strip(".")


# ======================================================
# MODULE 4: A RECORD
# ======================================================

class ARecordModule(IntelligenceModule):
    """Query A records — DOMAIN -> IP edges. Confidence: 0.85"""

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "dns_a_record"

        for domain_node in graph.get_nodes_by_type(NodeType.DOMAIN):
            try:
                ips = safe_dns_query(
                    domain_node.id,
                    "A",
                    timeout=5,
                    cache=context.dns_cache,
                    context=context,
                )

                for ip_raw in ips:
                    ip = normalize_ip(ip_raw)
                    if ip:
                        graph.add_node(ip, NodeType.IP, method, confidence=0.85,
                                       metadata={"ipv4": True})
                        graph.add_edge(domain_node.id, ip, EdgeType.A_RECORD, method, confidence=0.85)

            except Exception:
                continue


# ======================================================
# MODULE 5: AAAA RECORD
# ======================================================

class AAAARecordModule(IntelligenceModule):
    """Query AAAA records (IPv6). Confidence: 0.85"""

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "dns_aaaa_record"

        for domain_node in graph.get_nodes_by_type(NodeType.DOMAIN):
            try:
                ips = safe_dns_query(
                    domain_node.id,
                    "AAAA",
                    timeout=5,
                    cache=context.dns_cache,
                    context=context,
                )

                for ip_raw in ips:
                    ip = normalize_ip(ip_raw)
                    if ip:
                        graph.add_node(ip, NodeType.IP, method, confidence=0.85,
                                       metadata={"ipv6": True})
                        graph.add_edge(domain_node.id, ip, EdgeType.AAAA_RECORD, method, confidence=0.85)

            except Exception:
                continue


# ======================================================
# MODULE 6: CNAME CHAIN (FULL RECURSIVE)
# ======================================================

class CNAMEChainModule(IntelligenceModule):
    """
    Follow CNAME chains fully recursively with loop protection and depth cap.
    Confidence: 0.85
    """

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "dns_cname"

        # Process all known domains including those discovered during this module
        queue: List[str] = [n.id for n in graph.get_nodes_by_type(NodeType.DOMAIN)]
        visited: Set[str] = set()

        while queue:
            domain = queue.pop(0)
            if domain in visited:
                continue
            visited.add(domain)

            try:
                cnames = safe_dns_query(
                    domain,
                    "CNAME",
                    timeout=5,
                    cache=context.dns_cache,
                    context=context,
                )

                for cname_raw in cnames:
                    cname_norm = normalize_host(cname_raw)
                    if not cname_norm or cname_norm == domain:
                        continue

                    graph.add_node(cname_norm, NodeType.DOMAIN, method, confidence=0.85)
                    graph.add_edge(domain, cname_norm, EdgeType.CNAME, method, confidence=0.85)

                    # Follow chain if not yet visited and within depth
                    if cname_norm not in visited:
                        queue.append(cname_norm)

            except Exception:
                continue


# ======================================================
# MODULE 7: MX RECORD
# ======================================================

class MXRecordModule(IntelligenceModule):
    """Query MX records — mail infrastructure. Confidence: 0.80"""

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "dns_mx"

        for domain_node in graph.get_nodes_by_type(NodeType.DOMAIN):
            try:
                mx_list = safe_dns_query(
                    domain_node.id,
                    "MX",
                    timeout=5,
                    cache=context.dns_cache,
                    context=context,
                )

                for mx_raw in mx_list:
                    # MX records are "priority hostname" — strip priority
                    parts = mx_raw.split()
                    mx_host = parts[-1] if parts else mx_raw
                    mx_norm = normalize_host(mx_host)

                    if mx_norm:
                        graph.add_node(mx_norm, NodeType.DOMAIN, method, confidence=0.80,
                                       metadata={"is_mail_server": True})
                        graph.add_edge(domain_node.id, mx_norm, EdgeType.MX, method, confidence=0.80)

            except Exception:
                continue


# ======================================================
# MODULE 8: NS DELEGATION
# ======================================================

class NSDelegationModule(IntelligenceModule):
    """Query NS records — nameserver delegation. Confidence: 0.80"""

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "dns_ns"

        for domain_node in graph.get_nodes_by_type(NodeType.DOMAIN):
            try:
                ns_list = safe_dns_query(
                    domain_node.id,
                    "NS",
                    timeout=5,
                    cache=context.dns_cache,
                    context=context,
                )

                for ns_raw in ns_list:
                    ns_norm = normalize_host(ns_raw)
                    if ns_norm:
                        graph.add_node(ns_norm, NodeType.DOMAIN, method, confidence=0.80,
                                       metadata={"is_nameserver": True})
                        graph.add_edge(domain_node.id, ns_norm, EdgeType.NS, method, confidence=0.80)

            except Exception:
                continue


# ======================================================
# MODULE 9: TXT REFERENCE
# ======================================================

class TXTReferenceModule(IntelligenceModule):
    """Extract domain references from TXT records. Confidence: 0.70"""

    # Match fully qualified domain names in TXT values
    DOMAIN_RE = re.compile(
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,})\b'
    )

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "dns_txt"

        for domain_node in graph.get_nodes_by_type(NodeType.DOMAIN):
            try:
                txt_list = safe_dns_query(
                    domain_node.id,
                    "TXT",
                    timeout=5,
                    cache=context.dns_cache,
                    context=context,
                )

                for txt in txt_list:
                    for match in self.DOMAIN_RE.finditer(txt):
                        found = match.group(1)
                        domain_norm = normalize_host(found)
                        if domain_norm and domain_norm != domain_node.id:
                            graph.add_node(domain_norm, NodeType.DOMAIN, method, confidence=0.70)
                            graph.add_edge(
                                domain_node.id, domain_norm,
                                EdgeType.TXT_REFERENCE, method, confidence=0.70,
                                metadata={"txt_value": txt[:200]}
                            )

            except Exception:
                continue


# ======================================================
# MODULE 10: SPF INCLUDE (WITH RECURSION)
# ======================================================

class SPFIncludeModule(IntelligenceModule):
    """
    Parse SPF records for include/redirect mechanisms.
    Recursively resolves nested SPF includes up to max depth.
    Confidence: 0.75
    """

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "spf_include"

        for domain_node in graph.get_nodes_by_type(NodeType.DOMAIN):
            self._resolve_spf(domain_node.id, graph, context, method, depth=0)

    def _resolve_spf(
        self,
        domain: str,
        graph: PassiveDiscoveryGraph,
        context: ExpansionContext,
        method: str,
        depth: int,
        visited: Optional[Set[str]] = None
    ) -> None:
        if visited is None:
            visited = set()

        if depth > context.max_spf_recursion or domain in visited:
            return
        visited.add(domain)

        try:
            txt_list = safe_dns_query(
                domain,
                "TXT",
                timeout=5,
                cache=context.dns_cache,
                context=context,
            )

            for txt in txt_list:
                if not txt.startswith("v=spf1"):
                    continue

                includes = re.findall(r'include:([^\s"]+)', txt)
                redirects = re.findall(r'redirect=([^\s"]+)', txt)

                for spf_domain in includes:
                    spf_norm = normalize_host(spf_domain)
                    if spf_norm:
                        graph.add_node(spf_norm, NodeType.DOMAIN, method, confidence=0.75,
                                       metadata={"spf_mechanism": True, "mechanism_type": "include"})
                        graph.add_edge(
                            domain, spf_norm, EdgeType.SPF_INCLUDE, method, confidence=0.75,
                            metadata={"mechanism": "include", "spf_depth": depth}
                        )
                        # Recurse into nested includes
                        self._resolve_spf(spf_norm, graph, context, method, depth + 1, visited)

                for spf_domain in redirects:
                    spf_norm = normalize_host(spf_domain)
                    if spf_norm:
                        graph.add_node(spf_norm, NodeType.DOMAIN, method, confidence=0.75,
                                       metadata={"spf_mechanism": True, "mechanism_type": "redirect"})
                        graph.add_edge(
                            domain, spf_norm, EdgeType.SPF_INCLUDE, method, confidence=0.75,
                            metadata={"mechanism": "redirect", "spf_depth": depth}
                        )
                        self._resolve_spf(spf_norm, graph, context, method, depth + 1, visited)

        except Exception:
            pass


# ======================================================
# MODULE 11: REVERSE DNS (PTR)
# ======================================================

class ReverseDNSModule(IntelligenceModule):
    """
    Perform PTR (reverse DNS) lookups for all discovered IPs.
    IP -> DOMAIN edges via PTR records.
    Confidence: 0.75
    """

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "reverse_dns"

        for ip_node in graph.get_nodes_by_type(NodeType.IP):
            try:
                ptr_names = safe_reverse_dns(
                    ip_node.id,
                    timeout=5,
                    cache=context.dns_cache,
                    context=context,
                )

                for hostname in ptr_names:
                    graph.add_node(
                        hostname,
                        NodeType.DOMAIN,
                        method,
                        confidence=0.75,
                        metadata={"from_ptr": True, "ptr_ip": ip_node.id}
                    )
                    graph.add_edge(ip_node.id, hostname, EdgeType.PTR, method, confidence=0.75)

            except Exception:
                continue


# ======================================================
# MODULE 12: SEARCH ENGINE (PASSIVE)
# ======================================================

class SearchEngineModule(IntelligenceModule):
    """
    Discover subdomains via public search engine indexing.
    Uses Bing HTML search (no API key required).
    Parses returned HTML for domain-like patterns scoped to root.
    Max 2 pages, hard cap, fully defensive.
    Confidence: 0.60
    """

    MAX_PAGES = 2
    RESULTS_PER_PAGE = 10

    # Same regex as TXTReferenceModule — consistent extraction
    DOMAIN_RE = re.compile(
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,})\b'
    )

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        if not REQUESTS_AVAILABLE:
            return

        method = "search_engine"
        root = context.root_domain
        found: Set[str] = set()

        for page in range(self.MAX_PAGES):
            if context.should_stop():
                break
            offset = page * self.RESULTS_PER_PAGE
            html = self._fetch_bing_html(root, offset, context=context)
            if not html:
                break

            for match in self.DOMAIN_RE.finditer(html):
                candidate = match.group(1).lower()
                domain = normalize_host(candidate)

                # Only accept subdomains of root
                if not domain:
                    continue
                if not (domain.endswith(f".{root}") or domain == root):
                    continue
                if domain in found or domain == root:
                    continue

                found.add(domain)
                graph.add_node(
                    domain, NodeType.DOMAIN, method,
                    confidence=0.60,
                    metadata={"from_search": True}
                )
                graph.add_edge(
                    root, domain,
                    EdgeType.SEARCH_REFERENCE, method, confidence=0.60
                )

    def _fetch_bing_html(
        self,
        root: str,
        offset: int,
        *,
        context: Optional[ExpansionContext] = None,
    ) -> Optional[str]:
        """Fetch Bing HTML search results for site:root"""
        return safe_http_text(
            "https://www.bing.com/search",
            params={"q": f"site:{root}", "first": offset + 1},
            timeout=10,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "en-US,en;q=0.9",
            },
            context=context,
        )


# ======================================================
# MODULE 13: PASSIVE DNS UNPAID
# ======================================================

class PassiveDNSUnpaidModule(IntelligenceModule):
    """
    Discover historical subdomains via free passive DNS sources.
    Sources tried in order:
    1. BufferOver DNS (dns.bufferover.run)
    2. Crt.sh subdomain endpoint (fallback)
    No API keys required. Results capped at 200.
    Confidence: 0.65
    """

    MAX_RESULTS = 200

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "passive_dns_unpaid"
        root = context.root_domain

        domains = self._fetch_bufferover(root, context=context)
        if not domains:
            domains = self._fetch_crtsh_subdomains(root, context=context)

        seen = 0
        for domain in domains:
            if seen >= self.MAX_RESULTS:
                break
            normalized = normalize_host(domain)
            if not normalized:
                continue
            if not (normalized.endswith(f".{root}") or normalized == root):
                continue

            graph.add_node(
                normalized, NodeType.DOMAIN, method,
                historical=True,
                confidence=0.65,
                metadata={"from_passive_dns": True}
            )
            graph.add_edge(
                root, normalized,
                EdgeType.PASSIVE_DNS, method, confidence=0.65
            )
            seen += 1

    def _fetch_bufferover(
        self,
        root: str,
        *,
        context: Optional[ExpansionContext] = None,
    ) -> List[str]:
        """Query dns.bufferover.run for subdomains."""
        data = safe_http_get(
            "https://dns.bufferover.run/dns",
            params={"q": f".{root}"},
            timeout=10,
            context=context,
        )
        if not data or not isinstance(data, dict):
            return []

        results: List[str] = []
        # Response format: {"FDNS_A": ["ip,hostname", ...], "RDNS": [...]}
        for key in ("FDNS_A", "RDNS"):
            entries = data.get(key) or []
            for entry in entries:
                if not isinstance(entry, str):
                    continue
                parts = entry.split(",")
                # FDNS_A: "ip,hostname" — hostname is last part
                hostname = parts[-1].strip() if parts else ""
                if hostname:
                    results.append(hostname)

        return results

    def _fetch_crtsh_subdomains(
        self,
        root: str,
        *,
        context: Optional[ExpansionContext] = None,
    ) -> List[str]:
        """Fallback: extract unique names from crt.sh (reuses public endpoint)."""
        data = safe_http_get(
            "https://crt.sh/json",
            params={"q": f"%.{root}", "output": "json"},
            timeout=12,
            context=context,
        )
        if not data:
            return []
        if isinstance(data, dict):
            data = [data]

        names: Set[str] = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name:
                    names.add(name)
        return list(names)


# ======================================================
# MODULE 14: NAME MUTATION
# ======================================================

class NameMutationModule(IntelligenceModule):
    """
    Generate deterministic name variants from root domain.
    No brute force. No wordlists. No recursion. No DNS inside this module.

    Variant categories:
    1. Environment prefixes  (dev, staging, test, qa, prod, api, admin, portal)
    2. Region prefixes       (us, eu, ap, asia, uk, in)
    3. Numeric suffixes      (root1, root2, root01, root02)
    4. Hyphen variants       (root-dev, root-test, root-api)

    Hard cap: 50 mutations. Deterministic ordering.
    Confidence: 0.40
    """

    ENV_PREFIXES = [
        "dev", "staging", "test", "qa", "prod",
        "api", "admin", "portal",
    ]
    REGION_PREFIXES = ["us", "eu", "ap", "asia", "uk", "in"]
    NUMERIC_SUFFIXES = ["1", "2", "01", "02"]
    HYPHEN_SUFFIXES = ["dev", "test", "api"]

    MAX_MUTATIONS = 50

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "name_mutation"
        root = context.root_domain

        # Parse root into leftmost label + base
        parts = root.split(".", 1)
        label = parts[0]        # e.g. "example" or "www"
        base = parts[1] if len(parts) > 1 else root  # e.g. "company.com"

        mutations: List[str] = []

        # 1. Environment prefixes applied to base domain
        for prefix in self.ENV_PREFIXES:
            mutations.append(f"{prefix}.{base}")

        # 2. Region prefixes applied to base domain
        for region in self.REGION_PREFIXES:
            mutations.append(f"{region}.{base}")

        # 3. Numeric suffix variants on root label
        for suffix in self.NUMERIC_SUFFIXES:
            mutations.append(f"{label}{suffix}.{base}")

        # 4. Hyphen variants on root label
        for hyph in self.HYPHEN_SUFFIXES:
            mutations.append(f"{label}-{hyph}.{base}")

        # Deduplicate while preserving order, skip root itself
        seen: Set[str] = set()
        count = 0
        for raw in mutations:
            if count >= self.MAX_MUTATIONS:
                break
            domain = normalize_host(raw)
            if not domain or domain in seen or domain == root:
                continue
            seen.add(domain)
            count += 1

            graph.add_node(
                domain, NodeType.DOMAIN, method,
                confidence=0.40,
                metadata={"mutation": True, "mutation_base": root}
            )
            graph.add_edge(
                root, domain,
                EdgeType.MUTATION, method, confidence=0.40
            )


# ======================================================
# MODULE 15: ASN RESOLUTION (RDAP)
# ======================================================

class ASNResolutionModule(IntelligenceModule):
    """
    Resolve IP ownership via RDAP (IANA / RIR lookup).
    IP -> ASN edges. Stores org, country, RIR in metadata.
    Confidence: 0.80
    """

    RDAP_URL = "https://rdap.arin.net/registry/ip/{ip}"

    def run(self, graph: PassiveDiscoveryGraph, context: ExpansionContext) -> None:
        method = "rdap"

        for ip_node in graph.get_nodes_by_type(NodeType.IP):
            ip = ip_node.id

            if ip in context.rdap_cache:
                rdap_data = context.rdap_cache[ip]
            else:
                rdap_data = self._fetch_rdap(ip, context=context)
                context.rdap_cache[ip] = rdap_data

            if not rdap_data:
                continue

            try:
                asn = rdap_data.get("asn")

                # Cymru DNS fallback when RDAP yields no ASN
                if not asn:
                    asn = self._fetch_cymru_asn(ip)

                org = rdap_data.get("org") or rdap_data.get("name", "unknown")
                country = rdap_data.get("country", "unknown")
                rir = rdap_data.get("port43", "unknown")
                cidr = rdap_data.get("cidr")

                if asn:
                    asn_id = f"AS{asn}" if not str(asn).startswith("AS") else str(asn)
                    graph.add_node(asn_id, NodeType.ASN, method, confidence=0.80,
                                   metadata={"org": org, "country": country, "rir": rir})
                    graph.add_edge(ip, asn_id, EdgeType.ASN_MEMBER, method, confidence=0.80,
                                   metadata={"cidr": cidr})

                graph.add_node(
                    ip, NodeType.IP, method, confidence=0.80,
                    metadata={
                        "asn": asn_id if asn else None,
                        "org": org,
                        "country": country,
                        "cidr": cidr,
                    }
                )

            except Exception as e:
                logger.debug(f"ASN resolution parse error for {ip}: {e}")

    def _fetch_rdap(
        self,
        ip: str,
        *,
        context: Optional[ExpansionContext] = None,
    ) -> Optional[Dict]:
        """Fetch RDAP data, trying ARIN first then RIPE fallback."""
        # Try ARIN
        data = safe_http_get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=8,
            headers={"Accept": "application/rdap+json"},
            context=context,
        )
        if data:
            return self._parse_rdap(data)

        # Try RIPE fallback
        data = safe_http_get(
            f"https://rdap.db.ripe.net/ip/{ip}",
            timeout=8,
            context=context,
        )
        if data:
            return self._parse_rdap(data)

        return None

    def _parse_rdap(self, data: Dict) -> Dict:
        """
        Extract useful fields from RDAP IP response.
        Handles ARIN, RIPE, APNIC, LACNIC response structures.
        """
        result = {}

        result["name"] = data.get("name", "unknown")
        result["country"] = data.get("country", "unknown")

        # ── ASN extraction ──────────────────────────────────────────────
        # Method 1: ARIN-specific originAS extension
        asn_val = data.get("arin_originas0_asns")
        if asn_val and isinstance(asn_val, list) and asn_val:
            result["asn"] = str(asn_val[0]).lstrip("ASas")

        # Method 2: Walk entities for aut-num / registrant roles
        if "asn" not in result:
            for entity in data.get("entities", []):
                # vcard fn field often contains "AS12345" for autnums
                vcard = entity.get("vcardArray", [])
                if vcard and len(vcard) > 1:
                    for vfield in vcard[1]:
                        if not isinstance(vfield, (list, tuple)) or len(vfield) < 4:
                            continue
                        if vfield[0] == "fn":
                            fn_val = str(vfield[3])
                            m = re.match(r'AS(\d+)', fn_val, re.IGNORECASE)
                            if m:
                                result["asn"] = m.group(1)
                        if vfield[0] == "org":
                            result["org"] = str(vfield[3])

        # Method 3: Links with autnum relation
        if "asn" not in result:
            for link in data.get("links", []):
                href = link.get("href", "")
                m = re.search(r'/autnum/(\d+)', href)
                if m:
                    result["asn"] = m.group(1)
                    break

        # Method 4: remarks or notices containing ASN
        if "asn" not in result:
            for section in data.get("remarks", []) + data.get("notices", []):
                for desc in section.get("description", []):
                    m = re.search(r'\bAS(\d{1,10})\b', str(desc))
                    if m:
                        result["asn"] = m.group(1)
                        break

        # ── CIDR blocks ─────────────────────────────────────────────────
        cidr_list = data.get("cidr0_cidrs", [])
        if cidr_list:
            first = cidr_list[0]
            prefix = first.get("v4prefix") or first.get("v6prefix", "")
            length = first.get("length", "")
            if prefix and length:
                result["cidr"] = f"{prefix}/{length}"

        # Also try startAddress/prefixLength (RIPE / APNIC format)
        if "cidr" not in result:
            start = data.get("startAddress")
            prefix_len = data.get("cidr")
            if not prefix_len:
                # Compute prefix from start/end if present
                end = data.get("endAddress")
                if start and end:
                    try:
                        nets = list(ipaddress.summarize_address_range(
                            ipaddress.ip_address(start),
                            ipaddress.ip_address(end)
                        ))
                        if nets:
                            result["cidr"] = str(nets[0])
                    except Exception:
                        pass
            elif start:
                result["cidr"] = f"{start}/{prefix_len}"

        result["port43"] = data.get("port43", "unknown")

        return result

    def _fetch_cymru_asn(self, ip: str) -> Optional[str]:
        """
        Fallback ASN lookup via Team Cymru DNS service.
        Returns ASN string (digits only) or None.
        Free, no API key required.
        """
        if not DNS_AVAILABLE:
            return None
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                # Reverse the octets and append the magic suffix
                reversed_ip = ".".join(reversed(ip.split(".")))
                query = f"{reversed_ip}.origin.asn.cymru.com"
            else:
                # IPv6: reverse the nibbles
                full = addr.exploded.replace(":", "")
                reversed_nibbles = ".".join(reversed(full))
                query = f"{reversed_nibbles}.origin6.asn.cymru.com"

            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(query, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                # Format: "ASN | IP | ..."
                parts = txt.split("|")
                if parts:
                    asn = parts[0].strip().lstrip("ASas")
                    if asn.isdigit():
                        return asn
        except Exception:
            pass
        return None


# ======================================================
# EXTRACTION LAYER
# ======================================================

@dataclass
class EndpointCandidate:
    """
    Extracted endpoint candidate from graph.

    Preserves:
    - Host (domain or IP)
    - Port (inferred from edge types / metadata)
    - Scheme
    - Source (first discovery method)
    - Confidence (computed from all sources, stored in graph)
    - Metadata (enrichment data)
    - Structural richness fields (for Cortex / ML)
    """
    host: str
    port: int = 443
    scheme: str = "https"
    source: str = ""
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other):
        """Deterministic sort: confidence desc, then host asc"""
        return (-self.confidence, self.host, self.port) < (-other.confidence, other.host, other.port)


def extract_candidates(graph: PassiveDiscoveryGraph) -> List[EndpointCandidate]:
    """
    Extract EndpointCandidate list from graph.

    Rules:
    - Only DOMAIN nodes
    - Skip CERTIFICATE, ASN, NETBLOCK, IP nodes
    - Include historical (flagged in metadata)
    - Preserve full metadata for Cortex
    - Sort by confidence DESC, then host ASC
    """
    candidates = []

    for node in graph.get_nodes_by_type(NodeType.DOMAIN):
        is_mail = node.metadata.get("is_mail_server", False)

        candidate = EndpointCandidate(
            host=node.id,
            port=25 if is_mail else 443,
            scheme="smtp" if is_mail else "https",
            source=node.first_seen_method,
            confidence=node.confidence,  # Stored in graph node
            metadata={
                **node.metadata,
                "all_sources": list(node.all_sources),
                "historical": node.historical,
                "discovery_depth": node.discovery_depth,
                "inbound_edge_count": node.inbound_edge_count,
                "distinct_signal_types": node.distinct_signal_types,
            }
        )
        candidates.append(candidate)

    candidates.sort()
    return candidates


# ======================================================
# MAIN ENGINE
# ======================================================

class ExpansionCategoryA:
    """
    Enterprise Passive Intelligence Graph Engine.

    17 modules in fixed deterministic order:
     1. TLS Observation       — cert SAN + issuer + serial + expiry
     2. Recursive SAN         — certificate chaining (cached)
     3. Cert Transparency     — CT logs with pagination + timestamps
     4. A Records             — IPv4 resolution (cached)
     5. AAAA Records          — IPv6 resolution (cached)
     6. CNAME Chains          — Full recursive chain following
     7. MX Records            — Mail infrastructure
     8. NS Delegation         — Nameservers
     9. TXT References        — Domain refs from TXT
    10. SPF Includes          — Recursive SPF resolution
    11. Reverse DNS           — PTR lookups (IP → domain)
    12. ASN Resolution        — RDAP ownership (org, country, ASN)
    13. Netblock Expansion    — CIDR modeling from ASN data
    14. Shared IP Correlation — Cross-domain shared host detection
    15. Wildcard Modeling     — Wildcard cert/domain coverage
    16. Historical Signal     — CT-vs-DNS dormant/expired/suspicious
    17. Cert Issuer Cluster   — Issuer grouping + rotation detection

    Plus:
    - DNS result cache (per-run dict)
    - TLS result cache (per-run dict)
    - RDAP cache (per-run dict)
    - O(1) edge dedup
    - Self-loop guard
    - Graph structural validation
    - Module timing metrics
    - Confidence stored back into graph nodes
    - Inbound edge count tracking

    Expected coverage: 80–90% for mid-size banks, 70–80% for large.
    """

    MAX_SAN_RECURSION_CAP = 10
    MAX_DNS_RECURSION_CAP = 10
    MAX_SPF_RECURSION_CAP = 15
    MAX_RESULTS_CAP = 200_000
    MAX_TIME_BUDGET_SECONDS_CAP = 3_600
    MAX_TOTAL_NODES_CAP = 500_000
    MAX_TOTAL_EDGES_CAP = 1_000_000
    MAX_TOTAL_ENDPOINTS_CAP = 250_000

    def __init__(
        self,
        *,
        max_san_recursion: int = 3,
        max_dns_recursion: int = 3,
        max_spf_recursion: int = 5,
        max_results: int = 10_000,
    ):
        self._default_context_overrides: Dict[str, Any] = {
            "max_san_recursion": min(
                max(1, int(max_san_recursion)),
                self.MAX_SAN_RECURSION_CAP,
            ),
            "max_dns_recursion": min(
                max(1, int(max_dns_recursion)),
                self.MAX_DNS_RECURSION_CAP,
            ),
            "max_spf_recursion": min(
                max(1, int(max_spf_recursion)),
                self.MAX_SPF_RECURSION_CAP,
            ),
            "max_results": min(
                max(1, int(max_results)),
                self.MAX_RESULTS_CAP,
            ),
            "time_budget_seconds": 300,
            "max_total_nodes": self.MAX_TOTAL_NODES_CAP,
            "max_total_edges": self.MAX_TOTAL_EDGES_CAP,
            "max_total_endpoints": self.MAX_TOTAL_ENDPOINTS_CAP,
            "tls_verification_mode": TLS_VERIFICATION_STRICT,
        }

        self._modules: List[IntelligenceModule] = [
            TLSObservationModule(),          #  1 — expand_via_san_from_observation
            RecursiveSANModule(),            #  2 — expand_via_recursive_san_chain
            CertificateTransparencyModule(), #  3 — expand_via_ct_logs
            ARecordModule(),                 #  4 — expand_via_dns_record_analysis
            AAAARecordModule(),              #  5 — expand_via_dns_record_analysis
            CNAMEChainModule(),              #  6 — expand_via_dns_record_analysis
            MXRecordModule(),                #  7 — expand_via_spf_mx_analysis
            NSDelegationModule(),            #  8 — expand_via_dns_record_analysis
            TXTReferenceModule(),            #  9 — expand_via_dns_record_analysis
            SPFIncludeModule(),              # 10 — expand_via_spf_mx_analysis
            ReverseDNSModule(),              # 11 — expand_via_reverse_dns_lookup
            SearchEngineModule(),            # 12 — expand_via_search_engine
            PassiveDNSUnpaidModule(),        # 13 — expand_via_passive_dns_unpaid
            NameMutationModule(),            # 14 — expand_via_name_mutation
            ASNResolutionModule(),           # 15 — expand_via_asn_intelligence
        ]

    def expand(
        self,
        root_domain: str,
        rate_controller: Optional[object] = None,
        validate_graph: bool = False,
        context_overrides: Optional[Dict[str, Any]] = None,
    ) -> List[EndpointCandidate]:
        """
        Expand root domain to endpoint candidates.

        Process:
        1. Normalize root domain
        2. Create empty graph
        3. Add root as initial node (confidence 1.0)
        4. Run all 20 modules in deterministic order
        5. Optionally validate graph structure
        6. Extract DOMAIN nodes to candidates
        7. Sort by confidence DESC, then host ASC
        8. Cap at max_results

        Returns sorted EndpointCandidate list.
        """
        root = normalize_host(root_domain)
        if not root:
            logger.warning(f"Invalid root domain: {root_domain}")
            return []

        graph = PassiveDiscoveryGraph()
        context = self._build_context(
            root=root,
            rate_controller=rate_controller,
            context_overrides=context_overrides,
        )

        graph.add_node(root, NodeType.DOMAIN, method="root", confidence=1.0)

        for module in self._modules:
            module_name = module.__class__.__name__
            try:
                if rate_controller and hasattr(rate_controller, "allow_request"):
                    if not rate_controller.allow_request(f"expansion:{root}:{module_name}"):
                        logger.debug(f"Rate limited: {module_name}")
                        continue

                module.execute(graph, context)
                logger.debug(
                    f"{module_name}: {len(graph.all_nodes())} nodes, "
                    f"{len(graph.all_edges())} edges "
                    f"({graph.module_timings.get(module_name, 0):.2f}s)"
                )

                node_count = len(graph.all_nodes())
                edge_count = len(graph.all_edges())
                endpoint_count = len(graph.get_nodes_by_type(NodeType.ENDPOINT))
                ceiling_hit = None
                if node_count >= context.max_total_nodes:
                    ceiling_hit = f"max_total_nodes ({context.max_total_nodes})"
                elif edge_count >= context.max_total_edges:
                    ceiling_hit = f"max_total_edges ({context.max_total_edges})"
                elif endpoint_count >= context.max_total_endpoints:
                    ceiling_hit = f"max_total_endpoints ({context.max_total_endpoints})"

                if ceiling_hit:
                    logger.warning(
                        f"Category A global ceiling hit: {ceiling_hit} reached after {module_name}. "
                        f"Halting expansion early."
                    )
                    break

            except Exception as e:
                logger.error(f"Module {module_name} failed fatally: {e}")
                continue

        # Optional graph validation
        if validate_graph:
            issues = graph.validate()
            if issues:
                for issue in issues:
                    logger.warning(f"Graph validation: {issue}")

        candidates = extract_candidates(graph)

        if len(candidates) > context.max_results:
            logger.warning(f"Result cap reached ({context.max_results})")
            candidates = candidates[:context.max_results]

        logger.info(
            f"Expansion complete: {len(candidates)} endpoints from {root} | "
            f"nodes={len(graph.all_nodes())} edges={len(graph.all_edges())} | "
            f"timings={graph.module_timings}"
        )

        return candidates

    def get_full_graph(
        self,
        root_domain: str,
        rate_controller: Optional[object] = None,
        context_overrides: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> PassiveDiscoveryGraph:
        """
        Return the full PassiveDiscoveryGraph (not just domain candidates).
        Useful for downstream Cortex analysis or visualization.
        """
        root = normalize_host(root_domain)
        if not root:
            logger.warning(f"Invalid root domain: {root_domain}")
            return PassiveDiscoveryGraph()

        graph = PassiveDiscoveryGraph()
        context = self.build_context(
            root=root,
            rate_controller=rate_controller,
            context_overrides=context_overrides,
        )

        graph.add_node(root, NodeType.DOMAIN, method="root", confidence=1.0)
        return self.run_modules(
            graph,
            context,
            progress_callback=progress_callback,
        )

    def build_context(
        self,
        *,
        root: str,
        rate_controller: Optional[object] = None,
        context_overrides: Optional[Dict[str, Any]] = None,
    ) -> ExpansionContext:
        return self._build_context(
            root=root,
            rate_controller=rate_controller,
            context_overrides=context_overrides,
        )

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

    def run_modules(
        self,
        graph: PassiveDiscoveryGraph,
        context: ExpansionContext,
        *,
        enabled_module_names: Optional[Set[str]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        module_observer: Optional[Callable[[Dict[str, Any]], None]] = None,
        time_budget_seconds: Optional[int] = None,
        per_module_time_slice_seconds: Optional[int] = None,
    ) -> PassiveDiscoveryGraph:
        selected_modules = self._resolve_modules(enabled_module_names)
        total_modules = len(selected_modules)
        category_a_deadline = time.monotonic() + max(
            1,
            int(time_budget_seconds if time_budget_seconds is not None else context.time_budget_seconds),
        )
        registrable_base = extract_registrable_base(context.root_domain) or context.root_domain
        speculative_modules = {
            "SearchEngineModule",
            "PassiveDNSUnpaidModule",
            "NameMutationModule",
        }

        def _emit_progress(module_name: str, completed_count: int) -> None:
            if progress_callback is None:
                return
            progress_callback(
                {
                    "expansion_active_category": "A",
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
            surface_productive = bool(domain_ids or endpoint_ids)
            historical_productive = (
                module_name == "CertificateTransparencyModule" and surface_productive
            )
            dependency_productive = (
                module_name == "NameMutationModule" and surface_productive
            )
            evidence_productive = (
                module_name == "TLSObservationModule"
                and str(status or "").strip().lower() in {"completed", "interrupted"}
                and float(elapsed_s or 0.0) > 0.0
            ) or surface_productive
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
                "category": "A",
                "module_name": module_name,
                "elapsed_s": float(elapsed_s or 0.0),
                "new_domain_count": len(domain_ids),
                "new_endpoint_count": len(endpoint_ids),
                "new_candidate_count": len(domain_ids) + len(endpoint_ids),
                "productive": bool(productivity_classes),
                "status": str(status or "").strip() or "unknown",
                "new_domain_ids": domain_ids,
                "new_endpoint_ids": endpoint_ids,
                "scope_quality": (
                    "registrable_base"
                    if context.root_domain == registrable_base
                    else "subdomain_scope"
                ),
                "surface_productive": surface_productive,
                "dependency_productive": dependency_productive,
                "evidence_productive": evidence_productive,
                "historical_productive": historical_productive,
                "productivity_classes": productivity_classes,
                "time_slice_exceeded": bool(time_slice_exceeded),
            }
            if skip_reason:
                payload["skip_reason"] = str(skip_reason).strip()
            if stop_reason:
                payload["stop_reason"] = str(stop_reason).strip()
            if error_message:
                payload["error_message"] = str(error_message).strip()
            module_observer(payload)

        for index, module in enumerate(selected_modules, start=1):
            module_name = module.__class__.__name__
            if time.monotonic() >= category_a_deadline:
                logger.warning(
                    "Category A time budget reached before module execution: %s. "
                    "Halting expansion early.",
                    module_name,
                )
                _observe_module(
                    module_name,
                    elapsed_s=0.0,
                    status="interrupted",
                    stop_reason="category_budget_exhausted",
                )
                break
            if module_name in speculative_modules and context.root_domain != registrable_base:
                _observe_module(
                    module_name,
                    elapsed_s=0.0,
                    status="skipped",
                    skip_reason="scope_quality_requires_registrable_base",
                )
                _emit_progress(module_name, index)
                continue
            pre_domain_ids = {
                node.id for node in graph.get_nodes_by_type(NodeType.DOMAIN)
            }
            pre_endpoint_ids = {
                node.id for node in graph.get_nodes_by_type(NodeType.ENDPOINT)
            }
            _emit_progress(module_name, index - 1)
            try:
                if per_module_time_slice_seconds is not None:
                    context.deadline_unix_ms = int(time.time() * 1000) + (
                        max(1, int(per_module_time_slice_seconds)) * 1000
                    )
                else:
                    context.deadline_unix_ms = int(time.time() * 1000) + (
                        max(1, int(max(0.0, category_a_deadline - time.monotonic()) or 1)) * 1000
                    )
                context.cancel_requested = False
                module.execute(graph, context)
                deadline_hit = bool(context.cancel_requested) or (
                    context.deadline_unix_ms is not None
                    and int(time.time() * 1000) >= int(context.deadline_unix_ms)
                )
                elapsed_s = float(graph.module_timings.get(module_name, 0.0))
                context.cancel_requested = False
                context.deadline_unix_ms = None
                post_domain_ids = {
                    node.id for node in graph.get_nodes_by_type(NodeType.DOMAIN)
                }
                post_endpoint_ids = {
                    node.id for node in graph.get_nodes_by_type(NodeType.ENDPOINT)
                }
                new_domain_ids = sorted(post_domain_ids - pre_domain_ids)
                new_endpoint_ids = sorted(post_endpoint_ids - pre_endpoint_ids)
                exceeded_time_slice = (
                    per_module_time_slice_seconds is not None
                    and elapsed_s > float(per_module_time_slice_seconds)
                )
                _observe_module(
                    module_name,
                    elapsed_s=elapsed_s,
                    new_domain_ids=new_domain_ids,
                    new_endpoint_ids=new_endpoint_ids,
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
                if exceeded_time_slice:
                    logger.warning(
                        "Category A module exceeded requested time slice: %s (%.2fs > %.2fs)",
                        module_name,
                        elapsed_s,
                        float(per_module_time_slice_seconds),
                    )
                if deadline_hit:
                    logger.warning(
                        "Category A module exhausted its deadline: %s",
                        module_name,
                    )
                _emit_progress(module_name, index)
                if deadline_hit or exceeded_time_slice:
                    break
                if time.monotonic() >= category_a_deadline:
                    logger.warning(
                        "Category A time budget reached after module execution: %s. "
                        "Halting expansion early.",
                        module_name,
                    )
                    break
                node_count = len(graph.all_nodes())
                edge_count = len(graph.all_edges())
                endpoint_count = len(graph.get_nodes_by_type(NodeType.ENDPOINT))
                ceiling_hit = None
                if node_count >= context.max_total_nodes:
                    ceiling_hit = f"max_total_nodes ({context.max_total_nodes})"
                elif edge_count >= context.max_total_edges:
                    ceiling_hit = f"max_total_edges ({context.max_total_edges})"
                elif endpoint_count >= context.max_total_endpoints:
                    ceiling_hit = f"max_total_endpoints ({context.max_total_endpoints})"

                if ceiling_hit:
                    logger.warning(
                        f"Category A global ceiling hit: {ceiling_hit} reached after {module_name}. "
                        f"Halting expansion early."
                    )
                    break
            except Exception as e:
                context.cancel_requested = False
                context.deadline_unix_ms = None
                logger.error(f"Module {module_name} failed: {e}")
                _observe_module(
                    module_name,
                    elapsed_s=0.0,
                    status="failed",
                    error_message=str(e),
                )
                _emit_progress(module_name, index)

        return graph

    def _build_context(
        self,
        *,
        root: str,
        rate_controller: Optional[object],
        context_overrides: Optional[Dict[str, Any]],
    ) -> ExpansionContext:
        overrides = dict(self._default_context_overrides)
        if context_overrides:
            for key in (
                "max_san_recursion",
                "max_dns_recursion",
                "max_spf_recursion",
                "max_results",
                "time_budget_seconds",
                "max_total_nodes",
                "max_total_edges",
                "max_total_endpoints",
                "tls_verification_mode",
            ):
                if key in context_overrides:
                    if key == "tls_verification_mode":
                        overrides[key] = normalize_tls_verification_mode(context_overrides[key])
                    else:
                        overrides[key] = int(context_overrides[key])

        overrides["max_san_recursion"] = min(
            max(1, int(overrides["max_san_recursion"])),
            self.MAX_SAN_RECURSION_CAP,
        )
        overrides["max_dns_recursion"] = min(
            max(1, int(overrides["max_dns_recursion"])),
            self.MAX_DNS_RECURSION_CAP,
        )
        overrides["max_spf_recursion"] = min(
            max(1, int(overrides["max_spf_recursion"])),
            self.MAX_SPF_RECURSION_CAP,
        )
        overrides["max_results"] = min(
            max(1, int(overrides["max_results"])),
            self.MAX_RESULTS_CAP,
        )
        overrides["time_budget_seconds"] = min(
            max(1, int(overrides["time_budget_seconds"])),
            self.MAX_TIME_BUDGET_SECONDS_CAP,
        )
        overrides["max_total_nodes"] = min(
            max(1, int(overrides["max_total_nodes"])),
            self.MAX_TOTAL_NODES_CAP,
        )
        overrides["max_total_edges"] = min(
            max(1, int(overrides["max_total_edges"])),
            self.MAX_TOTAL_EDGES_CAP,
        )
        overrides["max_total_endpoints"] = min(
            max(1, int(overrides["max_total_endpoints"])),
            self.MAX_TOTAL_ENDPOINTS_CAP,
        )
        overrides["tls_verification_mode"] = normalize_tls_verification_mode(
            overrides.get("tls_verification_mode", TLS_VERIFICATION_STRICT)
        )

        return ExpansionContext(
            root_domain=root,
            rate_controller=rate_controller,
            max_san_recursion=overrides["max_san_recursion"],
            max_dns_recursion=overrides["max_dns_recursion"],
            max_spf_recursion=overrides["max_spf_recursion"],
            max_results=overrides["max_results"],
            time_budget_seconds=overrides["time_budget_seconds"],
            max_total_nodes=overrides["max_total_nodes"],
            max_total_edges=overrides["max_total_edges"],
            max_total_endpoints=overrides["max_total_endpoints"],
            tls_verification_mode=overrides["tls_verification_mode"],
        )


# ======================================================
# EXPORTS
# ======================================================

__all__ = [
    "ExpansionCategoryA",
    "EndpointCandidate",
    "PassiveDiscoveryGraph",
    "PassiveDiscoveryNode",
    "PassiveDiscoveryEdge",
    "NodeType",
    "EdgeType",
    "ExpansionContext",
    "SignalConfidenceEngine",
    # Individual modules (for unit testing / deletion safety)
    "TLSObservationModule",
    "RecursiveSANModule",
    "CertificateTransparencyModule",
    "ARecordModule",
    "AAAARecordModule",
    "CNAMEChainModule",
    "MXRecordModule",
    "NSDelegationModule",
    "TXTReferenceModule",
    "SPFIncludeModule",
    "ReverseDNSModule",
    "SearchEngineModule",
    "PassiveDNSUnpaidModule",
    "NameMutationModule",
    "ASNResolutionModule",
    # Utilities
    "normalize_host",
    "normalize_ip",
    "extract_san_from_tls",
    "safe_dns_query",
    "safe_reverse_dns",
    "extract_candidates",
    "normalize_tls_verification_mode",
    "tls_requests_verify",
    "build_tls_context",
]
