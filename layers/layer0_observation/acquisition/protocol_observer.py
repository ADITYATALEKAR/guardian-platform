"""
protocol_observer.py

Layer 0 Acquisition — The Sensor

This module is the "stethoscope" that touches endpoints and measures their response.
It performs minimal, legal, protocol-level interactions and captures timing + structure.

What it does:
    - DNS resolution (measure timing, capture path)
    - TCP connect (measure RTT, detect load balancers)
    - TLS handshake (capture certificate, cipher, timing)
    - HTTP HEAD (optional, measure response timing)

What it does NOT do:
    - Send payloads or parameters
    - Attempt authentication
    - Fuzz or scan for vulnerabilities
    - Interpret or judge results
    - Make risk decisions

Output:
    RawObservation dict containing all measured physics data
    This dict is then converted by observation_bridge.py for the physics engine

Metaphor:
    A doctor's stethoscope — touches gently to hear, doesn't diagnose.

Legal basis:
    Same as Pingdom, BitSight, SecurityScorecard — protocol presence only.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from infrastructure.discovery.browser_fallback import (
    browser_request,
    should_attempt_browser_fallback,
)


# =============================================================================
# Constants
# =============================================================================

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_HTTP_PORT = 443
DNS_TIMEOUT_SECONDS = 5.0
MAX_RETRIES = 2
TLS_PREFERRED_PORTS = {443, 465, 8443, 9443, 993, 995}
PLAINTEXT_HTTP_PORTS = {80, 8000, 8080, 8888}
PLAINTEXT_BANNER_PORTS = {25, 110, 143, 587, 2525}

# TLS ClientHello configuration (browser-like)
PREFERRED_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
]

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class DNSObservation:
    """Raw DNS resolution measurements."""
    resolved_ip: Optional[str] = None
    resolution_time_ms: Optional[float] = None
    error: Optional[str] = None
    timestamp_ms: int = 0


@dataclass
class TCPObservation:
    """Raw TCP connection measurements."""
    connected: bool = False
    connect_time_ms: Optional[float] = None
    local_port: Optional[int] = None
    error: Optional[str] = None
    timestamp_ms: int = 0


@dataclass
class TLSObservation:
    """Raw TLS handshake measurements and certificate data."""
    handshake_time_ms: Optional[float] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_suites: List[str] = field(default_factory=list)
    cert_extension_hints: List[str] = field(default_factory=list)
    supported_groups: List[str] = field(default_factory=list)
    signature_algorithms: List[str] = field(default_factory=list)
    
    # Certificate fields (raw, no interpretation)
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_not_before: Optional[str] = None
    cert_not_after: Optional[str] = None
    cert_serial: Optional[str] = None
    cert_fingerprint_sha256: Optional[str] = None
    cert_san: List[str] = field(default_factory=list)
    cert_public_key_algorithm: Optional[str] = None
    cert_public_key_size_bits: Optional[int] = None
    cert_must_staple: Optional[bool] = None
    cert_ocsp_urls: List[str] = field(default_factory=list)

    # Protocol details
    alpn_protocol: Optional[str] = None
    session_resumed: bool = False
    sni_mismatch: Optional[bool] = None
    ocsp_stapled: Optional[bool] = None
    
    error: Optional[str] = None
    timestamp_ms: int = 0


@dataclass
class HTTPObservation:
    """Raw HTTP HEAD response measurements."""
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp_ms: int = 0


@dataclass
class RawObservation:
    """
    Complete raw observation from a single endpoint probe.
    
    This is the output of the protocol observer.
    Contains all measured physics data, no interpretation.
    """
    # Identity
    endpoint: str
    entity_id: str
    observation_id: str
    timestamp_ms: int
    
    # Component observations
    dns: DNSObservation = field(default_factory=DNSObservation)
    tcp: TCPObservation = field(default_factory=TCPObservation)
    tls: TLSObservation = field(default_factory=TLSObservation)
    http: Optional[HTTPObservation] = None
    
    # Timing series (for jitter calculation)
    packet_spacing_ms: List[float] = field(default_factory=list)

    # Aggregate RTT-like total (derived)
    rtt_ms: Optional[float] = None

    # Attempt/fallback metadata (best-effort)
    attempt_protocols: List[str] = field(default_factory=list)
    attempt_path: str = ""
    attempt_count: int = 0
    
    # Meta
    probe_duration_ms: float = 0.0
    success: bool = False
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "endpoint": self.endpoint,
            "entity_id": self.entity_id,
            "observation_id": self.observation_id,
            "timestamp_ms": self.timestamp_ms,
            "dns": {
                "resolved_ip": self.dns.resolved_ip,
                "resolution_time_ms": self.dns.resolution_time_ms,
                "error": self.dns.error,
            },
            "tcp": {
                "connected": self.tcp.connected,
                "connect_time_ms": self.tcp.connect_time_ms,
                "error": self.tcp.error,
            },
            "tls": {
                "handshake_time_ms": self.tls.handshake_time_ms,
                "tls_version": self.tls.tls_version,
                "cipher_suite": self.tls.cipher_suite,
                "cipher_suites": self.tls.cipher_suites,
                "cert_extension_hints": self.tls.cert_extension_hints,
                "supported_groups": self.tls.supported_groups,
                "signature_algorithms": self.tls.signature_algorithms,
                "cert_subject": self.tls.cert_subject,
                "cert_issuer": self.tls.cert_issuer,
                "cert_not_before": self.tls.cert_not_before,
                "cert_not_after": self.tls.cert_not_after,
                "cert_serial": self.tls.cert_serial,
                "cert_fingerprint_sha256": self.tls.cert_fingerprint_sha256,
                "cert_san": self.tls.cert_san,
                "cert_public_key_algorithm": self.tls.cert_public_key_algorithm,
                "cert_public_key_size_bits": self.tls.cert_public_key_size_bits,
                "cert_must_staple": self.tls.cert_must_staple,
                "cert_ocsp_urls": self.tls.cert_ocsp_urls,
                "alpn_protocol": self.tls.alpn_protocol,
                "session_resumed": self.tls.session_resumed,
                "sni_mismatch": self.tls.sni_mismatch,
                "ocsp_stapled": self.tls.ocsp_stapled,
                "error": self.tls.error,
            },
            "http": {
                "status_code": self.http.status_code if self.http else None,
                "response_time_ms": self.http.response_time_ms if self.http else None,
                "headers": self.http.headers if self.http else {},
                "error": self.http.error if self.http else None,
            } if self.http else None,
            "packet_spacing_ms": self.packet_spacing_ms,
            "rtt_ms": self.rtt_ms,
            "attempt_protocols": self.attempt_protocols,
            "attempt_path": self.attempt_path,
            "attempt_count": self.attempt_count,
            "probe_duration_ms": self.probe_duration_ms,
            "success": self.success,
            "error": self.error,
        }


@dataclass
class ObservationSeries:
    """
    Aggregated multi-sample observation series for a single endpoint.
    """
    endpoint: str
    entity_id: str
    observations: List[RawObservation]
    timestamps_ms: List[int]
    rtt_ms: List[float]
    dns_time_ms: List[float]
    tcp_time_ms: List[float]
    tls_time_ms: List[float]
    packet_spacing_ms: List[float]
    per_sample_timeout_s: float
    max_window_ms: int
    max_window_hit: bool
    early_stop: bool
    elapsed_ms: int


# =============================================================================
# Helper Functions
# =============================================================================

def _now_ms() -> int:
    """Current time in milliseconds since epoch."""
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _generate_observation_id(endpoint: str, timestamp_ms: int) -> str:
    """Generate deterministic observation ID."""
    raw = f"{endpoint}:{timestamp_ms}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _generate_entity_id(hostname: str, port: int) -> str:
    """
    Canonical entity ID for Layer 0.

    Requirement: hostname:port (stable, deterministic).
    """
    host = (hostname or "").strip().lower()
    p = int(port) if port else DEFAULT_HTTP_PORT
    return f"{host}:{p}"


def _parse_endpoint(endpoint: str) -> Tuple[str, int]:
    """
    Parse endpoint into hostname and port.
    
    Accepts:
        - "example.com" -> ("example.com", 443)
        - "example.com:8443" -> ("example.com", 8443)
        - "https://example.com" -> ("example.com", 443)
        - "https://example.com:8443" -> ("example.com", 8443)
    """
    if "://" in endpoint:
        parsed = urlparse(endpoint)
        hostname = parsed.hostname or ""
        port = parsed.port or DEFAULT_HTTP_PORT
    else:
        if ":" in endpoint:
            parts = endpoint.rsplit(":", 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = DEFAULT_HTTP_PORT
        else:
            hostname = endpoint
            port = DEFAULT_HTTP_PORT
    
    return hostname.strip(), port


def _extract_public_key_info(cert_der: bytes) -> Dict[str, Any]:
    """
    Best-effort certificate public key + extension extraction.
    Returns unknown fields when cryptography is unavailable.
    """
    result: Dict[str, Any] = {
        "key_algorithm": None,
        "key_size_bits": None,
        "must_staple": None,
        "ocsp_urls": [],
    }
    if not cert_der or not CRYPTO_AVAILABLE:
        return result

    try:
        cert = x509.load_der_x509_certificate(cert_der)
        key = cert.public_key()

        if isinstance(key, rsa.RSAPublicKey):
            result["key_algorithm"] = "RSA"
            result["key_size_bits"] = int(key.key_size)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            curve = getattr(key, "curve", None)
            curve_name = getattr(curve, "name", "EC")
            result["key_algorithm"] = f"ECDSA_{str(curve_name).upper()}"
            result["key_size_bits"] = int(key.key_size)
        elif isinstance(key, ed25519.Ed25519PublicKey):
            result["key_algorithm"] = "ED25519"
            result["key_size_bits"] = 256
        elif isinstance(key, ed448.Ed448PublicKey):
            result["key_algorithm"] = "ED448"
            result["key_size_bits"] = 448
        else:
            result["key_algorithm"] = key.__class__.__name__.upper()
            result["key_size_bits"] = int(getattr(key, "key_size", 0) or 0) or None

        # Must-Staple is represented by TLSFeature extension with status_request.
        try:
            tls_feature = cert.extensions.get_extension_for_class(x509.TLSFeature)
            features = set(tls_feature.value)
            result["must_staple"] = x509.TLSFeatureType.status_request in features
        except Exception:
            result["must_staple"] = None

        # OCSP URLs from Authority Information Access.
        ocsp_urls: List[str] = []
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in aia.value:
                if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(str(desc.access_location.value))
        except Exception:
            pass
        result["ocsp_urls"] = sorted(set(ocsp_urls))
    except Exception:
        return result

    return result


# =============================================================================
# DNS Observation
# =============================================================================

def observe_dns(hostname: str, timeout: float = DNS_TIMEOUT_SECONDS) -> DNSObservation:
    """
    Resolve hostname and measure timing.
    
    This is the first "poke" — asking the DNS system where the endpoint lives.
    """
    obs = DNSObservation(timestamp_ms=_now_ms())
    
    try:
        start = time.perf_counter()
        
        # Set socket timeout for DNS
        socket.setdefaulttimeout(timeout)
        
        # Resolve hostname
        ip = socket.gethostbyname(hostname)
        
        end = time.perf_counter()
        
        obs.resolved_ip = ip
        obs.resolution_time_ms = (end - start) * 1000
        
    except socket.gaierror as e:
        obs.error = f"DNS resolution failed: {e}"
    except socket.timeout:
        obs.error = "DNS resolution timed out"
    except Exception as e:
        obs.error = f"DNS error: {type(e).__name__}: {str(e)[:100]}"
    
    return obs


# =============================================================================
# TCP Observation
# =============================================================================

def observe_tcp(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> Tuple[TCPObservation, Optional[socket.socket]]:
    """
    Establish TCP connection and measure timing.
    
    Returns the observation and the socket (if successful) for TLS use.
    """
    obs = TCPObservation(timestamp_ms=_now_ms())
    sock = None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start = time.perf_counter()
        sock.connect((ip, port))
        end = time.perf_counter()
        
        obs.connected = True
        obs.connect_time_ms = (end - start) * 1000
        obs.local_port = sock.getsockname()[1]
        
        return obs, sock
        
    except socket.timeout:
        obs.error = "TCP connection timed out"
    except ConnectionRefusedError:
        obs.error = "Connection refused"
    except OSError as e:
        obs.error = f"TCP error: {e}"
    except Exception as e:
        obs.error = f"TCP error: {type(e).__name__}: {str(e)[:100]}"
    
    if sock:
        try:
            sock.close()
        except Exception:
            pass
    
    return obs, None


# =============================================================================
# TLS Observation
# =============================================================================

def observe_tls(
    sock: socket.socket,
    hostname: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> TLSObservation:
    """
    Perform TLS handshake and capture certificate + protocol details.
    
    This is the core observation — reveals cryptographic health.
    """
    obs = TLSObservation(timestamp_ms=_now_ms())
    
    try:
        # Create SSL context (browser-like)
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Set ALPN protocols (HTTP/2 and HTTP/1.1)
        context.set_alpn_protocols(["h2", "http/1.1"])
        
        start = time.perf_counter()
        
        # Wrap socket with TLS
        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
        
        end = time.perf_counter()
        
        obs.handshake_time_ms = (end - start) * 1000
        
        # Get TLS version
        obs.tls_version = ssl_sock.version()
        
        # Get cipher suite
        cipher_info = ssl_sock.cipher()
        if cipher_info:
            obs.cipher_suite = cipher_info[0]
        try:
            shared = ssl_sock.shared_ciphers()
            if shared:
                obs.cipher_suites = [c[0] for c in shared if c and c[0]]
        except Exception:
            obs.cipher_suites = []
        
        # Get ALPN protocol
        obs.alpn_protocol = ssl_sock.selected_alpn_protocol()
        
        # Get certificate
        cert = ssl_sock.getpeercert()
        if cert:
            # Subject
            subject = cert.get("subject", ())
            if subject:
                subject_parts = []
                for rdn in subject:
                    for key, value in rdn:
                        subject_parts.append(f"{key}={value}")
                obs.cert_subject = ", ".join(subject_parts)
            
            # Issuer
            issuer = cert.get("issuer", ())
            if issuer:
                issuer_parts = []
                for rdn in issuer:
                    for key, value in rdn:
                        issuer_parts.append(f"{key}={value}")
                obs.cert_issuer = ", ".join(issuer_parts)
            
            # Validity dates
            obs.cert_not_before = cert.get("notBefore")
            obs.cert_not_after = cert.get("notAfter")
            
            # Serial number
            obs.cert_serial = str(cert.get("serialNumber", ""))
            
            # Subject Alternative Names
            san = cert.get("subjectAltName", ())
            obs.cert_san = [value for (key, value) in san if key == "DNS"]
            if hostname and obs.cert_san:
                host_l = hostname.lower().strip()
                matches = any(
                    host_l == san_name.lower().strip()
                    or (
                        san_name.startswith("*.")
                        and host_l.endswith(san_name[1:].lower())
                    )
                    for san_name in obs.cert_san
                )
                obs.sni_mismatch = not matches
            elif hostname and not obs.cert_san:
                obs.sni_mismatch = None

            # Best-available extension hints from cert fields
            ext_keys = []
            for k in (
                "subjectAltName",
                "issuerAltName",
                "crlDistributionPoints",
                "authorityInfoAccess",
                "ocsp",
                "caIssuers",
                "OCSP",
                "caIssuers",
            ):
                if k in cert:
                    ext_keys.append(k)
            obs.cert_extension_hints = ext_keys

        # Get certificate fingerprint (binary cert)
        cert_der = ssl_sock.getpeercert(binary_form=True)
        if cert_der:
            obs.cert_fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
            pk_info = _extract_public_key_info(cert_der)
            obs.cert_public_key_algorithm = pk_info.get("key_algorithm")
            obs.cert_public_key_size_bits = pk_info.get("key_size_bits")
            obs.cert_must_staple = pk_info.get("must_staple")
            obs.cert_ocsp_urls = pk_info.get("ocsp_urls", [])

        # Python may expose OCSP stapled response on some builds.
        try:
            ocsp_response = getattr(ssl_sock, "ocsp_response", None)
            if isinstance(ocsp_response, (bytes, bytearray)):
                obs.ocsp_stapled = len(ocsp_response) > 0
        except Exception:
            obs.ocsp_stapled = None
        
        # Check if session was resumed
        # Note: Python's ssl module doesn't expose this directly
        # We'd need to check session ID, but this is a best-effort flag
        obs.session_resumed = False
        
        ssl_sock.close()
        
    except ssl.SSLCertVerificationError as e:
        obs.error = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        obs.error = f"TLS error: {e}"
    except socket.timeout:
        obs.error = "TLS handshake timed out"
    except Exception as e:
        obs.error = f"TLS error: {type(e).__name__}: {str(e)[:100]}"
    
    return obs


# =============================================================================
# HTTP Observation (Optional)
# =============================================================================

def observe_http_head(
    hostname: str,
    port: int = DEFAULT_HTTP_PORT,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    use_tls: bool = True,
    request_headers: Optional[Dict[str, str]] = None,
) -> HTTPObservation:
    """
    Send HTTP HEAD request and measure response.
    
    This is optional — provides additional timing data.
    Uses a fresh connection to measure full round-trip.
    """
    obs = HTTPObservation(timestamp_ms=_now_ms())
    
    try:
        import http.client
        
        start = time.perf_counter()
        
        if use_tls:
            conn = http.client.HTTPSConnection(hostname, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(hostname, port, timeout=timeout)

        headers = dict(request_headers or {})
        headers.setdefault("User-Agent", "AVYAKTA-Observer/1.0")
        headers.setdefault("Accept", "*/*")
        headers.setdefault("Connection", "close")

        conn.request("HEAD", "/", headers=headers)
        response = conn.getresponse()
        
        end = time.perf_counter()
        
        obs.status_code = response.status
        obs.response_time_ms = (end - start) * 1000
        
        # Capture bounded full header map for posture extraction.
        all_headers = response.getheaders() or []
        for key, value in all_headers[:128]:
            k = str(key or "").strip().lower()
            if not k:
                continue
            v = str(value or "").strip()[:512]
            obs.headers[k] = v
        if should_attempt_browser_fallback(
            status_code=obs.status_code,
            headers=obs.headers,
        ):
            scheme = "https" if use_tls else "http"
            fallback = browser_request(
                method="HEAD",
                url=f"{scheme}://{hostname}:{port}/",
                timeout=timeout,
                headers=headers,
                allow_redirects=False,
                verify=use_tls,
            )
            if fallback is not None:
                obs.status_code = int(fallback.get("status", 0) or 0) or obs.status_code
                obs.headers = {
                    str(key or "").strip().lower(): str(value or "").strip()[:512]
                    for key, value in dict(fallback.get("headers", {}) or {}).items()
                    if str(key or "").strip()
                }

        conn.close()

    except Exception as e:
        obs.error = f"HTTP error: {type(e).__name__}: {str(e)[:100]}"
        scheme = "https" if use_tls else "http"
        fallback = browser_request(
            method="HEAD",
            url=f"{scheme}://{hostname}:{port}/",
            timeout=timeout,
            headers=dict(request_headers or {}),
            allow_redirects=False,
            verify=use_tls,
        )
        if fallback is not None:
            obs.error = None
            obs.status_code = int(fallback.get("status", 0) or 0) or None
            obs.headers = {
                str(key or "").strip().lower(): str(value or "").strip()[:512]
                for key, value in dict(fallback.get("headers", {}) or {}).items()
                if str(key or "").strip()
            }

    return obs


# =============================================================================
# Main Observer Function
# =============================================================================

def observe_endpoint(
    endpoint: str,
    include_http: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    retries: int = MAX_RETRIES
) -> RawObservation:
    """
    Perform complete observation of an endpoint.
    
    This is the main entry point — touches the endpoint and measures everything.
    
    Args:
        endpoint: URL or hostname to observe (e.g., "www.jpmorgan.com")
        include_http: Whether to include HTTP HEAD request
        timeout: Timeout for each operation in seconds
        retries: Number of retries on failure
    
    Returns:
        RawObservation containing all measured physics data
    """
    probe_start = time.perf_counter()
    timestamp_ms = _now_ms()
    
    hostname, port = _parse_endpoint(endpoint)
    entity_id = _generate_entity_id(hostname, port)
    observation_id = _generate_observation_id(endpoint, timestamp_ms)
    canonical_endpoint = f"{hostname}:{port}"

    obs = RawObservation(
        endpoint=canonical_endpoint,
        entity_id=entity_id,
        observation_id=observation_id,
        timestamp_ms=timestamp_ms,
    )
    
    timing_points: List[float] = []
    
    # --- DNS ---
    obs.attempt_protocols.append("dns")
    timing_points.append(time.perf_counter())
    obs.dns = observe_dns(hostname, timeout=timeout)
    timing_points.append(time.perf_counter())
    
    if obs.dns.error or not obs.dns.resolved_ip:
        obs.error = obs.dns.error or "DNS resolution failed"
        obs.probe_duration_ms = (time.perf_counter() - probe_start) * 1000
        obs.attempt_count = len(obs.attempt_protocols)
        obs.attempt_path = ">".join(obs.attempt_protocols)
        return obs
    
    # --- TCP ---
    obs.attempt_protocols.append("tcp")
    timing_points.append(time.perf_counter())
    obs.tcp, sock = observe_tcp(obs.dns.resolved_ip, port, timeout=timeout)
    timing_points.append(time.perf_counter())
    
    if obs.tcp.error or not sock:
        obs.error = obs.tcp.error or "TCP connection failed"
        obs.probe_duration_ms = (time.perf_counter() - probe_start) * 1000
        obs.attempt_count = len(obs.attempt_protocols)
        obs.attempt_path = ">".join(obs.attempt_protocols)
        return obs
    
    # --- Protocol-specific follow-up ---
    # "success" means we made a live protocol contact with the endpoint.
    # TLS success is richer than TCP-only contact, but TCP reachability on
    # non-TLS ports (or a TLS handshake failure on a reachable 443 host)
    # should still be preserved as evidence rather than discarded.
    if port in TLS_PREFERRED_PORTS:
        obs.attempt_protocols.append("tls")
        timing_points.append(time.perf_counter())
        obs.tls = observe_tls(sock, hostname, timeout=timeout)
        timing_points.append(time.perf_counter())

        if obs.tls.error:
            obs.error = obs.tls.error
        elif include_http:
            obs.attempt_protocols.append("http_head")
            timing_points.append(time.perf_counter())
            browser_headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Connection": "close",
            }
            obs.http = observe_http_head(
                hostname,
                port,
                timeout=timeout,
                request_headers=browser_headers,
            )
            timing_points.append(time.perf_counter())
            if obs.http and obs.http.error:
                obs.error = obs.http.error
    elif port in PLAINTEXT_HTTP_PORTS and include_http:
        obs.attempt_protocols.append("http_head")
        timing_points.append(time.perf_counter())
        browser_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "close",
        }
        obs.http = observe_http_head(
            hostname,
            port,
            timeout=timeout,
            request_headers=browser_headers,
        )
        timing_points.append(time.perf_counter())
        if obs.http and obs.http.error:
            obs.error = obs.http.error
    elif port in PLAINTEXT_BANNER_PORTS:
        # TCP reachability on banner-oriented ports is still meaningful contact.
        # Leave obs.error empty here unless TCP itself failed.
        pass

    # --- Calculate packet spacing for jitter ---
    if len(timing_points) >= 2:
        for i in range(1, len(timing_points)):
            spacing_ms = (timing_points[i] - timing_points[i - 1]) * 1000
            obs.packet_spacing_ms.append(spacing_ms)
    
    # --- Success ---
    obs.success = True
    obs.probe_duration_ms = (time.perf_counter() - probe_start) * 1000
    obs.attempt_count = len(obs.attempt_protocols)
    obs.attempt_path = ">".join(obs.attempt_protocols)
    # Aggregate RTT-like total time for Layer 0 series usage
    rtt_parts = [
        obs.dns.resolution_time_ms if obs.dns else None,
        obs.tcp.connect_time_ms if obs.tcp else None,
        obs.tls.handshake_time_ms if obs.tls else None,
        obs.http.response_time_ms if obs.http else None,
    ]
    obs.rtt_ms = sum(v for v in rtt_parts if isinstance(v, (int, float)))

    return obs


def observe_endpoint_series(
    endpoint: str,
    *,
    samples: int = 12,
    include_http: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    inter_sample_sleep_ms: int = 0,
    max_window_ms: int = 15000,
    variance_min_samples: int = 6,
    variance_rel_eps: float = 0.10,
    variance_stable_samples: int = 2,
) -> ObservationSeries:
    """
    Collect multiple observations for a single endpoint to build time-series data.

    Returns a list of RawObservation objects (length <= samples).
    """
    observations: List[RawObservation] = []

    # Canonicalize once for stable entity_id/endpoint
    hostname, port = _parse_endpoint(endpoint)
    canonical_endpoint = f"{hostname}:{port}"

    start_ms = _now_ms()
    target_samples = max(1, int(samples))

    # Cap per-sample timeout so N does not multiply worst-case duration
    per_sample_budget_s = max(0.5, min(float(timeout), max_window_ms / max(1, target_samples) / 1000.0))

    rtt_series_local: List[float] = []
    stable_hits = 0

    max_window_hit = False
    early_stop = False

    for _ in range(target_samples):
        elapsed_ms = _now_ms() - start_ms
        if elapsed_ms >= max_window_ms:
            max_window_hit = True
            break
        try:
            obs = observe_endpoint(
                endpoint=canonical_endpoint,
                include_http=include_http,
                timeout=per_sample_budget_s,
            )
            observations.append(obs)
        except Exception as e:
            timestamp_ms = _now_ms()
            observations.append(
                RawObservation(
                    endpoint=canonical_endpoint,
                    entity_id=_generate_entity_id(hostname, port),
                    observation_id=_generate_observation_id(canonical_endpoint, timestamp_ms),
                    timestamp_ms=timestamp_ms,
                    success=False,
                    error=f"Observation failed: {type(e).__name__}: {str(e)[:100]}",
                )
            )

        if observations and isinstance(observations[-1].rtt_ms, (int, float)):
            rtt_series_local.append(float(observations[-1].rtt_ms))

        # Adaptive early stop if variance stabilizes
        if len(rtt_series_local) >= max(variance_min_samples, 2):
            mean = sum(rtt_series_local) / len(rtt_series_local)
            var = sum((x - mean) ** 2 for x in rtt_series_local) / len(rtt_series_local)
            std = var ** 0.5
            rel = std / (abs(mean) + 1e-9)
            if rel <= variance_rel_eps:
                stable_hits += 1
            else:
                stable_hits = 0
            if stable_hits >= variance_stable_samples:
                early_stop = True
                break

        if inter_sample_sleep_ms > 0:
            time.sleep(inter_sample_sleep_ms / 1000.0)

    timestamps_ms: List[int] = []
    rtt_ms: List[float] = []
    dns_time_ms: List[float] = []
    tcp_time_ms: List[float] = []
    tls_time_ms: List[float] = []
    packet_spacing_ms: List[float] = []

    for obs in observations:
        if getattr(obs, "timestamp_ms", None) is not None:
            timestamps_ms.append(int(obs.timestamp_ms))
        if isinstance(obs.rtt_ms, (int, float)):
            rtt_ms.append(float(obs.rtt_ms))
        if obs.dns and isinstance(obs.dns.resolution_time_ms, (int, float)):
            dns_time_ms.append(float(obs.dns.resolution_time_ms))
        if obs.tcp and isinstance(obs.tcp.connect_time_ms, (int, float)):
            tcp_time_ms.append(float(obs.tcp.connect_time_ms))
        if obs.tls and isinstance(obs.tls.handshake_time_ms, (int, float)):
            tls_time_ms.append(float(obs.tls.handshake_time_ms))
        if obs.packet_spacing_ms:
            for v in obs.packet_spacing_ms:
                try:
                    packet_spacing_ms.append(float(v))
                except Exception:
                    continue

    total_elapsed_ms = _now_ms() - start_ms

    return ObservationSeries(
        endpoint=canonical_endpoint,
        entity_id=_generate_entity_id(hostname, port),
        observations=observations,
        timestamps_ms=timestamps_ms,
        rtt_ms=rtt_ms,
        dns_time_ms=dns_time_ms,
        tcp_time_ms=tcp_time_ms,
        tls_time_ms=tls_time_ms,
        packet_spacing_ms=packet_spacing_ms,
        per_sample_timeout_s=per_sample_budget_s,
        max_window_ms=max_window_ms,
        max_window_hit=max_window_hit,
        early_stop=early_stop,
        elapsed_ms=total_elapsed_ms,
    )


def observe_endpoints(
    endpoints: List[str],
    include_http: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> List[RawObservation]:
    """
    Observe multiple endpoints sequentially.
    
    Args:
        endpoints: List of URLs or hostnames to observe
        include_http: Whether to include HTTP HEAD requests
        timeout: Timeout for each operation
    
    Returns:
        List of RawObservation objects
    """
    observations = []
    
    for endpoint in endpoints:
        try:
            obs = observe_endpoint(
                endpoint=endpoint,
                include_http=include_http,
                timeout=timeout
            )
            observations.append(obs)
        except Exception as e:
            # Create failed observation
            timestamp_ms = _now_ms()
            hostname, port = _parse_endpoint(endpoint)
            observations.append(RawObservation(
                endpoint=f"{hostname}:{port}",
                entity_id=_generate_entity_id(hostname, port),
                observation_id=_generate_observation_id(endpoint, timestamp_ms),
                timestamp_ms=timestamp_ms,
                success=False,
                error=f"Observation failed: {type(e).__name__}: {str(e)[:100]}"
            ))
    
    return observations


# =============================================================================
# Testing / Demo
# =============================================================================

if __name__ == "__main__":
    # Demo: Observe a public endpoint
    print("Protocol Observer Demo")
    print("=" * 50)
    
    test_endpoint = "www.google.com"
    print(f"\nObserving: {test_endpoint}")
    
    obs = observe_endpoint(test_endpoint, include_http=True)
    
    print(f"\nResults:")
    print(f"  Entity ID: {obs.entity_id}")
    print(f"  Success: {obs.success}")
    print(f"  Duration: {obs.probe_duration_ms:.1f}ms")
    
    if obs.dns.resolved_ip:
        print(f"\n  DNS:")
        print(f"    IP: {obs.dns.resolved_ip}")
        print(f"    Time: {obs.dns.resolution_time_ms:.1f}ms")
    
    if obs.tcp.connected:
        print(f"\n  TCP:")
        print(f"    Connect time: {obs.tcp.connect_time_ms:.1f}ms")
    
    if obs.tls.tls_version:
        print(f"\n  TLS:")
        print(f"    Version: {obs.tls.tls_version}")
        print(f"    Cipher: {obs.tls.cipher_suite}")
        print(f"    Handshake: {obs.tls.handshake_time_ms:.1f}ms")
        print(f"    Cert expires: {obs.tls.cert_not_after}")
    
    if obs.http and obs.http.status_code:
        print(f"\n  HTTP:")
        print(f"    Status: {obs.http.status_code}")
        print(f"    Time: {obs.http.response_time_ms:.1f}ms")
    
    print(f"\n  Packet spacing (for jitter): {obs.packet_spacing_ms}")
    
    if obs.error:
        print(f"\n  Error: {obs.error}")
