from layers.layer0_observation.acquisition.protocol_observer import (
    RawObservation,
    DNSObservation,
    TCPObservation,
    TLSObservation,
)
from layers.layer0_observation.acquisition.observation_bridge import ObservationBridge
from infrastructure.unified_discovery_v2.snapshot_builder import SnapshotBuilder
from layers.layer1_trust_graph_dependency_modeling.dependency_builder import (
    build_trust_graph_delta,
    apply_graph_delta,
)
from layers.layer1_trust_graph_dependency_modeling.graph import TrustGraph


def _make_raw() -> RawObservation:
    ts = 1000
    dns = DNSObservation(resolved_ip="1.2.3.4", resolution_time_ms=5.0, timestamp_ms=ts)
    tcp = TCPObservation(connected=True, connect_time_ms=10.0, timestamp_ms=ts)
    tls = TLSObservation(
        handshake_time_ms=20.0,
        tls_version="TLS1.2",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        cipher_suites=["TLS_AES_128_GCM_SHA256"],
        cert_issuer="issuer",
        cert_fingerprint_sha256="abc",
        timestamp_ms=ts,
    )
    return RawObservation(
        endpoint="example.com:443",
        entity_id="example.com:443",
        observation_id="obs_1",
        timestamp_ms=ts,
        dns=dns,
        tcp=tcp,
        tls=tls,
        http=None,
        packet_spacing_ms=[1.0, 1.1, 1.2],
        rtt_ms=35.0,
        attempt_protocols=[],
        attempt_path="",
        attempt_count=0,
        probe_duration_ms=35.0,
        success=True,
        error=None,
    )


def _build_graph(raws):
    bridge = ObservationBridge()
    fps = bridge.process_series(raws)
    g = TrustGraph()
    delta = build_trust_graph_delta(fps, ingestion_ts_ms=raws[0].timestamp_ms)
    apply_graph_delta(g, delta)
    g.validate_integrity()
    return sorted(g.nodes.keys()), sorted(g.edges.keys())


def test_trustgraph_determinism():
    raws = [_make_raw()]

    # Build snapshot once (baseline sanity)
    sb = SnapshotBuilder()
    snapshot, _diff, _stats = sb.build_snapshot(
        cycle_id="cycle_000001",
        cycle_number=1,
        raw_observations=raws,
        previous_snapshot=None,
    )
    assert snapshot is not None

    nodes1, edges1 = _build_graph(raws)
    nodes2, edges2 = _build_graph(raws)

    assert nodes1 == nodes2
    assert edges1 == edges2
