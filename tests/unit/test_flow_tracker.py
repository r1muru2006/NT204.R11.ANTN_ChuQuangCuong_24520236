"""Unit tests for the flow/connection tracker (T07-T13)."""

from ids.common.config import PipelineConfig
from ids.common.models import NormalizedEvent
from ids.flow import FlowState, FlowTracker


def tcp_event(packet_id, src, dst, sport, dport, ts, flags="A", payload_len=0, app="UNKNOWN"):
    return NormalizedEvent(
        packet_id=packet_id,
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        ip_version=4,
        transport="TCP",
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags,
        payload_len=payload_len,
        application=app,
    )


def udp_event(packet_id, src, dst, sport, dport, ts, payload_len=0, app="UNKNOWN"):
    return NormalizedEvent(
        packet_id=packet_id,
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        ip_version=4,
        transport="UDP",
        src_port=sport,
        dst_port=dport,
        payload_len=payload_len,
        application=app,
    )


def test_t07_tcp_handshake_established():
    tracker = FlowTracker()
    tracker.process(tcp_event(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "S"))
    tracker.process(tcp_event(2, "10.0.0.2", "10.0.0.1", 80, 1111, 1.1, "SA"))
    flow = tracker.process(tcp_event(3, "10.0.0.1", "10.0.0.2", 1111, 80, 1.2, "A"))
    assert len(tracker) == 1
    assert flow.state == FlowState.ESTABLISHED
    assert flow.syn_count == 2
    assert flow.ack_count == 2


def test_t08_bidirectional_same_flow():
    tracker = FlowTracker()
    a = tracker.process(tcp_event(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "A", 10))
    b = tracker.process(tcp_event(2, "10.0.0.2", "10.0.0.1", 80, 1111, 1.1, "A", 20))
    assert a.flow_id == b.flow_id
    assert len(tracker) == 1
    assert a.forward_packet_count == 1 and a.forward_byte_count == 10
    assert a.backward_packet_count == 1 and a.backward_byte_count == 20


def test_t09_tcp_close_and_reset():
    tracker = FlowTracker()
    tracker.process(tcp_event(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "S"))
    tracker.process(tcp_event(2, "10.0.0.2", "10.0.0.1", 80, 1111, 1.1, "SA"))
    flow = tracker.process(tcp_event(3, "10.0.0.1", "10.0.0.2", 1111, 80, 1.2, "A"))
    tracker.process(tcp_event(4, "10.0.0.1", "10.0.0.2", 1111, 80, 1.3, "FA"))
    assert flow.state == FlowState.CLOSING
    tracker.process(tcp_event(5, "10.0.0.2", "10.0.0.1", 80, 1111, 1.4, "FA"))
    assert flow.state == FlowState.CLOSED

    reset = FlowTracker()
    rflow = reset.process(tcp_event(1, "10.0.0.5", "10.0.0.6", 2222, 80, 1.0, "A"))
    reset.process(tcp_event(2, "10.0.0.6", "10.0.0.5", 80, 2222, 1.1, "R"))
    assert rflow.state == FlowState.RESET
    assert rflow.rst_count == 1


def test_t10_udp_query_response_one_flow():
    tracker = FlowTracker()
    q = tracker.process(udp_event(1, "10.0.0.1", "8.8.8.8", 53000, 53, 1.0, 30, "DNS"))
    r = tracker.process(udp_event(2, "8.8.8.8", "10.0.0.1", 53, 53000, 1.1, 50, "DNS"))
    assert q.flow_id == r.flow_id
    assert len(tracker) == 1
    assert q.packet_count == 2
    assert q.byte_count == 80
    assert q.forward_packet_count == 1
    assert q.backward_packet_count == 1


def test_t11_concurrent_flows_stay_separate():
    tracker = FlowTracker()
    tracker.process(tcp_event(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "A"))
    tracker.process(tcp_event(2, "10.0.0.3", "10.0.0.2", 2222, 80, 1.1, "A"))
    tracker.process(tcp_event(3, "10.0.0.1", "10.0.0.2", 3333, 443, 1.2, "A"))
    assert len(tracker) == 3


def test_t12_idle_timeout_expires_flow():
    config = PipelineConfig(tcp_idle_timeout=10.0, udp_idle_timeout=5.0)
    tracker = FlowTracker(config)
    tracker.process(tcp_event(1, "10.0.0.1", "10.0.0.2", 1111, 80, 100.0, "A"))
    assert len(tracker) == 1
    tracker.process(tcp_event(2, "10.0.0.1", "10.0.0.2", 1111, 80, 200.0, "A"))
    expired = tracker.take_expired()
    assert len(expired) == 1
    assert len(tracker) == 1
    assert expired[0].flow_id == list(tracker.active_flows)[0]
    assert expired[0].last_seen == 100.0


def test_t12_udp_idle_timeout():
    config = PipelineConfig(udp_idle_timeout=5.0)
    tracker = FlowTracker(config)
    tracker.process(udp_event(1, "10.0.0.1", "10.0.0.2", 1, 2, 0.0))
    expired = tracker.expire(10.0)
    assert len(expired) == 1
    assert len(tracker) == 0


def test_t13_statistics_counters_and_duration():
    tracker = FlowTracker()
    tracker.process(tcp_event(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "S", 0))
    tracker.process(tcp_event(2, "10.0.0.2", "10.0.0.1", 80, 1111, 2.0, "SA", 0))
    flow = tracker.process(tcp_event(3, "10.0.0.1", "10.0.0.2", 1111, 80, 4.0, "PA", 100))
    assert flow.packet_count == 3
    assert flow.byte_count == 100
    assert flow.forward_packet_count == 2
    assert flow.backward_packet_count == 1
    assert flow.forward_byte_count == 100
    assert flow.duration == 3.0
    assert flow.start_time == 1.0 and flow.last_seen == 4.0


def test_t14_untrackable_event_returns_none_no_crash():
    tracker = FlowTracker()
    assert tracker.process(NormalizedEvent(packet_id=1)) is None
    assert tracker.process(
        NormalizedEvent(packet_id=2, transport="ICMP", src_ip="1.1.1.1", dst_ip="2.2.2.2")
    ) is None
    assert len(tracker) == 0


def test_finalize_returns_remaining_flows():
    tracker = FlowTracker()
    tracker.process(tcp_event(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "A"))
    remaining = tracker.finalize(now=2.0)
    assert len(remaining) == 1
    assert len(tracker) == 0
