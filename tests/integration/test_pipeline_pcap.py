"""Integration tests: parser -> decoder -> preprocessor -> flow tracker."""

from pathlib import Path

from ids.capture import read_pcap
from ids.common.config import PipelineConfig
from ids.flow import FlowState
from ids.parser import parse_packet
from ids.pipeline import Pipeline, run_pcap

REPO_ROOT = Path(__file__).resolve().parents[2]
CASE1 = REPO_ROOT / "TEST" / "case1"


class _Sink:
    def __init__(self):
        self.lines = []

    def write(self, text):
        self.lines.append(text)

    def flush(self):
        pass

    def text(self):
        return "".join(self.lines)


def _process_pcaps(pcaps, config=None):
    pipeline = Pipeline(config or PipelineConfig())
    events, flows = [], []
    packet_id = 0
    for path in pcaps:
        for pkt in read_pcap(str(path)):
            packet_id += 1
            event, _ = pipeline.process_event(parse_packet(pkt, packet_id))
            events.append(event)
            flows.extend(pipeline.drain_expired())
    flows.extend(pipeline.finalize())
    return events, flows


def test_run_pcap_tcp_handshake_produces_established_flow():
    events_sink, flows_sink = _Sink(), _Sink()
    count = run_pcap(
        str(CASE1 / "1.tcp_handshake" / "tcp_handshake.pcap"),
        events_sink,
        flows_sink,
        PipelineConfig(),
    )
    assert count == 3
    import json

    flows = [json.loads(line) for line in flows_sink.text().splitlines()]
    assert len(flows) == 1
    assert flows[0]["state"] == FlowState.ESTABLISHED
    assert flows[0]["packet_count"] == 3
    assert flows[0]["syn_count"] == 2
    assert flows[0]["ack_count"] == 2


def test_pipeline_decodes_http_form_body():
    events, _ = _process_pcaps([CASE1 / "5.http_post" / "http_post.pcap"])
    decoded = events[0].fields["decoded"]["body"]
    assert decoded["value"] == {"username": "alice", "password": "test"}
    assert events[0].fields["preprocess_status"] == "valid"


def test_pipeline_dns_query_response_single_flow():
    events, flows = _process_pcaps(
        [CASE1 / "7.dns_query" / "dns_query.pcap", CASE1 / "8.dns_response" / "dns_response.pcap"]
    )
    assert len(flows) == 1
    flow = flows[0]
    assert flow.protocol == "UDP"
    assert flow.packet_count == 2
    assert flow.forward_packet_count == 1
    assert flow.backward_packet_count == 1
    assert flow.application_protocol == "DNS"


def test_pipeline_malformed_event_does_not_crash():
    events, _ = _process_pcaps([CASE1 / "12.malformed" / "malformed.pcap"])
    assert events[0].fields["preprocess_status"] in ("partial", "invalid")
    assert events[0].fields["processing_action"] in ("mark", "accept", "skip")
    assert events[0].fields["reason"]
