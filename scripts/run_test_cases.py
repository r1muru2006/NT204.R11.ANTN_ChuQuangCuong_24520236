#!/usr/bin/env python3
"""Reproducible runner for the mandatory T01-T14 test cases.

Usage (from the repository root):

    python scripts/run_test_cases.py

Each case exercises the real implementation and writes its observed result to
``TEST/results/<case>.json`` plus a combined ``TEST/results/summary.json``.
Exit code is 0 only when every case passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from ids.common.config import PipelineConfig  # noqa: E402
from ids.common.models import NormalizedEvent  # noqa: E402
from ids.decoder import (  # noqa: E402
    decode_mime_payload,
    html_entity_decode,
    percent_decode,
    safe_text_decode,
)
from ids.flow import FlowState, FlowTracker  # noqa: E402
from ids.preprocessor import preprocess_event  # noqa: E402

RESULTS_DIR = REPO_ROOT / "TEST" / "results"


def _tcp(pid, src, dst, sport, dport, ts, flags="A", payload_len=0, app="UNKNOWN"):
    return NormalizedEvent(
        packet_id=pid,
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


def _udp(pid, src, dst, sport, dport, ts, payload_len=0, app="UNKNOWN"):
    return NormalizedEvent(
        packet_id=pid,
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


# --------------------------------------------------------------------------
# Case implementations
# --------------------------------------------------------------------------

def t01_http_url_decode():
    raw = "/search?q=%27%20OR%201%3D1&next=%2Fhome"
    decoded = percent_decode(raw)
    assert decoded.value == "/search?q=' OR 1=1&next=/home", decoded.value
    assert raw == "/search?q=%27%20OR%201%3D1&next=%2Fhome"
    return {"raw_uri": raw, "decoded_uri": decoded.value, "status": decoded.status}


def t02_html_entity_decode():
    raw = "&lt;script&gt;alert(1)&lt;/script&gt;"
    decoded = html_entity_decode(raw)
    assert decoded.value == "<script>alert(1)</script>", decoded.value
    return {"raw": raw, "decoded": decoded.value, "status": decoded.status}


def t03_smtp_mime_decode():
    import base64

    b64_body = base64.b64encode(b"Hello <b>MIME</b>").decode()
    b64 = decode_mime_payload(b64_body, "base64")
    qp = decode_mime_payload("caf=C3=A9=21", "quoted-printable")
    assert b64.value == "Hello <b>MIME</b>", b64.value
    assert qp.value == "café!", qp.value
    return {
        "base64": {"value": b64.value, "status": b64.status},
        "quoted_printable": {"value": qp.value, "status": qp.status},
    }


def t04_invalid_utf8():
    result = safe_text_decode(b"\xff\xfe\x00 malformed", "utf-8")
    assert result.status in ("partial", "error")
    assert isinstance(result.value, str)
    return {"status": result.status, "error": result.error, "value": result.value}


def t05_normalization_consistency():
    a = preprocess_event(
        _tcp(1, "10.0.0.1", "10.0.0.2", 1, 2, 1.0, app="http", payload_len=0)
    )
    b = preprocess_event(
        _tcp(2, "10.0.0.1", "10.0.0.2", 1, 2, 1.0, app="HTTP", payload_len=0)
    )
    assert a.transport == b.transport == "TCP"
    assert a.application == b.application == "HTTP"
    return {"transport": a.transport, "application": a.application}


def t06_missing_fields():
    processed = preprocess_event(NormalizedEvent(packet_id=1))
    assert processed.fields["preprocess_status"] == "invalid"
    assert processed.fields["reason"]
    return {
        "status": processed.fields["preprocess_status"],
        "action": processed.fields["processing_action"],
        "reason": processed.fields["reason"],
    }


def t07_tcp_handshake():
    tracker = FlowTracker()
    tracker.process(_tcp(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "S"))
    tracker.process(_tcp(2, "10.0.0.2", "10.0.0.1", 80, 1111, 1.1, "SA"))
    flow = tracker.process(_tcp(3, "10.0.0.1", "10.0.0.2", 1111, 80, 1.2, "A"))
    assert len(tracker) == 1
    assert flow.state == FlowState.ESTABLISHED
    return {"flows": len(tracker), "state": flow.state, "flow_id": flow.flow_id}


def t08_bidirectional_flow():
    tracker = FlowTracker()
    out = tracker.process(_tcp(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "A", 10))
    back = tracker.process(_tcp(2, "10.0.0.2", "10.0.0.1", 80, 1111, 1.1, "A", 20))
    assert out.flow_id == back.flow_id
    assert len(tracker) == 1
    return {
        "flow_id": out.flow_id,
        "forward_packets": out.forward_packet_count,
        "backward_packets": out.backward_packet_count,
    }


def t09_tcp_close_reset():
    tracker = FlowTracker()
    tracker.process(_tcp(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "A"))
    flow = tracker.process(_tcp(2, "10.0.0.1", "10.0.0.2", 1111, 80, 1.1, "FA"))
    assert flow.state == FlowState.CLOSING
    tracker.process(_tcp(3, "10.0.0.2", "10.0.0.1", 80, 1111, 1.2, "FA"))
    assert flow.state == FlowState.CLOSED

    reset = FlowTracker()
    rflow = reset.process(_tcp(9, "10.0.0.5", "10.0.0.6", 3333, 80, 2.0, "A"))
    reset.process(_tcp(10, "10.0.0.6", "10.0.0.5", 80, 3333, 2.1, "R"))
    assert rflow.state == FlowState.RESET
    return {"after_fin": FlowState.CLOSING, "after_second_fin": FlowState.CLOSED, "after_rst": rflow.state}


def t10_udp_query_response():
    tracker = FlowTracker()
    q = tracker.process(_udp(1, "10.0.0.1", "8.8.8.8", 53000, 53, 1.0, 30, "DNS"))
    r = tracker.process(_udp(2, "8.8.8.8", "10.0.0.1", 53, 53000, 1.1, 50, "DNS"))
    assert q.flow_id == r.flow_id
    assert q.packet_count == 2 and q.byte_count == 80
    return {"flows": len(tracker), "packet_count": q.packet_count, "byte_count": q.byte_count}


def t11_concurrent_flows():
    tracker = FlowTracker()
    tracker.process(_tcp(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "A"))
    tracker.process(_tcp(2, "10.0.0.3", "10.0.0.2", 2222, 80, 1.1, "A"))
    tracker.process(_tcp(3, "10.0.0.1", "10.0.0.2", 3333, 443, 1.2, "A"))
    assert len(tracker) == 3
    return {"active_flows": len(tracker), "flow_ids": sorted(tracker.active_flows)}


def t12_idle_timeout():
    config = PipelineConfig(tcp_idle_timeout=10.0, udp_idle_timeout=5.0)
    tracker = FlowTracker(config)
    tracker.process(_tcp(1, "10.0.0.1", "10.0.0.2", 1111, 80, 100.0, "A"))
    tracker.expire(now=115.0)
    assert len(tracker) == 0
    return {"active_after_timeout": len(tracker)}


def t13_flow_statistics():
    tracker = FlowTracker()
    tracker.process(_tcp(1, "10.0.0.1", "10.0.0.2", 1111, 80, 1.0, "S", 0))
    tracker.process(_tcp(2, "10.0.0.2", "10.0.0.1", 80, 1111, 2.0, "SA", 0))
    flow = tracker.process(_tcp(3, "10.0.0.1", "10.0.0.2", 1111, 80, 4.0, "PA", 100))
    assert flow.packet_count == 3
    assert flow.byte_count == 100
    assert flow.forward_packet_count == 2 and flow.backward_packet_count == 1
    assert flow.duration == 3.0
    return {
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "forward_packet_count": flow.forward_packet_count,
        "backward_packet_count": flow.backward_packet_count,
        "duration": flow.duration,
        "syn_count": flow.syn_count,
        "ack_count": flow.ack_count,
    }


def t14_malformed_event():
    tracker = FlowTracker()
    assert tracker.process(NormalizedEvent(packet_id=1)) is None
    processed = preprocess_event(NormalizedEvent(packet_id=1))
    assert processed.fields["preprocess_status"] == "invalid"
    return {"tracked_flow": None, "preprocess_status": processed.fields["preprocess_status"]}


CASES = [
    ("T01", "http_url_decode", t01_http_url_decode),
    ("T02", "html_entity_decode", t02_html_entity_decode),
    ("T03", "smtp_mime_decode", t03_smtp_mime_decode),
    ("T04", "invalid_utf8", t04_invalid_utf8),
    ("T05", "normalization", t05_normalization_consistency),
    ("T06", "missing_fields", t06_missing_fields),
    ("T07", "tcp_handshake", t07_tcp_handshake),
    ("T08", "bidirectional_flow", t08_bidirectional_flow),
    ("T09", "tcp_close_reset", t09_tcp_close_reset),
    ("T10", "udp_query_response", t10_udp_query_response),
    ("T11", "concurrent_flows", t11_concurrent_flows),
    ("T12", "idle_timeout", t12_idle_timeout),
    ("T13", "flow_statistics", t13_flow_statistics),
    ("T14", "malformed_event", t14_malformed_event),
]


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary = []
    failures = 0
    for case_id, name, func in CASES:
        record = {"case": f"{case_id}_{name}", "status": "PASS"}
        try:
            record["observed"] = func()
        except Exception as exc:  # report honestly, keep going
            record["status"] = "FAIL"
            record["error"] = f"{type(exc).__name__}: {exc}"
            failures += 1
        summary.append(record)
        (RESULTS_DIR / f"{case_id}_{name}.json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"[{record['status']}] {record['case']}")
        if record["status"] == "FAIL":
            print(f"        {record['error']}")

    (RESULTS_DIR / "summary.json").write_text(
        json.dumps(
            {"total": len(summary), "passed": len(summary) - failures, "failed": failures, "results": summary},
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"\n{len(summary) - failures}/{len(summary)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
