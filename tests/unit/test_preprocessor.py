"""Unit tests for the preprocessor module (T05, T06, T14)."""

from ids.common.config import (
    ACTION_ACCEPT,
    ACTION_MARK,
    ACTION_SKIP,
    PREPROCESS_INVALID,
    PREPROCESS_PARTIAL,
    PREPROCESS_VALID,
    PipelineConfig,
)
from ids.common.models import NormalizedEvent
from ids.preprocessor import preprocess_event, validate_event


def _valid_event(**overrides):
    base = dict(
        packet_id=1,
        timestamp=1.0,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        ip_version=4,
        transport="TCP",
        src_port=12345,
        dst_port=80,
    )
    base.update(overrides)
    return NormalizedEvent(**base)


def test_validate_valid_event():
    result = validate_event(_valid_event())
    assert result.status == PREPROCESS_VALID
    assert result.reasons == []


def test_validate_missing_ip_is_invalid():
    result = validate_event(NormalizedEvent(packet_id=2))
    assert result.status == PREPROCESS_INVALID
    assert "missing_ip" in result.reasons


def test_validate_bad_port_is_invalid():
    result = validate_event(_valid_event(dst_port=99999))
    assert result.status == PREPROCESS_INVALID
    assert "invalid_dst_port" in result.reasons


def test_validate_unknown_transport_is_partial():
    result = validate_event(_valid_event(transport="OTHER", src_port=None, dst_port=None))
    assert result.status == PREPROCESS_PARTIAL
    assert "unsupported_transport" in result.reasons


def test_preprocess_valid_metadata():
    processed = preprocess_event(_valid_event())
    assert processed.fields["preprocess_status"] == PREPROCESS_VALID
    assert processed.fields["processing_action"] == ACTION_ACCEPT
    assert processed.fields["reason"] == []


def test_preprocess_missing_fields_is_consistent():
    processed = preprocess_event(NormalizedEvent(packet_id=3))
    assert processed.fields["preprocess_status"] == PREPROCESS_INVALID
    assert processed.fields["processing_action"] == ACTION_MARK
    assert "missing_ip" in processed.fields["reason"]
    assert processed.fields.get("headers") is None or isinstance(processed.fields.get("headers"), dict)


def test_preprocess_normalizes_transport_and_protocol_case():
    a = preprocess_event(_valid_event(transport="tcp", application="http"))
    b = preprocess_event(_valid_event(transport="TCP", application="HTTP"))
    assert a.transport == b.transport == "TCP"
    assert a.application == b.application == "HTTP"


def test_preprocess_normalizes_ip_forms():
    processed = preprocess_event(_valid_event(src_ip="2001:0DB8::0001"))
    assert processed.src_ip == "2001:db8::1"
    assert processed.fields["preprocess_original"]["src_ip"] == "2001:0DB8::0001"


def test_preprocess_normalizes_http_header_names():
    event = _valid_event(
        application="HTTP",
        fields={"headers": {"content-type": "text/html", "HOST": "Example.COM"}},
    )
    processed = preprocess_event(event)
    assert set(processed.fields["headers"]) == {"Content-Type", "Host"}


def test_preprocess_normalizes_dns_domain():
    event = _valid_event(
        application="DNS",
        fields={"questions": [{"name": "Example.COM.", "qtype": 1, "qclass": 1}]},
    )
    processed = preprocess_event(event)
    assert processed.fields["questions"][0]["name"] == "example.com"


def test_preprocess_uri_absolute_url_host_lowercased():
    event = _valid_event(
        application="HTTP", fields={"uri": "HTTP://Example.COM/Path?q=1", "headers": {}}
    )
    processed = preprocess_event(event)
    assert processed.fields["uri"] == "http://example.com/Path?q=1"


def test_preprocess_invalid_policy_skip():
    config = PipelineConfig(invalid_event_policy="skip")
    processed = preprocess_event(NormalizedEvent(packet_id=9), config)
    assert processed.fields["processing_action"] == ACTION_SKIP


def test_preprocess_invalid_policy_retain():
    config = PipelineConfig(invalid_event_policy="retain")
    processed = preprocess_event(NormalizedEvent(packet_id=9), config)
    assert processed.fields["processing_action"] == ACTION_ACCEPT


def test_preprocess_malformed_event_no_crash():
    event = NormalizedEvent(packet_id=10, error="parse_error: ValueError: boom")
    processed = preprocess_event(event)
    assert processed.fields["preprocess_status"] == PREPROCESS_INVALID
    assert any("event_error" in r for r in processed.fields["reason"])
