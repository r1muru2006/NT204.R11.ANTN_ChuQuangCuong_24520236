"""Unit tests for the decoder module (T01-T04, T14 partial coverage)."""

import base64

from ids.common.config import (
    DECODE_DECODED,
    DECODE_ERROR,
    DECODE_NOT_APPLICABLE,
    DECODE_PARTIAL,
    DECODE_UNCHANGED,
    PipelineConfig,
)
from ids.common.models import NormalizedEvent
from ids.decoder import (
    decode_base64,
    decode_event,
    decode_mime_payload,
    decode_quoted_printable,
    form_decode,
    html_entity_decode,
    percent_decode,
    safe_text_decode,
)


def test_percent_decode_basic():
    result = percent_decode("%27%20OR%201%3D1")
    assert result.value == "' OR 1=1"
    assert result.status == DECODE_DECODED


def test_percent_decode_leaves_plus_untouched():
    result = percent_decode("a+b")
    assert result.value == "a+b"


def test_percent_decode_unchanged():
    result = percent_decode("/index.html")
    assert result.value == "/index.html"
    assert result.status == DECODE_UNCHANGED


def test_percent_decode_malformed_is_partial_not_crash():
    result = percent_decode("100%")
    assert result.value == "100%"
    assert result.status == DECODE_PARTIAL
    assert result.error == "malformed_percent_sequence"


def test_form_decode_urlencoded():
    result = form_decode("username=alice&password=test")
    assert result.value == {"username": "alice", "password": "test"}


def test_form_decode_plus_and_percent():
    result = form_decode("q=%27%20OR%201%3D1&b=x+y")
    assert result.value == {"q": "' OR 1=1", "b": "x y"}


def test_form_decode_duplicate_keys_preserved():
    result = form_decode("a=1&a=2")
    assert result.value == {"a": ["1", "2"]}


def test_html_entity_decode():
    result = html_entity_decode("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert result.value == "<script>alert(1)</script>"
    assert result.status == DECODE_DECODED


def test_base64_decode():
    result = decode_base64(base64.b64encode(b"Hello MIME!").decode())
    assert result.value == b"Hello MIME!"
    assert result.status == DECODE_DECODED


def test_base64_decode_invalid_is_error():
    result = decode_base64("!!!!not base64!!!!")
    assert result.status == DECODE_ERROR
    assert result.error


def test_quoted_printable_decode():
    result = decode_quoted_printable("caf=C3=A9")
    assert result.value == "café".encode("utf-8")
    assert result.status == DECODE_DECODED


def test_mime_payload_base64():
    body = base64.b64encode(b"<b>hi</b>").decode()
    result = decode_mime_payload(body, "base64")
    assert result.value == "<b>hi</b>"
    assert result.status == DECODE_DECODED


def test_mime_payload_quoted_printable():
    result = decode_mime_payload("caf=C3=A9", "quoted-printable")
    assert result.value == "café"


def test_mime_payload_unsupported():
    result = decode_mime_payload("data", "x-custom")
    assert result.status == DECODE_NOT_APPLICABLE


def test_safe_text_decode_invalid_utf8():
    result = safe_text_decode(b"\xff\xfe\x00bad", "utf-8")
    assert result.status == DECODE_PARTIAL
    assert result.error
    assert isinstance(result.value, str)


def test_decode_event_preserves_raw_uri():
    event = NormalizedEvent(
        packet_id=1,
        application="HTTP",
        fields={
            "type": "request",
            "uri": "/search?q=%27%20OR%201%3D1",
            "headers": {},
            "body": "",
        },
    )
    decoded = decode_event(event)
    assert decoded.fields["uri"] == "/search?q=%27%20OR%201%3D1"
    assert decoded.fields["decoded"]["uri"]["value"] == "/search?q=' OR 1=1"
    assert decoded.fields["decode_status"] == DECODE_DECODED


def test_decode_event_form_body():
    event = NormalizedEvent(
        packet_id=2,
        application="HTTP",
        fields={
            "type": "request",
            "uri": "/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "user=a%40b.com&pw=p%27w",
        },
    )
    decoded = decode_event(event)
    assert decoded.fields["decoded"]["body"]["value"] == {"user": "a@b.com", "pw": "p'w"}


def test_decode_event_smtp_mime_base64():
    body = base64.b64encode(b"<b>hi</b>").decode()
    event = NormalizedEvent(
        packet_id=3,
        application="SMTP",
        fields={
            "mime": {
                "headers": {
                    "Content-Type": "text/plain; charset=utf-8",
                    "Content-Transfer-Encoding": "base64",
                },
                "body": body,
            }
        },
    )
    decoded = decode_event(event)
    assert decoded.fields["decoded"]["mime_body"]["value"] == "<b>hi</b>"
    assert decoded.fields["mime"]["body"] == body


def test_decode_event_disabled():
    event = NormalizedEvent(
        packet_id=4,
        application="HTTP",
        fields={"uri": "/a%20b", "headers": {}, "body": ""},
    )
    decoded = decode_event(event, PipelineConfig(enable_decoder=False))
    assert "decoded" not in decoded.fields
