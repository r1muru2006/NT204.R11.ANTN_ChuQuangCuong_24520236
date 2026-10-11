"""Encoding/representation decoding for IDS events.

The decoder converts data from an encoded/represented form into a directly
analyzable form **without changing its logical meaning**. It never performs
cryptographic decryption: percent-decoding, HTML entity decoding, Base64 and
Quoted-Printable are representations, not encryption.

Every decode operation returns a :class:`DecodeResult` that carries the decoded
value, a status and, on failure, an error message. A single decoding failure is
reported through metadata and never terminates the pipeline.
"""

from __future__ import annotations

import base64
import binascii
import html
import quopri
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_to_bytes

from ids.common.config import (
    DECODE_DECODED,
    DECODE_ERROR,
    DECODE_NOT_APPLICABLE,
    DECODE_PARTIAL,
    DECODE_UNCHANGED,
)

__all__ = [
    "DecodeResult",
    "form_decode",
    "percent_decode",
    "html_entity_decode",
    "decode_base64",
    "decode_quoted_printable",
    "safe_text_decode",
    "decode_mime_payload",
]

_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_INVALID_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


@dataclass
class DecodeResult:
    """Result of a single decoding operation."""

    value: Any
    status: str = DECODE_UNCHANGED
    method: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when no hard decoding error occurred."""
        return self.status != DECODE_ERROR

    @property
    def decoded(self) -> bool:
        """True when a successful decoding changed the value."""
        return self.status == DECODE_DECODED


def _decode_bytes(raw: bytes, encoding: str = "utf-8") -> DecodeResult:
    """Decode raw bytes, transparently reporting malformed sequences."""
    try:
        return DecodeResult(raw.decode(encoding, errors="strict"), DECODE_DECODED)
    except UnicodeDecodeError as exc:
        text = raw.decode(encoding, errors="replace")
        return DecodeResult(
            text,
            DECODE_PARTIAL,
            error=f"{encoding}_decode_error: {exc}",
        )


def form_decode(text: str, *, recursive: bool = False) -> DecodeResult:
    """Decode ``application/x-www-form-urlencoded`` data into a mapping.

    ``+`` means a space and each component is percent-decoded, per the
    ``application/x-www-form-urlencoded`` rules. Duplicate keys are preserved as
    a list so no submitted value is lost.
    """
    if not isinstance(text, str):
        return DecodeResult(text, DECODE_NOT_APPLICABLE, "form")
    if text == "":
        return DecodeResult({}, DECODE_UNCHANGED, "form")

    out: dict[str, Any] = {}
    status = DECODE_UNCHANGED
    errors: list[str] = []

    for pair in re.split(r"[&;]", text):
        if pair == "":
            continue
        key_raw, _, value_raw = pair.partition("=")
        key_res = percent_decode(key_raw.replace("+", " "), recursive=recursive)
        value_res = percent_decode(value_raw.replace("+", " "), recursive=recursive)
        for part in (key_res, value_res):
            if part.status == DECODE_DECODED:
                status = DECODE_DECODED
            elif part.status == DECODE_PARTIAL:
                status = DECODE_PARTIAL
            elif part.status == DECODE_ERROR:
                status = DECODE_ERROR
            if part.error:
                errors.append(part.error)

        key = str(key_res.value)
        value = value_res.value
        if key in out:
            existing = out[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                out[key] = [existing, value]
        else:
            out[key] = value

    return DecodeResult(out, status, "form", "; ".join(errors) or None)


def html_entity_decode(text: str) -> DecodeResult:
    """Decode HTML entities such as ``&lt;script&gt;`` -> ``<script>``.

    Only textual fields should be passed here; binary data must not be treated
    as HTML.
    """
    if not isinstance(text, str):
        return DecodeResult(text, DECODE_NOT_APPLICABLE, "html")
    if "&" not in text:
        return DecodeResult(text, DECODE_UNCHANGED, "html")
    try:
        decoded = html.unescape(text)
    except Exception as exc:  # defensive
        return DecodeResult(text, DECODE_ERROR, "html", f"{type(exc).__name__}: {exc}")
    status = DECODE_DECODED if decoded != text else DECODE_UNCHANGED
    return DecodeResult(decoded, status, "html")


def _as_bytes(data: str | bytes) -> bytes:
    if isinstance(data, bytes):
        return data
    return data.encode("utf-8", errors="strict")


def decode_base64(data: str | bytes) -> DecodeResult:
    """Decode SMTP/MIME Base64 content into raw bytes.

    This is a *representation* decode, not decryption. Whitespace/newlines are
    ignored and missing padding is tolerated, as commonly seen in MIME bodies.
    """
    if not isinstance(data, (str, bytes)):
        return DecodeResult(data, DECODE_NOT_APPLICABLE, "base64")
    try:
        raw = _as_bytes(data)
    except UnicodeEncodeError as exc:
        return DecodeResult(data, DECODE_ERROR, "base64", str(exc))
    cleaned = re.sub(rb"\s+", b"", raw)
    if cleaned == b"":
        return DecodeResult(b"", DECODE_UNCHANGED, "base64")
    padding = b"=" * ((-len(cleaned)) % 4)
    try:
        decoded = base64.b64decode(cleaned + padding, validate=True)
    except (binascii.Error, ValueError) as exc:
        return DecodeResult(data, DECODE_ERROR, "base64", f"{type(exc).__name__}: {exc}")
    status = DECODE_DECODED if decoded != raw else DECODE_UNCHANGED
    return DecodeResult(decoded, status, "base64")


def decode_quoted_printable(data: str | bytes) -> DecodeResult:
    """Decode SMTP/MIME Quoted-Printable content into raw bytes."""
    if not isinstance(data, (str, bytes)):
        return DecodeResult(data, DECODE_NOT_APPLICABLE, "quoted_printable")
    try:
        raw = _as_bytes(data)
    except UnicodeEncodeError as exc:
        return DecodeResult(data, DECODE_ERROR, "quoted_printable", str(exc))
    try:
        decoded = quopri.decodestring(raw)
    except Exception as exc:  # defensive
        return DecodeResult(data, DECODE_ERROR, "quoted_printable", f"{type(exc).__name__}: {exc}")
    status = DECODE_DECODED if decoded != raw else DECODE_UNCHANGED
    return DecodeResult(decoded, status, "quoted_printable")


def safe_text_decode(data: bytes, encoding: str = "utf-8") -> DecodeResult:
    """Decode bytes as text, reporting malformed sequences as ``partial``.

    Never raises and never silently turns malformed input into valid-looking
    data without a status.
    """
    if not isinstance(data, (bytes, bytearray)):
        return DecodeResult(data, DECODE_NOT_APPLICABLE, "text")
    try:
        return _decode_bytes(bytes(data), encoding)
    except LookupError as exc:
        return DecodeResult(data, DECODE_ERROR, "text", f"unknown_encoding: {exc}")


def decode_mime_payload(
    body: str | bytes, transfer_encoding: str, charset: str = "utf-8"
) -> DecodeResult:
    """Decode a declared MIME transfer encoding to a text payload.

    ``transfer_encoding`` comes from the message's ``Content-Transfer-Encoding``
    header. Unsupported/unknown encodings are reported as ``not_applicable``
    instead of being guessed.
    """
    te = (transfer_encoding or "").strip().lower()
    if te == "base64":
        raw = decode_base64(body)
        method = "base64"
    elif te in ("quoted-printable", "quoted_printable"):
        raw = decode_quoted_printable(body)
        method = "quoted_printable"
    elif te in ("", "7bit", "8bit", "binary"):
        try:
            raw = DecodeResult(_as_bytes(body), DECODE_UNCHANGED, te or "identity")
        except UnicodeEncodeError as exc:
            return DecodeResult(body, DECODE_ERROR, te or "identity", str(exc))
        method = te or "identity"
    else:
        return DecodeResult(
            body,
            DECODE_NOT_APPLICABLE,
            te,
            f"unsupported_transfer_encoding: {te}",
        )

    if raw.status == DECODE_ERROR:
        return DecodeResult(body, DECODE_ERROR, method, raw.error)

    text = safe_text_decode(bytes(raw.value), charset)
    if text.status == DECODE_ERROR:
        return DecodeResult(body, DECODE_ERROR, method, text.error)

    if text.status == DECODE_PARTIAL:
        status = DECODE_PARTIAL
    elif raw.status == DECODE_DECODED:
        status = DECODE_DECODED
    else:
        status = DECODE_UNCHANGED
    return DecodeResult(text.value, status, method, text.error)


def percent_decode(text: str, *, recursive: bool = False) -> DecodeResult:
    """Decode HTTP/URI percent-encoding (``%27`` -> ``'``).

    ``+`` is intentionally *not* converted to a space here: that rule only
    applies to ``application/x-www-form-urlencoded`` (see :func:`form_decode`).
    """
    if not isinstance(text, str):
        return DecodeResult(text, DECODE_NOT_APPLICABLE, "percent")
    if "%" not in text:
        return DecodeResult(text, DECODE_UNCHANGED, "percent")

    malformed = bool(_INVALID_PERCENT_RE.search(text))
    try:
        raw = unquote_to_bytes(text)
        result = _decode_bytes(raw)
    except Exception as exc:  # defensive: never propagate to the pipeline
        return DecodeResult(text, DECODE_ERROR, "percent", f"{type(exc).__name__}: {exc}")

    result.method = "percent"
    if malformed:
        result.status = DECODE_PARTIAL
        result.error = "malformed_percent_sequence"

    if recursive and result.ok and result.value != text and "%" in str(result.value):
        nested = percent_decode(str(result.value), recursive=True)
        if nested.ok:
            result.value = nested.value

    if result.value == text:
        if not malformed:
            result.status = DECODE_UNCHANGED
    elif result.status == DECODE_UNCHANGED:
        result.status = DECODE_DECODED
    return result
