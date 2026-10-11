"""Preprocessing: validation and normalization of normalized IDS events.

The preprocessor gives downstream modules (flow tracker, feature extractor) a
consistent representation. It validates required/optional fields, normalizes
representations, handles missing/unsupported data consistently and annotates
every event with ``preprocess_status``, ``processing_action`` and ``reason``.

Rules:
    * Validation never raises for a single malformed event; the event is marked
      ``invalid``/``partial`` instead.
    * Normalization preserves the original value under
      ``fields['preprocess_original']`` whenever it changes a value, so no
      evidence is destroyed.
    * Missing scalar values are represented as ``None`` and missing collections
      as appropriate empty collections.
"""

from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

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

__all__ = [
    "ValidationResult",
    "validate_event",
    "preprocess_event",
]

KNOWN_TRANSPORTS = {"TCP", "UDP", "ICMP", "OTHER"}
SUPPORTED_TRANSPORTS = {"TCP", "UDP"}
MAX_PORT = 65535


@dataclass
class ValidationResult:
    """Outcome of validating a single event."""

    status: str = PREPROCESS_VALID
    reasons: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.status == PREPROCESS_VALID


def _is_valid_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_PORT


def validate_event(event: NormalizedEvent) -> ValidationResult:
    """Validate required fields, ports, timestamp and protocol.

    Returns a :class:`ValidationResult` with status ``valid``, ``partial`` or
    ``invalid`` plus human-readable reasons. Never raises.
    """
    reasons: list[str] = []

    if event.error:
        return ValidationResult(PREPROCESS_INVALID, [f"event_error: {event.error}"])

    if event.timestamp is None:
        reasons.append("missing_timestamp")
    else:
        try:
            if float(event.timestamp) < 0:
                reasons.append("negative_timestamp")
        except (TypeError, ValueError):
            reasons.append("invalid_timestamp")

    if not event.src_ip or not event.dst_ip:
        return ValidationResult(PREPROCESS_INVALID, reasons + ["missing_ip"])

    for label, value in (("src_ip", event.src_ip), ("dst_ip", event.dst_ip)):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return ValidationResult(PREPROCESS_INVALID, reasons + [f"invalid_{label}"])

    if event.ip_version not in (4, 6):
        reasons.append("invalid_ip_version")

    transport = (event.transport or "").upper()
    if transport in SUPPORTED_TRANSPORTS:
        for label, value in (("src_port", event.src_port), ("dst_port", event.dst_port)):
            if not _is_valid_port(value):
                return ValidationResult(PREPROCESS_INVALID, reasons + [f"invalid_{label}"])
    elif transport in KNOWN_TRANSPORTS:
        reasons.append("unsupported_transport")
    else:
        reasons.append("missing_transport")

    status = PREPROCESS_VALID if not reasons else PREPROCESS_PARTIAL
    return ValidationResult(status, reasons)


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _normalize_protocol(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().upper()


def _normalize_port(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_header_name(name: str) -> str:
    """Canonicalize an HTTP header name (``content-type`` -> ``Content-Type``)."""
    return "-".join(
        part[:1].upper() + part[1:].lower() for part in name.strip().split("-")
    )


def _normalize_uri(uri: str) -> str:
    """Safely normalize a URI/path without decoding or dropping evidence.

    Only the scheme and host of absolute URLs are lowercased; the path, query
    and fragment are preserved verbatim so downstream analysis still sees the
    original request.
    """
    uri = uri.strip()
    parts = urlsplit(uri)
    if parts.scheme and parts.netloc:
        return urlunsplit(
            (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
        )
    return uri


def _record_original(originals: dict[str, Any], key: str, old: Any, new: Any) -> None:
    if old != new:
        originals.setdefault(key, old)


def _normalize_fields(fields: dict[str, Any], originals: dict[str, Any]) -> None:
    """Normalize nested application fields (HTTP headers/URI, DNS names)."""
    headers = fields.get("headers")
    if isinstance(headers, dict):
        normalized_headers: dict[str, Any] = {}
        for key, value in headers.items():
            new_key = _normalize_header_name(str(key))
            if new_key != key:
                originals.setdefault("headers", {})[str(key)] = new_key
            normalized_headers[new_key] = value
        fields["headers"] = normalized_headers

    uri = fields.get("uri")
    if isinstance(uri, str):
        new_uri = _normalize_uri(uri)
        _record_original(originals, "uri", uri, new_uri)
        fields["uri"] = new_uri

    for section in ("questions", "answers"):
        entries = fields.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if isinstance(name, str):
                new_name = _normalize_domain(name)
                _record_original(originals, f"{section}.name", name, new_name)
                entry["name"] = new_name


def _policy_action(policy: str) -> str:
    return {
        "mark": ACTION_MARK,
        "skip": ACTION_SKIP,
        "retain": ACTION_ACCEPT,
    }.get(policy, ACTION_MARK)


def preprocess_event(
    event: NormalizedEvent, config: PipelineConfig | None = None
) -> NormalizedEvent:
    """Validate and normalize an event, annotating it with metadata.

    Metadata written into ``fields``:
        ``preprocess_status``  valid | partial | invalid
        ``processing_action``  accept | mark | skip
        ``reason``             list of reasons (empty when valid)
    """
    config = config or PipelineConfig()
    out = copy.deepcopy(event)
    if not config.enable_preprocessor:
        return out

    fields = out.fields if out.fields is not None else {}
    out.fields = fields
    originals: dict[str, Any] = {}

    validation = validate_event(event)

    new_transport = _normalize_protocol(out.transport)
    _record_original(originals, "transport", out.transport, new_transport)
    out.transport = new_transport

    new_application = _normalize_protocol(out.application)
    _record_original(originals, "application", out.application, new_application)
    out.application = new_application

    for label in ("src_ip", "dst_ip"):
        value = getattr(out, label)
        if isinstance(value, str):
            try:
                new_value = _normalize_ip(value)
            except ValueError:
                new_value = value
            _record_original(originals, label, value, new_value)
            setattr(out, label, new_value)

    out.src_port = _normalize_port(out.src_port)
    out.dst_port = _normalize_port(out.dst_port)

    _normalize_fields(fields, originals)

    reasons = list(validation.reasons)
    status = validation.status
    if status == PREPROCESS_INVALID:
        action = _policy_action(config.invalid_event_policy)
    elif "unsupported_transport" in reasons:
        action = _policy_action(config.unsupported_protocol_policy)
    else:
        action = ACTION_ACCEPT

    if originals:
        fields["preprocess_original"] = originals
    fields["preprocess_status"] = status
    fields["processing_action"] = action
    fields["reason"] = reasons
    return out
