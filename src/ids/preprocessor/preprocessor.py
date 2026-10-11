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
