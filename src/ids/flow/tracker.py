"""Bidirectional flow / connection tracker.

Packets sharing the same canonical 5-tuple (``src_ip``, ``dst_ip``,
``src_port``, ``dst_port``, ``protocol``) belong to a single flow, regardless of
direction. The tracker maintains per-flow statistics, TCP state and idle
expiration, and exports :class:`~ids.flow.models.FlowRecord` objects.

``byte_count`` is the sum of transport/application payload bytes (see
``ids.flow.models``).
"""

from __future__ import annotations

import time
from typing import Any

from ids.common.config import PipelineConfig
from ids.common.models import NormalizedEvent
from ids.flow.models import (
    CLOSED,
    CLOSING,
    ESTABLISHED,
    NEW,
    RESET,
    Direction,
    Endpoint,
    FlowKey,
    FlowRecord,
)

__all__ = ["FlowTracker"]

TRACKED_PROTOCOLS = {"TCP", "UDP"}


class FlowTracker:
    """Tracks bidirectional flows and their per-flow statistics."""

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self.config = config or PipelineConfig()
        self._flows: dict[str, FlowRecord] = {}
        self._keys: dict[str, FlowKey] = {}
        self._tcp_meta: dict[str, dict[str, Any]] = {}

    # -- inspection -----------------------------------------------------
    @property
    def active_flows(self) -> dict[str, FlowRecord]:
        """Return the live active-flow table (keyed by ``flow_id``)."""
        return self._flows

    def get(self, flow_id: str) -> FlowRecord | None:
        return self._flows.get(flow_id)

    def __len__(self) -> int:
        return len(self._flows)

    # -- helpers --------------------------------------------------------
    @staticmethod
    def _key_for(event: NormalizedEvent) -> FlowKey | None:
        protocol = (event.transport or "").upper()
        if protocol not in TRACKED_PROTOCOLS:
            return None
        if not event.src_ip or not event.dst_ip:
            return None
        if event.src_port is None or event.dst_port is None:
            return None
        first = Endpoint(event.src_ip, int(event.src_port))
        second = Endpoint(event.dst_ip, int(event.dst_port))
        return FlowKey.from_endpoints(protocol, first, second)

    def process(
        self, event: NormalizedEvent, auto_expire: bool = False
    ) -> FlowRecord | None:
        """Update (or create) the flow for ``event`` and return its record.

        Returns ``None`` for events that cannot be tracked (unsupported
        protocol, missing addresses/ports) instead of raising.
        """
        if not self.config.enable_flow_tracker:
            return None
        try:
            key = self._key_for(event)
        except (TypeError, ValueError):
            return None
        if key is None:
            return None

        timestamp = self._timestamp(event)
        if auto_expire and timestamp is not None:
            self.expire(timestamp)

        flow = self._flows.get(key.flow_id)
        if flow is None:
            flow = FlowRecord(
                flow_id=key.flow_id,
                protocol=key.protocol,
                endpoint_a=str(key.endpoint_a),
                endpoint_b=str(key.endpoint_b),
                start_time=timestamp,
                last_seen=timestamp,
                state=NEW,
            )
            self._flows[key.flow_id] = flow
            self._keys[key.flow_id] = key

        direction = key.direction(Endpoint(event.src_ip, event.src_port))
        payload_len = int(event.payload_len or 0)

        flow.packet_count += 1
        flow.byte_count += payload_len
        if direction == Direction.BACKWARD:
            flow.backward_packet_count += 1
            flow.backward_byte_count += payload_len
        else:
            flow.forward_packet_count += 1
            flow.forward_byte_count += payload_len

        if event.application and event.application.upper() != "UNKNOWN":
            if flow.application_protocol in ("", "UNKNOWN"):
                flow.application_protocol = event.application.upper()

        if key.protocol == "TCP":
            self._apply_tcp_flags(flow, event)

        self._update_times(flow, timestamp)
        return flow

    def _apply_tcp_flags(self, flow: FlowRecord, event: NormalizedEvent) -> None:
        """Count TCP control flags and advance the connection state."""
        flags = (event.tcp_flags or "").upper()
        meta = self._tcp_meta.setdefault(
            flow.flow_id, {"syn_seen": False, "fin_seen": set()}
        )

        if "S" in flags:
            flow.syn_count += 1
            meta["syn_seen"] = True
        if "A" in flags:
            flow.ack_count += 1
        if "F" in flags:
            flow.fin_count += 1
        if "R" in flags:
            flow.rst_count += 1

        self._advance_tcp_state(flow, flags, event, meta)

    @staticmethod
    def _advance_tcp_state(
        flow: FlowRecord, flags: str, event: NormalizedEvent, meta: dict[str, Any]
    ) -> None:
        """Advance the TCP state, tolerating missing/reordered/retransmitted packets."""
        has_syn = "S" in flags
        has_ack = "A" in flags
        has_fin = "F" in flags

        if "R" in flags:
            flow.state = RESET
            return

        if has_fin:
            direction = f"{event.src_ip}:{event.src_port}"
            meta["fin_seen"].add(direction)
            if flow.state == CLOSING or len(meta["fin_seen"]) >= 2:
                flow.state = CLOSED
            else:
                flow.state = CLOSING
            return

        if flow.state in (NEW,):
            # SYN and SYN/ACK keep the flow in the handshake phase; the final
            # ACK (or any non-SYN packet when the capture starts mid-stream)
            # establishes the connection.
            if has_syn:
                return
            if has_ack:
                flow.state = ESTABLISHED

    @staticmethod
    def _timestamp(event: NormalizedEvent) -> float | None:
        if event.timestamp is None:
            return None
        try:
            return float(event.timestamp)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _update_times(flow: FlowRecord, timestamp: float | None) -> None:
        if timestamp is None:
            return
        if flow.start_time is None:
            flow.start_time = timestamp
        flow.last_seen = timestamp if flow.last_seen is None else max(flow.last_seen, timestamp)
        flow.duration = (
            (flow.last_seen - flow.start_time)
            if flow.start_time is not None and flow.last_seen is not None
            else 0.0
        )

    # -- expiration (implemented in a later step) ----------------------
    def expire(self, now: float | None = None) -> list[FlowRecord]:
        _ = now
        return []
