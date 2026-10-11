"""Data models for bidirectional flow / connection tracking.

``byte_count`` **definition** (used consistently project-wide): the sum of
transport/application *payload* bytes observed for the flow (the parser's
``payload_len``), i.e. not captured frame bytes and not IP/TCP header bytes.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from typing import Any

__all__ = [
    "Endpoint",
    "FlowKey",
    "FlowRecord",
    "FlowState",
    "Direction",
]

# TCP-like connection states.
NEW = "NEW"
ESTABLISHED = "ESTABLISHED"
CLOSING = "CLOSING"
CLOSED = "CLOSED"
RESET = "RESET"


class FlowState:
    """Namespace for flow state constants."""

    NEW = NEW
    ESTABLISHED = ESTABLISHED
    CLOSING = CLOSING
    CLOSED = CLOSED
    RESET = RESET


class Direction:
    """Packet direction relative to a flow's canonical endpoints."""

    FORWARD = "forward"
    BACKWARD = "backward"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Endpoint:
    """A flow endpoint (IP address and, for transport flows, port)."""

    ip: str
    port: int | None = None

    def sort_key(self) -> tuple[int, int, int]:
        try:
            addr = ipaddress.ip_address(self.ip)
            version, value = addr.version, int(addr)
        except ValueError:
            version, value = 99, 0
        return (version, value, -1 if self.port is None else self.port)

    def __str__(self) -> str:
        if self.port is None:
            return self.ip
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True)
class FlowKey:
    """Canonical, order-independent bidirectional flow key.

    The two endpoints are always stored in a deterministic order so that
    ``A -> B`` and ``B -> A`` map to the same key and therefore the same flow.
    """

    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint

    @classmethod
    def from_endpoints(
        cls, protocol: str, first: Endpoint, second: Endpoint
    ) -> "FlowKey":
        if first.sort_key() <= second.sort_key():
            a, b = first, second
        else:
            a, b = second, first
        return cls(protocol.upper(), a, b)

    @property
    def flow_id(self) -> str:
        return (
            f"{self.protocol}|{self.endpoint_a.ip}:{self.endpoint_a.port}"
            f"<->{self.endpoint_b.ip}:{self.endpoint_b.port}"
        )

    def direction(self, src: Endpoint) -> str:
        """Return the direction of a packet originating at ``src``."""
        if src == self.endpoint_a:
            return Direction.FORWARD
        if src == self.endpoint_b:
            return Direction.BACKWARD
        return Direction.UNKNOWN


@dataclass
class FlowRecord:
    """Aggregated state and statistics for a single bidirectional flow."""

    flow_id: str
    protocol: str
    application_protocol: str = "UNKNOWN"
    endpoint_a: str = ""
    endpoint_b: str = ""
    start_time: float | None = None
    last_seen: float | None = None
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: str = NEW

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))
