from dataclasses import dataclass, asdict
from typing import Any
import json

@dataclass
class NormalizedEvent:
    packet_id: int
    timestamp: float | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None
    transport: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    payload_len: int = 0
    application: str = "UNKNOWN"
    direction: str | None = None
    fields: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d["fields"] is None:
            d["fields"] = {}
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))
