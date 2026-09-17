from scapy.packet import Packet
from models import NormalizedEvent

def parse_packet(pkt: Packet, packet_id: int):
    event = NormalizedEvent(packet_id=packet_id)
    try:
        event.timestamp = float(getattr(pkt, "time", 0.0))
        if IP not in pkt:
            event.error = "No IPv4 header"
            return event
        ip = pkt[IP]
        event.src_ip = ip.src
        event.dst_ip = ip.dst
        event.ip_version = int(ip.version)

        payload = b""

        ...

        return event
    except Exception as exc:
        event.error = f"parse_error: {type(exc).__name__}: {exc}"
        return event