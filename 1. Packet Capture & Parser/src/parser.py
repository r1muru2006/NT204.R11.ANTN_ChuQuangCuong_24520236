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

        if TCP in pkt:
            tcp = pkt[TCP]
            event.transport = "TCP"
            event.src_port = int(tcp.sport)
            event.dst_port = int(tcp.dport)
            event.tcp_flags = _tcp_flags(tcp.flags)
            event.tcp_seq = int(tcp.seq)
            event.tcp_ack = int(tcp.ack)
            if tcp.payload:
                payload = bytes(tcp.payload)
        elif UDP in pkt:
            udp = pkt[UDP]
            event.transport = "UDP"
            event.src_port = int(udp.sport)
            event.dst_port = int(udp.dport)
            if udp.payload:
                payload = bytes(udp.payload)
        else:
            event.transport = "OTHER"
        ...

        return event
    except Exception as exc:
        event.error = f"parse_error: {type(exc).__name__}: {exc}"
        return event