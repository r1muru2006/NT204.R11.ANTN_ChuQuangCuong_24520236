from scapy.packet import Packet
from models import NormalizedEvent

HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}

def _tcp_flags(flags):
    try:
        return str(flags)
    except Exception:
        return repr(flags)


def detect_application(payload, src_port, dst_port, pkt):
    stripped = payload.lstrip()
    first = stripped.split(b" ", 1)[0] if stripped else b""
    if first in HTTP_METHODS and (b"HTTP/1." in stripped[:512] or b"\r\n" in stripped[:512]):
        return "HTTP"
    if stripped.startswith(b"HTTP/1.0") or stripped.startswith(b"HTTP/1.1"):
        return "HTTP"
    if isinstance(pkt, HTTPRequest) or isinstance(pkt, HTTPResponse):
        return "HTTP"
    if DNS in pkt or src_port in (53, 5353) or dst_port in (53, 5353):
        return "DNS"
    if src_port == 25 or dst_port == 25 or src_port == 587 or dst_port == 587 or src_port == 465 or dst_port == 465:
        upper = stripped.upper()
        if upper.startswith((b"HELO ", b"EHLO ", b"MAIL FROM:", b"RCPT TO:", b"DATA", b"QUIT", b"RSET", b"NOOP", b"VRFY", b"250 ", b"220 ", b"221 ", b"354 ", b"550 ", b"553 ")):
            return "SMTP"
    return "UNKNOWN"


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

        event.payload_len = len(payload)
        event.application = detect_application(payload, event.src_port, event.dst_port, pkt)


        return event
    except Exception as exc:
        event.error = f"parse_error: {type(exc).__name__}: {exc}"
        return event