from scapy.packet import Packet
from models import NormalizedEvent

HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}


def _safe_decode(data):
    return data.decode("utf-8", errors="replace")

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


def parse_http(payload: bytes, event: NormalizedEvent):
    text = _safe_decode(payload)
    lines = text.split("\r\n")
    if not lines:
        return
    start = lines[0]
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i] != "":
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
    body = "\r\n".join(lines[i + 1:]) if i < len(lines) else ""
    f = event.fields or {}
    if start.startswith("HTTP/"):
        parts = start.split(" ", 2)
        f.update({"type": "response", "version": parts[0]})
        if len(parts) >= 2 and parts[1].isdigit():
            f["status_code"] = int(parts[1])
        if len(parts) == 3:
            f["reason"] = parts[2]
    else:
        parts = start.split(" ", 2)
        f.update({"type": "request"})
        if len(parts) >= 1:
            f["method"] = parts[0]
        if len(parts) >= 2:
            f["uri"] = parts[1]
        if len(parts) >= 3:
            f["version"] = parts[2]
    f["headers"] = headers
    f["body"] = body
    event.fields = f


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
        if event.application == "HTTP":
            parse_http(payload, event)

        return event
    except Exception as exc:
        event.error = f"parse_error: {type(exc).__name__}: {exc}"
        return event