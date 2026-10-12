from pathlib import Path

from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    wrpcap,
)


# ============================================================
# Configuration
# ============================================================

BASE_DIR = Path(__file__).resolve().parent


# ============================================================
# Helper
# ============================================================

def create_case(case_number, case_name, packets):
    """
    Create:

        <number>.<case_name>./
            <case_name>.pcap

    Example:

        1.tcp_handshake./
            tcp_handshake.pcap
    """

    case_dir = BASE_DIR / f"{case_number}.{case_name}."
    case_dir.mkdir(parents=True, exist_ok=True)

    pcap_path = case_dir / f"{case_name}.pcap"

    wrpcap(str(pcap_path), packets)

    print(f"[+] Created: {case_dir}")
    print(f"    PCAP: {pcap_path}")


# ============================================================
# 1. TCP Handshake
# ============================================================

client_ip = "192.168.1.10"
server_ip = "192.168.1.20"

client_port = 12345
server_port = 80

tcp_handshake = [
    # SYN
    Ether() /
    IP(src=client_ip, dst=server_ip) /
    TCP(
        sport=client_port,
        dport=server_port,
        flags="S",
        seq=1000,
    ),

    # SYN/ACK
    Ether() /
    IP(src=server_ip, dst=client_ip) /
    TCP(
        sport=server_port,
        dport=client_port,
        flags="SA",
        seq=2000,
        ack=1001,
    ),

    # ACK
    Ether() /
    IP(src=client_ip, dst=server_ip) /
    TCP(
        sport=client_port,
        dport=server_port,
        flags="A",
        seq=1001,
        ack=2001,
    ),
]

create_case(
    1,
    "tcp_handshake",
    tcp_handshake,
)


# ============================================================
# 2. TCP Data
# ============================================================

tcp_data = [
    Ether() /
    IP(src=client_ip, dst=server_ip) /
    TCP(
        sport=client_port,
        dport=server_port,
        flags="PA",
        seq=1001,
        ack=2001,
    ) /
    Raw(load=b"Hello TCP"),
]

create_case(
    2,
    "tcp_data",
    tcp_data,
)


# ============================================================
# 3. UDP
# ============================================================

udp_packet = [
    Ether() /
    IP(src=client_ip, dst=server_ip) /
    UDP(
        sport=12345,
        dport=9999,
    ) /
    Raw(load=b"Hello UDP"),
]

create_case(
    3,
    "udp",
    udp_packet,
)


# ============================================================
# 4. HTTP GET
# ============================================================

http_get = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: TestClient/1.0\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)

http_get_packet = [
    Ether() /
    IP(src=client_ip, dst=server_ip) /
    TCP(
        sport=12346,
        dport=80,
        flags="PA",
        seq=1,
        ack=1,
    ) /
    Raw(load=http_get),
]

create_case(
    4,
    "http_get",
    http_get_packet,
)


# ============================================================
# 5. HTTP POST
# ============================================================

http_post = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 29\r\n"
    b"\r\n"
    b"username=alice&password=test"
)

http_post_packet = [
    Ether() /
    IP(src=client_ip, dst=server_ip) /
    TCP(
        sport=12347,
        dport=80,
        flags="PA",
        seq=1,
        ack=1,
    ) /
    Raw(load=http_post),
]

create_case(
    5,
    "http_post",
    http_post_packet,
)


# ============================================================
# 6. HTTP Response
# ============================================================

http_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 5\r\n"
    b"\r\n"
    b"hello"
)

http_response_packet = [
    Ether() /
    IP(src=server_ip, dst=client_ip) /
    TCP(
        sport=80,
        dport=12348,
        flags="PA",
        seq=1,
        ack=1,
    ) /
    Raw(load=http_response),
]

create_case(
    6,
    "http_response",
    http_response_packet,
)


# ============================================================
# 7. DNS Query
# ============================================================

dns_query = [
    Ether() /
    IP(src=client_ip, dst="8.8.8.8") /
    UDP(
        sport=53000,
        dport=53,
    ) /
    DNS(
        id=0x1234,
        qr=0,
        rd=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A",
        ),
    ),
]

create_case(
    7,
    "dns_query",
    dns_query,
)


# ============================================================
# 8. DNS Response
# ============================================================

dns_response = [
    Ether() /
    IP(src="8.8.8.8", dst=client_ip) /
    UDP(
        sport=53,
        dport=53000,
    ) /
    DNS(
        id=0x1234,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A",
        ),
        an=DNSRR(
            rrname="example.com",
            type="A",
            ttl=300,
            rdata="93.184.216.34",
        ),
    ),
]

create_case(
    8,
    "dns_response",
    dns_response,
)


# ============================================================
# 9. SMTP Commands
# ============================================================

smtp_commands = [
    Ether() /
    IP(src=client_ip, dst=server_ip) /
    TCP(
        sport=40000,
        dport=25,
        flags="PA",
        seq=1,
        ack=1,
    ) /
    Raw(
        load=(
            b"EHLO example.com\r\n"
            b"MAIL FROM:<alice@example.com>\r\n"
            b"RCPT TO:<bob@example.com>\r\n"
        )
    ),
]

create_case(
    9,
    "smtp_command",
    smtp_commands,
)


# ============================================================
# 10. SMTP Response
# ============================================================

smtp_response = [
    Ether() /
    IP(src=server_ip, dst=client_ip) /
    TCP(
        sport=25,
        dport=40000,
        flags="PA",
        seq=1,
        ack=1,
    ) /
    Raw(
        load=b"250 OK\r\n"
    ),
]

create_case(
    10,
    "smtp_response",
    smtp_response,
)


# ============================================================
# 11. Unknown Protocol
# ============================================================

unknown_packet = [
    Ether() /
    IP(
        src=client_ip,
        dst=server_ip,
        proto=99,
    ) /
    Raw(
        load=b"UNKNOWN_PROTOCOL_TEST"
    ),
]

create_case(
    11,
    "unknown",
    unknown_packet,
)


# ============================================================
# 12. Malformed / Missing Transport
# ============================================================

malformed_packet = [
    Ether() /
    IP(
        src=client_ip,
        dst=server_ip,
    ),
]

create_case(
    12,
    "malformed",
    malformed_packet,
)


# ============================================================
# Done
# ============================================================

print()
print("=" * 60)
print("All test PCAP files created successfully.")
print("=" * 60)