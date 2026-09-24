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


OUT = Path("TEST/pcaps")
OUT.mkdir(parents=True, exist_ok=True)


def save(name, packets):
    path = OUT / name
    wrpcap(str(path), packets)
    print(f"[+] Created: {path}")


client = "10.0.0.1"
server = "10.0.0.2"


# ============================================================
# 01 - TCP THREE-WAY HANDSHAKE
# ============================================================

syn = (
    Ether()
    / IP(src=client, dst=server)
    / TCP(
        sport=12345,
        dport=80,
        flags="S",
        seq=1000,
    )
)

synack = (
    Ether()
    / IP(src=server, dst=client)
    / TCP(
        sport=80,
        dport=12345,
        flags="SA",
        seq=2000,
        ack=1001,
    )
)

ack = (
    Ether()
    / IP(src=client, dst=server)
    / TCP(
        sport=12345,
        dport=80,
        flags="A",
        seq=1001,
        ack=2001,
    )
)

save(
    "01_tcp_handshake.pcap",
    [syn, synack, ack],
)


# ============================================================
# 02 - TCP DATA
# ============================================================

packet = (
    Ether()
    / IP(src=client, dst=server)
    / TCP(
        sport=12345,
        dport=80,
        flags="PA",
        seq=1001,
        ack=2001,
    )
    / Raw(b"Hello TCP")
)

save(
    "02_tcp_data.pcap",
    [packet],
)


# ============================================================
# 03 - UDP
# ============================================================

packet = (
    Ether()
    / IP(src=client, dst=server)
    / UDP(
        sport=50000,
        dport=50001,
    )
    / Raw(b"Hello UDP")
)

save(
    "03_udp.pcap",
    [packet],
)


# ============================================================
# 04 - HTTP GET
# ============================================================

payload = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: TestClient\r\n"
    b"\r\n"
)

packet = (
    Ether()
    / IP(src=client, dst=server)
    / TCP(
        sport=50000,
        dport=80,
        flags="PA",
    )
    / Raw(payload)
)

save(
    "04_http_get.pcap",
    [packet],
)


# ============================================================
# 05 - HTTP POST
# ============================================================

body = b"username=alice&password=test"

payload = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: "
    + str(len(body)).encode()
    + b"\r\n"
    b"\r\n"
    + body
)

packet = (
    Ether()
    / IP(src=client, dst=server)
    / TCP(
        sport=50001,
        dport=80,
        flags="PA",
    )
    / Raw(payload)
)

save(
    "05_http_post.pcap",
    [packet],
)


# ============================================================
# 06 - HTTP RESPONSE
# ============================================================

payload = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 5\r\n"
    b"\r\n"
    b"hello"
)

packet = (
    Ether()
    / IP(src=server, dst=client)
    / TCP(
        sport=80,
        dport=50000,
        flags="PA",
    )
    / Raw(payload)
)

save(
    "06_http_response.pcap",
    [packet],
)


# ============================================================
# 07 - DNS QUERY
# ============================================================

packet = (
    Ether()
    / IP(src=client, dst="8.8.8.8")
    / UDP(
        sport=53000,
        dport=53,
    )
    / DNS(
        id=0x1234,
        rd=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A",
        ),
    )
)

save(
    "07_dns_query.pcap",
    [packet],
)


# ============================================================
# 08 - DNS RESPONSE
# ============================================================

packet = (
    Ether()
    / IP(src="8.8.8.8", dst=client)
    / UDP(
        sport=53,
        dport=53000,
    )
    / DNS(
        id=0x1234,
        qr=1,
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
    )
)

save(
    "08_dns_response.pcap",
    [packet],
)


# ============================================================
# 09 - SMTP COMMAND
# ============================================================

payload = (
    b"EHLO example.com\r\n"
    b"MAIL FROM:<alice@example.com>\r\n"
    b"RCPT TO:<bob@example.com>\r\n"
)

packet = (
    Ether()
    / IP(src=client, dst=server)
    / TCP(
        sport=55000,
        dport=25,
        flags="PA",
    )
    / Raw(payload)
)

save(
    "09_smtp_command.pcap",
    [packet],
)


# ============================================================
# 10 - SMTP RESPONSE
# ============================================================

payload = b"250 OK\r\n"

packet = (
    Ether()
    / IP(src=server, dst=client)
    / TCP(
        sport=25,
        dport=55000,
        flags="PA",
    )
    / Raw(payload)
)

save(
    "10_smtp_response.pcap",
    [packet],
)


# ============================================================
# 11 - UNKNOWN PROTOCOL
# ============================================================

packet = (
    Ether()
    / IP(
        src=client,
        dst=server,
        proto=99,
    )
    / Raw(b"UNKNOWN_PROTOCOL")
)

save(
    "11_unknown.pcap",
    [packet],
)


# ============================================================
# 12 - MALFORMED / EMPTY PAYLOAD
# ============================================================

packet = (
    Ether()
    / IP(
        src=client,
        dst=server,
    )
)

save(
    "12_malformed.pcap",
    [packet],
)


print()
print("[+] Finished.")
print(f"[+] PCAP directory: {OUT.resolve()}")