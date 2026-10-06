from typing import Callable
from scapy.all import sniff, rdpcap
from scapy.packet import Packet

Handler = Callable[[Packet, int], None]


def read_pcap(path: str):
    return rdpcap(path)



def live_capture(interface: str, handler: Handler, count: int = 0, timeout: int = 0):
    counter = {"id": 0}
    def on_packet(pkt: Packet):
        counter["id"] += 1
        try:
            handler(pkt, counter["id"])
        except Exception:
            pass
    sniff(iface=interface, prn=on_packet, store=False, count=count, timeout=timeout)