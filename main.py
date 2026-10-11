import argparse
import json
import sys
from pathlib import Path

# Use the src/ layout without requiring an editable install.
SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ids.capture import live_capture, read_pcap  # noqa: E402
from ids.parser import parse_packet  # noqa: E402


def write_event(event, fp):
    fp.write(event.to_json() + "\n")
    fp.flush()


def main():
    ap = argparse.ArgumentParser(description="Packet Capture & Parser for a simple IDS")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", "-i", help="Network interface for live capture")
    src.add_argument("--pcap", "-r", help="PCAP file to parse")
    ap.add_argument("--output", "-o", default="output/events.jsonl", help="JSON Lines output")
    ap.add_argument("--count", type=int, default=0, help="Live packets; 0 means unlimited")
    ap.add_argument("--timeout", type=int, default=None, help="Live capture timeout in seconds")
    args = ap.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fp:
        if args.pcap:
            try:
                packets = read_pcap(args.pcap)
            except Exception as exc:
                print(f"Cannot read PCAP: {exc}", file=sys.stderr)
                return 2
            for packet_id, pkt in enumerate(packets, start=1):
                event = parse_packet(pkt, packet_id)
                write_event(event, fp)
        else:
            live_capture(
                args.interface,
                lambda pkt, packet_id: write_event(parse_packet(pkt, packet_id), fp),
                args.count,
                args.timeout,
            )
    print(f"[+] Output: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
