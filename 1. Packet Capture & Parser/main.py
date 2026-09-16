#!/usr/bin/env python3
import argparse
import json
from src.capture import read_pcap, live_capture


def main():
    argps = argparse.ArgumentParser(description="Packet Capture & Parser for IDS")

    argps.add_argument("--interface", "-i", help="Network interface for live capture")
    argps.add_argument("--output", "-o", default="output/events.jsonl", help="JSON Lines output")
    argps.add_argument("--count", type=int, default=0, help="Live packets; 0 means unlimited")
    argps.add_argument("--timeout", type=int, default=None, help="Live capture timeout in seconds")

    args = argps.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fp:
        live_capture(args.interface, lambda pkt, packet_id: None, args.count, args.timeout)
    print(f"[+] Output: {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
