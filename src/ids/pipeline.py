"""End-to-end IDS processing pipeline.

    Packet Capture & Parser  ->  Decoder  ->  Preprocessor  ->  Flow Tracker

The pipeline keeps stable input/output contracts: it consumes the
``NormalizedEvent`` produced by the parser and enriches it in place, while
emitting ``FlowRecord`` objects separately so downstream consumers never depend
on the tracker's internal implementation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ids.capture import live_capture, read_pcap
from ids.common.config import ACTION_SKIP, PipelineConfig
from ids.common.logging_utils import configure_logging, get_logger
from ids.common.models import NormalizedEvent
from ids.decoder import decode_event
from ids.flow import FlowRecord, FlowTracker
from ids.parser import parse_packet
from ids.preprocessor import preprocess_event

__all__ = ["Pipeline", "main", "run_pcap", "run_live"]

logger = get_logger("pipeline")


class Pipeline:
    """Orchestrates decoding, preprocessing and flow tracking for events."""

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self.config = config or PipelineConfig()
        self.tracker = FlowTracker(self.config)

    def process_event(
        self, event: NormalizedEvent
    ) -> tuple[NormalizedEvent, FlowRecord | None]:
        """Decode and preprocess one event, then update flow tracking.

        Returns the processed event and its flow record (``None`` when the flow
        tracker is disabled or the event is not trackable). The event is always
        returned, even when its ``processing_action`` is ``skip``; callers that
        honour the skip policy should check ``fields['processing_action']``.
        """
        event = decode_event(event, self.config)
        event = preprocess_event(event, self.config)
        action = (event.fields or {}).get("processing_action")
        flow = None
        if action != ACTION_SKIP:
            flow = self.tracker.process(event)
        return event, flow

    def drain_expired(self) -> list[FlowRecord]:
        return self.tracker.take_expired()

    def finalize(self) -> list[FlowRecord]:
        return self.tracker.finalize()


def _write_line(fp, obj) -> None:
    fp.write(obj.to_json() + "\n")
    fp.flush()


def run_pcap(
    pcap_path: str,
    events_fp,
    flows_fp,
    config: PipelineConfig,
) -> int:
    """Process every packet in a PCAP file. Returns the number of packets."""
    pipeline = Pipeline(config)
    packets = read_pcap(pcap_path)
    count = 0
    for packet_id, pkt in enumerate(packets, start=1):
        count += 1
        try:
            event = parse_packet(pkt, packet_id)
            event, _flow = pipeline.process_event(event)
        except Exception as exc:  # one packet must never stop the pipeline
            logger.warning("packet %s failed: %s", packet_id, exc)
            continue
        if (event.fields or {}).get("processing_action") != ACTION_SKIP:
            _write_line(events_fp, event)
        for flow in pipeline.drain_expired():
            _write_line(flows_fp, flow)
    for flow in pipeline.finalize():
        _write_line(flows_fp, flow)
    return count


def run_live(
    interface: str,
    events_fp,
    flows_fp,
    config: PipelineConfig,
    count: int = 0,
    timeout: int | None = None,
) -> None:
    """Process live packets until ``count`` packets or ``timeout`` seconds."""
    pipeline = Pipeline(config)

    def handle(pkt, packet_id: int) -> None:
        try:
            event = parse_packet(pkt, packet_id)
            event, _flow = pipeline.process_event(event)
        except Exception as exc:
            logger.warning("packet %s failed: %s", packet_id, exc)
            return
        if (event.fields or {}).get("processing_action") != ACTION_SKIP:
            _write_line(events_fp, event)
        for flow in pipeline.drain_expired():
            _write_line(flows_fp, flow)

    live_capture(interface, handle, count, timeout)
    for flow in pipeline.finalize():
        _write_line(flows_fp, flow)


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Packet Capture, Parser, Decoder, Preprocessor and Flow Tracker for a simple IDS"
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", "-i", help="Network interface for live capture")
    src.add_argument("--pcap", "-r", help="PCAP file to parse")
    ap.add_argument("--output", "-o", default="output/events.jsonl", help="Event JSON Lines output")
    ap.add_argument(
        "--flows-output", default="output/flows.jsonl", help="Flow JSON Lines output"
    )
    ap.add_argument("--count", type=int, default=0, help="Live packets; 0 means unlimited")
    ap.add_argument("--timeout", type=int, default=None, help="Live capture timeout in seconds")
    ap.add_argument("--config", help="Path to a JSON configuration file")
    ap.add_argument("--tcp-timeout", type=float, default=None, help="TCP idle timeout (s)")
    ap.add_argument("--udp-timeout", type=float, default=None, help="UDP idle timeout (s)")
    ap.add_argument("--no-decode", action="store_true", help="Disable the decoder")
    ap.add_argument("--no-preprocess", action="store_true", help="Disable the preprocessor")
    ap.add_argument("--no-flow", action="store_true", help="Disable the flow tracker")
    ap.add_argument("--log-level", default=None, help="Logging level (e.g. INFO, DEBUG)")
    return ap


def _config_from_args(args) -> PipelineConfig:
    config = PipelineConfig.from_json_file(args.config) if args.config else PipelineConfig()
    if args.no_decode:
        config.enable_decoder = False
    if args.no_preprocess:
        config.enable_preprocessor = False
    if args.no_flow:
        config.enable_flow_tracker = False
    if args.tcp_timeout is not None:
        config.tcp_idle_timeout = args.tcp_timeout
    if args.udp_timeout is not None:
        config.udp_idle_timeout = args.udp_timeout
    if args.log_level:
        config.log_level = args.log_level
    return config


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = _config_from_args(args)
    configure_logging(config.log_level)

    events_path = Path(args.output)
    flows_path = Path(args.flows_output)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    flows_path.parent.mkdir(parents=True, exist_ok=True)

    with events_path.open("w", encoding="utf-8") as events_fp, flows_path.open(
        "w", encoding="utf-8"
    ) as flows_fp:
        if args.pcap:
            try:
                count = run_pcap(args.pcap, events_fp, flows_fp, config)
            except Exception as exc:
                print(f"Cannot read PCAP: {exc}", file=sys.stderr)
                return 2
            logger.info("processed %s packets from %s", count, args.pcap)
        else:
            run_live(
                args.interface,
                events_fp,
                flows_fp,
                config,
                args.count,
                args.timeout,
            )

    print(f"[+] Events: {events_path}")
    print(f"[+] Flows:  {flows_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
