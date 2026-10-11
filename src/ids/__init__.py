"""Simple IDS/IPS processing pipeline.

Modules:
    capture        Live and offline (PCAP) packet capture.
    parser         Raw packet to normalized event parsing.
    decoder        Encoding/representation decoding of event fields.
    preprocessor   Validation and normalization of events.
    flow           Bidirectional flow / connection tracking.
    pipeline       End-to-end orchestration of the modules above.
"""

__version__ = "0.2.0"
