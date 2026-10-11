# NT204.R11.ANTN — Intrusion Detection System (IDS/IPS)

A small Python IDS/IPS processing pipeline built on Scapy.

* **Assignment 1** — packet capture and parsing into normalized JSONL events.
* **Assignment 2** — decoder, preprocessor and bidirectional flow/connection
  tracker layered on top of Assignment 1.

```
Packet Capture & Parser  ->  Decoder  ->  Preprocessor  ->  Flow Tracker  ->  Feature Extractor
```

## Requirements

* Python 3.10+
* [Scapy](https://scapy.readthedocs.io/) (packet capture/parsing)
* pytest (tests only)

```bash
pip install -e .            # installs scapy
pip install -e ".[dev]"     # adds pytest
# or simply:
pip install scapy pytest
```

Running from a checkout without installing is supported: `main.py` adds `src/`
to `sys.path` automatically.

## Usage

The single CLI entry point is `main.py` (equivalent to
`python -m ids.pipeline` after installation).

Offline PCAP processing:

```bash
python main.py --pcap capture.pcap --output output/events.jsonl --flows-output output/flows.jsonl
```

Live capture:

```bash
sudo python main.py --interface eth0 --count 100 --timeout 30
```

Useful options:

| Option | Meaning |
|--------|---------|
| `-i, --interface` | live capture interface |
| `-r, --pcap` | offline PCAP file |
| `-o, --output` | event JSONL output (default `output/events.jsonl`) |
| `--flows-output` | flow JSONL output (default `output/flows.jsonl`) |
| `--count` / `--timeout` | live capture limits |
| `--tcp-timeout` / `--udp-timeout` | idle timeouts in seconds |
| `--config` | load a JSON configuration file |
| `--no-decode` / `--no-preprocess` / `--no-flow` | disable a stage |
| `--log-level` | e.g. `INFO`, `DEBUG` |

To reproduce the original Assignment 1 output exactly (parser only):

```bash
python main.py --pcap "TEST/Bai1/4.http_get/http_get.pcap" \
    -o /tmp/out.jsonl --flows-output /tmp/flows.jsonl \
    --no-decode --no-preprocess --no-flow
diff /tmp/out.jsonl "TEST/Bai1/4.http_get/output.jsonl"   # identical
```

## Configuration

All policies are configurable through `PipelineConfig`
(`src/ids/common/config.py`) and a JSON file (see
`config/ids.example.json`):

```json
{
  "enable_decoder": true,
  "html_entity_decoding": true,
  "max_decode_size": 1000000,
  "decode_recursive": false,
  "enable_preprocessor": true,
  "invalid_event_policy": "mark",
  "unsupported_protocol_policy": "mark",
  "enable_flow_tracker": true,
  "tcp_idle_timeout": 300.0,
  "udp_idle_timeout": 60.0,
  "log_level": "INFO"
}
```

* `invalid_event_policy` / `unsupported_protocol_policy`: `mark`, `retain` or
  `skip`.
* Idle timeouts are in seconds and applied by the flow tracker.

```bash
python main.py --pcap capture.pcap --config config/ids.example.json
```

## Project layout

```
.
├── main.py                     # CLI entry point
├── pyproject.toml
├── config/ids.example.json     # example configuration
├── src/ids/
│   ├── common/                 # NormalizedEvent, PipelineConfig, logging
│   ├── capture/                # live + PCAP capture
│   ├── parser/                 # packet -> NormalizedEvent
│   ├── decoder/                # percent/form/HTML/MIME decoding
│   ├── preprocessor/           # validation + normalization
│   ├── flow/                   # bidirectional flow tracker
│   └── pipeline.py             # end-to-end orchestration
├── tests/unit/                 # decoder, preprocessor, flow tracker
├── tests/integration/          # PCAP-driven pipeline tests
├── TEST/                       # reproducible test cases + recorded results
├── scripts/run_test_cases.py   # T01-T14 runner
└── docs/                       # architecture + assignment notes
```

See [`docs/architecture.md`](docs/architecture.md) for module contracts and
design decisions.

## Tests

```bash
python -m pytest                 # unit + integration tests
python scripts/run_test_cases.py # mandatory T01-T14, writes TEST/results/
```

`python scripts/run_test_cases.py` runs the 14 mandatory cases deterministically
and records the observed values under `TEST/results/`. The case specification is
in [`TEST/cases/README.md`](TEST/cases/README.md).

## Implementation status

| Component | Status |
|-----------|--------|
| Packet capture (live + PCAP) | Implemented |
| Parser (IPv4/TCP/UDP/HTTP/DNS/SMTP) | Implemented |
| Decoder (percent, form, HTML, Base64, QP, charset) | Implemented |
| Preprocessor (validation, normalization, policies) | Implemented |
| Flow/connection tracker (TCP state, UDP, timeouts, stats) | Implemented |
| Pipeline integration and CLI | Implemented |
| Feature extractor / detection engine | Not implemented (out of scope) |
| TLS/HTTPS, DoH/DoT or crypto decryption | Not implemented (out of scope) |

### Known limitations

* Live capture requires elevated privileges and a real interface.
* DNS/SMTP parsing operates per TCP segment; application messages split across
  segments are only partially reconstructed.
* `byte_count` counts payload bytes, not frame bytes (see architecture doc).
* IPv6 is parsed at the IP layer, but application detection focuses on the
  Assignment 1 protocol set.

## AI usage

* **Assignment 1 (earlier work):** ChatGPT — consulted for packet field
  reference, Scapy examples and the initial test kit
  (`TEST/Bai1/test.py`, parser).
* **Assignment 2 (this work):** an AI coding assistant (opencode CLI) was used
  to inspect the repository, refactor it into the `src/ids` package, and
  implement the decoder, preprocessor, flow tracker, pipeline, tests and
  documentation. Source sections produced/refactored with AI assistance:
  `src/ids/decoder/`, `src/ids/preprocessor/`, `src/ids/flow/`,
  `src/ids/pipeline.py`, `src/ids/common/`, `tests/`, `scripts/run_test_cases.py`
  and this README.

All AI-assisted code was executed and tested against the recorded results in
`TEST/results/` and can be explained in detail.
