# NT204.R11.ANTN — Intrusion Detection System (IDS/IPS)

A small Python IDS/IPS processing pipeline built on Scapy, developed in two
equally important cases/stages.

## Case 1 — Packet Capture & Parser

Capture live or offline (PCAP) traffic and parse every packet into a normalized
JSONL event, with IPv4/TCP/UDP handling and HTTP/DNS/SMTP application detection.

* Modules: `src/ids/capture/`, `src/ids/parser/`, `src/ids/common/models.py`
* Output: one `NormalizedEvent` per packet (JSON Lines)

## Case 2 — Decoder, Preprocessor & Flow/Connection Tracker

Decode encoded fields, validate and normalize events, and group packets into
bidirectional flows with connection state and statistics.

* Modules: `src/ids/decoder/`, `src/ids/preprocessor/`, `src/ids/flow/`
* Output: enriched events plus `FlowRecord` records (JSON Lines)

Both cases are first-class and integrated behind the same CLI. Case 2 consumes
the `NormalizedEvent` contract produced by Case 1, and disabling Case 2's stages
(`--no-decode --no-preprocess --no-flow`) reproduces Case 1 output exactly.

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

To reproduce the original Case 1 output exactly (parser only):

```bash
python main.py --pcap "TEST/case1/4.http_get/http_get.pcap" \
    -o /tmp/out.jsonl --flows-output /tmp/flows.jsonl \
    --no-decode --no-preprocess --no-flow
diff /tmp/out.jsonl "TEST/case1/4.http_get/output.jsonl"   # identical
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
├── TEST/
│   ├── case1/                  # Case 1 artifacts (PCAP inputs + recorded output)
│   └── case2/                  # Case 2 definitions + results/T01-T14
├── scripts/run_test_cases.py   # T01-T14 runner
└── docs/                       # architecture + case notes
```

See [`docs/architecture.md`](docs/architecture.md) for module contracts and
design decisions.

## Tests

```bash
python -m pytest                 # unit + integration tests
python scripts/run_test_cases.py # mandatory T01-T14, writes TEST/case2/results/
```

`python scripts/run_test_cases.py` runs the 14 mandatory cases deterministically
and records the observed values under `TEST/case2/results/`. The case
specification is in [`TEST/case2/README.md`](TEST/case2/README.md). Case 1
artifacts are under `TEST/case1/`.

## Implementation status

### Case 1 — Packet Capture & Parser

| Component | Status |
|-----------|--------|
| Live packet capture | Implemented |
| PCAP import / offline processing | Implemented |
| IPv4 / TCP / UDP parsing | Implemented |
| Application detection + parsing (HTTP/DNS/SMTP) | Implemented |
| Normalized event + JSONL output | Implemented |

### Case 2 — Decoder, Preprocessor & Flow/Connection Tracker

| Component | Status |
|-----------|--------|
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
  Case 1 protocol set.

## AI usage

* **Case 1 (earlier work):** ChatGPT — consulted for packet field reference,
  Scapy examples and the initial test kit (`TEST/case1/test.py`, parser).
* **Case 2 (this work):** an AI coding assistant (opencode CLI) was used to
  inspect the repository, refactor it into the `src/ids` package, and implement
  the decoder, preprocessor, flow tracker, pipeline, tests and documentation.
  Source sections produced/refactored with AI assistance:
  `src/ids/decoder/`, `src/ids/preprocessor/`, `src/ids/flow/`,
  `src/ids/pipeline.py`, `src/ids/common/`, `tests/`, `scripts/run_test_cases.py`
  and this README.

All AI-assisted code was executed and tested against the recorded results in
`TEST/case2/results/` and can be explained in detail.
