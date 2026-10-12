# Architecture

## Processing pipeline

```
Live / PCAP
    |
    v
Packet Capture & Parser   capture.py, parser.py, common/models.py
    |  NormalizedEvent (JSONL)
    v
Decoder                   decoder/decoder.py
    |  fields['decoded'], fields['decode_status']
    v
Preprocessor              preprocessor/preprocessor.py
    |  fields['preprocess_status'], fields['processing_action'], fields['reason']
    v
Flow / Connection Tracker flow/tracker.py, flow/models.py
    |  FlowRecord (JSONL)
    v
Feature Extractor (future)
```

`ids.pipeline.Pipeline` wires the stages together. Each stage is also usable
independently.

## Module responsibilities and contracts

### capture (`ids.capture`)
* `read_pcap(path)` → Scapy packet list.
* `live_capture(interface, handler, count, timeout)` → calls
  `handler(packet, packet_id)` per packet.

### parser (`ids.parser`)
* `parse_packet(packet, packet_id)` → `NormalizedEvent`. Never raises for a
  malformed packet: errors are recorded in `NormalizedEvent.error`.

### common.models (`NormalizedEvent`)
Stable Case 1 event schema:

```
packet_id, timestamp, src_ip, dst_ip, ip_version, transport,
src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, payload_len,
application, direction, fields, error
```

`fields` is a free-form mapping holding per-application data (`uri`, `body`,
`headers`, DNS `questions`/`answers`, SMTP `commands`/`responses`/`mime`, ...).

### decoder (`ids.decoder`)
Pure functions returning `DecodeResult(value, status, method, error)`:

* `percent_decode`, `form_decode`, `html_entity_decode`
* `decode_base64`, `decode_quoted_printable`, `safe_text_decode`
* `decode_mime_payload(body, transfer_encoding, charset)`

`decode_event(event, config)` enriches an event:

```json
"fields": {
  "decoded": {"uri": {"value": "...", "status": "decoded", "method": "percent"}},
  "decode_status": "decoded",
  "decode_errors": ["..."]
}
```

Raw `uri`/`body`/headers are **never overwritten**. `decode_status` is one of
`decoded`, `unchanged`, `partial`, `error`, `not_applicable`. Decoding never
raises; a failure is reported in metadata and the pipeline continues.

### preprocessor (`ids.preprocessor`)
* `validate_event(event)` → `ValidationResult(status, reasons)` where status is
  `valid`, `partial` or `invalid`.
* `preprocess_event(event, config)` → copy with:
  * normalized `transport`, `application`, IPs, ports, HTTP header names, DNS
    domains, absolute-URL scheme/host;
  * original values preserved under `fields['preprocess_original']` when changed;
  * `fields['preprocess_status']`, `fields['processing_action']`
    (`accept`/`mark`/`skip`) and `fields['reason']`.

### flow (`ids.flow`)
* `Endpoint`, `FlowKey` (canonical, order-independent bidirectional key),
  `FlowRecord`.
* `FlowTracker.process(event)` → `FlowRecord` (or `None` for untrackable
  events). Tracks packet/byte counters per direction, SYN/ACK/FIN/RST counts
  and TCP state (`NEW` → `ESTABLISHED` → `CLOSING` → `CLOSED`/`RESET`).
* `FlowTracker.expire(now)` / `take_expired()` / `finalize()` implement
  configurable TCP/UDP idle timeouts and flow export.

**`byte_count` definition:** the sum of transport/application *payload* bytes
(the parser's `payload_len`). It is not frame bytes and excludes IP/TCP header
bytes. The same definition is used for both directions project-wide.

## Design decisions

* **Frozen Case 1 schema.** New metadata is added inside `fields` (a
  free-form mapping) rather than as new dataclass attributes, so the original
  Case 1 JSONL output is reproduced byte-for-byte when the new stages are
  disabled (`--no-decode --no-preprocess --no-flow`).
* **Canonical flow key.** Endpoints are sorted by (IP version, numeric IP,
  port) so `A→B` and `B→A` collapse to one key and one `flow_id`.
* **Mid-connection captures.** A TCP flow whose first observed packet is ACK
  (no SYN) becomes `ESTABLISHED` instead of assuming every capture starts with
  a handshake.
* **Safe by default.** Every stage catches per-event errors and annotates the
  event instead of aborting the run.
