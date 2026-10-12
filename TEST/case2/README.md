# Case 2 mandatory cases (T01–T14)

Reproduce all cases with:

```bash
python scripts/run_test_cases.py
```

Results are written to `TEST/case2/results/`. The same behaviour is covered by
`tests/unit/` and `tests/integration/`.

| ID | Test | Input / scenario | Expected result |
|----|------|------------------|-----------------|
| T01 | HTTP URL decoding | URI with percent-encoding (`%27%20OR%201%3D1`) | Correct decoded value; raw URI preserved |
| T02 | HTML entity decoding | `&lt;script&gt;...` in HTTP text | Correct decoded text; no crash |
| T03 | SMTP MIME Base64/QP | MIME body with declared encoding | Correct decoded body + decode status |
| T04 | Invalid UTF-8 | Payload that is not valid UTF-8 | `partial`/`error` status; program continues |
| T05 | Normalization | Differing case/representation of protocol/header/domain | Consistent normalized value after preprocess |
| T06 | Missing fields | Event missing non-required fields | Consistent `null`/missing handling; no exception |
| T07 | TCP handshake | SYN → SYN/ACK → ACK | One flow; state `ESTABLISHED` |
| T08 | Bidirectional flow | A→B and B→A with the same 5-tuple | Same `flow_id`; correct direction counts |
| T09 | TCP close/reset | FIN/ACK and RST | State `CLOSING` → `CLOSED`, or `RESET` |
| T10 | UDP query/response | DNS UDP in both directions | One UDP flow; correct packet/byte counts |
| T11 | Concurrent flows | ≥2 connections with different endpoints/ports | Flows stay separate |
| T12 | Idle timeout | Flow with no packet longer than the timeout | Flow expired and removed from the active table |
| T13 | Statistics | Multiple bidirectional packets | Correct packet/byte/flag counters and duration |
| T14 | Malformed event | Invalid/unsupported event | No crash; appropriate status/reason |

## Notes on expectations

* T04 uses `ids.decoder.safe_text_decode`; partial decoding returns a
  replacement-character string plus an explicit error string, never an
  exception.
* T06/T14 use the default policy `invalid_event_policy="mark"`, so invalid
  events are retained but marked (`processing_action="mark"`). Set the policy to
  `skip` to drop them.
* T09 counts FIN/RST flags per packet; a second FIN (other direction) closes
  the flow.
* Byte counters use transport/application payload bytes (see
  `src/ids/flow/models.py`).
