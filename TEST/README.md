# Test artifacts

This directory holds the reproducible test material for both assignment phases.

```
TEST/
├── README.md            # this file
├── case1/               # Case 1 artifacts (PCAP inputs + recorded JSONL output)
└── case2/               # Case 2 definitions (T01-T14) + recorded results
    ├── README.md
    └── results/         # Recorded, reproducible results for T01-T14
```

## Running the tests

Unit and integration tests (pytest):

```bash
python -m pytest
```

Reproducible T01–T14 cases (writes `TEST/case2/results/<case>.json` and `summary.json`):

```bash
python scripts/run_test_cases.py
```

Exit code is `0` only when all 14 cases pass. Every result file records the
observed values so the output can be verified without trusting a summary.

## Case 1 artifacts (`case1/`)

`case1/test.py` generated the 12 PCAP test inputs. Each
`<n>.<case>/` directory stores its `.pcap` and the `output.jsonl` produced by
the parser. These are historical artifacts of Case 1 and match the
current parser exactly. To reproduce one of them with the new CLI and the
pipeline disabled:

```bash
python main.py --pcap "TEST/case1/4.http_get/http_get.pcap" \
    -o /tmp/out.jsonl --flows-output /tmp/flows.jsonl \
    --no-decode --no-preprocess --no-flow
diff /tmp/out.jsonl "TEST/case1/4.http_get/output.jsonl"
```

## Case 2 cases (`case2/`)

See [`case2/README.md`](case2/README.md) for the T01–T14 specification. The
results in `case2/results/` were produced by `scripts/run_test_cases.py`;
re-running the script regenerates them deterministically (no wall-clock
dependence).
