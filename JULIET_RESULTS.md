# SqC — Juliet Benchmark Results

**Last Updated**: 2026-08-24
**Benchmark**: [NIST Juliet Test Suite v1.3](https://samate.nist.gov/SARD/test-suites/112) for C/C++

> **Note**: This file tracks current state only. All benchmark results are
> stored in `data/benchmarks.db` (SQLite) — use `python -m bench runs` to
> list runs, `python -m bench compare BASE TARGET` for deltas, or the MCP
> Juliet benchmark tools (`get_results`, `compare_runs`, `get_cwe_detail`).
> For the full round-by-round engineering history (every FP-reduction round,
> per-CWE tier breakdowns, competitor comparisons, and the pre-fast-mode
> version history), see [`docs/juliet-history.rst`](docs/juliet-history.rst).

---

## Current State (v0.4.249)

Run `sqc-0.4.249-107be7f0`, completed 2026-08-24 (~48 min wall time, fast mode).

| Metric | Value |
|--------|-------|
| **Rules Implemented** | 311 CERT C rules (305 enabled by default) |
| **Juliet CWEs Scanned** | 79 (fast mode, CWE-matched rules) |
| **True Positives** | 22,261 |
| **False Positives** | 3,121 |
| **TP Rate** | **87.7%** |
| **Per-file Detection Rate** | 38.0% (19,101 / 50,256 files) |
| **Zero-FP CWEs** | 44 of 79 (with real detections; 12 more scanned CWEs have zero detections) |
| **Benchmark Mode** | Fast (per-CWE manifests, 0% noise) |

**100% precision, with detections (44)**: CWE-78, 114, 188, 190, 194, 195, 197,
226, 242, 244, 252, 253, 273, 327, 338, 366, 367, 398, 426, 459, 464, 467, 468,
469, 479, 480, 481, 482, 561, 562, 563, 587, 590, 591, 666, 674, 680, 681, 685,
690, 758, 761, 789, 843.

**Zero-detection CWEs** (rules mapped but 0 violations, 12): CWE-23, 123, 176,
259, 321, 328, 570, 571, 667, 672, 676, 762.

### Recent Progress (fast-mode benchmarks, v0.3.20 → v0.4.249)

| Version | CWEs Scanned | TP | FP | TP Rate |
|---------|-------------:|---:|---:|--------:|
| v0.3.20 | 68 | 7,918 | 9,371 | 45.8% |
| v0.3.37 | 68 | 8,508 | 9,067 | 48.4% |
| v0.4.84 | 74 | 21,759 | 4,250 | 83.7% |
| v0.4.116 | 74 | 21,770 | 4,220 | 83.8% |
| **v0.4.249** | **79** | **22,261** | **3,121** | **87.7%** |

The rise from ~48% (v0.3.37) to 87.7% (v0.4.249) spans dozens of releases of
targeted rule and false-positive work (const-eval value-range analysis,
cross-file prescan, macro-expansion, taint tracking, and per-rule tuning) plus
11 additional CWEs added to the fast-mode manifest set since v0.4.116. Use
`python -m bench compare BASE TARGET` to inspect any specific pair of versions,
or see [`docs/juliet-history.rst`](docs/juliet-history.rst) for the full
narrative of every intermediate round.
