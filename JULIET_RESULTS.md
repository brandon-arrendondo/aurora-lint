# SqC — Juliet Benchmark Results

**Last Updated**: 2026-09-02
**Benchmark**: [NIST Juliet Test Suite v1.3](https://samate.nist.gov/SARD/test-suites/112) for C/C++

> **Note**: This file tracks current state only. All benchmark results are
> stored in `data/benchmarks.db` (SQLite) — use `python -m bench runs` to
> list runs, `python -m bench compare BASE TARGET` for deltas, or the MCP
> Juliet benchmark tools (`get_results`, `compare_runs`, `get_cwe_detail`).
> For the full round-by-round engineering history (every FP-reduction round,
> per-CWE tier breakdowns, competitor comparisons, and the pre-fast-mode
> version history), see [`docs/juliet-history.rst`](docs/juliet-history.rst).

---

<!-- BENCH:JULIET_CURRENT:START -->
## Current State (v0.4.321)

Run `sqc-0.4.321-daff4cf0`, completed 2026-09-02 (fast mode, ~27 min wall time).

| Metric | Value |
|--------|-------|
| **Rules Implemented** | 311 CERT C rules (307 enabled by default) |
| **Juliet CWEs Scanned** | 79 (fast mode, CWE-matched rules) |
| **True Positives** | 22,210 |
| **False Positives** | 3,288 |
| **TP Rate** | **87.1%** |
| **Per-file Detection Rate** | 38.0% (19,073 / 50,256 files) |
| **Zero-FP CWEs** | 43 of 79 (with real detections; 13 more scanned CWEs have zero detections) |
| **Benchmark Mode** | Fast (per-CWE manifests, 0.0% noise) |

**100% precision, with detections (43)**: CWE-78, 114, 188, 190, 194, 195, 197, 226, 242, 244, 252, 253, 273, 327, 338, 367, 398, 426, 459, 464, 467, 468, 469, 479, 480, 481, 482, 561, 562, 563, 587, 590, 591, 666, 674, 680, 681, 685, 690, 758, 761, 789, 843.

**Zero-detection CWEs** (rules mapped but 0 violations, 13): CWE-23, 123, 176, 259, 321, 328, 366, 570, 571, 667, 672, 676, 762.
<!-- BENCH:JULIET_CURRENT:END -->

Regenerate this section with `python -m bench render-docs` (defaults to the
latest completed fast-mode run; see `bench/render_docs.py`).

### Recent Progress (fast-mode benchmarks, v0.3.20 → v0.4.321)

| Version | CWEs Scanned | TP | FP | TP Rate |
|---------|-------------:|---:|---:|--------:|
| v0.3.20 | 68 | 7,918 | 9,371 | 45.8% |
| v0.3.37 | 68 | 8,508 | 9,067 | 48.4% |
| v0.4.84 | 74 | 21,759 | 4,250 | 83.7% |
| v0.4.116 | 74 | 21,770 | 4,220 | 83.8% |
| v0.4.249 | 79 | 22,261 | 3,121 | 87.7% |
| v0.4.301 | 79 | 22,239 | 3,117 | 87.7% |
| **v0.4.321** | **79** | **22,210** | **3,288** | **87.1%** |

The rise from ~48% (v0.3.37) to 87.7% (v0.4.249) spans dozens of releases of
targeted rule and false-positive work (const-eval value-range analysis,
cross-file prescan, macro-expansion, taint tracking, and per-rule tuning) plus
11 additional CWEs added to the fast-mode manifest set since v0.4.116. TP rate
has been flat-to-slightly-down from v0.4.249 through v0.4.321 (~70 further
releases, 87.7% → 87.1%) — work in that window targeted real-world precision,
not Juliet, and the 0.6-point dip is the cost of that trade rather than a
Juliet regression to chase. Use `python -m bench compare BASE TARGET` to
inspect any specific pair of versions, or see
[`docs/juliet-history.rst`](docs/juliet-history.rst) for the full narrative of
every intermediate round.

### The TP rate is not the ceiling signal — the flaw-hit rate is

87.1% is the share of sqc's Juliet findings that are true positives. It says
how clean the output is, not how much of the suite's planted defect set sqc
actually locates. That second number is the **flaw-hit rate: 12.9%**
(17,100 of 132,406 flaw lines hit, v0.4.321), and it has not moved in weeks.

Both figures are real, and quoting only the first overstates the tool. The
per-file detection rate (38.0%, 19,073 of 50,256 files) sits between them:
sqc flags something in over a third of flawed files, but lands on the
specific planted flaw line in about an eighth of cases. When judging
headroom, the flaw-hit rate is the honest signal, and it is the one to watch
for movement.

Note also that Juliet exercises only part of the suite: 127 rules have any
Juliet true positive. See
[README.md's rule-suite coverage section](README.md#rule-suite-coverage) for
what that leaves unmeasured across the full 311.
