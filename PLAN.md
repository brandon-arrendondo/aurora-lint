# SqC — Plans & Roadmap

Last Updated: 2026-04-19 (v0.3.103)

Juliet benchmark v0.3.103: 24,518 TP / 13,358 FP (64.7% TP rate), 41.5% per-file.
Cumulative v0.3.93 → v0.3.103: TP rate +3.0pp, FP −2,410 (−15.3%), zero net
other-rule regressions. Real-world v0.3.93 → v0.3.98: −343 violations;
v0.3.98 → v0.3.103: zero delta (Juliet-specific fixes — no new
FunctionSummary fields since v0.3.102).

## Competitor Benchmark Summary (v0.3.75)

5-tool comparison on 15 overlapping Juliet CWEs (28,488 files):

  clang-tidy: 13,952 TP /    116 FP (91.6%) — highest precision
  Frama-C:     8,609 TP /  5,510 FP (61.0%)
  SqC:        27,882 TP / 23,003 FP (54.8%) — broadest coverage (118 CWEs)
  Infer:       4,971 TP /  6,428 FP (43.6%)
  cppcheck:   29,377 TP / 51,361 FP (36.4%) — highest recall

SqC wins outright on CWE-690 (94.6%) and CWE-761 (100%).
Biggest gaps vs best competitor (clang-tidy unless noted, v0.3.96 current):
  CWE-190: 58.6% vs 94.3% (−35.7pp) — INT32-C/INT30-C (was −46.9pp, task 54 done)
  CWE-191: 53.9% vs 94.4% (−40.5pp) — INT32-C/INT30-C (was −48.9pp, task 54 done)
  CWE-369: 53.9% vs 94.7% (−40.8pp) — INT33-C/FLP03-C (was −57.8pp, task 55 done)
  CWE-476: 59.6% vs 94.3% (−34.7pp) — EXP34-C (was −43.5pp, task 57 done)
  CWE-121: 55.7% vs 86.6% (−30.9pp) — STR31-C/ARR38-C (was −37.8pp, task 56 done)
  CWE-415: 58.2% vs 80.0% (−21.8pp) — MEM01-C (was −36.6pp, task 58 done)
  CWE-416: 92.9% vs 60.3% (+32.6pp) — MEM01-C EXCEEDS target (task 58 done)
  CWE-401: 77.6% vs 83.9% (−6.3pp) — MEM31-C (was −33.2pp, task 59 done)
  CWE-78:  94.8% (+32.0pp since v0.3.93) — now EXCEEDS clang-tidy 91.6%
                                          (tasks 67-68, 49A + 49B + 49C + 49D)
  CWE-194: 69.4% (+11.0pp since v0.3.95) — INT31-C taint-aware (task 69 + 49C)
  CWE-195: 52.5% (+ 3.8pp since v0.3.95) — INT31-C taint-aware (task 69 + 49C)

For completed work, see the `release`-tagged entries in the
`todo-sqlite-cli` DB: `todo-sqlite-cli list --tag release --status done`
or `todo-sqlite-cli export-completed --since YYYY-MM-DD`.
For benchmark data, see JULIET_RESULTS.md and REALWORLD_RESULTS.md.
For competitor research and academic references, see docs/bibliography.rst.

## Task backlog

Tasks are tracked in `todo-sqlite-cli.db` (resolved via the `.todo-sqlite-cli`
marker at the repo root). Use the CLI, not this file:

- `todo-sqlite-cli next` — single task to work on right now
- `todo-sqlite-cli list` — all active + pending
- `todo-sqlite-cli list --status all` — including done
- `todo-sqlite-cli show <id>` — full details

Original PLAN.md task IDs (prior to the 2026-04-20 import) are preserved
as `plan-id:NN` tags on each task; the CLI's own IDs are 1–23.

Default test strategy for all tasks: pre-commit hooks (cargo test + cargo fmt),
then Juliet benchmark and real-world benchmark to validate.
