# Per-codebase aurora-lint rule configs (real-world benchmark)

Each real-world benchmark codebase gets its own aurora-lint rules manifest here, the
real-world analog of a project shipping its own `aurora-lint-rules.toml` (cf.
`d_lib_common/conf/aurora-lint-rules.toml`). The real-world runner
(`bench/realworld_runner.py`) reads the per-codebase manifest named in the
`CODEBASES[<name>]["sqc"]["manifest"]` registry entry and reuses it for **every**
run of that codebase, so rules that do not apply are ignored consistently —
exactly as you would configure aurora-lint on a real project.

A codebase with no entry here falls back to the shared benchmark base,
`rules_templates/rules-benchmark.toml`.

## Config vs. oracle (two layers of false-positive control)

1. **This config = categorical policy.** Disable a *whole rule* only when it is
   categorically inapplicable to the codebase (Windows-only rules on a POSIX
   target; `FIO50-C` separate-function FP; chroot rules for a non-privileged
   tool; advisory-style rules the project rejects). This is the coarse filter.
2. **The `ground_truth` oracle = per-finding truth.** Among the rules that stay
   enabled, individual findings are labelled TP/FP in `data/benchmarks.db`
   (`python -m bench realworld-import-labels`). Analyzer *misfires* — a valid
   rule that is simply wrong on a given pattern (e.g. `FIO47-C` on
   `<inttypes.h>` `PRIxNN` macros) — are **not** disabled here; they stay
   enabled so their false positives are *measured* (and motivate fixing the
   analyzer) rather than hidden.

## Status

| Codebase  | Config                | Adjudicated? |
|-----------|-----------------------|--------------|
| libcrc    | `libcrc-rules.toml`   | **Full** — every enabled-rule finding labelled (422; 13 TP / 409 FP). See `data/precision_audit/libcrc/`. |
| sqlite    | `sqlite-rules.toml`   | Incremental — scoped to shipped `src/`+`ext/`; DCL05 disabled; INT32-C increment 1 done (47 labels). See `data/precision_audit/sqlite/`. |
| mosquitto | *(base manifest)*     | Partial — v0.4.22 4-rule sample only |
| curl      | *(base manifest)*     | Partial — v0.4.22 4-rule sample only |
| hostap    | *(base manifest)*     | Partial — v0.4.22 4-rule sample only |
| lua       | `lua-rules.toml`      | **Full** — 5th ground-truth oracle (0 TP / 3309 FP / 2 FN). See `data/precision_audit/lua/`. |
| raylib    | `raylib-rules.toml`   | **Full** — 6th ground-truth oracle, structural-C99 target (23/23 files, 5263 labels, 2.6% precision/87.3% recall). See `data/precision_audit/raylib/`. |
| pureftpd  | `pureftpd-rules.toml` | Partial, scoped — SQL-client-API oracle (task 301). `src/log_mysql.c`+`log_pgsql.c`+headers fully labelled (449 findings; 25.4% precision); rest of the daemon scanned but unlabeled. See `data/precision_audit/pureftpd/`. |
| sel4      | `sel4-rules.toml`     | Partial, scoped — 8th oracle, formally verified microkernel (task 381). Onboarded to give MSC12-C a 2nd real measurement (10.0%, 40 findings labelled); MSC12-C stays disabled here too (same busy-wait/no-op-stub/macro-hidden-effect FP families as the other 7). Rest of the codebase scanned but unlabeled. See `data/precision_audit/sel4/`. |

libcrc is the worked template (small enough to read and label exhaustively).
mosquitto/curl/hostap grow their labels incrementally; they keep using the
base manifest until a tailored config is justified by an audit. pureftpd is
scoped-full: exhaustively labelled within its onboarding purpose (the
SQL-client files), partial on the rest of the daemon by design, not by
oversight.

## Adding / tailoring a codebase (the incremental loop)

1. Scan with the candidate config + the codebase's include/context flags
   (see the codebase's `CODEBASES` entry for `includes` / `extra_args`):

       aurora-lint <codebase> -I ... -d ... --manifest conf/realworld/<cb>-rules.toml \
           --export data/precision_audit/<cb>/<cb>_cfg.json

2. Decide categorical disables → write `conf/realworld/<cb>-rules.toml` (start
   from `rules_templates/rules-benchmark.toml`, add per-codebase disables with a
   one-line rationale each) and set `manifest` in the `CODEBASES` registry.
3. Adjudicate findings TP/FP (read the code; Claude- or human-in-the-loop) into
   `data/precision_audit/<cb>/adjudication_<cb>_<ver>.csv`
   (`rule,idx,project,file,line,verdict,reason`). For a large codebase use the
   sampling loop instead of a full sweep:

       python -m bench realworld-unlabeled <RUN> --rule X --project <cb> --seed S --limit N

4. Import (pins labels to the codebase's commit; idempotent — re-running only
   adds new labels):

       python -m bench realworld-import-labels data/precision_audit/<cb>/<csv> \
           --run <RUN> --source <cb>_audit_<ver> --adjudicator claude

## Auto-scoring

When `python -m bench realworld-run` finishes, it ingests the results and
**auto-scores** them against the oracle, writing a `<run-dir>.score.json`
sidecar and printing a one-line measured precision/recall. Scoring only joins
findings to *existing* labels — it never adjudicates new findings (that needs
judgment). Re-run scoring any time with `python -m bench realworld-score <RUN>`.
