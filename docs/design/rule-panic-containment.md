# Containing a rule's panic to the rule and file it happened in

**Status:** proposal, with a prototype on this branch. Needs Brandon's
decision; if adopted, the ADR text at the end goes into `docs/adr/`.

## The problem

One rule's bug in one construct in one file ends the whole scan with no
output. MEM35-C slices the call text between the first `(` and the first
`)` after `sizeof`. In

```c
struct node *new = malloc(cb + (sizeof *new) + (sizeof pool->mark));
```

the first `)` comes before the first `(`, so the slice panics with
`begin > end`. The scan prints `thread '<unnamed>' panicked at
src/rules/cert_c/MEM/MEM35-C/mem35_c.rs:180:50` and exits 101. It writes no
export, and it loses every finding every other rule had already produced, in
that file and in every other file. A CI job sees a crash. A benchmark run sees
`FAILED` for the whole corpus.

The MEM35-C slice is being fixed in its own right. This document is about the
class: a panic is always a bug, but one rule's bug should cost that rule's
findings for that file, and it should never pass silently.

## What the code does today

- **Unwinding is available.** `Cargo.toml` sets `panic` in no profile (it
  has only `[profile.dev]` debug-info settings), so release builds unwind.
  Containment depends on that: under `panic = "abort"`, `catch_unwind`
  catches nothing and we are back to today's behavior. Any packaging that
  sets `panic = "abort"` would silently undo this design. The ADR
  should forbid it, and `containment.rs` asserts it with
  `#[cfg(panic = "abort")] compile_error!(...)`.
- **Nothing catches a panic.** There is no `catch_unwind` in `src/`.
- **Parallel mode re-raises on the main thread.** `analyze_project` maps the
  files on a rayon pool (`par_bridge().map(...).collect()` inside
  `pool.install`). A worker's panic propagates out of `install`, `run()`
  never returns, and `main` never reaches its exit-code logic, hence 101.
  Sequential mode (`--jobs 1`, or a single file) panics straight up the call
  stack, with the same result.
- **The prescan and the macro-gap audit have the same shape:**
  `par_iter().map(process_file).collect()` in `prescan.rs` and
  `macro_gaps.rs`. A panic in either one ends the scan before a single rule
  runs.
- **Exit codes:** `0` clean or under threshold, `1` findings over a
  `--fail-on-*` threshold, `2` the scan could not run (`main` maps any
  `Err`). There is no code for "ran, but incompletely".

## Where to catch

**Two layers: around each rule's check of each file, and around each whole
file.** Both are in the prototype.

1. **Rule x file:** around `rule.check(&root_node, &source)` in
   `analyze_one_file`. This is the only granularity that keeps everything
   unrelated to the bug. In the MEM35-C case it keeps the other rules'
   findings in that file and all findings in every other file. A rule
   instance is already fresh per file (`RuleRegistry::new()` per file in
   both modes), so a rule that panicked carries no state into the next
   file, and the rest of that file's rules run on.
2. **File:** around all of `analyze_one_file`, which covers parsing, the
   parse-repair passes, and the per-file CFG and value-range build
   (`build_file_analysis`). A panic there loses that file's findings and
   nothing else. In sequential mode the parser is rebuilt afterwards, since
   it may have been mid-file.

Rejected alternatives:

- **Per file only.** This is simpler, but one rule's bug would cost every
  other rule's findings in the file. The rule x file layer costs one more
  call per rule per file (see Cost below).
- **Disable the rule for the rest of the scan after its first panic.**
  Panics are construct-specific. MEM35-C is correct on every allocation
  that does not have this shape, so disabling it would throw away good
  findings to save a few duplicate failure lines.
- **Per rule across all files**, meaning wrapping a rule's whole run.
  Rules run per file inside the per-file loop, so there is no such call
  to wrap.

**Not yet contained (stage 2):** the prescan and the macro-gap audit. The
same `contain` wraps each `process_file` call. But a prescan failure is
different in kind: that file's cross-file facts (function summaries, macro
table, allocators) go missing, and that can change findings in OTHER files
both ways. So it needs its own stage (`Stage::Prescan`), reported as
"cross-file context incomplete", and the same exit code. The prototype
leaves both as they are today, so a panic there still aborts.

### UnwindSafe and the state a contained panic can leave

`contain` wraps its closure in `AssertUnwindSafe`. The closures borrow
`&mut` parser and suppression state and the shared `&ProjectContext`, so
none of them is `UnwindSafe` as written. The assertion is a claim about what a
half-finished check can leave inconsistent:

| State | Shared by | After a contained panic |
|---|---|---|
| Rule instance (its `RefCell` fields) | that rule, that file | Dropped with the per-file registry. Not reused. |
| `FileAnalysis` (CFGs, value ranges) | every rule on the file | Read-only once built. A panic in the build is the file layer's. |
| `ProjectContext` | every file, every thread | Read-only during rule checks. `side_effects` is a `OnceLock`: a panicking initializer leaves it empty, and the next caller retries. |
| Global `Mutex`es (`deallocator_candidates::ROWS`, `const_eval` tables) | all threads | Every lock site already does `lock().unwrap_or_else(\|e\| e.into_inner())`, so poisoning does not cascade. A new global `Mutex` must follow the same pattern. The ADR says so. |
| `deallocator_candidates::PENDING` (thread-local) | rules on this thread, flushed per file | **Would leak.** The panicking rule's partial rows would be flushed under this file, or after a file-level panic under the NEXT file. The prototype snapshots `pending_len()` before each check and truncates back on a panic. |
| `dead_regions` cache, `result_checks` expansion parser (thread-locals) | this thread | Keyed by source hash, and filled by `or_insert_with`. A panic mid-compute inserts nothing. The parser is a tree-sitter `Parser` between parses. |
| `SuppressionManager` (`&mut`) | this file | Filled from the file's comments before the rules run. Not written by checks. |

Residual risk: a per-file memo that one rule half-filled before panicking
could mislead a later rule on the same file. No such memo exists today; the
CFG and value-range results are built before any rule runs. Each failure
names its file so a reader knows which file to distrust.

## How a contained failure is reported

**Loudly, with everything else kept.** The scan's output is real but
incomplete. Discarding it all, which is today's behavior, is worse for
every consumer. Passing it as complete would be worse still, so that is
not an option.

- **Text (stderr), one line per failure.** The format is stable enough to
  scrape: `Error: rule failure: RULE: FILE: MESSAGE [at SRC:LINE:COL]`, or
  `Error: file failure: FILE: ...`. After the lines comes a summary:
  `Error: scan INCOMPLETE: N internal failure(s) in M file(s) (rule ...);
  the findings above omit what failed. This is an aurora-lint bug; please
  report it.` A panic hook installed once per process keeps the default
  `thread '...' panicked at` text quiet for a contained panic and defers to
  the previous hook for any other panic. Without it, one bad rule on 500
  files prints 500 panic banners.
- **Exit code `3` = incomplete.** This is new. It takes precedence over
  `1`: a gate that passes on "no findings over threshold" must not pass
  when a rule did not run. `2` keeps its meaning (the scan could not run at
  all). `3` is returned whether or not `--fail-on-*` is set, because a
  silently partial scan is precisely what a CI user cannot detect. If
  someone needs a partial scan to pass, that is an opt-in flag (say
  `--allow-incomplete`), not a default. The prototype does not add one.
- **SARIF (not in the prototype).** Set `invocations[0].executionSuccessful:
  false`, and add one `toolExecutionNotifications` entry per failure:
  `level: "error"`, `message.text`, `locations[0]` pointing at the file,
  `associatedRule.id` for a rule failure, and `properties.stage` /
  `properties.panicLocation`. That is where SARIF 2.1.0 puts "the tool hit
  a problem", and where GitHub code scanning surfaces tool errors.
  `export_all_violations` would take the failures as one more argument; it
  has a single call site.
- **JSON export.** Unchanged. It is a bare array of findings, so a failure
  record cannot go in it without breaking every reader. That includes
  `bench/` and benchmarking_db. Failures go to stderr and SARIF, and the exit
  code says the array is incomplete. If a machine-readable list is wanted
  next to the JSON array, add `--report-failures PATH`, on the pattern of
  `--report-macro-gaps PATH`.
- **Library API.** `AnalysisResults` gains `failures:
  Vec<containment::ScanFailure>`. Adding a public field breaks downstream
  struct literals, which is fine within 0.x for v0.7.0. `main` is the only
  caller in this crate.

### Release note and docs (when it lands)

A new exit code changes what existing output means, so it goes under
**Changed** (ADR-0009), with the `docs/cli-usage.rst` Exit Codes table and
README's exit-code line updated in the same commit. A draft note: "A rule
that hits an internal error on one file no longer stops the whole scan. Its
findings for that file are omitted, the error is reported, and the scan
exits with the new code 3 (incomplete), whatever the `--fail-on-*` setting."

## What the bench runner does with it

Today `run_one` marks a scan `ok` only on exit 0 with a parsable export, so
a panic is `FAILED` and the corpus is missing from the run. Exit 3 should
stay **not ok for scoring**. An incomplete scan is missing the panicking
rule's findings on that file, so they drop out of precision and recall as
if the rule had decided not to report. That is not a measurement of the
rule. What changes is diagnosis: the export now exists, and the failure
lines are in the scan's log.

Proposed:

- `rc == 3` -> `ok = False`, and the run line reads
  `INCOMPLETE (N rule failures: MEM35-C ...)` instead of a bare `FAILED`.
- Parse the `Error: rule failure:` / `file failure:` lines from the log into
  the `.meta.json` sidecar as `scan_failures` (rule, file, message), so a
  queued run's failure reaches benchmarking_db without anyone reading logs.
- Keep refusing to ingest the scan into a scored run. Brandon could choose
  instead to ingest it flagged as incomplete; benchmarking_db would then
  need an assertion that refuses to cite it. Of the two, refusing is the
  smaller change and the safer default.

## Cost

`catch_unwind` costs nothing on the path where nothing panics. Rust unwinds
from tables (no `setjmp`, no per-call registration), so what remains is one
non-inlined call plus a landing pad per wrapped call. The extra calls are
about (enabled rules) x (files), a few hundred per file, against rule checks
that each walk the whole tree. The prototype's A/B against `main` is in the
next section.

## Prototype (this branch)

- `src/analyze/containment.rs`: `contain`, `ScanFailure`, `Stage`,
  `EXIT_INCOMPLETE = 3`, and the quiet panic hook, with unit tests.
- `analyze_one_file`: contains each `rule.check` and rolls back the
  deallocator-candidate buffer on a panic.
  `analyze_one_file_contained`: the file layer, used by both the parallel
  and the sequential loop.
- `AnalysisResults.failures`. `main` prints the failure lines and the
  summary, and returns 3.
- The `panic = "abort"` compile-time guard.
- Not done: SARIF notifications, the prescan and macro-gap stage, the bench
  runner, docs and release note.

Measured on the MEM35-C reproducer above, plus one unrelated file
(`--jobs 4` and `--jobs 1` agree):

- `main`: exit 101, no export.
- prototype: exit 3. All 15 findings from the other rules and the other
  file are exported. One failure line names MEM35-C, the file, the panic
  message and `mem35_c.rs:180:50`. The default panic banner is not printed.

A/B against `main` on real corpora (identical finding multisets, wall-clock
medians of alternating runs): see the table below. These are local
measurements on one node, not project figures.

Three alternating runs per corpus, `main` 1d8778d5 against the prototype,
runner flags, no header tree (windev-04, WSL2, 4 cores):

| Corpus | Findings (both) | Identical multiset | Median main | Median prototype | Runs main / prototype (s) |
|---|---|---|---|---|---|
| ventoy | 2294 | yes | 15.7 s | 26.8 s | 15.7, 15.5, 27.1 / 26.8, 4.2, 27.1 |
| lua | 3653 | yes | 29.8 s | 30.1 s | 19.1, 29.8, 30.3 / 30.1, 29.9, 30.3 |
| mosquitto | 3436 | yes | 106.5 s | 95.8 s | 106.5, 95.6, 121.5 / 83.0, 95.8, 96.1 |
| curl | 16878 | yes | 165.5 s | 164.6 s | 165.5, 164.0, 176.2 / 164.6, 165.3, 153.3 |

The findings are identical on all four. The timing spread within one
binary on this node (ventoy 15-27 s, mosquitto 96-122 s) is far larger than
any difference between the binaries. Wherever the runs are steady (curl,
lua), the two builds are within 1% of each other. So any overhead is below
what this node can resolve. A precise figure needs the benchmark host's
exclusive slot.

## Draft ADR (if adopted)

> **00NN. A rule's internal failure costs that rule's findings for that file,
> and is never silent**
>
> **Status:** Accepted
>
> **Context.** A panic in one rule's check of one construct used to end the
> whole scan with exit 101 and no output, discarding every other rule's
> findings in every file. MEM35-C did this on an allocation size of the form
> `n + (sizeof *p) + (sizeof s->f)`. Panics are always bugs, but they are
> construct-specific: the rule is right on everything else, and every other
> rule is unaffected.
>
> **Decision.**
> 1. A panic during a rule's check of a file is contained to that (rule,
>    file): that rule's findings for that file are dropped, and every other
>    finding stands. A panic while reading, parsing or analyzing a file
>    outside any rule is contained to that file. A panic while collecting
>    cross-file context is contained to that file's contribution and
>    reported as incomplete context.
> 2. A contained failure is always reported, and is never only logged: one
>    line per failure on stderr naming the rule, the file and the panic
>    location, a summary, SARIF `toolExecutionNotifications` with
>    `executionSuccessful: false`, and exit code **3 (incomplete)**. Code 3
>    takes precedence over 1 and applies with or without `--fail-on-*`. A
>    partial scan never exits 0 or 1.
> 3. The JSON findings export stays a bare array of findings. Failures do
>    not go into it.
> 4. Release builds unwind. `panic = "abort"` is not set in any profile or
>    packaging, since it would silently undo 1.
> 5. Process-wide state that a check can reach is panic-tolerant: a global
>    `Mutex` recovers from poisoning (`unwrap_or_else(|e| e.into_inner())`),
>    and per-thread buffers that span a check are rolled back on failure.
>
> **Consequences.** A contained panic is still a bug, and it is still fixed
> at its cause (ADR-0005 for a misfire, ADR-0006 for a text-for-AST read).
> Containment buys the rest of the scan, not permission to keep the bug. A
> benchmark scan that exits 3 is not scored: its precision and recall would
> treat a crashed rule as a rule that chose not to report. "Incomplete" is
> a distinct state from "failed to run" (2) and from "findings over
> threshold" (1). Tooling that treats any nonzero exit as failure is
> unaffected, and tooling that checks for exactly 1 must learn 3.
