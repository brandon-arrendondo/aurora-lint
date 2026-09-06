# Frama-C on the real-world suite: why it is bounded and partial

**Status:** IMPLEMENTED (2026-09-04, task 767). Read the "What a Frama-C row
means" section before quoting any Frama-C real-world figure — the bound is
not a tuning detail, it is what the number means.

## The problem

Every other tool in the comparison answers "what is wrong with this file?".
Frama-C's EVA plugin answers a different question — "what values can these
variables hold, starting from *here*?" — and `here` is a single entry point
you must name. `frama-c -eva` without `-main` looks for `main`. That is fine
for Juliet, where each test case is a self-contained file with a known
`_bad`/`_good` entry, and it is exactly why the four competitor Juliet runs in
`data/competitor_results/` exist while the real-world side had nothing.

On a real codebase neither half of that holds:

- **Most of the corpus has no `main` at all.** libcrc, raylib and mosquitto's
  `lib/` are libraries. seL4 is a kernel with a boot entry, not a `main`.
- **Where a `main` exists it is the wrong entry point.** curl's `main` is in
  `src/tool_main.c`; the code the oracle is adjudicated over is `lib/`.
  Reaching a decoder in `lib/` from `main` requires EVA to symbolically
  execute argument parsing, TLS setup and an event loop first.
- **Whole-program EVA does not terminate on this scale.** The published
  Frama-C Juliet run took 9,914 s over 6 CWEs of files averaging under 200
  lines. curl's in-scope tree is three orders of magnitude larger, with
  function pointers, recursion and unbounded loops throughout. This is not a
  "give it more budget" problem; it is the analysis EVA is documented to be.

So Frama-C cannot be swept the way cppcheck is. The honest options were to
leave it unrun, or to run something bounded and say precisely what the bound
costs. This document is the second.

## What is actually run

`bench/realworld_runner.py`, `--tool frama-c`. Per translation unit named by
the checkout's `compile_commands.json` (in-scope subset — see below), EVA is
invoked once per function that TU defines:

```
frama-c -eva -eva-precision 1 -machdep gcc_x86_64 \
        -lib-entry -main=<function> \
        -compilation-db <filtered compile DB> \
        <translation unit>
```

The compile-database option was renamed between the two versions this repo
cares about — `-json-compilation-database` through 32.0 (what the published
competitor Juliet runs used), `-compilation-db` from 33.0. The runner probes
`frama-c -kernel-h` once and uses whichever the installed binary accepts.
Getting this wrong is not loudly wrong: every EVA invocation aborts with
`option is unknown`, and without the probe the run tallied 22 *analysis
failures* on libcrc rather than one configuration error.

`-lib-entry` is the load-bearing flag: it tells EVA to start from an arbitrary
function with *unknown* globals rather than from a fully-initialised program
state. That is what makes a library function analysable at all, and it is also
why the results are noisier than a whole-program run would be — EVA must
assume a hostile caller.

Three bounds, all overridable by environment variable:

| Knob | Env var | Default |
|------|---------|---------|
| Per-EVA-invocation timeout | `SQC_BENCH_FRAMAC_ENTRY_TIMEOUT_S` | 60 s |
| Entry points per translation unit | `SQC_BENCH_FRAMAC_MAX_ENTRIES_PER_TU` | 8 |
| Wall clock for the whole project | `SQC_BENCH_FRAMAC_BUDGET_S` | 4 h |
| EVA precision level | `SQC_BENCH_FRAMAC_PRECISION` | 1 |

### Round-robin, not file-by-file

Entry points are visited breadth-first across translation units: pass 0 gives
every TU its first entry point, pass 1 its second, and so on. Spending the
budget depth-first would analyse the alphabetically-first handful of files
exhaustively and never open the rest, which is a *biased* sample of the
codebase rather than a shallow one. A budget that runs out mid-pass still
leaves every file represented up to the depth reached.

Within a TU, externally-linked functions are ordered before `static` ones:
those are the library's own API, the code a caller can actually reach, and so
the code worth spending a bounded budget on first.

### Entry-point discovery is textual, on purpose

`_c_function_definitions` finds top-level function definitions with a regex
plus a paren-balance check for the opening brace. It is not a parse. It does
not have to be: its only job is to *propose* entry points, and Frama-C rejects
a name it does not know with `cannot find entry point`, which the runner
detects, logs and skips without counting as either a failure or an analysed
entry. A false positive costs one fast invocation. The alternative — a
`frama-c -metrics` pass per TU purely to enumerate functions — buys accuracy
the harness does not need at the price of an extra process per file.

In practice it is accurate enough to be uninteresting: on sqlite it finds 93
definitions in `where.c`, 125 in `main.c` and 136 in `os_unix.c`, in ~3 ms per
file, leading with the `sqlite3_*` public API in each.

### Scope

Both build-based tools filter the checkout's `compile_commands.json` down to
the same fileset `_count_c_source` counts: under a curated cppcheck
`source_dir`, minus aurora-lint's `--exclude` globs. All five tools are then measured
over one denominator. Duplicate TUs are dropped (curl compiles `lib/` twice,
once for the shared and once for the static library), which would otherwise
inflate both the clock and the finding count. The filtered database is written
next to the run's other artifacts, so what was analysed is recoverable from
the results directory alone.

Findings outside the checkout root are discarded — a captured TU pulls in
`/usr/include`, and an alarm attributed to libc is not a finding about this
codebase.

### Counting

Alarms are counted as **distinct `(file, line, kind)`**. EVA re-reports the
same alarm from every entry point that reaches it, so a raw count would scale
with `FRAMAC_MAX_ENTRIES_PER_TU` rather than with the codebase: two runs at
different caps would not be comparable to each other, let alone to another
tool. `kind` is EVA's own alarm text (`out of bounds read`, `signed
overflow`, `division by zero`, …), which is the closest thing EVA has to a
rule id and is what the per-rule breakdown is keyed on.

## What a Frama-C row means

**It is a partial scan, and the run records how partial.** Every run writes a
`coverage` block into `<run_id>.framac.json`, mirrored into the run's
`.meta.json` whenever it is partial:

```json
"coverage": {
  "tus_total": 33, "entries_total": 121, "entries_analyzed": 105,
  "entries_pct": 86.8, "timeouts": 5, "failures": 9,
  "budget_s": 180, "budget_exhausted": false, "partial": true
}
```

That is a real lua run (`MAX_ENTRIES_PER_TU=4`, 180 s budget, 144.7 s used):
541 distinct alarms across 31 of 33 translation units, led by `unaligned
pointer creation`, `out of bounds read` and `non-finite double value`. Note
`partial` is true even though the budget was *not* exhausted — 5 entry points
timed out and 9 failed, so 105 of 121 were analysed. Budget exhaustion is one
way to be partial, not the only one.

`failures` is almost entirely translation units that cannot be preprocessed
because `setup-compile-commands.yml` deleted a generated header its own
compile database still references (libcrc's `tab/gentab32.inc` is the worked
example; tracked separately). An entry EVA aborted on is counted as a failure,
never as coverage.

Consequences that must travel with any published figure:

- **A finding count is a floor, never a total.** Unanalysed entry points hide
  alarms; a Frama-C count is not comparable to a cppcheck or aurora-lint count as a
  volume measure.
- **Precision is the only defensible cross-tool statistic here** — the
  fraction of what Frama-C *did* report that is real. That is unaffected by
  how much it did not reach.
- **Recall is not expressible at all** from a partial scan, and no Frama-C
  recall number should be published.
- **Two Frama-C runs are comparable only at identical knob settings and on
  identical hardware.** The budget is wall clock, so a faster node reaches
  more entry points and reports more alarms from the same source.
- **`coverage` is persisted, not just printed.** It lands in
  `<run_id>.framac.json`, in the run's `.meta.json`, and in the
  `realworld_results.coverage` column, so a row in the database cannot be read
  as a complete scan by mistake. The run line prints `PARTIAL <pct>%` too.

`entries_pct` belongs in any table that carries a Frama-C column.

## Why not the alternatives

**Whole-program EVA from each project's real `main()`.** Faithful to how
Frama-C is meant to be used, and it is what a Frama-C expert doing a
single-project audit would do. It also yields nothing here: libcrc, raylib and
seL4 have no `main`, and on curl, sqlite and hostap the analysis exhausts any
budget before reaching the oracle's scope. A table of six empty cells is worse
than a labelled partial one.

**Frama-C's `analysis-scripts` / `frama-c-script make-wrapper` workflow.** The
supported route for a real codebase, and the right answer if the goal were to
verify one project. It is an interactive, per-project effort — stubbing libc
usage, choosing entry points, iterating on precision — measured in
engineer-days per corpus, not a sweep. That is a research contribution about
Frama-C, not a measurement of aurora-lint.

**Skipping Frama-C on real-world code.** What the suite did until this task,
and it left `docs/tool-comparison.rst` comparing five tools on Juliet and
three on real code — with the one benchmark that answers "how does it do on
code someone actually shipped" missing its two strongest competitors.

## Cost

Frama-C is the expensive tool by a wide margin, which is why the default
budget is a ceiling rather than a target. For scale, on the existing suite:
cppcheck's run-215 sweep of 8 projects took 11,452 s against aurora-lint's ~491 s, and
Frama-C's 6-CWE Juliet run alone took 9,914 s. A five-tool real-world sweep is
a multi-hour job and wants scheduling through `benchmarking_db`'s queue rather
than a local invocation.

## Version note

The published competitor Juliet runs used Frama-C **32.0 (Germanium)**;
`playbooks/install-static-analyzers.yml` installs whatever opam currently
resolves, which as of 2026-09-04 is **33.0 (Arsenic)**. The runner records the
version it actually saw in the `run_id`, so the difference is visible in the
data — but a single-date, single-version table still needs the re-run tracked
as task 768.
