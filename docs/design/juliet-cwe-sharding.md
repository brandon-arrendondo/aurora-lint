# Scoping: Sharding the long-pole Juliet CWEs

**Status:** SCOPED, NOT IMPLEMENTED (2026-08-27). Tracked as task 388 (P4,
`benchmark`). This document was written on the **work node**, which has no
Juliet suite (`~/toolchain/benchmarks/` absent) and an empty
`data/benchmarks.db` (0 runs, 0 `cwe_scans`). Everything below marked
**[verified]** was read out of the source in this repo and is reliable.
Everything marked **[MEASURE]** is an assumption the benchmark node must
confirm *before* writing code — several of them can invalidate the whole
approach, so do them first (§6).

**Driver:** Juliet wall time is `max(single_CWE_duration)`, not
`sum(all_durations)/jobs`. 12 jobs buys ~4.9x. Adding jobs cannot help.

---

## 1. Problem statement

`bench/runner.py:307-315` submits exactly one `ProcessPoolExecutor` future
per CWE directory, and `_scan_single_cwe` pins the child to `-j 1`
(`bench/runner.py:130`) with the comment "single-threaded: runner
parallelizes at CWE level". **[verified]** So one CWE is one indivisible
serial unit of work.

Per task 388's 2026-07-28 timing analysis (v0.4.126-v0.4.169), three CWEs
consume nearly the entire wall-clock budget on their own:

| CWE     | Files | Duration      |
|---------|------:|---------------|
| CWE-121 Stack Overflow    | 5906 | ~2100-2300s |
| CWE-78 Command Injection  | 5600 | ~1950s      |
| CWE-190 Integer Overflow  | 5040 | ~1600-1740s |

Once the other ~76 CWEs drain, workers idle against this handful. Classic
long-pole/straggler.

### 1a. What `duration_s` actually measures

`start_time` is taken at `bench/runner.py:121` and `duration_s` is computed
at line 135, **immediately after `subprocess.run` returns and before
`analyze_cwe` is called**. **[verified]** So the numbers above are *aurora-lint
subprocess time only*.

This scope is already documented and honestly surfaced — no bug here:
`bench/db.py:635-642` states `analysis_s` "sums each CWE's own
aurora-lint-subprocess duration (each including its own prescan+scan)" and notes it
normally exceeds `wall_s` under parallelism; `bench/db.py:330-332` repeats
it; `bench/__main__.py:116` prints "summed per-CWE aurora-lint time". **[verified]**

The residue that *does* matter for this work is narrower: the **Python
analysis phase** (`analyze_cwe`, which re-reads and re-parses every `.c`
file in the CWE) is not separately timed anywhere. It is excluded from
`analysis_s` and conflated with scheduling idle inside `wall_s`, so its
size is unknown.

Two consequences:

- The long pole in `duration_s` is genuinely the Rust scan, so sharding the
  aurora-lint invocation is aimed at the right thing.
- If the Python phase turns out to be a large fraction of per-CWE wall
  time, it is a *second* long pole that sharding the subprocess alone will
  not fix, and the shard design must fan out the analysis too (it can — see
  §3). Time it before trusting any speedup projection (§6.0).

---

## 2. The shard boundary already exists

`bench/analyzer.py:299-304` **[verified]**:

```python
# Find all C files (handle subdirectory layout like CWE-121)
subdirs = sorted(cwe_dir.glob('s*'))
if subdirs and subdirs[0].is_dir():
    search_dirs = subdirs
else:
    search_dirs = [cwe_dir]
```

Large Juliet CWEs ship pre-split into `s01/`, `s02/`, … subdirectories, and
the analyzer already walks them as independent units. That is the natural
shard boundary: **one pool slot per `sNN`**, no synthetic file grouping
needed.

**[MEASURE]** Confirm which of CWE-121/78/190 actually have `sNN` subdirs
and how many each has — this sets the achievable shard count. The comment
above only proves CWE-121 does. If a long-pole CWE is flat, use the
fallback in §5.

## 3. The metrics math shards cleanly

Every counter `analyze_cwe` accumulates is additive, and every rate is
derived once at the end. **[verified]**

- Additive per-file counters: `tp_count`, `fp_count`, `flaw_lines_total`,
  `flaw_lines_detected`, `cwe_matched_tp`, `cwe_matched_fp`, `noise_count`,
  `flaw_hit_detected`, `files_analyzed`, the `violations` list, and the
  `rule_tp`/`rule_fp`/`rule_flaw` defaultdicts.
- Loop-local additive accumulators: `files_with_bad_section`,
  `files_detected`, `total_flaw_lines_for_hit`.
- Derived-at-the-end only: `_finalize_cwe_rates` (`bench/analyzer.py:425`)
  computes `tp_rate_pct`, `flaw_detection_rate_pct`, `noise_ratio`,
  `per_file_rate`, `flaw_hit_rate`; `_build_rule_breakdown`
  (`bench/analyzer.py:453`) folds the per-rule dicts.

So the refactor is mechanical:

1. Extract the `for search_dir in search_dirs:` body
   (`bench/analyzer.py:316-330`) into `analyze_shard(csv_path, search_dir,
   cwe_id, cwe_scan_id) -> ShardPartial`, returning the raw counters
   **without** calling either finalizer.
2. Add `merge_shards(partials) -> CWEAnalysis` that sums the counters,
   concatenates `violations`, merges the rule dicts, then calls
   `_finalize_cwe_rates` and `_build_rule_breakdown` **exactly once**.
3. `analyze_cwe` becomes `merge_shards([analyze_shard(d) for d in
   search_dirs])` — identical behaviour for the unsharded path, which is
   what makes the equivalence gate in §6.3 meaningful.

**Do not** recompute rates per shard and average them. The rates are
ratios of summed counters; averaging ratios is wrong and will silently
skew every metric the paper cites.

### 3a. Filename keying is safe under sharding

`parse_sqc_csv` keys violations by bare filename (`c_file.name`,
`bench/analyzer.py:348-349`), not full path. **[verified]** Under
sharding each shard analyzes only its own directory against its own CSV,
so a same-named file in a sibling shard cannot be mis-attributed —
sharding is strictly *safer* here than the monolithic path. (The
monolithic path's latent same-name collision risk across `sNN` dirs is
pre-existing and out of scope.)

---

## 4. The prescan is the make-or-break constraint

Today each CWE scan passes `-d <cwe_dir> -d <testcasesupport>`
(`bench/runner.py:127-129`) **[verified]**, so aurora-lint prescans the whole CWE
for cross-file context. **Naively sharding makes all N shards repeat that
full-CWE prescan, which can eat the entire gain** — this is the single
most likely way for this work to produce a disappointing result.

aurora-lint already has the escape hatch: `--save-prescan` / `--load-prescan`,
documented as "Load prescan context from cache instead of scanning -d
directories". **[verified]** In `src/analyze/mod.rs:261-287`, `load_prescan`
short-circuits `prescan_directories` entirely and deserializes the same
`ProjectContext`; `save_prescan` writes it at `src/analyze/mod.rs:300-308`.
Since the bench passes no `-I`, `resolve_includes`
(`src/analyze/mod.rs:290-297`) is skipped, so a loaded context is
equivalent to a freshly prescanned one.

### 4a. There is no standalone prescan mode

`--save-prescan` is a side effect *inside* `load_project_context`, reached
only on a real analysis run. **[verified]** You cannot ask aurora-lint to "just
prescan". Two ways to live with that:

- **Warm step (recommended).** Before fanning out a big CWE, run one cheap
  invocation whose PATH is a single `.c` file but whose `-d` is the whole
  CWE dir, with `--save-prescan`. The prescan follows `-d`, not PATH, so
  this produces the full-CWE context at the cost of one prescan plus one
  file's analysis. Then every shard runs with `--load-prescan` and **no**
  `-d`.
- **Piggyback (rejected).** Let shard 0 carry `--save-prescan` and have the
  others poll for the file. The cache is written before the analysis phase,
  so it does appear early — but it makes shard startup racy and
  order-dependent for no real saving. Don't.

The warm step is serial per CWE. That is fine: it costs one prescan where
the status quo pays N of them, and it only applies to the handful of CWEs
big enough to shard.

**[MEASURE]** The prescan fraction of a big CWE's `duration_s`. This is the
number that decides whether the whole task is worth doing. Get it with
`-v` (per-rule scanning progress) or by timing a `--save-prescan` warm run
against a full run on CWE-121. If prescan is a large majority of the 2100s,
sharding the analysis buys much less than the file counts suggest and the
task should be reconsidered rather than implemented.

---

## 5. Fallback for a flat long-pole CWE

If §2's measurement shows a long-pole CWE has no `sNN` split, aurora-lint's CLI
gives no way to pass a file list — PATH is "a file, directory, or git
repository" **[verified]**, and `--exclude` is subtractive-only, so
expressing "just this bucket" needs one exclude glob per non-member file.
Unworkable.

Use a **symlink farm**: deterministically bucket the CWE's `.c` files into
N groups, materialize each bucket as a temp dir of symlinks, point a shard's
PATH at it, and keep `--load-prescan` for context. Cheap, reliable, and it
composes with §4. Note that the analyzer's shard must then be pointed at
the *real* files for section parsing, not the symlink dir, or resolve the
symlinks first.

---

## 6. Order of work (measure before coding)

- **6.0** Time the Python `analyze_cwe` phase — as its own column, or at
  minimum logged. It is the one piece of per-CWE cost nothing currently
  measures (§1a), and its size decides whether §3's fan-out has to cover
  the analysis as well as the subprocess.
- **6.1** Measure the prescan fraction on CWE-121 (§4). **Gate:** if
  prescan dominates, stop and re-scope.
- **6.2** Confirm `sNN` presence and count for CWE-121/78/190 (§2).
- **6.3** Implement §3's analyzer split + §4's warm step. **Acceptance gate:
  a sharded run and a monolithic run of the same CWE at the same commit must
  produce a byte-identical violation set and identical `cwe_metrics` row.**
  Anything less and the benchmark's numbers are no longer comparable to the
  46 historical runs — which matters more than the speedup.

### 6a. Phase 0: free win, independent of all of the above

`work_items` already carries `file_count` (`bench/runner.py:278-280`)
**[verified]**, but items are submitted in sorted-CWE-name order
(`bench/runner.py:272`, `309`). `ProcessPoolExecutor` dispatches in
submission order, so **sorting `work_items` by `file_count` descending
before the submit loop** is longest-processing-time-first scheduling: a
one-line change, no correctness risk, no schema impact, and it shortens the
tail on its own by making sure the big CWEs start at t=0 instead of
whenever their name comes up. Do this regardless of whether sharding
proceeds.

---

## 7. Schema and resume constraints (do not break these)

- `cwe_scans` has `UNIQUE(run_id, cwe_dir_name)` — **one row per CWE per
  run**. **[verified]** Shards must aggregate into that single row, not
  insert rows of their own. Adding shard rows would break `compare_runs`,
  `get_cwe_detail`, and the historical-run comparisons.
- Resume is per-CWE: `get_completed_cwes` (`bench/db.py:412`) selects
  `cwe_dir_name` where `status='completed'`, and `create_cwe_scan`
  (`bench/db.py:371-389`) resets a partial row and purges its child rows in
  `violations` / `cwe_metrics` / `rule_cwe_breakdown`. **[verified]** Keep
  resume granularity at the CWE level — a half-finished CWE re-runs all its
  shards. Shard-level resume is not worth the schema churn for a P4.
- `violations` rows carry `cwe_scan_id`; all shards of a CWE share the one
  scan_id. No change needed.

---

## 8. Scope notes carried from task 388

- CWE-count growth (74 → 79, from v0.4.139) driving part of the wall-time
  increase is **expected and fine** — not what this task is about.
- This is Juliet-only. Real-world runs cap out near 10 minutes on the
  largest codebases; no sharding needed there.
- P4: iteration-speed convenience, not a blocker. If §6.1's gate fails,
  closing the task as "measured, not worth it" is a perfectly good outcome
  — record the prescan number in the task either way, since it's useful
  independent of this work.

---

## 9. Protocol reminder

Per `CLAUDE.md`: never modify code while a benchmark is running (the
benchmark executes `target/release/aurora-lint`), and bump version + commit +
`cargo build --release` *before* starting any run. The measurements in §6
require running aurora-lint against Juliet, so sequence them against benchmark
occupancy on that node.
