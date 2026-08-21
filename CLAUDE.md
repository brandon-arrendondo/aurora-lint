# Claude Code Project Instructions

## Benchmark Workflow (CRITICAL)

See `docs/index.rst` (Benchmark Setup / Running Benchmarks sections) for full MCP server tool reference and troubleshooting.

### Data Storage

All benchmark results are stored in **`data/benchmarks.db`** (SQLite, WAL mode).
This is the single source of truth for Juliet and real-world benchmark data.
Historical results from `JULIET_RESULTS.md` and `REALWORLD_RESULTS.md` have been
backfilled. New runs write directly to this database.

**Key tables**: `runs` (one row per benchmark), `cwe_scans` (one per CWE per run),
`violations` (every individual finding), `cwe_metrics` (pre-computed TP/FP/rates),
`rule_cwe_breakdown` (per-rule per-CWE counts), `realworld_runs` + `realworld_results`,
`ground_truth` (adjudicated real-world TP/FP oracle keyed on project+commit+file+line+rule;
`python -m bench realworld-score RUN` for measured precision/recall).

### Running Benchmarks

The MCP server (`mcp_servers/server.py`) launches `python -m bench juliet` which:
- Uses **fast mode by default** (per-CWE manifests, CWE-matched rules only)
- Runs CWEs in parallel via `ProcessPoolExecutor`
- Writes results directly to SQLite (no intermediate text files)
- Supports resume: re-running skips already-completed CWEs

CLI alternative (not through MCP):
```bash
python -m bench juliet [--full] [--jobs N]
python -m bench status [RUN_ID]
python -m bench compare BASE TARGET
python -m bench runs
```

### Protocol

1. **Version bump + commit BEFORE benchmark**: Always bump the version in `Cargo.toml`,
   rebuild (`cargo build --release`), and commit before starting a benchmark run.
   The run_id is derived from version + commit SHA (e.g., `sqc-0.3.20-abc1234`).

2. **NEVER modify code while a benchmark is running**: The benchmark uses
   `target/release/sqc`. If you rebuild while it's running, you corrupt results
   mid-run. Make ALL code changes and commits BEFORE starting the benchmark.

3. **Wait for completion**: Fast-mode Juliet benchmarks take ~32-40 minutes.
   Real-world sqc-only takes ~10-15 minutes. Full Juliet suite
   takes ~40-50 minutes. Check status with `get_status()` no more than once
   every 5 minutes.

4. **Compare runs**: After a benchmark completes, use `compare_runs()` to compare
   against previous runs. Use `get_cwe_detail()` for per-CWE deep dives.
   Historical runs are available with suffix `-historical` (e.g., `sqc-0.3.17-historical`).

5. **Workflow sequence**:
   ```
   implement changes → bump version → commit → build release → run benchmark → wait → analyze
   ```

6. **Delta-adjudicate before citing precision/recall for a changed rule (CRITICAL)**:
   `ground_truth` is keyed on exact `(project, commit, file, line, rule)` tuples,
   adjudicated at a specific past audit's snapshot. When a rule's detection logic
   changes (any commit touching `src/rules/cert_c/**/*.rs` that alters what it
   flags — not a pure refactor), its new findings land at `(file, line)` pairs
   that were **never adjudicated**, so they're silently excluded from the
   precision/recall denominator in either direction. A raw-count jump or a
   flat "precision held" number computed only over the labeled sample can
   both look clean while the real picture is unmeasured underneath. Before
   writing "precision improved/held" or "FP reduced" into a commit message,
   task note, or the paper for a changed rule:
   - Pull the new unlabeled findings for that rule only:
     `bench realworld-unlabeled RUN --rule RULE_ID --project P --json`
     (repeat per affected project, or omit `--project` and split after).
   - **Derive each project's in-scope file predicate from its own
     `data/precision_audit/<project>/README.md` BEFORE batching** — not
     after. Task 420's delta-adjudication found 2,548 of 4,026 (63%) raw
     unlabeled findings were out-of-scope noise (test harnesses, vendored
     deps, language bindings) that should never have been batched; mosquitto
     alone was 73% contamination. Scoping after the fact means redoing
     already-completed adjudication batches.
   - Batch (~110-150 findings/batch), adjudicate, and import via
     `bench realworld-import-labels` — same workflow as a fresh oracle build.
     See `data/precision_audit/DELTA_MEM31_TASK420.md` for a fully worked
     example (6 projects, 14 batches, 1,478 findings, 0.7% delta precision —
     a very different number than the aggregate raw-count comparison
     suggested).
   - Only after that pass is ground_truth updated for the new lines should a
     precision/recall claim about the changed rule be published.

### Querying Results

The MCP tools (`get_results`, `get_cwe_detail`, `compare_runs`, `list_runs`) query
SQLite first, falling back to legacy text files for old runs. 46 Juliet runs
(v0.2.1 through current) and 21 real-world runs are in the database.

---

## Task tracking

This repo uses `todo-sqlite-cli` for TODOs. The DB path is resolved via the
`.todo-sqlite-cli` marker at the repo root.

**Before planning or coding, ask the DB:**

- `todo-sqlite-cli next` — the single task to work on right now.
- `todo-sqlite-cli list` — all active (in-progress + pending), in-progress
  first then by priority.
- `todo-sqlite-cli show <id>` — full task detail.
- Every command supports `--json`.

**When picking up work:** `todo-sqlite-cli start <id>` before coding,
`todo-sqlite-cli done <id>` when committed.

**When a new task surfaces:**
`todo-sqlite-cli add "title" --details "..." --tag <area> --priority <1-5>`
(1 = highest). `--depends-on <id>` links prerequisites; tasks with unmet
deps are skipped by `next` and shown `[blocked]` in `list`.

Original task IDs (prior to the 2026-04-20 import) are preserved
as `plan-id:NN` tags; CLI IDs are independent AUTOINCREMENT integers.

**Release history** also lives in the DB — each CHANGELOG entry is a
`release`-tagged done task with `completed_at` set to the release date.
Rebuild a changelog with `todo-sqlite-cli export-completed` (bound by
`--since`/`--until`), or slice by section with
`todo-sqlite-cli list --status done --tag changed`
(also: `benchmark`, `added`, `fixed`, `task`).

---

## Documentation

| File | Contents |
|------|----------|
| `README.md` | Tool overview, installation, usage, CLI reference |
| `JULIET_RESULTS.md` | Juliet benchmark data by sqc version |
| `REALWORLD_RESULTS.md` | Real-world codebase results (7 projects × 3 tools) |
| `docs/index.rst` | Developer guide: advanced usage, CI/CD, benchmarks, testing, contributing |
| `docs/design/*.md` | Scoping docs for in-progress/completed capabilities (e.g. macro-expansion, project-relevance-gating). Not in the Sphinx toctree — read directly. **Their "Status" header goes stale once the work ships**; check `todo-sqlite-cli show <task>` for the real status before trusting the header, and check whether the feature needs a mention in `docs/cli-usage.rst`/`docs/architecture.rst` once it ships. |
| `docs/design/internal-capability-catalog.md` | Browsable-by-concept catalog of every reusable primitive in `src/utility/cert_c/*.rs`/`src/analyze/*.rs` (macro detection, declarator resolution, lvalue/aliasing, VRA, CFG, function summaries, suppression, cross-file `ProjectContext`). Read this before writing any new AST/text heuristic — see Code Navigation below. |

---

## Project Structure

- `src/rules/cert_c/` - CERT C rule implementations
- `src/analyze/` - Analysis infrastructure (CFG, null state, VRA, prescan)
- `bench/` - Benchmark infrastructure (runner, analyzer, SQLite DB, CLI)
- `mcp_servers/` - MCP servers for Juliet and real-world benchmarks
- `data/` - Benchmark database (benchmarks.db), prescan caches
- `scripts/` - Workflow helpers, coverage gate
- `docs/` - Developer guide (index.rst), bibliography

## Code Navigation (clew)

This repo is indexed by [`clew`](https://github.com/tvanfossen/clew), registered as
the `clew` MCP server in `.mcp.json` (gitignored — each machine runs its own
`clew init --repo-root <path-to-this-repo>` once; see the clew repo's README).
It builds a queryable symbol database (call graph, threads, locks, requirements,
file docs) from rustdoc + tree-sitter, served over four tools: `dossier` (everything
about one named symbol — signature, body, callers/callees, locks held, in one call),
`search` (find a name, or a whole layer like `corpus='locks'`/`corpus='threads'`),
`index` (admin: `status`/`refresh`), `propose_declaration`.

**Prefer `dossier`/`search` over `grep`/`Read` for "what calls X", "where is Y
defined", "what locks does this function hold" style questions** — one call
instead of several, and it already has the call graph resolved. Fall back to
reading source directly for anything the index can only point at (exact comment
text, line-by-line logic).

Rebuild after non-trivial changes: `clew --output <db path from index(action='status')> --repo-root . --rebuild`.
The MCP tools also offer to build/refresh on first use if no index exists yet.

**Before implementing any new AST/text heuristic, check
`docs/design/internal-capability-catalog.md` first** (task 479, filed after
task 475 nearly re-implemented DCL40-C's `is_defined_macro_name`/
`ProjectContext::defined_macro_names` cross-file macro-detection as a fresh
ALL_CAPS-name heuristic — a plain keyword grep for "macro detection" missed
it on the first pass). That catalog exists precisely because `search` does
literal token-conjunction matching: it finds `is_defined_macro_name`
instantly when queried with words close to its own doc comment, but returns
nothing useful for a vague concept phrase that doesn't appear verbatim
anywhere. If the catalog doesn't cover it, try `dossier`/`search` with
vocabulary close to an actual function/doc-comment wording, then grep
`src/utility/cert_c/` and `src/analyze/` directly by what the primitive
*does* — this has caught real scoping bugs before (ARR39-C task 146,
CON34-C task 385).

## Build & Test

```bash
cargo build
cargo test --package sqc --lib -- rules::cert_c::RULE_ID::tests  # inline unit tests
cargo test --package sqc --lib -- RULE_ID  # all tests (inline + generated from .c files)
cargo fmt
```

## Rule Implementation

**NEVER add embedded unit tests in rule implementation files:**
- ❌ NO `#[cfg(test)]` modules in `src/rules/cert_c/*/*/*.rs` files
- ❌ NO inline test functions with hardcoded C code snippets
- ✅ Test cases come from `.c` files in `tests/` directory (auto-generated into Rust tests)
- ✅ If no test cases exist for a rule, implement WITHOUT tests (this is acceptable)

For each new rule:
1. Create `src/rules/cert_c/CATEGORY/RULE_ID/rule_id_c.rs`
2. Register in `mod.rs` and enable in the TOML
3. Build and test

**Before writing a fix for a macro-related false positive/negative**, check
whether `src/analyze/macro_expand.rs` already solves it — do NOT reach for a
name-heuristic workaround first. sqc has a real, name-independent
macro-expansion engine (`collect_function_macros`, `macro_nulls_param_indices`
for "safe free" macros that free+null their arg, `macro_output_param_indices`
for output-param macros), already wired into MEM30-C, MEM31-C, EXP33-C, and
DCL31-C. See `docs/design/macro-expansion.md` for the full design rationale
and a per-rule disposition table (which rules are already on the engine,
which are legitimately definition-side and should stay off it). Its
"Status" line at the top is stale (says "no implementation yet" from the
original scoping date) — trust the phase stock-takes further down the file,
not that header.

## Git Commit Rules (CRITICAL)

**EXPLICITLY DENIED:**
- `git commit --no-verify` - NEVER use this flag. Pre-commit hooks MUST pass. Only humans can skip hooks.
- `Co-Authored-By: Claude` - NEVER add Claude as co-author. This is a corporate repository.
- Any hook-skipping flags (`--no-gpg-sign`, etc.)

**REQUIRED:**
- All pre-commit hooks must pass before commit succeeds
- If hooks fail, FIX the underlying issue (don't bypass)
- Standard commit message format without AI attribution
