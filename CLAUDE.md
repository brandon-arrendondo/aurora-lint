# Claude Code Project Instructions

## /work-active Workflow (CONDITIONAL)

**ONLY follow this workflow IF:**
- Current git branch matches pattern `claude-work-active-*` (check with `git branch --show-current`)
- OR you're explicitly working on proposals from `AGENTS/PROPOSALS/ACTIVE/`
- OR the user invoked `/work-active` earlier in this session

**If NOT in a /work-active session, ignore this section.**

When working on proposals from `/work-active` command (implementing CERT C rules):

**IMPORTANT: On every continuation (especially after context compaction):**
- ALWAYS re-read your current active proposal before continuing work
- Verify you're following the Implementation Constraints section
- Check Implementation Log to see what's already been completed

```bash
# Re-read current proposal (replace with actual file path)
cat AGENTS/PROPOSALS/ACTIVE/{SELECTED_SUBDIR}/{CURRENT_PROPOSAL}.md
```

### For EACH Rule Implementation

1. Create `src/rules/cert_c/CATEGORY/RULE_ID/rule_id_c.rs`
2. Register in `mod.rs` and enable in the TOML
3. Build and test
4. Commit and move proposal to STAGED

### Implementation Rules (CRITICAL)

**NEVER add embedded unit tests in rule implementation files:**
- ❌ NO `#[cfg(test)]` modules in `src/rules/cert_c/*/*/*.rs` files
- ❌ NO inline test functions with hardcoded C code snippets
- ✅ Test cases come from `.c` files in `tests/` directory (auto-generated into Rust tests)
- ✅ If no test cases exist for a rule, implement WITHOUT tests (this is acceptable)

**Why:**
- Embedded tests are redundant (same stub pattern with different hardcoded C)
- Poor separation of responsibilities (implementation vs. testing)
- Test infrastructure auto-generates tests from `.c` files

**If this workflow wasn't followed earlier in the session, start following it NOW.**

---

## /gather-opinions Workflow (CONDITIONAL)

**ONLY follow this workflow IF:**
- Current git branch matches pattern `opinions/*` (check with `git branch --show-current`)
- OR the user invoked `/gather-opinions` earlier in this session

**If NOT in a /gather-opinions session, ignore this section.**

### Branch Name Format
```
opinions/{persona-slug}-{reviewer}-{date}
```

### On Every Continuation (CRITICAL - After Context Compaction)

**Step 1: Detect workflow from branch name**
```bash
git branch --show-current
# If matches opinions/*, you are in /gather-opinions workflow
```

**Step 2: Extract persona from branch and re-read persona file**
```bash
# Parse persona slug from branch name (between opinions/ and reviewer name)
# Then read the matching persona file from AGENTS/PERSONAS/
cat AGENTS/PERSONAS/{matching-persona}.md
```

**Step 3: Re-read the workflow definition (source of truth)**
```bash
cat .claude/commands/gather-opinions.md
```

**Step 4: Check TodoWrite state for current progress**
- The TodoWrite tool persists across compaction
- Expect exactly 6 todos:

  *Workflow steps for current proposal:*
  1. "LOCK + Read proposal {PROPOSAL}" - `in_progress` or `completed`
  2. "Read ALL related_files for {RULE_ID}" - `pending`, `in_progress`, or `completed`
  3. "Form opinion on {PROPOSAL}" - `pending`, `in_progress`, or `completed`
  4. "Record + commit + UNLOCK {PROPOSAL}" - `pending` or `in_progress`

  *Tracking:*
  5. "Next: {NEXT_PROPOSAL}" - `pending`
  6. "Progress: N/TOTAL reviewed" - `in_progress`

- **⚠️ Do NOT modify this structure or batch proposals** - it enables recovery
- Resume from whichever workflow step (1-4) is `in_progress`
- If todos have deviated from this structure, reset to correct format before continuing
- **CRITICAL:** Step 2 requires reading ALL files in `related_files` frontmatter - no skipping

**Anti-pattern to watch for:** If Claude starts batching proposals or modifying the 6-todo structure for "efficiency," this BREAKS the workflow. The number of proposals is irrelevant - never batch, regardless of scale.

**Step 5: Continue the workflow as defined in gather-opinions.md**

### Why This Matters

- Branch name encoding enables workflow recovery after compaction
- Re-reading persona file ensures consistent analysis perspective
- gather-opinions.md is the single source of truth for workflow steps
- TodoWrite tracking ensures no proposals are skipped across compactions

**If this workflow wasn't followed earlier in the session, start following it NOW.**

---

## Benchmark Workflow (CRITICAL)

See `docs/index.rst` (Benchmark Setup / Running Benchmarks sections) for full MCP server tool reference and troubleshooting.

### Data Storage

All benchmark results are stored in **`data/benchmarks.db`** (SQLite, WAL mode).
This is the single source of truth for Juliet and real-world benchmark data.
Historical results from `JULIET_RESULTS.md` and `REALWORLD_RESULTS.md` have been
backfilled. New runs write directly to this database.

**Key tables**: `runs` (one row per benchmark), `cwe_scans` (one per CWE per run),
`violations` (every individual finding), `cwe_metrics` (pre-computed TP/FP/rates),
`rule_cwe_breakdown` (per-rule per-CWE counts), `realworld_runs` + `realworld_results`.

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

3. **Wait for completion**: Fast-mode Juliet benchmarks take ~13-19 minutes
   (avg 15.5). Real-world sqc-only takes ~10-15 minutes. Full Juliet suite
   takes ~40-50 minutes. Check status with `get_status()` no more than once
   every 5 minutes.

4. **Compare runs**: After a benchmark completes, use `compare_runs()` to compare
   against previous runs. Use `get_cwe_detail()` for per-CWE deep dives.
   Historical runs are available with suffix `-historical` (e.g., `sqc-0.3.17-historical`).

5. **Workflow sequence**:
   ```
   implement changes → bump version → commit → build release → run benchmark → wait → analyze
   ```

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
| `REALWORLD_RESULTS.md` | Real-world codebase results (5 projects × 3 tools) |
| `docs/index.rst` | Developer guide: advanced usage, CI/CD, benchmarks, testing, contributing |

---

## Project Structure

- `src/rules/cert_c/` - CERT C rule implementations
- `src/analyze/` - Analysis infrastructure (CFG, null state, VRA, prescan)
- `bench/` - Benchmark infrastructure (runner, analyzer, SQLite DB, CLI)
- `mcp_servers/` - MCP servers for Juliet and real-world benchmarks
- `data/` - Benchmark database (benchmarks.db), prescan caches
- `scripts/` - Workflow helpers, coverage gate
- `docs/` - Developer guide (index.rst), bibliography
- `AGENTS/PROPOSALS/ACTIVE/` - Proposals to implement
- `AGENTS/PROPOSALS/STAGED/` - Completed proposals

## Build & Test

```bash
cargo build
cargo test --package sqc --lib -- rules::cert_c::RULE_ID::tests  # inline unit tests
cargo test --package sqc --lib -- RULE_ID  # all tests (inline + generated from .c files)
cargo fmt
```

## Git Commit Rules (CRITICAL)

**EXPLICITLY DENIED:**
- `git commit --no-verify` - NEVER use this flag. Pre-commit hooks MUST pass. Only humans can skip hooks.
- `Co-Authored-By: Claude` - NEVER add Claude as co-author. This is a corporate repository.
- Any hook-skipping flags (`--no-gpg-sign`, etc.)

**REQUIRED:**
- All pre-commit hooks must pass before commit succeeds
- If hooks fail, FIX the underlying issue (don't bypass)
- Standard commit message format without AI attribution

**Example Commit:**
```bash
git add files...
git commit -m "P2-RULE-ID: Implementation complete

- Brief description of changes
- Test results"
```
