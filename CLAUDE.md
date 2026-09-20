# Claude Code Project Instructions

Full CLI reference and troubleshooting live in `docs/index.rst` (Benchmark
Setup / Running Benchmarks). This file holds only what changes what you *do*.

---

## Benchmark Workflow (CRITICAL)

Policy record: `docs/adr/0004-postgres-is-the-single-source-of-truth.md`.
What follows is the mechanics.

### Where benchmark data lives

**Every OFFICIAL number comes from the `sqc_bench` Postgres instance**, reached
through the separate **`benchmarking_db`** repo. "Official" means anything
published as this project's measurement — README, the paper, a release note,
any claim made outside. It is the sole source of truth for both historical
benchmark data and adjudication data. If a run is meant to count as ours, it is
queued through `benchmarking_db` and lands in Postgres.

**Running benchmarks locally is fully supported.** A fresh clone gets a working
setup from `cargo build --release` plus the checkouts in
`docs/benchmark-setup.rst`, and may capture results however it likes.
`data/benchmarks.db` has no special standing over a CSV — it is this checkout's
record of its own runs. So a figure computed from it describes *those runs*,
not the project's measurements, and must never be transcribed into a published
document or cited as a project result.

**The test for any new benchmarking/measurement code: would a stranger cloning
this repo need it to evaluate aurora-lint on their own codebase?** If no, it
belongs in
`benchmarking_db`. Two corollaries:

- Do not reintroduce a local mirror, cache, or sync of benchmark data for speed
  or offline use. That paradigm was deliberately abandoned: it restores a
  per-node copy of a corpus this checkout alone already fills 6.5 GB with, and
  adds a second thing that can go stale or disagree. Centralizing in Postgres
  is what makes a worker node disposable.
- Do not add maintainer-workflow machinery here to save a hop. Multi-node
  coordination, shared-instance credentials, queue plumbing and cross-machine
  reconciliation are `benchmarking_db`'s.

**This repo stays Postgres-blind**: no DSN, no connection code, no awareness of
the shared instance in anything you add. That seam is what keeps `bench/`
usable by a fresh clone. See `benchmarking_db/docs/ownership.md` for what that
repo owns.

**The adjudication dataset** (TP/FP/FN labels, `(project, codebase_commit,
file_path, line, rule_id)`-keyed) lives in its own repo, `benchmark_adjudication`
— PR-gated, SHA-pinned provenance, reviewed for disclosure-safety per commit
before merge (see `docs/adr/0007`). It is a standalone dataset, not a copy of
this repo's working data: `ground_truth` in Postgres is exported into it via
`benchmarking_db`'s `bin/export_ground_truth_to_adjudication_repo.py`. Do not
put it, or a mirror of it, in this repo.

### Local SQLite storage (the local-run path)

A local run writes to **`data/benchmarks.db`** (SQLite, WAL) — gitignored, so
no clone inherits anyone else's.

**Tables**: `runs` (one per benchmark), `cwe_scans` (one per CWE per run),
`violations` (every finding), `cwe_metrics` (precomputed TP/FP/rates),
`rule_cwe_breakdown`, `realworld_runs` + `realworld_results`, `ground_truth`
(local adjudication store — **not** the oracle; the oracle is
`benchmarking_db`'s, which is why `realworld-import-labels` requires
`--local-oracle`: writing here is something you state, not fall into).

### Running benchmarks

Everything runs synchronously in your terminal — no server, no polling.
`python -m bench juliet` uses fast mode by default (per-CWE manifests,
CWE-matched rules), runs CWEs in parallel, writes straight to SQLite, and
resumes by skipping completed CWEs.

```bash
python -m bench juliet [--full] [--jobs N]
python -m bench status [RUN_ID]
python -m bench compare BASE TARGET
python -m bench runs
python -m bench corpus-check   # are the real-world checkouts still pinned?

# Real-world: sqc + cppcheck + clang-tidy against real C codebases, local and
# sequential (bench/realworld_runner.py). Defaults to sqc against every
# codebase; narrow with --tool/--codebase.
python -m bench realworld-run [--tool sqc,cppcheck,clang-tidy] [--codebase C,C]
python -m bench realworld [RUN]        # FP dashboard
python -m bench realworld-score [RUN]  # measured precision/recall vs oracle
```

**Run `corpus-check` before any real-world run or precision claim.** Pins live
in `data/benchmark_repos.json` (shared with
`playbooks/setup-benchmark-repos.yml`), but provisioning pins a checkout once
and nothing holds it there — a `git pull` on a tracking branch drifts it
silently, and the runner records whatever SHA it finds rather than asserting
the expected one. Since `ground_truth` is keyed on
`(project, commit, file, line, rule)`, findings from a drifted tree fall out of
the precision/recall denominator with no error. The check exits nonzero and
prints the `git checkout --detach` fix per row. It also flags untracked **and
gitignored** `*.c`/`*.h` files: aurora-lint dispatches on file extension and
never
consults git, so a build run inside a checkout (e.g. sqlite's generated
`sqlite3.c` amalgamation) contaminates a scan while staying invisible to
`git status`.

### Protocol

1. **Commit BEFORE benchmarking. Do NOT bump the version** unless Brandon asks.
   Rebuild (`cargo build --release`) and commit — and push, if the run goes
   through `benchmarking_db`'s queue, which fetches from origin and never from
   your working tree.

   Why no bump: `run_id` is `sqc-{version}-{sha}`, so the **SHA** is what
   discriminates runs; the version added readability only. With several nodes
   committing in parallel a per-task bump collides constantly and **silently** —
   both sides write the same string, so git reports no conflict and `doctor`
   only checks display ids. Version numbers are a **release** artifact.

   **The binary is `aurora-lint`; the benchmark tool id is still `sqc`.** The
   crate and binary were renamed, but `realworld_results.tool`, the
   `runs.sqc_version` column and the `sqc-{version}-{sha}` run_id prefix all
   stay `sqc`, because Postgres rows and `ground_truth`'s
   `(project, commit, file, line, rule)` keys are written that way. Renaming
   the identifier forks the namespace and silently drops every historical row
   out of comparison. Do not "fix" the `"sqc"` literals in `bench/`.

   **Consequence to accept:** address a real-world run by its integer id and a
   Juliet run by its full run_id or SHA. A bare version string is now
   ambiguous and quoting one without a SHA is meaningless — say
   `0.4.336-27785c4a`, or just the SHA.

2. **NEVER modify code while a benchmark is running.** It uses
   `target/release/aurora-lint`; rebuilding mid-run corrupts results. Make all
   changes and commits first.

3. **Wait for completion.** Fast-mode Juliet ~32-40 min, full Juliet ~40-50 min,
   real-world sqc-only ~10-15 min. Check `python -m bench status` at most every
   5 minutes, or just watch it.

4. **Compare runs** with `python -m bench compare`; `status RUN_ID` for a
   per-run summary. Historical runs carry a `-historical` suffix.

5. **Sequence**: implement → commit (+ push, if queueing) → build release →
   run benchmark → wait → analyze.

6. **Delta-adjudicate before citing precision/recall for a changed rule
   (CRITICAL).** `ground_truth` is keyed on exact
   `(project, commit, file, line, rule)` tuples adjudicated at a past
   snapshot. When a rule's detection logic changes (any commit under
   `src/rules/cert_c/**/*.rs` that alters what it flags — not a pure
   refactor), its new findings land at `(file, line)` pairs that were **never
   adjudicated**, so they fall outside the denominator in either direction. A
   raw-count jump and a flat "precision held" over the labeled sample can both
   look clean while the real picture is unmeasured. Before writing "precision
   improved/held" or "FP reduced" into a commit message, task note, or the
   paper:

   - **Gate the delta-adjudication task on any known-but-unfixed FP driver for
     that rule.** Adjudicating a dump that a cheap follow-up fix is about to
     shrink wastes the work — a structural fix to one rule's detection logic
     can cut its real-world finding count dramatically on its own. Search the
     backlog for open FP-reduction tasks against the same rule and add them
     with `--depends-on` so `next` skips the adjudication until they land;
     then re-measure.
   - Pull only that rule's new unlabeled findings:
     `bench realworld-unlabeled RUN --rule RULE_ID --project P --json`.
   - **Derive each project's in-scope file predicate from its section of
     `docs/design/realworld-corpus-scope.md` BEFORE batching.** A sizeable
     share of raw unlabeled findings can be out-of-scope noise (test
     harnesses, vendored deps, bindings) — this varies sharply by project, so
     read the section rather than assuming. Scoping afterwards means redoing
     completed batches. That doc is the tracked rationale; the
     machine-readable form is `scope_include`/`scope_exclude` in
     `data/benchmark_repos.json`. Your own pass's working data goes under
     `data/precision_audit/`, gitignored (see `docs/adr/0007`) — nothing a
     fresh clone has populated, and never the source of the predicate.
   - Batch ~110-150 findings, adjudicate, import with
     `bench realworld-import-labels`.
   - Only once `ground_truth` covers the new lines may a precision/recall
     claim about that rule be published.

### Querying results

The `bench` CLI (`status`, `compare`, `runs`, `realworld`, `realworld-score`)
reads **local SQLite only**. It cannot see the shared record and never will —
right for local work, never right for citing a project figure.

For real history use `benchmarking_db`'s MCP servers (`sqc-benchmark-query`:
`list_runs`, `get_run_status`, `compare_runs`, `get_realworld_results`,
`get_cwe_detail`), or that repo's CLI on the benchmark host. **No run counts or
metrics are quoted in this file on purpose** — a number here goes stale
silently. Ask the source.

### Refreshing published doc numbers

`python -m bench render-docs --realworld-run RUN [--juliet-run RUN] [--check]`
regenerates README's Benchmark Highlights table from whichever db it is handed,
bounded by the `<!-- BENCH:HIGHLIGHTS:START/END -->` markers; everything
outside them is hand-written and untouched. `--realworld-run` has no default on
purpose — pass a run you know is validly adjudicated, not the newest.

**Published numbers come from Postgres via `benchmarking_db`'s
`bin/refresh_tools_sqc_docs.py`** — not the better source, the only correct
one. It calls this repo's own `bench/render_docs.py` functions pointed at
Postgres, so output shape is identical and nothing here gains Postgres
awareness.

Pointing `render-docs` at local `data/benchmarks.db` is fine for writing up
your *own* runs. It must never produce a table committed to this project's
README or the paper: those numbers would describe one checkout while presenting
as the project's measurements. Plausible and wrong.

Either path, review the diff. The tool rewrites only the marker-bounded block;
prose near it is a judgment call it deliberately leaves alone.

---

## Task tracking

Task tracking is maintainer infrastructure, not part of what a clone needs to
build, test, or evaluate aurora-lint — same test as everywhere else in this
file. The backlog lives in a `todo-sqlite-cli` database the maintainer owns
and syncs across nodes; it is **not git-tracked and not part of this repo** —
a fresh clone has no task DB, and doesn't need one. (Earlier revisions of
this repo committed a `todo-sqlite-cli.db` per repo with a git merge driver
and pack-size tuning; that setup is retired — nothing task-related is
git-tracked anymore, so there is no DB to pull, merge, or run `doctor` on as
part of cloning or contributing here.)

If you're contributing without access to that DB, you don't need it: branch,
commit, and open a PR as normal, same as any other project. If you do have
access (ask the maintainer), tasks for this repo are tagged so they can be
told apart from `benchmarking_db`'s and `sqc_paper`'s within the same
database — rule behaviour, FP/FN work, docs, and packaging belong here;
ground_truth quality, corpus scope, and Postgres/backup infra belong to
`benchmarking_db`; paper drafting/figures/submission belong to `sqc_paper`.
Ask "which repo's files change" to decide, not the tag on the task, which
lies often enough to be useless alone. Adjudication itself isn't a
task-tracking concern at all — it's a PR to `benchmark_adjudication` (see
above).

**Task titles are internal and never published.** `CHANGELOG.md`'s
`[Unreleased]` block and the release notes are generated from the task DB,
but only from tasks tagged `release-note` whose body carries both a
`release-note: <bullet>` line and a `category: added|fixed|removed` line
(`docs/adr/0009`: the changelog is for users of the tool, three headings, no
"Changed"). A note that locates a defect in a real-world corpus
(`file.c:123`, disclosure/maintainer/CVE wording) is refused even when
tagged, and `scripts/check_changelog_safety.py` screens the committed file in
pre-commit, CI and the release workflow (`docs/adr/0007`). So when a done
task shipped something a user should hear about, tag it and write the note
and its category for publication — the title is not the note. The dated
release sections are curated by hand and the generator never touches them.

---

## Documentation

| File | Contents |
|------|----------|
| `README.md` | Tool overview, installation, usage, CLI reference |
| `docs/index.rst` | Developer guide: advanced usage, CI/CD, benchmarks, testing, contributing |
| `docs/adr/*.md` | Architectural Decision Records — settled policy questions, not in the Sphinx toctree. **Read before proposing to change a rule's core behavior, disable/deprioritize a rule off a benchmark result, or otherwise relitigate something already decided.** Unlike `docs/design/`, these don't go stale — read the index at `docs/adr/README.md` first. |
| `docs/design/*.md` | Scoping docs, not in the Sphinx toctree — read directly. **Their "Status" headers go stale once work ships**; trust `todo-sqlite-cli show <task>` instead, and check whether the feature needs a mention in `docs/cli-usage.rst`/`docs/architecture.rst`. |
| `docs/design/internal-capability-catalog.md` | Catalog of every reusable primitive in `src/utility/cert_c/*.rs` and `src/analyze/*.rs`. **Read before writing any new AST/text heuristic.** |
| `docs/design/gate-status-sop.md` | Weekly read on distance to the maintenance-mode gate and a publishable paper. Run it *here* — its table says which check lives in which repo. |
| `docs/design/realworld-corpus-scope.md` | Per-codebase oracle scope: which trees count as the shipped product and why. **Read its project section before batching a delta-adjudication or changing a runner `--exclude`.** |
| `../sqc_paper/` | The paper, in its own repo. Numbers in it must trace to Postgres via `benchmarking_db`. Its backlog and figure generator went with it. |

## Project Structure

- `src/rules/cert_c/` — CERT C rule implementations
- `src/analyze/` — analysis infrastructure (CFG, null state, VRA, prescan)
- `bench/` — benchmark infrastructure (runner, analyzer, SQLite DB, CLI)
- `data/` — benchmark database, prescan caches
- `scripts/` — workflow helpers, coverage gate
- `docs/` — developer guide, bibliography

## Code Navigation (clew)

Indexed by [`clew`](https://github.com/tvanfossen/clew), registered as the
`clew` MCP server in `.mcp.json` (gitignored — each machine runs `clew init`
once; it registers the server but installs nothing, so the machine also needs
the `clew-trace` package for `clew-mcp` to resolve). It serves a symbol
database — call graph, threads, locks, file docs — over `dossier` (everything
about one symbol in one call), `search` (a name, or a layer like
`corpus='locks'`), `index`, and `propose_declaration`.

**Prefer `dossier`/`search` over `grep`/`Read`** for "what calls X", "where is Y
defined", "what locks does this hold" — one call, call graph already resolved.
Read source directly only for what the index can point at but not contain
(exact comment text, line-by-line logic).

No manual indexing step is required: the DB lives outside the repo under
`~/.local/state/clew/targets/`, and the MCP tools build it on first use — a
fresh node with no `~/.local/state/clew` is expected, not broken. To build
eagerly (e.g. warming before a benchmark), run `clew --repo-root .`, and
`clew --repo-root . --rebuild` after non-trivial changes. **Omit `--output`
both times**: with it omitted clew writes where the MCP server reads; passing
`--output clew.db` writes into the current directory, which the server never
looks at, leaving a stray file and still paying for a cold build.

**Before implementing any new AST/text heuristic, check
`docs/design/internal-capability-catalog.md` first.** That catalog exists
because `search` matches literal token conjunctions: it finds a function
instantly when queried in words close to its own doc comment, and returns
nothing for a vague concept phrase. A rule once nearly re-implemented existing
cross-file macro detection from scratch because a keyword grep for "macro
detection" missed it. If the catalog does not cover it, try `dossier`/`search`
with vocabulary close to an actual doc comment, then grep
`src/utility/cert_c/` and `src/analyze/` by what the primitive *does*.

**New reusable capability that doesn't exist yet defaults to this utility
layer, not `lang_parsing_substrate`** — see
`docs/adr/0003-utility-layer-vs-substrate.md` for the line between the two
and when promotion to the substrate is worth it later.

## Build & Test

```bash
cargo build
cargo test --package aurora-lint --lib -- rules::cert_c::RULE_ID::tests  # inline unit tests
cargo test --package aurora-lint --lib -- RULE_ID  # all tests (inline + generated from .c files)
cargo fmt
```

## Rule Implementation

**Before changing a rule's detection behavior to reduce noise, or proposing
to disable/deprioritize a rule based on its benchmark numbers, read
`docs/adr/0001`, `0002` and `0005`.** These come up repeatedly and are
already settled: noise gets handled by suppression/config, not by softening
detection logic (0001); a low real-world TP rate alone doesn't mean a rule
is broken or unneeded (0002); and a misfire (the finding names a construct
that isn't actually there) is always a bug to fix regardless of corpus —
don't let 0001/0002 talk you out of fixing one (0005).

**Before resolving what an identifier occurrence refers to — its type,
qualifiers, or declaration — use `resolve_identifier_declarator` and its
neighbors, never a text/name match.** `docs/adr/0006` has three independent
rules that shipped real bugs by matching on spelling instead of resolving
scope.

**Before gating a rule on whether its node has a parser `ERROR` ancestor,
read `docs/adr/0008`.** Measured, not assumed: `ERROR` ancestry doesn't
predict correctness in either direction, and a blanket gate would silently
drop real findings from rules whose true output concentrates in damaged
files. Diagnose what was actually misread instead — usually a preprocessor
construct reaching a rule that assumes it's looking at a C expression.

**NEVER add embedded unit tests in rule implementation files:**
- ❌ NO `#[cfg(test)]` modules in `src/rules/cert_c/*/*/*.rs`
- ❌ NO inline test functions with hardcoded C snippets
- ✅ Test cases come from `.c` files in `tests/` (auto-generated into Rust tests)
- ✅ If a rule has no test cases, implement it WITHOUT tests — that is fine

For each new rule: create `src/rules/cert_c/CATEGORY/RULE_ID/rule_id_c.rs`,
register in `mod.rs`, enable in the TOML, then build and test — **and add a
block for it to every `conf/realworld/*-rules.toml`**, which the
`check-realworld-manifests` hook requires before the commit lands. Those
manifests are standalone (no `extends`), so a rule with no entry is silently
dark on the whole real-world suite and can never reach the oracle. Say
`enabled = true` unless the rule is categorically inapplicable to that
codebase; every `false` needs a comment naming one of the three reasons in
`conf/realworld/README.md`.

**Before fixing a macro-related FP/FN**, check whether
`src/analyze/macro_expand.rs` already solves it — do **not** reach for a
name-heuristic workaround. aurora-lint has a real, name-independent
macro-expansion
engine (`collect_function_macros`, `macro_nulls_param_indices` for free+null
"safe free" macros, `macro_output_param_indices` for output-param macros),
already wired into a growing list of rules. Don't trust a rule list quoted
here or anywhere else in prose — it is exactly the kind of live number this
file's own "Maintaining this file" section warns against, and it has
already gone stale twice. Get the current list directly:
`grep -rl 'macro_expand::' src/rules/`.
`docs/design/macro-expansion.md` has the rationale and a per-rule disposition
table; its "Status" header is stale, so trust the phase stock-takes below it.

**Before writing a new rule, check whether its defect concept already overlaps
an enabled rule** (search `rules_templates/rules-all.toml` descriptions and the
capability catalog). Overlap is expected — CERT-C's own rules/recommendations
split covers the same defect from two angles. **Default to letting both rules
fire.** Suppress one only on demonstrated *total* subsumption across every
ground-truth-labeled instance, not frequent co-location. See
`docs/design/cross-rule-overlap.md` for the policy and a counterexample where
hard precedence in either direction is measurably wrong.

## Git Commit Rules (CRITICAL)

**EXPLICITLY DENIED:**
- `git commit --no-verify` — never. Pre-commit hooks MUST pass; only humans skip
  hooks. Same for any other hook-skipping flag (`--no-gpg-sign`, etc.).
- `Co-Authored-By: Claude` — never add Claude as co-author.

  **The reason is placement, not prohibition.** Claude's contribution is
  acknowledged deliberately, in README.md's "AI Assistance" section. The trailer
  would repeat that fact in every one of thousands of commits, crowding out the
  message and telling a reader nothing the README has not already said clearly
  once. So do not read this as attribution being a compliance problem, and do
  not remove the README section for consistency. Acknowledge once, visibly.
  (`sqc_paper` deliberately differs and keeps the trailer — the PDF is its
  deliverable and nobody else works in its history.)

  **Enforced by a `commit-msg` hook** (`scripts/check_commit_message.py`), because
  prose alone did not hold. A human co-author named normally still passes.
  `commit-msg` is a *second* hook type, so a clone that ran `pre-commit
  install` before the hook existed has the config and no hook, silently. One
  manual pass fixes it:

  ```bash
  pre-commit install --hook-type commit-msg
  ```

  `default_install_hook_types` in `.pre-commit-config.yaml` covers every fresh
  install, so this is only for older clones.

**REQUIRED:** hooks pass before a commit succeeds; if they fail, fix the cause;
standard commit message format without AI attribution.

---

## Maintaining this file

This file is prepended to **every** session's context, on every node. A line
earns its place only by changing what an agent does. Before adding anything,
apply these:

- **Rules and rationale, not history.** Keep the decision rule and enough *why*
  that an agent will not "helpfully" undo it or misjudge a novel case. Cut the
  incident narrative that produced it — dated postmortems, which task collided
  with which, what a specific run measured. If an example is what makes a rule
  persuasive, compress it to one clause.
- **No live numbers, ids, or statuses.** Anything that changes on its own —
  run counts, metrics, "task N is pending at P5", active-task lists — goes
  stale silently and is worse than absent, because it reads as current. Name
  the source to ask instead.
- **State a thing once.** If it is already in `README.md`, `docs/index.rst` or
  a design doc, link it rather than restating it.
- **Prefer the imperative.** "Run X before Y" beats a paragraph explaining that
  running X before Y is generally advisable.
- **Put durable per-session facts in memory, not here.** Fleet topology, node
  capabilities and personal working preferences belong in the memory directory;
  this file is for the repo's own rules.
- When a section stops being true, delete it in the same commit that makes it
  untrue.
