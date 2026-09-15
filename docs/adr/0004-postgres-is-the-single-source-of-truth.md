# 0004. Postgres (via `benchmarking_db`) is the single source of truth for published data; local storage is working data only

## Status

Accepted

## Context

Every OFFICIAL number this project publishes — README, the paper, a release
note, any claim made outside this checkout — has to trace to one place.
Without a firm rule, it's tempting to cite a fast local run because it's
convenient, or to treat a local SQLite number as "close enough" to a project
figure.

aurora-lint fully supports running benchmarks locally
(`data/benchmarks.db`, SQLite, gitignored) — that's necessary for
day-to-day development, A/B comparisons while iterating on a rule fix, and
evaluating the tool on an arbitrary codebase without needing shared
infrastructure. That's deliberate and shouldn't be discouraged. The tension
is that local runs are fast and always available, but describe only that
one checkout's run — not comparable across nodes/commits/time without a
shared, durable, authoritative record.

## Decision

Postgres (`sqc_bench`, reached through the separate `benchmarking_db` repo)
is the sole source of truth for both historical benchmark data and
adjudication (`ground_truth`) data. Anything published as this project's
measurement traces to Postgres. Full mechanics are in `CLAUDE.md`'s
Benchmark Workflow section; this ADR is the policy record for *why*.

Local storage (SQLite `data/benchmarks.db`, CSVs, scratch files) is fully
legitimate for:

- Day-to-day development and A/B comparisons while iterating on a fix, on
  any node — this is how most FP-reduction work in this project gets
  measured before it's ever adjudicated.
- Evaluating aurora-lint against an arbitrary codebase (the "stranger
  cloning this repo" use case `CLAUDE.md` tests new benchmarking code
  against).

It is never legitimate for:

- A number transcribed into README, the paper, a release note, or any
  external claim.
- A "project" precision/recall figure — a local number describes that
  checkout's run, not the project's measurement, even if it was measured
  carefully.

The ingest path for anything meant to count as official: generate the
needed data (locally or through the queue), then land it in Postgres. The
official benchmarking server is what runs the real-world and Juliet suites
against specific pinned commits to populate Postgres for citable runs — that
node's output is what gets treated as canonical for a given commit. For A/B
comparisons during development, local node benchmarking is fine and
expected; it just isn't citable on its own.

## Consequences

- `bench realworld-import-labels --local-oracle` writing to local SQLite is
  something a session explicitly opts into, never something it falls into
  by habit.
- Don't reintroduce a per-node cache/mirror/sync of the Postgres data for
  speed or offline use — that restores the "which copy is current" problem
  centralizing in Postgres was adopted to kill, and this repo stays
  Postgres-blind by design (see `CLAUDE.md`).
- `render-docs` pointed at local `data/benchmarks.db` is fine for writing up
  a node's own runs; it must never produce a table that lands in this
  project's README or the paper.
- The local-A/B-then-delta-adjudicate pattern (measure a fix's before/after
  on a local checkout, label the result "local, not a project measurement,"
  then hand the new/moved findings to `benchmarking_db` for Postgres
  adjudication before citing precision) is the sanctioned shape for rule
  work — not a workaround, the intended path.
