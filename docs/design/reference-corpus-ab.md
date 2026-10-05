# Reference shadow corpus: A/B a rule change on code nobody tuned against

**Status:** tooling in place (`bench reference-fetch`, `bench reference-ab`);
not yet part of any review gate.

## Why

The real-world oracle corpora in `data/benchmark_repos.json` are where rules
get tuned. Every fix gets checked against them, so over time they stop being an
unbiased sample. A change can look clean across all of them while it moves
findings on the kind of code they don't contain. More oracle corpora help, but
each one costs adjudication and joins the tuned set as soon as it lands.

The shadow set solves this differently. It is a list of C codebases, each
pinned to a commit SHA, that is **never labeled and never tuned against**. It
can't tell you whether a change is right. It tells you **what else the change
moved**: findings added or removed, per rule and per codebase, and especially
movement in rules the change was not meant to touch.

## The rules for using it

1. **No labels, ever.** Shadow-set findings never go into `ground_truth`,
   locally or in Postgres, and never feed a precision/recall figure.
   `bench realworld-import-labels` refuses any project named in
   `data/reference_corpus.json`, and a test keeps the two name sets disjoint.
   If a shadow codebase is ever promoted to an oracle corpus, it moves out of
   this file first.
2. **No reporting.** Its findings, counts and deltas are not published,
   cited, or sent upstream. The one exception is a critical defect worth
   disclosing, which goes through the normal disclosure process
   (`docs/adr/0007`) like any other.
3. **Don't tune to it.** A shadow delta is a prompt to look, not a target. If
   one exposes a misfire, fix it on its merits (`docs/adr/0005`) with a
   `tests/` fixture that reproduces the construct, not with the shadow file
   as evidence. A change whose only justification is "fewer shadow findings"
   is overfitting to a second set, and that defeats the purpose.
4. **Selection is for breadth only.** Codebases are chosen to cover domains,
   coding styles and sizes the oracle corpora don't. License terms and how
   receptive upstream is to contributions were deliberately left out, because
   nothing here is ever contributed back.

## What is in it

`data/reference_corpus.json` has `name`, `repo`, `ref` (the release tag the pin
came from, or the default branch where a project tags nothing), `commit`,
`domain` and `tier`. Pins were resolved with `git ls-remote` against each
project's latest stable release. Re-pinning costs nothing, because no labels
depend on these SHAs. But an A/B only compares like with like when both sides
are scanned at the same pins, and the tool guarantees that because it scans
both binaries in one invocation.

Tiers are cumulative: `quick` (small codebases, cheap enough for every change),
`standard`, and `large` (kernels, interpreters, databases; opt in). Every
codebase is scanned whole under `rules_templates/rules-all.toml`. There is no
per-codebase manifest, include path or scope exclusion, because that tuning is
what makes the oracle set non-neutral.

## Running it

```bash
# A base binary, built at the commit before the change:
git worktree add --detach /tmp/base-wt HEAD~1
(cd /tmp/base-wt && CARGO_TARGET_DIR=/tmp/base-target cargo build --release)

cargo build --release                      # the target binary
python -m bench reference-fetch --tier quick
python -m bench reference-ab --base /tmp/base-target/release/aurora-lint \
    --tier quick --rules EXP33-C,EXP34-C
```

Checkouts go under `BENCH_ROOT/shadow_corpus/` (shallow, detached at the pin, and
re-checked and cleaned before every scan). Scans are cached under
`data/reference_ab/scans/<binary sha256>/`, so a base binary is scanned once
however many targets are compared against it. The full delta (every added,
removed and message-changed finding) is written to
`data/reference_ab/ab-<base>-<target>.json`. All of `data/reference_ab/` is
gitignored local working data.

## Reading the output

- **A rule marked `<- not an intended rule`** is the signal this exists for.
  Either the change has an effect the author didn't mean, or the rule list
  passed to `--rules` was incomplete. Explain it before calling the change
  clean.
- **Breadth** (the `codebases` column). Movement concentrated in one codebase
  usually means one construct. Movement spread across many usually means a
  general behaviour change.
- **A scan that fails or times out on only one side** is a regression on
  held-out code. Treat it as a bug.
- **Message-only changes** count separately. The location is the same but the
  text differs.

This complements the oracle-corpus delta-adjudication step in `CLAUDE.md`
rather than replacing it. Precision and recall still come only from the oracle.
