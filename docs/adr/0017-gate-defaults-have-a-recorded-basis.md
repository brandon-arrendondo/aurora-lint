# 0017. Every numeric gate default has a recorded source, calibration, or proposed change

## Status

Proposed (2026-10-06), pending the maintainer's decision on the two open
items below. This is the aurora-lint counterpart of knots'
`ADR-0003: Every gate default has a recorded source or calibration`.

## Context

aurora-lint's CI and pre-commit configuration decide whether a change lands.
Two of the numbers behind those gates had no recorded reason, and a third
disagreed with itself. A default with no stated basis can't be defended, can't
be revisited when the code changes under it, and invites a reader to take it
for a published standard.

This ADR covers every numeric default found in `.pre-commit-config.yaml`,
`.github/workflows/*.yml` and `scripts/coverage-gate.sh`. There are only
these: the coverage floor and the AIRD gate. The other hooks (`cargo fmt`,
`cargo clippy -D warnings`, the project lints) take no threshold, and the
workflows' numbers are runner and tool versions, not gates. A **source** is a
primary document that states the number. A **calibration** is a measurement,
with its method and date. A default with neither is marked **no basis**.

## Decision

1. **A gate default is a source or a calibration, stated in the table below.**
   A new or changed default adds its row in the same change.
2. **A floor set under a measured value is a calibration, not a source.** It
   says where the project stood on the day, not what it should be.
3. **A number that appears in more than one place has one value.** The
   coverage gate's argument is passed explicitly by CI; the script's own
   default is the same number.

## The defaults

| Default | Where | Source or calibration |
|---------|-------|-----------------------|
| 75% line coverage | `ci.yml` (`scripts/coverage-gate.sh 75`), comment in `.pre-commit-config.yaml` | **Calibration, original (2026-03-24).** Introduced in the commit that added the gate, when the suite measured 76.6% line coverage (2,732 tests, excluding the paths below), so the floor was set 1.6 points under the measured value. **Source, after the fact.** 75% is the "commendable" level in Google's published guideline of 60% "acceptable", 75% "commendable" and 90% "exemplary" (Bender, Arguelles and Ivanković, "Code Coverage Best Practices", Google Testing Blog, 7 Aug 2020, which says it prefers teams choose their own value and that there is no ideal number). Nobody chose 75 from that source; it matches it. **Current coverage is not measured here**; CI computes it on every run and uploads `lcov.info`. |
| Coverage exclusions (`ui/`, `main.rs`, `integration.rs`, `progress.rs`, `export/`, `files/`, `manifest/`) | `scripts/coverage-gate.sh` | **No basis beyond the comment** ("untestable code": GUI, CLI entry, test harness, terminal and file I/O, TOML loading). They change what 75% means, so they are listed. The comment predates the current tree; whether each path is still all I/O is not re-checked here. |
| AIRD <= 85 | `.pre-commit-config.yaml` (`knots` hook, no `args:` override), `ci.yml` job name and step | **Calibration, inherited.** It is knots' own default (`--aird-threshold=85` in the `knots` hook), not an aurora-lint choice. knots records its basis in its ADR-0003: chosen because the 76-100 bucket held 1-2% of functions in the six calibration corpora, and it still selects the top ~1% of C (1.08% of the paper's six C corpora, 0.74% of held-out C). On Rust it selects 0.04% and on JS/TS 0.15%. aurora-lint's gated code is Rust and Python, so knots' own calibration says this gate rarely fires here. |

### AIRD on aurora-lint's own code (calibration, 2026-10-06)

Method: knots 1.18.0, `--format ndjson`, every tracked `*.rs` and `*.py` file
passed as a file list (how pre-commit invokes the hook) at `7414ccba`.

| Language | Functions | p99 | p99.9 | max | Over 85 |
|----------|----------:|----:|------:|----:|--------:|
| Rust | 9,082 | 67 | 84 | 86 | 1 |
| Python | 582 | 56 | 71 | 71 | 0 |

So the gate is near its ceiling: 20 Rust functions score 80 or more and one
scores 86. This measurement used knots 1.18.0. The hook is pinned to
`knots-pre-commit` `v1.13.1`, and knots changed how it counts since (its
ADR-0001), so **whether CI passes at this commit under the pinned version was
not checked here**. Moving the pin is a separate decision.

AIRD also depends on how knots is invoked. Passing a directory with `-r`
scores the same functions higher than passing the files, through the
file-level coupling multiplier: `knots -r src bench scripts` reports 42
functions over 85 where the file list reports 1, and one function that scores
100 under `-r` scores 85 as a file list. The hook uses the file list, so the
gate means the file-list figure; a reader reproducing it with `-r` will see a
different number.

## Open items for the maintainer

1. **`scripts/coverage-gate.sh` disagreed with itself.** Its usage text says
   the default threshold is 80, its code uses 81, and the gate everyone runs
   is 75. Nothing relies on the default (CI passes 75), but a bare invocation
   would gate at a number nobody chose. This change sets both to 75.
2. **The AIRD gate and the pin.** Two things are proposed, not done: (a) move
   the `knots` hook from `v1.13.1` to a release whose counting matches the
   measurement above, and (b) if one Rust function over 85 is unacceptable
   there, either extract it or record a justified suppression. Neither is
   made here because both change what the hook passes.
3. **The knots scope comment names `mcp_servers/`**, which does not exist in
   the tree. The hook's `types_or: [rust, python]` selects by file type, so
   nothing is lost, but the comment is stale.

## Not covered

- The coverage figure today; run `scripts/coverage-gate.sh 75` where
  `cargo-llvm-cov` is installed.
- Whether the exclusion list still matches the code it describes.
- `.pre-commit-config.yaml`'s commented `--cognitive-threshold=20` example. It
  is an example, not a shipped default; knots' ADR-0003 records that 20 has
  no source.
