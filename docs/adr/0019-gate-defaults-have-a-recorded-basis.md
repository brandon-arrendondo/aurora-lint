# 0019. Every numeric gate default has a recorded source, calibration, or proposed change

## Status

Proposed (2026-10-06), pending the maintainer's decision on the open
items below. This is the aurora-lint counterpart of knots'
`ADR-0003: Every gate default has a recorded source or calibration`.

## Context

aurora-lint's CI and pre-commit configuration decide whether a change lands.
The draft found no local recorded basis for the inherited AIRD threshold,
and the coverage default disagreed with the floor CI passes. A default with no stated basis can't be defended, can't
be revisited when the code changes under it, and invites a reader to take it
for a published standard.

This ADR covers numeric quality thresholds found in `.pre-commit-config.yaml`,
`.github/workflows/*.yml` and `scripts/`. There are only
these: the coverage floor and the AIRD gate. Re-checked against
`93fb2c464` on 2026-10-15; the robustness job also sets a 45-minute timeout
and 1,500 mutants, which control execution time and test sampling, not a
quality score. Neither has a recorded calibration here.
The other hooks (`cargo fmt`,
`cargo clippy -D warnings`, the project lints) take no threshold, and the
remaining workflow numbers are runner and tool versions, not quality thresholds. A **source** is a
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
| 75% line coverage | `ci.yml` (`scripts/coverage-gate.sh 75`), comment in `.pre-commit-config.yaml` | **Calibration, original (2026-03-24).** Introduced in `eb2cd4915`, the commit that added the gate, when the suite measured 76.6% line coverage (2,732 tests, excluding only `ui/` and `main.rs`), so the floor was set 1.6 points under the measured value. **Source, after the fact.** 75% is the "commendable" level in Google's published guideline of 60% "acceptable", 75% "commendable" and 90% "exemplary" (Bender, Arguelles and Ivanković, "Code Coverage Best Practices", [Google Testing Blog, 7 Aug 2020](https://testing.googleblog.com/2020/08/code-coverage-best-practices.html), which says it prefers teams choose their own value and that there is no ideal number). Nobody chose 75 from that source; it matches it. **Current coverage is not measured here**; CI computes it on every run and uploads `lcov.info`. |
| Coverage exclusions (`ui/`, `main.rs`, `integration.rs`, `progress.rs`, `export/`, `files/`, `manifest/`) | `scripts/coverage-gate.sh` | **No basis beyond the comment** ("untestable code": GUI, CLI entry, test harness, terminal and file I/O, TOML loading). They change what 75% means, so they are listed. The comment predates the current tree; whether each path is still all I/O is not re-checked here. |
| AIRD <= 85 | `.pre-commit-config.yaml` (`knots` hook, no `args:` override), `ci.yml` job name and step | **Calibration, inherited.** It is knots' own default (`--aird-threshold=85` in the `knots` hook), not an aurora-lint choice. knots records its basis in its [ADR-0003](https://github.com/brandon-arrendondo/knots/blob/6a719eb68e574894752c331bcd244e3a40b97147/docs/adr/0003-gate-defaults-have-a-recorded-basis.md): chosen because the 76-100 bucket held 1-2% of functions in the six calibration corpora, and it still selects the top ~1% of C (1.08% of the paper's six C corpora, 0.74% of held-out C). On Rust it selects 0.04% and on JS/TS 0.15%. aurora-lint's gated code is Rust and Python; the cited calibration covers Rust, not Python, and uses knots 1.18.0 rather than the pinned 1.13.1. It does not establish the firing rate on current aurora-lint. |

### AIRD on aurora-lint's own code (historical calibration, 2026-10-06)

Method: knots 1.18.0, `--format ndjson`, every tracked `*.rs` and `*.py` file
passed as a file list (how pre-commit invokes the hook) at `7414ccba`.

| Language | Functions | p99 | p99.9 | max | Over 85 |
|----------|----------:|----:|------:|----:|--------:|
| Rust | 9,082 | 67 | 84 | 86 | 1 |
| Python | 582 | 56 | 71 | 71 | 0 |

At that snapshot, 20 Rust functions scored 80 or more and one scored 86.
These are historical figures, not a measurement of current main. This
measurement used knots 1.18.0. The hook is pinned to
`knots-pre-commit` `v1.13.1`, and knots changed how it counts since (its
ADR-0001), so **whether CI passes at this commit under the pinned version was
not checked by that measurement**. Moving the pin is a separate decision.

AIRD also depends on how knots is invoked. In that historical measurement, passing a directory with `-r`
scored the same functions higher than passing the files, through the
file-level coupling multiplier: `knots -r src bench scripts` reported 42
functions over 85 where the file list reported 1, and one function that scored
100 under `-r` scored 85 as a file list. The hook uses the file list, so the
gate means the file-list figure; a reader reproducing it with `-r` will see a
different number.

## Open items for the maintainer

1. **`scripts/coverage-gate.sh` disagreed with itself.** Its usage text says
   the default threshold is 80, its code uses 81, and the gate everyone runs
   is 75. Nothing relies on the default (CI passes 75), but a bare invocation
   would gate at a different floor. The 81% default did have a dated
   calibration: `e1cfcda7e` (2026-04-01) records 81.05% measured coverage.
   That does not justify calling it the current CI floor. This change sets
   both to the 75 that CI passes.
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
